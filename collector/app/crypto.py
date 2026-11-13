"""原件加密：AES-256-GCM（cryptography）。

密文布局（所有字段均为大端/定长）：

    MAGIC(10) | VERSION(1) | NONCE(12) | CIPHERTEXT+TAG(n)

- MAGIC 固定为 ``b"INVPDFGCM"``，用于快速识别明文/密文，绝不把明文误当密文；
- AES-GCM 的 AAD 绑定附件身份（代际、UID、MIME 部分序号、文件名、明文摘要），
  因此把**另一附件的密文**换进来会因 AAD 不匹配而解密失败；
- 数据库另存整份密文的 sha256，文件被截断/篡改/替换时在解密前即被拒绝。

密钥只从 ``data_dir`` 之外的只读文件加载，支持 32 字节原始密钥或 64 位十六进制。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"INVPDFGCM"
VERSION = 1
HEADER_LEN = len(MAGIC) + 1 + 12  # magic + version + nonce
TAG_LEN = 16
MIN_BLOB_LEN = HEADER_LEN + TAG_LEN
_KEY_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class CryptoError(RuntimeError):
    """密钥加载/密文解析类错误（配置或数据问题）。"""


class MigrationKeyMismatchError(CryptoError):
    """当前加载的密钥与库中已有密文不一致，拒绝继续迁移。"""


class BlobIntegrityError(CryptoError):
    """密文损坏、被篡改或被其它附件的密文替换，必须拒绝下载。"""


@dataclass(frozen=True)
class BlobIdentity:
    """一个附件原件的稳定身份，写入 AES-GCM AAD。"""

    uidvalidity: int
    uid: int
    part_number: str
    filename: str
    plain_sha256: str
    plain_size: int

    def aad(self) -> bytes:
        payload = {
            "domain": "invoice-pdf-blob",
            "v": VERSION,
            "uidvalidity": int(self.uidvalidity),
            "uid": int(self.uid),
            "part": self.part_number,
            "filename": self.filename,
            "sha256": self.plain_sha256,
            "size": int(self.plain_size),
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_key_file(path: str, data_dir: str) -> tuple[bytes, str]:
    """从数据目录之外的只读文件加载 256 位密钥。

    返回 ``(key, key_id)``。任何"密钥可能被数据备份带出"或密钥格式不对的情况
    都在启动阶段直接失败，避免带病运行。
    """
    real_path = os.path.realpath(path)
    real_data = os.path.realpath(data_dir)
    if os.path.commonpath([real_data, real_path]) == real_data:
        raise CryptoError(
            f"密钥文件 {real_path} 位于数据目录 {real_data} 之内；"
            "密钥必须放在数据目录之外，避免随原件备份一起泄露"
        )
    if not os.path.isfile(real_path):
        raise CryptoError(f"密钥文件不存在: {real_path}")
    try:
        # 始终以只读方式打开，绝不回写/轮换密钥
        with open(real_path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        raise CryptoError(f"密钥文件读取失败: {exc}") from exc

    if len(raw) == 32:
        # 原始二进制密钥：绝不 strip —— 任意字节都可能是密钥的一部分
        key = raw
    else:
        stripped = raw.strip()
        if len(stripped) == 64 and _KEY_HEX_RE.match(
            stripped.decode("ascii", errors="ignore")
        ):
            key = bytes.fromhex(stripped.decode("ascii"))
        elif len(stripped) == 32:
            # 32 字节原始密钥 + 文件末尾换行/空白
            key = stripped
        else:
            raise CryptoError(
                f"密钥文件长度不合法（{len(raw)} 字节）："
                "需要 32 字节原始密钥或 64 位十六进制"
            )
    key_id = hashlib.sha256(key).hexdigest()[:32]
    return key, key_id


class BlobCipher:
    def __init__(self, key: bytes, key_id: str) -> None:
        if len(key) != 32:
            raise CryptoError("AES-256 需要 32 字节密钥")
        self._key = bytes(key)
        self._aes = AESGCM(self._key)
        self.key_id = key_id

    @classmethod
    def from_file(cls, path: str, data_dir: str) -> "BlobCipher":
        key, key_id = load_key_file(path, data_dir)
        return cls(key, key_id)

    @staticmethod
    def is_ciphertext(blob: bytes) -> bool:
        return len(blob) >= MIN_BLOB_LEN and blob.startswith(MAGIC)

    def encrypt(self, plaintext: bytes, identity: BlobIdentity) -> bytes:
        nonce = os.urandom(12)
        # 防御性校验：AAD 中的明文摘要必须与实际明文一致
        if sha256_hex(plaintext) != identity.plain_sha256:
            raise CryptoError("待加密明文的摘要与附件身份不一致")
        sealed = self._aes.encrypt(nonce, plaintext, identity.aad())
        return MAGIC + bytes([VERSION]) + nonce + sealed

    def decrypt(self, blob: bytes, identity: BlobIdentity,
                expected_cipher_sha256: str | None = None) -> bytes:
        """解密并校验完整性；任何异常都转换为 BlobIntegrityError。

        调用方（下载接口）必须把异常当作"拒绝下载"，不能返回部分内容。
        """
        if expected_cipher_sha256:
            actual = sha256_hex(blob)
            # 常量时间比较，避免任何摘要侧信道
            if not hmac.compare_digest(actual, expected_cipher_sha256):
                raise BlobIntegrityError("密文文件摘要与索引不一致（损坏或被替换）")
        if len(blob) < MIN_BLOB_LEN:
            raise BlobIntegrityError("密文长度不足")
        if not blob.startswith(MAGIC):
            raise BlobIntegrityError("密文魔数不匹配（可能是明文或被替换）")
        version = blob[len(MAGIC)]
        if version != VERSION:
            raise BlobIntegrityError(f"不支持的密文版本: {version}")
        nonce = blob[len(MAGIC) + 1:HEADER_LEN]
        sealed = blob[HEADER_LEN:]
        try:
            plaintext = self._aes.decrypt(nonce, sealed, identity.aad())
        except InvalidTag as exc:
            raise BlobIntegrityError(
                "AES-GCM 校验失败：密文损坏或来自其它附件"
            ) from exc
        if not hmac.compare_digest(sha256_hex(plaintext), identity.plain_sha256):
            raise BlobIntegrityError("解密后的明文摘要不匹配")
        return plaintext
