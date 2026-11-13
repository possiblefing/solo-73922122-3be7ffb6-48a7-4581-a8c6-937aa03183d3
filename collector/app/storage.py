"""原件落盘：staging 与正式文件一律是 AES-256-GCM 密文。

目录布局（相对 blob_root）：
    uidvalidity-<UIDVALIDITY>/uid-<UID>/<部分序号>__<文件名>.enc

- 新采集 PDF 在内存中即加密，暂存文件（staging）和发布后的正式文件都只有密文，
  明文从不落到收票原件目录；
- 半封附件只存在于 staging，API 只索引 blob_root 下的正式文件，因此断流/落盘
  失败/进程退出都不会暴露半封附件；
- 正式目录使用 os.replace 原子发布（同文件系统内为原子操作）；
- 路径由 UIDVALIDITY、UID、MIME 部分序号决定，重试天然幂等，不会重复或覆盖错文件。

历史明文迁移使用另一条路径（见 migration.py）：密文先写入单独的迁移暂存区，
全部就绪后才在同一 SQLite 事务中切换附件索引，旧明文文件保持可下载直到切换成功。
"""
from __future__ import annotations

import os
import shutil
import uuid
from dataclasses import dataclass
from typing import Sequence

from .crypto import BlobCipher, BlobIdentity, sha256_hex
from .pdf_extract import PdfPart, stored_filename

CIPHER_SUFFIX = ".enc"


@dataclass(frozen=True)
class EncryptedBlob:
    """已加密附件在正式目录中的位置与完整性信息。"""

    storage_path: str
    plain_sha256: str
    cipher_sha256: str
    plain_size: int
    cipher_size: int


def cipher_filename(plain_stored_name: str) -> str:
    return plain_stored_name + CIPHER_SUFFIX


def plain_name_from_cipher(cipher_stored_name: str) -> str:
    """密文文件名 -> 明文原名（用于校验 AAD 中绑定的身份）。"""
    if cipher_stored_name.endswith(CIPHER_SUFFIX):
        return cipher_stored_name[: -len(CIPHER_SUFFIX)]
    return cipher_stored_name


class Storage:
    def __init__(self, blob_root: str, staging_root: str,
                 migration_staging_root: str, cipher: BlobCipher) -> None:
        self.blob_root = blob_root
        self.staging_root = staging_root
        self.migration_staging_root = migration_staging_root
        self._cipher = cipher
        os.makedirs(blob_root, exist_ok=True)
        os.makedirs(staging_root, exist_ok=True)
        os.makedirs(migration_staging_root, exist_ok=True)

    # ---- 路径 ----
    @property
    def key_id(self) -> str:
        return self._cipher.key_id

    def relative_dir(self, uidvalidity: int, uid: int) -> str:
        return os.path.join(f"uidvalidity-{uidvalidity}", f"uid-{uid}")

    def cipher_relative_path(self, uidvalidity: int, uid: int,
                             plain_stored_name: str) -> str:
        return os.path.join(
            self.relative_dir(uidvalidity, uid), cipher_filename(plain_stored_name)
        )

    def absolute_path(self, relative_path: str) -> str:
        return os.path.join(self.blob_root, relative_path)

    # ---- 采集：staging -> 原子发布 ----
    def new_staging_dir(self) -> str:
        path = os.path.join(self.staging_root, f"tmp-{uuid.uuid4().hex}")
        os.makedirs(path, exist_ok=False)
        return path

    def new_migration_staging_dir(self, job_id: int) -> str:
        path = os.path.join(self.migration_staging_root, f"job-{job_id}")
        shutil.rmtree(path, ignore_errors=True)
        os.makedirs(path, exist_ok=False)
        return path

    def write_staged(self, staging_dir: str, part: PdfPart,
                     uidvalidity: int, uid: int) -> EncryptedBlob:
        """在内存中加密单个 PDF，把密文写入 staging（临时文件 + fsync + rename）。"""
        name = stored_filename(part)
        identity = BlobIdentity(
            uidvalidity=uidvalidity, uid=uid, part_number=part.part_number,
            filename=name, plain_sha256=sha256_hex(part.payload),
            plain_size=len(part.payload),
        )
        ciphertext = self._cipher.encrypt(part.payload, identity)
        staged_path = os.path.join(staging_dir, cipher_filename(name))
        tmp_path = os.path.join(staging_dir, f".{name}.part")
        with open(tmp_path, "wb") as fh:
            fh.write(ciphertext)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, staged_path)
        self._fsync_dir(staging_dir)
        return EncryptedBlob(
            storage_path=self.cipher_relative_path(uidvalidity, uid, name),
            plain_sha256=identity.plain_sha256,
            cipher_sha256=sha256_hex(ciphertext),
            plain_size=len(part.payload),
            cipher_size=len(ciphertext),
        )

    def publish_all(self, staging_dir: str, parts: Sequence[PdfPart],
                    blobs: Sequence[EncryptedBlob],
                    uidvalidity: int, uid: int) -> list[EncryptedBlob]:
        """整封附件密文全部落盘成功后，一次性原子发布到正式目录。"""
        rel_dir = os.path.join(self.blob_root, self.relative_dir(uidvalidity, uid))
        os.makedirs(rel_dir, exist_ok=True)
        for part in parts:
            name = stored_filename(part)
            src = os.path.join(staging_dir, cipher_filename(name))
            dst = os.path.join(rel_dir, cipher_filename(name))
            os.replace(src, dst)
        self._fsync_dir(rel_dir)
        return list(blobs)

    def discard(self, staging_dir: str) -> None:
        """失败/断流后清理该封的全部临时文件。"""
        shutil.rmtree(staging_dir, ignore_errors=True)

    def discard_migration_staging(self, job_id: int) -> None:
        shutil.rmtree(
            os.path.join(self.migration_staging_root, f"job-{job_id}"),
            ignore_errors=True,
        )

    def cleanup_stale_staging(self) -> int:
        """进程启动时清掉上次崩溃遗留的采集临时目录，返回清理数量。

        迁移暂存区单独清理（见 MigrationManager.startup_cleanup），
        两处都只可能存放密文。
        """
        removed = 0
        if not os.path.isdir(self.staging_root):
            return removed
        for name in os.listdir(self.staging_root):
            if name.startswith("tmp-"):
                shutil.rmtree(os.path.join(self.staging_root, name), ignore_errors=True)
                removed += 1
        return removed

    def cleanup_stale_migration_staging(self) -> int:
        removed = 0
        if not os.path.isdir(self.migration_staging_root):
            return removed
        for name in os.listdir(self.migration_staging_root):
            if name.startswith("job-"):
                shutil.rmtree(
                    os.path.join(self.migration_staging_root, name), ignore_errors=True
                )
                removed += 1
        return removed

    def remove_plain_file(self, relative_path: str) -> bool:
        """删除历史明文原件的正式文件；文件已不存在视为已清理。"""
        abs_path = self.absolute_path(relative_path)
        try:
            os.remove(abs_path)
        except FileNotFoundError:
            return False
        self._fsync_dir(os.path.dirname(abs_path))
        return True

    @staticmethod
    def _fsync_dir(path: str) -> None:
        try:
            fd = os.open(path, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            pass
