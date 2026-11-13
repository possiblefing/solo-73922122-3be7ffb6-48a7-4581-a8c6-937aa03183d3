"""原件下载：密文解密后返回原 PDF；任何完整性问题一律拒绝，不返回部分内容。

并发约定（BlobGate）：
- 下载在"读锁"内重新读取索引 -> 读取文件 -> 解密校验 -> 得到完整内存字节后释放；
- 迁移清理旧明文在"写锁"内删除文件。
两者互斥。因此：
- 迁移绝不可能在下载读取文件的中途删除文件；
- 下载在放行响应时已经拿到完整字节，慢客户端也不会让"已获准的下载"被截断；
- 索引行也只在读锁内读取，不会读到切换前旧行、却在切换清理后去开旧文件。
"""
from __future__ import annotations

import io
import os
import threading
import zipfile

from .crypto import BlobCipher, BlobIdentity, BlobIntegrityError
from .database import Database
from .storage import Storage, plain_name_from_cipher

class BlobGate:
    """读写互斥门：下载/读取持读锁，迁移清理持写锁（写者优先避免饥饿）。"""

    def __init__(self) -> None:
        self._cond = threading.Condition()
        self._readers = 0
        self._writer = False
        self._waiting_writers = 0

    class _Read:
        def __init__(self, gate: "BlobGate") -> None:
            self._gate = gate

        def __enter__(self) -> None:
            self._gate._acquire_read()

        def __exit__(self, *exc: object) -> None:
            self._gate._release_read()

    class _Write:
        def __init__(self, gate: "BlobGate") -> None:
            self._gate = gate

        def __enter__(self) -> None:
            self._gate._acquire_write()

        def __exit__(self, *exc: object) -> None:
            self._gate._release_write()

    def read(self) -> "_Read":
        return BlobGate._Read(self)

    def write(self) -> "_Write":
        return BlobGate._Write(self)

    def _acquire_read(self) -> None:
        with self._cond:
            while self._writer or self._waiting_writers > 0:
                self._cond.wait()
            self._readers += 1

    def _release_read(self) -> None:
        with self._cond:
            self._readers -= 1
            if self._readers == 0:
                self._cond.notify_all()

    def _acquire_write(self) -> None:
        with self._cond:
            self._waiting_writers += 1
            try:
                while self._writer or self._readers > 0:
                    self._cond.wait()
                self._writer = True
            finally:
                self._waiting_writers -= 1

    def _release_write(self) -> None:
        with self._cond:
            self._writer = False
            self._cond.notify_all()


class BlobUnavailableError(RuntimeError):
    """密文损坏 / 被替换 / 缺失：必须拒绝下载。"""


def _unique_zip_names(pairs: list[tuple[str, str]]) -> list[str]:
    """生成 ZIP 内唯一文件名。

    ``pairs`` 为 (下载名, 落盘名)。落盘名带部分序号前缀（如 ``1.2__``），
    同名附件因此可以稳定区分；只有确实重名时才追加序号。
    """
    names: list[str] = []
    used: set[str] = set()
    counts: dict[str, int] = {}
    for download_name, _ in pairs:
        counts[download_name] = counts.get(download_name, 0) + 1
    for download_name, stored_name in pairs:
        # 重名的一组全部改用带部分序号的落盘名，保持对称、可预测
        candidate = stored_name if counts[download_name] > 1 else download_name
        if candidate in used:
            stem, dot, ext = candidate.rpartition(".")
            index = 2
            while f"{stem} ({index}){dot}{ext}" in used:
                index += 1
            candidate = f"{stem} ({index}){dot}{ext}"
        used.add(candidate)
        names.append(candidate)
    return names


def _identity_from_attachment(att) -> BlobIdentity:
    # AAD 绑定的是落盘名（<部分序号>__<原文件名>），采集与迁移都按此加密；
    # 索引里的 filename 只是下载时展示的原文件名，二者不能混用。
    return BlobIdentity(
        uidvalidity=int(att["uidvalidity"]),
        uid=int(att["uid"]),
        part_number=str(att["part_number"]),
        filename=plain_name_from_cipher(os.path.basename(str(att["storage_path"]))),
        plain_sha256=str(att["plain_sha256"] or ""),
        plain_size=int(att["size_bytes"]),
    )


def _read_bytes(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def decode_attachment(storage: Storage, cipher: BlobCipher, att) -> bytes:
    """读取并解密单个附件。调用前必须已持有 BlobGate 读锁（或明知无并发）。

    任何异常都转换为 BlobUnavailableError；调用方必须拒绝，绝不返回部分内容。
    """
    state = att["storage_state"]
    abs_path = storage.absolute_path(str(att["storage_path"]))
    root = os.path.realpath(storage.blob_root)
    target = os.path.realpath(abs_path)
    try:
        inside = os.path.commonpath([root, target]) == root
    except ValueError:
        inside = False
    if not inside:
        raise BlobUnavailableError("原件路径越界")
    if not os.path.isfile(target):
        raise BlobUnavailableError("原件缺失")
    try:
        blob = _read_bytes(target)
    except OSError as exc:
        raise BlobUnavailableError(f"原件读取失败: {exc}") from exc

    if state == "cipher":
        if not att["plain_sha256"] or not att["cipher_sha256"]:
            raise BlobUnavailableError("密文索引缺少完整性摘要")
        try:
            return cipher.decrypt(
                blob, _identity_from_attachment(att), str(att["cipher_sha256"])
            )
        except BlobIntegrityError as exc:
            raise BlobUnavailableError(str(exc)) from exc
    if state == "plain":
        # 历史明文迁移期间的兼容读取；迁移完成后索引不会再是 plain
        if not blob.startswith(b"%PDF"):
            raise BlobUnavailableError("明文原件内容异常（非 PDF）")
        return blob
    raise BlobUnavailableError(f"未知的存储状态: {state}")


class DownloadService:
    """下载入口：索引读取、文件读取、解密都在同一个 BlobGate 读锁内完成。"""

    def __init__(self, db: Database, storage: Storage, cipher: BlobCipher,
                 gate: BlobGate) -> None:
        self._db = db
        self._storage = storage
        self._cipher = cipher
        self._gate = gate

    def attachment_pdf(self, attachment_pk: int) -> tuple[str, bytes]:
        with self._gate.read():
            row = self._db.get_attachment(attachment_pk)
            if row is None:
                raise KeyError("附件不存在")
            payload = decode_attachment(self._storage, self._cipher, row)
            return str(row["filename"]), payload

    def source_bundle_zip(self, uidvalidity: int, uid: int) -> bytes:
        with self._gate.read():
            epoch = self._db.query_one(
                "SELECT id FROM mailbox_epochs WHERE uidvalidity=?",
                (uidvalidity,),
            )
            if epoch is None:
                raise KeyError(f"UIDVALIDITY={uidvalidity} 代际不存在")
            msg = self._db.get_message(epoch["id"], uid)
            if msg is None:
                raise KeyError(f"UIDVALIDITY={uidvalidity}, UID={uid} 无记录")
            attachments = self._db.list_attachments_with_source(msg["id"])
            if not attachments:
                raise KeyError("该邮件没有已落盘的 PDF 附件")
            # 先逐份解密到内存，全部成功后才组装 ZIP：绝不返回部分 ZIP
            payloads = [
                (str(att["filename"]), str(att["storage_path"]),
                 decode_attachment(self._storage, self._cipher, att))
                for att in attachments
            ]
        # 同名附件（同一封里的 invoice.pdf）用部分序号前缀区分，避免 ZIP 内重名丢失
        names = _unique_zip_names(
            [(filename, plain_name_from_cipher(os.path.basename(path)))
             for filename, path, _ in payloads]
        )
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, (_, _, payload) in zip(names, payloads):
                zf.writestr(name, payload)
        return buffer.getvalue()

    def verify_message_attachments(self, message_pk: int) -> dict:
        results = []
        with self._gate.read():
            for att in self._db.list_attachments_with_source(message_pk):
                entry = {"attachment_id": att["id"],
                         "storage_state": att["storage_state"],
                         "ok": True, "error": None}
                if att["storage_state"] == "cipher":
                    try:
                        decode_attachment(self._storage, self._cipher, att)
                    except BlobUnavailableError as exc:
                        entry["ok"] = False
                        entry["error"] = str(exc)
                results.append(entry)
        return {"message_id": message_pk,
                "all_ok": all(r["ok"] for r in results),
                "attachments": results}
