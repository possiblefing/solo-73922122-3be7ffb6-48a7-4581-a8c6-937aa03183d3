"""构造"历史明文"库：模拟加密功能上线前的数据目录，用于迁移演示与测试。

直接使用采集服务的库结构与落盘布局：
- attachments.storage_state='plain'，storage_path 指向明文 PDF；
- 明文文件名 <部分序号>__<原文件名>（无 .enc 后缀）；
- 两代 UIDVALIDITY 并存，覆盖"邮箱重建后旧原件也要迁移"的场景。

容器内用法（对已有数据目录追加历史明文库）：
  python -m app.legacy --data-dir /data
"""
from __future__ import annotations

import argparse
import os

from .database import Database
from .pdf_extract import PdfPart, stored_filename


def make_pdf(tag: str) -> bytes:
    return (f"%PDF-1.4\n% legacy {tag}\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n").encode()


LEGACY_MESSAGES = [
    # (uidvalidity, uid, subject, [(part_number, filename, tag)])
    (1000, 1, "Legacy INV-1", [("1.2", "invoice.pdf", "L1")]),
    (1000, 2, "Legacy INV-2", [("1.2", "invoice.pdf", "L2a"),
                               ("1.3", "invoice.pdf", "L2b")]),
    (1000, 3, "Legacy no attachment", []),
    (2000, 1, "Legacy rebuilt INV-3", [("1.2", "rebuilt.pdf", "L3")]),
]


def seed_legacy_plaintext(data_dir: str, uidvalidity_base: int = 1000) -> int:
    """写入历史明文演示数据。

    ``uidvalidity_base`` 为批次起点，每批占用两个代际
    （base 与 base+1000），多次演示互不干扰；已存在的邮件按
    (UIDVALIDITY, UID) 幂等跳过。
    """
    db = Database(os.path.join(data_dir, "collector.db"))
    blob_root = os.path.join(data_dir, "blobs")
    created = 0
    try:
        for uidvalidity, uid, subject, parts in LEGACY_MESSAGES:
            uv = uidvalidity_base + (0 if uidvalidity == 1000 else 1000)
            epoch_id = db.get_or_create_epoch(uv, "INBOX")
            if db.get_message(epoch_id, uid) is not None:
                continue
            subject = f"{subject} [{uidvalidity_base}]"
            rel_dir = os.path.join(f"uidvalidity-{uv}", f"uid-{uid}")
            abs_dir = os.path.join(blob_root, rel_dir)
            os.makedirs(abs_dir, exist_ok=True)
            conn = db.begin()
            try:
                message_pk = db.insert_message(
                    conn, epoch_id, uid, "done", None, 1024, subject,
                    "legacy@example", f"<{subject}@example>",
                )
                for part_number, filename, tag in parts:
                    payload = make_pdf(tag)
                    part = PdfPart(
                        part_number=part_number, filename=filename,
                        content_type="application/pdf", payload=payload,
                    )
                    name = stored_filename(part)
                    with open(os.path.join(abs_dir, name), "wb") as fh:
                        fh.write(payload)
                        fh.flush()
                        os.fsync(fh.fileno())
                    db.insert_attachment(
                        conn, message_pk, part_number, filename,
                        "application/pdf", len(payload),
                        os.path.join(rel_dir, name), storage_state="plain",
                    )
                db.commit()
                created += 1
            except Exception:
                db.rollback()
                raise
    finally:
        db.close()
    return created


def main() -> None:
    parser = argparse.ArgumentParser(description="写入历史明文演示数据")
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--uidvalidity-base", type=int, default=1000,
                        help="本批历史代际起点（每次演示递增，避免重复）")
    args = parser.parse_args()
    os.makedirs(args.data_dir, exist_ok=True)
    created = seed_legacy_plaintext(args.data_dir, args.uidvalidity_base)
    print(f"历史明文演示数据：新增 {created} 封（data-dir={args.data_dir}）")


if __name__ == "__main__":
    main()
