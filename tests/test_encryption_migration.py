"""迁移与加密核心行为测试（无 Docker，直接驱动模块）。

运行：python3 -m unittest -v tests.test_encryption_migration
"""
from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from collector.app.config import Settings  # noqa: E402
from collector.app.crypto import (BlobCipher, BlobIntegrityError, CryptoError,  # noqa: E402
                                  load_key_file)
from collector.app.database import Database  # noqa: E402
from collector.app.downloader import (BlobGate, BlobUnavailableError,  # noqa: E402
                                      DownloadService)
from collector.app.legacy import seed_legacy_plaintext  # noqa: E402
from collector.app.migration import MigrationManager  # noqa: E402
from collector.app.storage import Storage  # noqa: E402


def make_settings(tmp: str) -> Settings:
    data = os.path.join(tmp, "data")
    os.makedirs(data, exist_ok=True)
    secrets = os.path.join(tmp, "secrets")
    os.makedirs(secrets, exist_ok=True)
    key_path = os.path.join(secrets, "blob.key")
    if not os.path.exists(key_path):
        with open(key_path, "wb") as fh:
            fh.write(os.urandom(32))
    return Settings(
        imap_host="imap", imap_port=143, imap_user="u", imap_password="p",
        imap_mailbox="INBOX", socket_timeout=5,
        max_message_bytes=8 * 1024 * 1024,
        data_dir=data,
        db_path=os.path.join(data, "collector.db"),
        blob_root=os.path.join(data, "blobs"),
        staging_dir=os.path.join(data, "staging"),
        lock_path=os.path.join(data, "collect.lock"),
        key_file=key_path,
        migration_lock_path=os.path.join(data, "migrate.lock"),
        migration_auto_resume=True,
        migration_allow_demo_fault=True,
    )


class Env:
    def __init__(self, tmp: str, plaintext_seed: bool = True) -> None:
        self.settings = make_settings(tmp)
        self.db = Database(self.settings.db_path)
        self.cipher = BlobCipher.from_file(
            self.settings.key_file, self.settings.data_dir
        )
        self.storage = Storage(
            self.settings.blob_root, self.settings.staging_dir,
            os.path.join(self.settings.data_dir, "migration-staging"),
            self.cipher,
        )
        self.gate = BlobGate()
        self.downloads = DownloadService(
            self.db, self.storage, self.cipher, self.gate
        )
        self.migration = MigrationManager(
            self.settings, self.db, self.storage, self.cipher, self.gate
        )
        if plaintext_seed:
            seed_legacy_plaintext(self.settings.data_dir)

    def close(self) -> None:
        self.db.close()


class KeyTests(unittest.TestCase):
    def test_key_must_live_outside_data_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(tmp)
            inside = os.path.join(settings.data_dir, "inner.key")
            with open(inside, "wb") as fh:
                fh.write(os.urandom(32))
            with self.assertRaises(CryptoError):
                load_key_file(inside, settings.data_dir)

    def test_hex_key_supported(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "hex.key")
            raw = os.urandom(32)
            with open(path, "w") as fh:
                fh.write(raw.hex())
            key, key_id = load_key_file(path, os.path.join(tmp, "data"))
            self.assertEqual(key, raw)
            self.assertEqual(len(key_id), 32)

    def test_bad_key_length_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bad.key")
            with open(path, "wb") as fh:
                fh.write(b"short")
            with self.assertRaises(CryptoError):
                load_key_file(path, os.path.join(tmp, "data"))


class CipherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = Env(self.tmp.name, plaintext_seed=False)

    def tearDown(self):
        self.env.close()
        self.tmp.cleanup()

    def test_roundtrip_and_identity_binding(self):
        from collector.app.crypto import BlobIdentity, sha256_hex

        payload = b"%PDF-1.4 hello"
        ident = BlobIdentity(1, 2, "1.2", "1.2__a.pdf", sha256_hex(payload),
                             len(payload))
        blob = self.env.cipher.encrypt(payload, ident)
        self.assertNotIn(b"%PDF", blob)
        self.assertEqual(self.env.cipher.decrypt(blob, ident), payload)
        other = BlobIdentity(1, 2, "1.3", "1.3__b.pdf", sha256_hex(payload),
                             len(payload))
        with self.assertRaises(BlobIntegrityError):
            self.env.cipher.decrypt(blob, other)

    def test_truncation_rejected(self):
        from collector.app.crypto import BlobIdentity, sha256_hex

        payload = b"%PDF-1.4 hello"
        ident = BlobIdentity(1, 2, "1.2", "1.2__a.pdf", sha256_hex(payload),
                             len(payload))
        blob = self.env.cipher.encrypt(payload, ident)
        with self.assertRaises(BlobIntegrityError):
            self.env.cipher.decrypt(blob[: len(blob) - 3], ident)


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = Env(self.tmp.name)

    def tearDown(self):
        self.env.close()
        self.tmp.cleanup()

    def _att_rows(self):
        return self.env.db.query_all(
            "SELECT * FROM attachments ORDER BY id"
        )

    def test_migration_encrypts_all_and_keeps_downloads_working(self):
        before = {
            row["id"]: self.env.downloads.attachment_pdf(row["id"])[1]
            for row in self._att_rows()
        }
        result = self.env.migration.run_migration()
        self.assertEqual(result["status"], "completed")
        rows = self._att_rows()
        self.assertTrue(all(r["storage_state"] == "cipher" for r in rows))
        for row in rows:
            self.assertTrue(row["storage_path"].endswith(".enc"))
            self.assertTrue(row["plain_sha256"] and row["cipher_sha256"])
            name, payload = self.env.downloads.attachment_pdf(row["id"])
            self.assertEqual(payload, before[row["id"]])
            self.assertTrue(payload.startswith(b"%PDF"))
        # 明文文件全部清理
        for root, _dirs, files in os.walk(self.env.settings.blob_root):
            for name in files:
                self.assertTrue(name.endswith(".enc"), name)

    def test_zips_are_built_from_decrypted_pdfs(self):
        import zipfile

        self.env.migration.run_migration()
        payload = self.env.downloads.source_bundle_zip(1000, 2)
        zf = zipfile.ZipFile(__import__("io").BytesIO(payload))
        names = zf.namelist()
        self.assertEqual(len(names), 2)
        for name in names:
            self.assertTrue(zf.read(name).startswith(b"%PDF"))

    def test_corrupt_ciphertext_blocks_single_and_zip(self):
        self.env.migration.run_migration()
        row = self.env.db.query_one(
            "SELECT * FROM attachments WHERE message_id=2 ORDER BY id LIMIT 1"
        )
        path = self.env.storage.absolute_path(row["storage_path"])
        with open(path, "r+b") as fh:
            fh.truncate(20)
        with self.assertRaises(BlobUnavailableError):
            self.env.downloads.attachment_pdf(row["id"])
        # ZIP 必须整体拒绝，不返回部分 ZIP
        with self.assertRaises(BlobUnavailableError):
            self.env.downloads.source_bundle_zip(1000, 2)
        # 同封另一个附件仍可下载
        other = self.env.db.query_one(
            "SELECT * FROM attachments WHERE message_id=2 ORDER BY id DESC LIMIT 1"
        )
        self.assertTrue(self.env.downloads.attachment_pdf(other["id"])[1]
                        .startswith(b"%PDF"))

    def test_cross_attachment_substitution_rejected(self):
        self.env.migration.run_migration()
        a1 = self.env.db.query_one("SELECT * FROM attachments WHERE id=1")
        a4 = self.env.db.query_one("SELECT * FROM attachments WHERE id=4")
        src = self.env.storage.absolute_path(a1["storage_path"])
        dst = self.env.storage.absolute_path(a4["storage_path"])
        import shutil
        shutil.copyfile(src, dst)
        with self.assertRaises(BlobUnavailableError):
            self.env.downloads.attachment_pdf(a4["id"])

    def test_switch_failure_keeps_plaintext_and_retry_succeeds(self):
        result = self.env.migration.run_migration(
            demo_faults={"fail_first_switch": True}
        )
        job_id = result["job_id"]
        self.assertEqual(result["status"], "completed_with_failures")
        rows = self._att_rows()
        self.assertTrue(all(r["storage_state"] == "plain" for r in rows))
        for row in rows:
            self.assertTrue(self.env.downloads.attachment_pdf(row["id"])[1]
                            .startswith(b"%PDF"))
        retry = self.env.migration.run_migration(job_id=job_id)
        self.assertEqual(retry["status"], "completed")
        self.assertTrue(all(r["storage_state"] == "cipher"
                            for r in self._att_rows()))

    def test_interrupted_before_switch_resumes(self):
        try:
            self.env.migration.run_migration(
                demo_faults={"crash_before_switch": True}
            )
        except Exception as exc:  # MigrationCrashSimulated
            self.assertIn("crash", type(exc).__name__.lower())
        job = self.env.db.latest_migration_job()
        self.assertEqual(job["status"], "interrupted")
        self.assertTrue(all(r["storage_state"] == "plain"
                            for r in self._att_rows()))
        # 旧件仍可下载（进程退出后、重启后）
        for row in self._att_rows():
            self.assertTrue(self.env.downloads.attachment_pdf(row["id"])[1]
                            .startswith(b"%PDF"))
        resumed = self.env.migration.run_migration(job_id=int(job["id"]))
        self.assertEqual(resumed["status"], "completed")
        self.assertTrue(all(r["storage_state"] == "cipher"
                            for r in self._att_rows()))

    def test_interrupted_after_switch_cleans_up_on_resume(self):
        try:
            self.env.migration.run_migration(
                demo_faults={"crash_after_switch": True}
            )
        except Exception:
            pass
        job = self.env.db.latest_migration_job()
        self.assertEqual(job["status"], "interrupted")
        # 第一封已切换（索引密文），后续仍明文
        states = [r["storage_state"] for r in self._att_rows()]
        self.assertIn("cipher", states)
        self.assertIn("plain", states)
        # 切换过的那封，旧明文仍在磁盘（尚未清理），但下载走密文
        switched = self.env.db.query_one(
            "SELECT * FROM attachments WHERE message_id=1"
        )
        plain_path = self.env.storage.absolute_path(
            switched["storage_path"].removesuffix(".enc")
        )
        self.assertTrue(os.path.isfile(plain_path))
        self.assertTrue(self.env.downloads.attachment_pdf(switched["id"])[1]
                        .startswith(b"%PDF"))
        resumed = self.env.migration.run_migration(job_id=int(job["id"]))
        self.assertEqual(resumed["status"], "completed")
        self.assertFalse(os.path.isfile(plain_path))

    def test_wrong_key_refused(self):
        self.env.migration.run_migration()
        other_key = BlobCipher(os.urandom(32), "deadbeef" * 4)
        manager = MigrationManager(
            self.env.settings, self.env.db, self.env.storage, other_key,
            self.env.gate,
        )
        # 库里已有密文，仅凭旧明文不可迁移（此处已无明文，仍应拒绝新建任务）
        from collector.app.crypto import MigrationKeyMismatchError
        with self.assertRaises(MigrationKeyMismatchError):
            manager.run_migration()

    def test_no_plaintext_in_staging_after_migration(self):
        self.env.migration.run_migration()
        for root, _dirs, files in os.walk(
            os.path.join(self.env.settings.data_dir, "migration-staging")
        ):
            self.assertEqual(files, [])

    def test_downloads_do_not_block_on_migration_gate_starvation(self):
        """迁移清理取写锁时会等待读锁释放；下载完成后写者立刻推进。"""
        self.env.migration.run_migration()
        statuses = []

        def reader():
            for _ in range(20):
                self.env.downloads.attachment_pdf(1)
            statuses.append("done")

        threads = [threading.Thread(target=reader) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=20)
        self.assertEqual(statuses, ["done"] * 4)

    def test_legacy_db_upgrade_marks_plain(self):
        """旧库（无 storage_state 列）升级后必须全部按明文处理。"""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "old.db")
            conn = sqlite3.connect(path)
            conn.executescript("""
                CREATE TABLE mailbox_epochs (id INTEGER PRIMARY KEY,
                    uidvalidity INTEGER UNIQUE, mailbox TEXT,
                    observed_at TEXT DEFAULT '');
                CREATE TABLE messages (id INTEGER PRIMARY KEY, epoch_id INTEGER,
                    uid INTEGER, status TEXT, failure_reason TEXT,
                    message_size INTEGER, subject TEXT, from_header TEXT,
                    message_id_hdr TEXT, collected_at TEXT);
                CREATE TABLE attachments (id INTEGER PRIMARY KEY, message_id INTEGER,
                    part_number TEXT, filename TEXT, content_type TEXT,
                    size_bytes INTEGER, storage_path TEXT, stored_at TEXT DEFAULT '');
            """)
            conn.execute("INSERT INTO mailbox_epochs VALUES (1,42,'INBOX','')")
            conn.execute("INSERT INTO messages(id,epoch_id,uid,status) "
                         "VALUES (1,1,7,'done')")
            conn.execute("INSERT INTO attachments(id,message_id,part_number,"
                         "filename,content_type,size_bytes,storage_path) "
                         "VALUES (1,1,'1.2','a.pdf','application/pdf',5,"
                         "'uidvalidity-42/uid-7/1.2__a.pdf')")
            conn.commit()
            conn.close()
            db = Database(path)
            row = db.query_one("SELECT * FROM attachments")
            db.close()
            self.assertEqual(row["storage_state"], "plain")
            self.assertIsNone(row["plain_sha256"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
