"""SQLite 持久层。

记录 UIDVALIDITY、UID、逐封采集进度、附件索引，以及历史明文 -> 密文的迁移状态。

所有"索引 + 进度"的写入都在同一事务内提交（见 collector.py），查询接口只可能
看到完整提交的邮件，永远不会看到半封附件。

加密/迁移的文件读写一律在 SQLite 事务之外完成：只有元数据切换使用短事务，
从而保证文件 I/O 不持有 SQLite 写锁。
"""
from __future__ import annotations

import os
import sqlite3
import threading
from typing import Any, Iterable, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS mailbox_epochs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    uidvalidity     INTEGER NOT NULL UNIQUE,
    mailbox         TEXT NOT NULL,
    observed_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS messages (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    epoch_id        INTEGER NOT NULL REFERENCES mailbox_epochs(id),
    uid             INTEGER NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('done', 'failed', 'oversize')),
    failure_reason  TEXT,
    message_size    INTEGER,
    subject         TEXT,
    from_header     TEXT,
    message_id_hdr  TEXT,
    collected_at    TEXT,
    UNIQUE(epoch_id, uid)
);

CREATE TABLE IF NOT EXISTS attachments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id      INTEGER NOT NULL REFERENCES messages(id),
    part_number     TEXT NOT NULL,
    filename        TEXT NOT NULL,
    content_type    TEXT NOT NULL,
    size_bytes      INTEGER NOT NULL,
    storage_path    TEXT NOT NULL,
    stored_at       TEXT NOT NULL DEFAULT (datetime('now')),
    storage_state   TEXT NOT NULL DEFAULT 'plain'
                    CHECK (storage_state IN ('plain', 'cipher')),
    plain_sha256    TEXT,
    cipher_sha256   TEXT,
    key_id          TEXT,
    UNIQUE(message_id, part_number)
);

CREATE TABLE IF NOT EXISTS collection_runs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    epoch_id            INTEGER REFERENCES mailbox_epochs(id),
    uidvalidity         INTEGER,
    started_at          TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at         TEXT,
    status              TEXT NOT NULL DEFAULT 'running'
                        CHECK (status IN ('running', 'completed', 'aborted', 'busy')),
    total_seen          INTEGER NOT NULL DEFAULT 0,
    processed_ok        INTEGER NOT NULL DEFAULT 0,
    failed              INTEGER NOT NULL DEFAULT 0,
    oversize            INTEGER NOT NULL DEFAULT 0,
    skipped_terminal    INTEGER NOT NULL DEFAULT 0,
    attachments_saved   INTEGER NOT NULL DEFAULT 0,
    note                TEXT
);

CREATE TABLE IF NOT EXISTS migration_jobs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    status              TEXT NOT NULL DEFAULT 'running'
                        CHECK (status IN ('running', 'interrupted', 'completed',
                                          'completed_with_failures', 'failed')),
    started_at          TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at         TEXT,
    total_messages      INTEGER NOT NULL DEFAULT 0,
    crash_before_switch INTEGER NOT NULL DEFAULT 0,
    crash_after_switch  INTEGER NOT NULL DEFAULT 0,
    fail_first_switch   INTEGER NOT NULL DEFAULT 0,
    note                TEXT
);

CREATE TABLE IF NOT EXISTS migration_items (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id              INTEGER NOT NULL REFERENCES migration_jobs(id),
    message_id          INTEGER NOT NULL REFERENCES messages(id),
    status              TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'ready', 'switched',
                                          'completed', 'failed')),
    total_attachments   INTEGER NOT NULL DEFAULT 0,
    encrypted_attachments INTEGER NOT NULL DEFAULT 0,
    error               TEXT,
    updated_at          TEXT NOT NULL DEFAULT (datetime('now')),
    completed_at        TEXT,
    switch_fault_done   INTEGER NOT NULL DEFAULT 0,
    UNIQUE(job_id, message_id)
);

CREATE TABLE IF NOT EXISTS migration_blobs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id          INTEGER NOT NULL REFERENCES migration_jobs(id),
    item_id         INTEGER NOT NULL REFERENCES migration_items(id),
    attachment_id   INTEGER NOT NULL REFERENCES attachments(id),
    plain_rel_path  TEXT NOT NULL,
    cipher_rel_path TEXT NOT NULL,
    plain_sha256    TEXT NOT NULL,
    cipher_sha256   TEXT NOT NULL,
    plain_size      INTEGER NOT NULL,
    cipher_size     INTEGER NOT NULL,
    key_id          TEXT NOT NULL,
    UNIQUE(job_id, attachment_id)
);

CREATE INDEX IF NOT EXISTS idx_attachments_state
    ON attachments(storage_state);
CREATE INDEX IF NOT EXISTS idx_migration_items_job
    ON migration_items(job_id, status);
"""
ATTACHMENT_UPGRADE_COLUMNS = (
    ("storage_state", "TEXT NOT NULL DEFAULT 'plain'"),
    ("plain_sha256", "TEXT"),
    ("cipher_sha256", "TEXT"),
    ("key_id", "TEXT"),
)


class Database:
    def __init__(self, db_path: str) -> None:
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=10000")
        self._lock = threading.RLock()
        with self._lock:
            # 旧库升级必须先补列，再执行 SCHEMA（SCHEMA 里的索引依赖新列）
            self._upgrade_attachments()
            self._conn.executescript(SCHEMA)
            self._conn.commit()
            # 上次进程退出时仍处于 running 的采集，标记为 aborted（可被重新采集）
            self._conn.execute(
                "UPDATE collection_runs SET status='aborted', "
                "finished_at=datetime('now'), "
                "note=COALESCE(note,'') || ' [进程重启，自动中断标记]' "
                "WHERE status='running'"
            )
            # 迁移任务同理：进程退出即中断，稍后由迁移管理器续办
            self._conn.execute(
                "UPDATE migration_jobs SET status='interrupted', "
                "note=COALESCE(note,'') || ' [进程重启，自动中断标记]' "
                "WHERE status='running'"
            )
            self._conn.commit()

    def _upgrade_attachments(self) -> None:
        table_exists = self._conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='attachments'"
        ).fetchone()
        if not table_exists:
            return
        existing = {
            row["name"]
            for row in self._conn.execute("PRAGMA table_info(attachments)")
        }
        for name, decl in ATTACHMENT_UPGRADE_COLUMNS:
            if name not in existing:
                self._conn.execute(
                    f"ALTER TABLE attachments ADD COLUMN {name} {decl}"
                )
        # 旧库中全部原件都是明文，显式归一化，绝不把历史行误判为密文
        self._conn.execute(
            "UPDATE attachments SET storage_state='plain' "
            "WHERE storage_state IS NULL OR storage_state=''"
        )

    # ---- 基础工具 ----
    @property
    def lock(self) -> threading.RLock:
        return self._lock

    def query_all(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, tuple(params)).fetchall()

    def query_one(self, sql: str, params: Iterable[Any] = ()) -> Optional[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, tuple(params)).fetchone()

    def begin(self) -> sqlite3.Connection:
        """调用方在同一线程内随后使用 commit()/rollback()。"""
        self._lock.acquire()
        try:
            self._conn.execute("BEGIN IMMEDIATE")
        except Exception:
            self._lock.release()
            raise
        return self._conn

    def commit(self) -> None:
        try:
            self._conn.commit()
        finally:
            self._lock.release()

    def rollback(self) -> None:
        try:
            self._conn.rollback()
        finally:
            self._lock.release()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ---- UIDVALIDITY / 邮箱代际 ----
    def get_or_create_epoch(self, uidvalidity: int, mailbox: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM mailbox_epochs WHERE uidvalidity=?",
                (uidvalidity,),
            ).fetchone()
            if row is not None:
                return int(row["id"])
            cur = self._conn.execute(
                "INSERT INTO mailbox_epochs(uidvalidity, mailbox) VALUES (?, ?)",
                (uidvalidity, mailbox),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def latest_epoch(self) -> Optional[sqlite3.Row]:
        return self.query_one(
            "SELECT * FROM mailbox_epochs ORDER BY uidvalidity DESC, id DESC LIMIT 1"
        )

    def list_epochs(self) -> list[sqlite3.Row]:
        return self.query_all("SELECT * FROM mailbox_epochs ORDER BY id")

    # ---- 采集运行记录 ----
    def start_run(self, uidvalidity: Optional[int], epoch_id: Optional[int]) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO collection_runs(epoch_id, uidvalidity) VALUES (?, ?)",
                (epoch_id, uidvalidity),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def finish_run(self, run_id: int, status: str, counters: dict[str, int],
                   note: Optional[str] = None) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE collection_runs SET status=?, finished_at=datetime('now'), "
                "total_seen=?, processed_ok=?, failed=?, oversize=?, "
                "skipped_terminal=?, attachments_saved=?, note=? WHERE id=?",
                (
                    status,
                    counters.get("total_seen", 0),
                    counters.get("processed_ok", 0),
                    counters.get("failed", 0),
                    counters.get("oversize", 0),
                    counters.get("skipped_terminal", 0),
                    counters.get("attachments_saved", 0),
                    note,
                    run_id,
                ),
            )
            self._conn.commit()

    def list_runs(self, limit: int = 50) -> list[sqlite3.Row]:
        return self.query_all(
            "SELECT * FROM collection_runs ORDER BY id DESC LIMIT ?", (limit,)
        )

    def attach_epoch(self, run_id: int, epoch_id: int, uidvalidity: int) -> None:
        """IMAP 连接成功、拿到 UIDVALIDITY 后，把运行记录挂到对应邮箱代际。"""
        with self._lock:
            self._conn.execute(
                "UPDATE collection_runs SET epoch_id=?, uidvalidity=? WHERE id=?",
                (epoch_id, uidvalidity, run_id),
            )
            self._conn.commit()

    # ---- 单封邮件：进度 + 索引在同一事务内提交 ----
    def get_message(self, epoch_id: int, uid: int) -> Optional[sqlite3.Row]:
        return self.query_one(
            "SELECT * FROM messages WHERE epoch_id=? AND uid=?", (epoch_id, uid)
        )

    def insert_message(self, conn: sqlite3.Connection, epoch_id: int, uid: int,
                       status: str, failure_reason: Optional[str],
                       message_size: Optional[int], subject: Optional[str],
                       from_header: Optional[str], message_id_hdr: Optional[str]) -> int:
        cur = conn.execute(
            "INSERT INTO messages(epoch_id, uid, status, failure_reason, message_size, "
            "subject, from_header, message_id_hdr, collected_at) "
            "VALUES (?,?,?,?,?,?,?,?, datetime('now'))",
            (epoch_id, uid, status, failure_reason, message_size,
             subject, from_header, message_id_hdr),
        )
        return int(cur.lastrowid)

    def insert_attachment(self, conn: sqlite3.Connection, message_row_id: int,
                          part_number: str, filename: str, content_type: str,
                          size_bytes: int, storage_path: str,
                          storage_state: str = "plain",
                          plain_sha256: Optional[str] = None,
                          cipher_sha256: Optional[str] = None,
                          key_id: Optional[str] = None) -> None:
        conn.execute(
            "INSERT INTO attachments(message_id, part_number, filename, content_type, "
            "size_bytes, storage_path, storage_state, plain_sha256, cipher_sha256, "
            "key_id) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (message_row_id, part_number, filename, content_type,
             size_bytes, storage_path, storage_state, plain_sha256,
             cipher_sha256, key_id),
        )

    # ---- 查询接口 ----
    def list_messages(self, epoch_id: Optional[int] = None,
                      status: Optional[str] = None, limit: int = 200) -> list[sqlite3.Row]:
        sql = (
            "SELECT m.*, e.uidvalidity FROM messages m "
            "JOIN mailbox_epochs e ON e.id=m.epoch_id WHERE 1=1"
        )
        params: list[Any] = []
        if epoch_id is not None:
            sql += " AND m.epoch_id=?"
            params.append(epoch_id)
        if status is not None:
            sql += " AND m.status=?"
            params.append(status)
        sql += " ORDER BY e.uidvalidity, m.uid LIMIT ?"
        params.append(limit)
        return self.query_all(sql, params)

    def get_message_with_epoch(self, message_pk: int) -> Optional[sqlite3.Row]:
        return self.query_one(
            "SELECT m.*, e.uidvalidity FROM messages m "
            "JOIN mailbox_epochs e ON e.id=m.epoch_id WHERE m.id=?",
            (message_pk,),
        )

    def list_attachments(self, message_pk: int) -> list[sqlite3.Row]:
        return self.query_all(
            "SELECT * FROM attachments WHERE message_id=? ORDER BY part_number",
            (message_pk,),
        )

    def list_attachments_with_source(self, message_pk: int) -> list[sqlite3.Row]:
        """附件 + 来源（UIDVALIDITY/UID）；解密时 AAD 需要这些字段。"""
        return self.query_all(
            "SELECT a.*, m.epoch_id, m.uid, e.uidvalidity FROM attachments a "
            "JOIN messages m ON m.id=a.message_id "
            "JOIN mailbox_epochs e ON e.id=m.epoch_id "
            "WHERE a.message_id=? ORDER BY a.part_number",
            (message_pk,),
        )

    def get_attachment(self, attachment_pk: int) -> Optional[sqlite3.Row]:
        return self.query_one(
            "SELECT a.*, m.epoch_id, m.uid, e.uidvalidity FROM attachments a "
            "JOIN messages m ON m.id=a.message_id "
            "JOIN mailbox_epochs e ON e.id=m.epoch_id WHERE a.id=?",
            (attachment_pk,),
        )

    def distinct_cipher_key_ids(self) -> list[str]:
        rows = self.query_all(
            "SELECT DISTINCT key_id FROM attachments "
            "WHERE storage_state='cipher' AND key_id IS NOT NULL"
        )
        return [str(r["key_id"]) for r in rows]

    def progress_for_epoch(self, epoch_id: int) -> sqlite3.Row:
        return self.query_one(
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN status='done' THEN 1 ELSE 0 END) AS done, "
            "SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) AS failed, "
            "SUM(CASE WHEN status='oversize' THEN 1 ELSE 0 END) AS oversize, "
            "COALESCE((SELECT COUNT(*) FROM attachments a JOIN messages m2 "
            "          ON m2.id=a.message_id WHERE m2.epoch_id=?),0) AS attachments "
            "FROM messages WHERE epoch_id=?",
            (epoch_id, epoch_id),
        )

    # ---------------------------------------------------------------- 迁移任务
    def create_migration_job(self, crash_before_switch: bool = False,
                             crash_after_switch: bool = False,
                             fail_first_switch: bool = False) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO migration_jobs(crash_before_switch, crash_after_switch, "
                "fail_first_switch) VALUES (?,?,?)",
                (int(crash_before_switch), int(crash_after_switch),
                 int(fail_first_switch)),
            )
            job_id = int(cur.lastrowid)
            total = self._conn.execute(
                "SELECT COUNT(*) FROM messages m WHERE EXISTS ("
                "  SELECT 1 FROM attachments a WHERE a.message_id=m.id "
                "  AND a.storage_state='plain')"
            ).fetchone()[0]
            self._conn.execute(
                "INSERT INTO migration_items(job_id, message_id, total_attachments) "
                "SELECT ?, m.id, (SELECT COUNT(*) FROM attachments a "
                "  WHERE a.message_id=m.id AND a.storage_state='plain') "
                "FROM messages m WHERE EXISTS ("
                "  SELECT 1 FROM attachments a WHERE a.message_id=m.id "
                "  AND a.storage_state='plain') ORDER BY m.id",
                (job_id,),
            )
            self._conn.execute(
                "UPDATE migration_jobs SET total_messages=? WHERE id=?",
                (int(total), job_id),
            )
            self._conn.commit()
            return job_id

    def get_migration_job(self, job_id: int) -> Optional[sqlite3.Row]:
        return self.query_one(
            "SELECT * FROM migration_jobs WHERE id=?", (job_id,)
        )

    def latest_migration_job(self) -> Optional[sqlite3.Row]:
        return self.query_one(
            "SELECT * FROM migration_jobs ORDER BY id DESC LIMIT 1"
        )

    def list_migration_jobs(self, limit: int = 50) -> list[sqlite3.Row]:
        return self.query_all(
            "SELECT * FROM migration_jobs ORDER BY id DESC LIMIT ?", (limit,)
        )

    def unfinished_migration_jobs(self) -> list[sqlite3.Row]:
        return self.query_all(
            "SELECT * FROM migration_jobs WHERE status IN ('running','interrupted') "
            "ORDER BY id"
        )

    def set_migration_job_status(self, job_id: int, status: str,
                                 note: Optional[str] = None,
                                 finished: bool = False) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE migration_jobs SET status=?, note=?, "
                "finished_at=CASE WHEN ? THEN datetime('now') ELSE finished_at END "
                "WHERE id=?",
                (status, note, int(finished), job_id),
            )
            self._conn.commit()

    def migration_item_counts(self, job_id: int) -> dict[str, int]:
        rows = self.query_all(
            "SELECT status, COUNT(*) AS n FROM migration_items "
            "WHERE job_id=? GROUP BY status", (job_id,)
        )
        counts = {str(r["status"]): int(r["n"]) for r in rows}
        total = sum(counts.values())
        counts["total"] = total
        counts["done"] = counts.get("completed", 0)
        return counts

    def list_migration_items(self, job_id: Optional[int] = None,
                             status: Optional[str] = None,
                             limit: int = 500) -> list[sqlite3.Row]:
        sql = (
            "SELECT i.*, m.uid, m.subject, m.status AS message_status, "
            "e.uidvalidity FROM migration_items i "
            "JOIN messages m ON m.id=i.message_id "
            "JOIN mailbox_epochs e ON e.id=m.epoch_id WHERE 1=1"
        )
        params: list[Any] = []
        if job_id is not None:
            sql += " AND i.job_id=?"
            params.append(job_id)
        if status is not None:
            sql += " AND i.status=?"
            params.append(status)
        sql += " ORDER BY i.job_id DESC, e.uidvalidity, m.uid LIMIT ?"
        params.append(limit)
        return self.query_all(sql, params)

    def get_migration_item(self, job_id: int, message_id: int) -> Optional[sqlite3.Row]:
        return self.query_one(
            "SELECT * FROM migration_items WHERE job_id=? AND message_id=?",
            (job_id, message_id),
        )

    def get_migration_item_by_id(self, item_id: int) -> Optional[sqlite3.Row]:
        return self.query_one("SELECT * FROM migration_items WHERE id=?", (item_id,))

    def pending_migration_items(self, job_id: int) -> list[sqlite3.Row]:
        """本轮需要处理的邮件项：未完成的 + 之前失败可重试的。"""
        return self.query_all(
            "SELECT * FROM migration_items WHERE job_id=? "
            "AND status IN ('pending','ready','switched','failed') ORDER BY id",
            (job_id,),
        )

    def plain_attachments_for_message(self, message_id: int) -> list[sqlite3.Row]:
        return self.query_all(
            "SELECT * FROM attachments WHERE message_id=? AND storage_state='plain' "
            "ORDER BY part_number", (message_id,)
        )

    def count_plain_attachments(self, message_id: int) -> int:
        row = self.query_one(
            "SELECT COUNT(*) AS n FROM attachments WHERE message_id=? "
            "AND storage_state='plain'", (message_id,)
        )
        return int(row["n"]) if row else 0

    # ---- 迁移状态机：每个转换都是一个短事务 ----
    def set_migration_item_state(self, item_id: int, status: str,
                                 error: Optional[str] = None,
                                 encrypted_attachments: Optional[int] = None,
                                 completed: bool = False) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE migration_items SET status=?, error=?, "
                "encrypted_attachments=COALESCE(?, encrypted_attachments), "
                "updated_at=datetime('now'), "
                "completed_at=CASE WHEN ? THEN datetime('now') ELSE completed_at END "
                "WHERE id=?",
                (status, error, encrypted_attachments, int(completed), item_id),
            )
            self._conn.commit()

    def commit_item_ready(self, item_id: int, job_id: int,
                          blobs: list[dict[str, Any]]) -> None:
        """密文已全部发布落盘后，记录逐附件完整性信息并把该封置为 ready。"""
        conn = self.begin()
        try:
            for blob in blobs:
                conn.execute(
                    "INSERT INTO migration_blobs(job_id, item_id, attachment_id, "
                    "plain_rel_path, cipher_rel_path, plain_sha256, cipher_sha256, "
                    "plain_size, cipher_size, key_id) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(job_id, attachment_id) DO UPDATE SET "
                    "plain_rel_path=excluded.plain_rel_path, "
                    "cipher_rel_path=excluded.cipher_rel_path, "
                    "plain_sha256=excluded.plain_sha256, "
                    "cipher_sha256=excluded.cipher_sha256, "
                    "plain_size=excluded.plain_size, "
                    "cipher_size=excluded.cipher_size, key_id=excluded.key_id",
                    (job_id, item_id, blob["attachment_id"],
                     blob["plain_rel_path"], blob["cipher_rel_path"],
                     blob["plain_sha256"], blob["cipher_sha256"],
                     blob["plain_size"], blob["cipher_size"], blob["key_id"]),
                )
            conn.execute(
                "UPDATE migration_items SET status='ready', error=NULL, "
                "encrypted_attachments=?, updated_at=datetime('now') WHERE id=?",
                (len(blobs), item_id),
            )
            self.commit()
        except Exception:
            self.rollback()
            raise

    def list_migration_blobs(self, item_id: int) -> list[sqlite3.Row]:
        return self.query_all(
            "SELECT * FROM migration_blobs WHERE item_id=? ORDER BY attachment_id",
            (item_id,),
        )

    def switch_item_to_cipher(self, item_id: int,
                              updates: list[dict[str, Any]]) -> None:
        """把一封邮件的全部附件索引原子切换到密文。

        索引切换与迁移项状态在同一事务内提交：要么全部附件指向密文，
        要么全部维持明文——不存在明密文混用的中间状态。
        """
        conn = self.begin()
        try:
            for upd in updates:
                cur = conn.execute(
                    "UPDATE attachments SET storage_path=?, storage_state='cipher', "
                    "size_bytes=?, plain_sha256=?, cipher_sha256=?, key_id=? "
                    "WHERE id=? AND storage_state='plain'",
                    (upd["cipher_rel_path"], int(upd["plain_size"]),
                     upd["plain_sha256"], upd["cipher_sha256"], upd["key_id"],
                     upd["attachment_id"]),
                )
                if cur.rowcount != 1:
                    raise RuntimeError(
                        f"附件 {upd['attachment_id']} 索引状态异常，拒绝切换"
                    )
            conn.execute(
                "UPDATE migration_items SET status='switched', error=NULL, "
                "updated_at=datetime('now') WHERE id=?",
                (item_id,),
            )
            self.commit()
        except Exception:
            self.rollback()
            raise
