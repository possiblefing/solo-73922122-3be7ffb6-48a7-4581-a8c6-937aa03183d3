"""历史明文原件 -> AES-256-GCM 密文的按邮件迁移。

迁移单封邮件（一个 migration_item）分三段，任何一段都可被进程退出打断并续办：

1. **encrypt（准备）** —— 在 SQLite 事务之外读取明文、加密、写迁移暂存区，
   然后 fsync + 原子 rename 发布到正式目录（``<原名>.enc``）。
   此时索引仍指向明文，下载行为完全不变。全部附件密文验证通过后才落一次短事务，
   把该封置为 ready（同时记录逐附件完整性摘要）。
2. **switch（切换）** —— 单个短事务内把该封**全部**附件从明文索引切成密文索引。
   切换失败则回滚：旧明文索引与文件原样保留、仍可下载，可重试。
   切换成功后，旧明文第一次清理失败也可以重做（幂等）。
3. **cleanup（清理）** —— 先逐份验证密文可解密，再删除该封旧明文与迁移暂存；
   核对索引里已无该封明文后才把迁移项置为 completed。
   只有到这一步才算"该封迁移完成"。

并发与锁：
- 迁移持独立的 ``migrate.lock`` 进程锁，与采集锁分离，采集可同时进行；
- 迁移的文件读写全部在 SQLite 事务之外，只在状态转换时使用短事务，
  因此加密/读写文件不持有 SQLite 写锁；
- 下载持 ``BlobGate`` 读锁完成"读索引 + 读文件 + 解密"，迁移删除旧明文持写锁，
  两者互斥，已获准的下载不会被截断。

崩溃恢复（重启后自动续办）：
- 索引仍为明文（切换未提交）：旧件可下载，重新做幂等 prepare 后再切换；
- 索引已为密文（切换已提交）：直接续做 cleanup；
- cleanup 时密文校验失败：若旧明文仍在则用它重建密文（自愈），否则该封标记失败并
  拒绝下载——绝不删除唯一可用的原件。
"""
from __future__ import annotations

import os
import threading
from typing import Any, Optional

from .config import Settings
from .crypto import (BlobCipher, BlobIdentity, BlobIntegrityError,
                     MigrationKeyMismatchError, sha256_hex)
from .database import Database
from .downloader import BlobGate
from .process_lock import ProcessLock
from .storage import Storage, cipher_filename, plain_name_from_cipher

ACTIVE_ITEM_STATES = ("pending", "ready", "switched")


class MigrationBusyError(RuntimeError):
    """已有迁移在进行（本进程线程或其它进程持锁）。"""


class MigrationConfigError(RuntimeError):
    """迁移前置条件不满足（如密钥不属于待迁移附件）。"""


class MigrationCrashSimulated(RuntimeError):
    """演示用：在"切换前/切换后"故意终止进程。"""


class MigrationFaultInjected(RuntimeError):
    """演示用：让该封第一次切换必定失败，验证"切换失败保留旧件可下载"。"""


class MigrationManager:
    def __init__(self, settings: Settings, db: Database, storage: Storage,
                 cipher: BlobCipher, gate: BlobGate) -> None:
        self._settings = settings
        self._db = db
        self._storage = storage
        self._cipher = cipher
        self._gate = gate
        self._process_lock = ProcessLock(settings.migration_lock_path)
        self._thread_lock = threading.Lock()

    # ---------------------------------------------------------------- 启动
    def startup_reconcile(self) -> dict[str, Any]:
        """进程启动时：清理迁移暂存区，并（默认）自动续办全部未完成的迁移。"""
        removed = self._storage.cleanup_stale_migration_staging()
        interrupted = self._db.unfinished_migration_jobs()
        resumed: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        if self._settings.migration_auto_resume and interrupted:
            for job in interrupted:
                try:
                    resumed.append(self.run_migration(job_id=int(job["id"])))
                except (MigrationBusyError, MigrationKeyMismatchError) as exc:
                    errors.append({"job_id": int(job["id"]), "error": str(exc)})
        return {
            "stale_migration_staging_cleaned": removed,
            "interrupted_jobs": len(interrupted),
            "auto_resumed": resumed,
            "errors": errors,
        }

    def reconcile_status_only(self) -> dict[str, Any]:
        """不执行迁移，只清理暂存并报告待续办任务（用于续办被禁用时）。"""
        return {
            "stale_migration_staging_cleaned":
                self._storage.cleanup_stale_migration_staging(),
            "interrupted_jobs": len(self._db.unfinished_migration_jobs()),
            "auto_resumed": [],
            "errors": [],
        }

    # ---------------------------------------------------------------- 入口
    def run_migration(self, job_id: Optional[int] = None,
                      demo_faults: Optional[dict[str, bool]] = None
                      ) -> dict[str, Any]:
        """执行/续办一个迁移任务；job_id=None 时新建任务（只含仍有明文的邮件）。

        ``demo_faults`` 只在新建任务时写入任务记录（演示"切换前/后退出"与
        "首次切换失败"）。
        """
        if not self._thread_lock.acquire(blocking=False):
            raise MigrationBusyError("本进程已有迁移在执行")
        try:
            with self._process_lock:
                return self._run_locked(job_id, demo_faults or {})
        finally:
            self._thread_lock.release()

    def _assert_key_matches_existing_cipher(self) -> None:
        known = set(self._db.distinct_cipher_key_ids())
        if known and self._cipher.key_id not in known:
            raise MigrationKeyMismatchError(
                "当前密钥与库中已有密文不匹配；拒绝迁移，避免新旧密文混淆"
            )

    def create_job(self, demo_faults: Optional[dict[str, bool]] = None) -> int:
        """新建迁移任务（只含仍有明文的邮件），供后台执行前先拿到任务 ID。"""
        self._assert_key_matches_existing_cipher()
        faults = demo_faults or {}
        return self._db.create_migration_job(
            crash_before_switch=bool(faults.get("crash_before_switch")),
            crash_after_switch=bool(faults.get("crash_after_switch")),
            fail_first_switch=bool(faults.get("fail_first_switch")),
        )

    # ---------------------------------------------------------------- 主循环
    def _run_locked(self, job_id: Optional[int],
                    demo_faults: dict[str, bool]) -> dict[str, Any]:
        db = self._db
        self._assert_key_matches_existing_cipher()
        created = False
        if job_id is None:
            job_id = self.create_job(demo_faults)
            created = True
        else:
            job = db.get_migration_job(job_id)
            if job is None:
                raise MigrationConfigError(f"迁移任务 {job_id} 不存在")
        assert job_id is not None
        db.set_migration_job_status(job_id, "running")

        try:
            for item in db.pending_migration_items(job_id):
                self._process_item(job_id, int(item["id"]))
        finally:
            self._finalize_job_status(job_id)
        return {
            "job_id": job_id,
            "created": created,
            "status": db.get_migration_job(job_id)["status"],
            "counts": db.migration_item_counts(job_id),
        }

    def _finalize_job_status(self, job_id: int) -> None:
        db = self._db
        counts = db.migration_item_counts(job_id)
        job = db.get_migration_job(job_id)
        if job is None or job["status"] != "running":
            return
        pending = sum(counts.get(s, 0) for s in ACTIVE_ITEM_STATES)
        if pending > 0:
            db.set_migration_job_status(
                job_id, "interrupted", note="仍有未完成邮件，可再次发起迁移续办"
            )
        elif counts.get("failed", 0) > 0:
            db.set_migration_job_status(
                job_id, "completed_with_failures",
                note=f"{counts.get('failed', 0)} 封失败（旧明文保留可下载）",
                finished=True,
            )
        else:
            db.set_migration_job_status(
                job_id, "completed",
                note="全部邮件索引指向密文，旧明文与暂存已清理",
                finished=True,
            )

    # ---------------------------------------------------------------- 单封
    def _process_item(self, job_id: int, item_id: int) -> str:
        db = self._db
        item = db.get_migration_item_by_id(item_id)
        if item is None:
            return "skipped"
        message_id = int(item["message_id"])
        plain_count = db.count_plain_attachments(message_id)
        cipher_count = self._count_cipher_attachments(message_id)

        if plain_count > 0 and cipher_count > 0:
            # 同一封不可能既索引明文又索引密文；保守失败，拒绝猜测
            db.set_migration_item_state(
                item_id, "failed",
                error="该封附件索引同时存在明文与密文，拒绝猜测明密文",
            )
            return "failed"
        if plain_count == 0 and cipher_count == 0:
            db.set_migration_item_state(
                item_id, "failed", error="该封已无任何附件原件，无法迁移"
            )
            return "failed"
        if plain_count == 0:
            # 切换已提交，只是清理没做完（或清理失败被重试）
            return self._finish_item(job_id, item_id, message_id)

        # 仍有明文索引：从这里开始（重新）准备密文，幂等
        if item["status"] == "failed":
            db.set_migration_item_state(item_id, "pending", error=None)
        try:
            blobs = self._prepare_item(job_id, item_id, message_id)
        except MigrationCrashSimulated:
            raise
        except Exception as exc:
            db.set_migration_item_state(
                item_id, "failed", error=f"密文准备失败: {exc}"
            )
            return "failed"

        # ---- 演示故障：切换前进程退出（索引仍明文，旧件可下载）----
        if self._job_flag(job_id, "crash_before_switch"):
            self._clear_job_flag(job_id, "crash_before_switch")
            raise MigrationCrashSimulated(
                f"演示故障：邮件 {message_id} 全部密文已就绪，切换索引前进程退出"
            )

        try:
            self._maybe_inject_switch_fault(item_id)
            db.switch_item_to_cipher(item_id, blobs)
        except Exception as exc:
            # 事务已回滚：旧明文索引与文件原样保留，仍可下载，可重试
            db.set_migration_item_state(
                item_id, "failed",
                error=f"索引切换失败（旧明文保留可下载）: {exc}",
            )
            return "failed"

        # ---- 演示故障：切换后进程退出（索引已密文，旧明文待清理）----
        if self._job_flag(job_id, "crash_after_switch"):
            self._clear_job_flag(job_id, "crash_after_switch")
            raise MigrationCrashSimulated(
                f"演示故障：邮件 {message_id} 索引已切到密文，清理旧明文前进程退出"
            )

        return self._finish_item(job_id, item_id, message_id)

    def _count_cipher_attachments(self, message_id: int) -> int:
        row = self._db.query_one(
            "SELECT COUNT(*) AS n FROM attachments WHERE message_id=? "
            "AND storage_state='cipher'", (message_id,)
        )
        return int(row["n"]) if row else 0

    def verify_job_ciphertexts(self, job_id: int) -> dict[str, Any]:
        """只读巡检：确认已完成任务的密文仍可解密（不触碰明文与索引）。

        迁移完成后若磁盘上的密文被损坏或替换，逐邮件状态应如实暴露问题，
        而不是继续显示 completed。此接口不修改任何状态。
        """
        from .downloader import BlobUnavailableError, decode_attachment

        problems: list[dict[str, Any]] = []
        plaintext_remaining = 0
        checked = 0
        for item in self._db.list_migration_items(job_id=job_id, limit=100000):
            message = self._db.get_message_with_epoch(int(item["message_id"]))
            if message is None:
                problems.append({"item_id": item["id"], "error": "邮件记录不存在"})
                continue
            for att in self._db.list_attachments_with_source(int(item["message_id"])):
                if att["storage_state"] == "plain":
                    plaintext_remaining += 1
                    continue
                checked += 1
                try:
                    decode_attachment(self._storage, self._cipher, att)
                except (BlobUnavailableError, Exception) as exc:
                    problems.append({
                        "item_id": item["id"],
                        "attachment_id": att["id"],
                        "error": str(exc),
                    })
        return {
            "job_id": job_id,
            "checked": checked,
            "plaintext_attachments_remaining": plaintext_remaining,
            "all_ok": not problems,
            "problems": problems,
        }

    # ---------------------------------------------------------------- 准备密文
    def _prepare_item(self, job_id: int, item_id: int,
                      message_id: int) -> list[dict[str, Any]]:
        """事务外：读取明文 -> 加密 -> 暂存 -> 发布 -> 验证；最后短事务置 ready。

        已存在且可解密的同身份密文直接复用：崩溃重入不重复加密、不重复写盘。
        """
        db = self._db
        message = db.get_message_with_epoch(message_id)
        if message is None:
            raise MigrationConfigError("邮件记录不存在")
        if message["status"] != "done":
            raise MigrationConfigError(
                f"邮件状态为 {message['status']}，没有可迁移的原件"
            )
        uidvalidity = int(message["uidvalidity"])
        uid = int(message["uid"])
        attachments = db.plain_attachments_for_message(message_id)
        if not attachments:
            raise MigrationConfigError("该封没有明文附件")

        staging_dir = self._storage.new_migration_staging_dir(job_id)
        try:
            prepared: list[dict[str, Any]] = []
            for att in attachments:
                plain_rel = str(att["storage_path"])
                stored_name = os.path.basename(plain_rel)
                plain_filename = plain_name_from_cipher(stored_name)
                # 迁移期间可能有并发下载，读明文与后面删明文都用同一把门
                with self._gate.read():
                    plaintext = self._read_bytes(
                        self._storage.absolute_path(plain_rel)
                    )
                plain_sha = sha256_hex(plaintext)
                identity = BlobIdentity(
                    uidvalidity=uidvalidity, uid=uid,
                    part_number=str(att["part_number"]),
                    filename=plain_filename,
                    plain_sha256=plain_sha,
                    plain_size=len(plaintext),
                )
                cipher_rel = self._storage.cipher_relative_path(
                    uidvalidity, uid, plain_filename
                )
                final_abs = self._storage.absolute_path(cipher_rel)

                if self._cipher_file_is_valid(final_abs, identity):
                    # 上次运行已发布同一份合法密文：直接复用，不重复加密
                    cipher_sha = sha256_hex(self._read_bytes(final_abs))
                    cipher_size = os.path.getsize(final_abs)
                else:
                    ciphertext = self._cipher.encrypt(plaintext, identity)
                    staged = os.path.join(staging_dir, cipher_filename(stored_name))
                    tmp = staged + ".part"
                    with open(tmp, "wb") as fh:
                        fh.write(ciphertext)
                        fh.flush()
                        os.fsync(fh.fileno())
                    self._fsync_dir(staging_dir)
                    target_dir = os.path.dirname(final_abs)
                    os.makedirs(target_dir, exist_ok=True)
                    os.replace(tmp, final_abs)
                    self._fsync_dir(target_dir)
                    cipher_sha = sha256_hex(ciphertext)
                    cipher_size = len(ciphertext)

                # 发布后立即完整解密验证：损坏/身份不符在切换前就被拦下
                blob = self._read_bytes(final_abs)
                plain_again = self._cipher.decrypt(blob, identity, cipher_sha)
                if sha256_hex(plain_again) != plain_sha:
                    raise BlobIntegrityError("新密文解密后的明文摘要不一致")

                prepared.append({
                    "attachment_id": int(att["id"]),
                    "plain_rel_path": plain_rel,
                    "cipher_rel_path": cipher_rel,
                    "plain_sha256": plain_sha,
                    "cipher_sha256": cipher_sha,
                    "plain_size": len(plaintext),
                    "cipher_size": cipher_size,
                    "key_id": self._cipher.key_id,
                })
            # 一封的全部密文都验证通过后，才落一次短事务标记 ready
            db.commit_item_ready(item_id, job_id, prepared)
            return prepared
        finally:
            self._storage.discard_migration_staging(job_id)

    def _cipher_file_is_valid(self, path: str, identity: BlobIdentity) -> bool:
        if not os.path.isfile(path):
            return False
        try:
            with open(path, "rb") as fh:
                blob = fh.read()
            plaintext = self._cipher.decrypt(blob, identity)
            return sha256_hex(plaintext) == identity.plain_sha256
        except (BlobIntegrityError, OSError):
            return False

    @staticmethod
    def _read_bytes(path: str) -> bytes:
        with open(path, "rb") as fh:
            return fh.read()

    # ---------------------------------------------------------------- 清理
    def _finish_item(self, job_id: int, item_id: int, message_id: int) -> str:
        """验证密文 -> 删除旧明文与残留暂存 -> 核对索引 -> 标记 completed。"""
        db = self._db
        message = db.get_message_with_epoch(message_id)
        if message is None:
            db.set_migration_item_state(item_id, "failed", error="邮件记录不存在")
            return "failed"
        blobs = db.list_migration_blobs(item_id)
        if not blobs:
            db.set_migration_item_state(
                item_id, "switched",
                error="缺少迁移密文记录，无法确认密文完整性",
            )
            return "failed"

        try:
            for blob in blobs:
                if not self._blob_verifies(blob, message):
                    # 密文损坏/被替换：优先用仍在的旧明文重建，否则保留原件拒绝完成
                    if not self._repair_blob(blob, message):
                        db.set_migration_item_state(
                            item_id, "switched",
                            error=(
                                "密文校验失败且旧明文缺失/不可用，"
                                f"附件 {blob['attachment_id']} 拒绝下载"
                            ),
                        )
                        return "failed"
            # 全部密文可解密：此刻才允许删除该封旧明文
            with self._gate.write():
                for blob in blobs:
                    self._storage.remove_plain_file(str(blob["plain_rel_path"]))
            self._storage.discard_migration_staging(job_id)
            if db.count_plain_attachments(message_id) != 0:
                raise MigrationConfigError("该封仍有明文索引，不能报迁移完成")
            db.set_migration_item_state(
                item_id, "completed", error=None, completed=True
            )
            return "completed"
        except MigrationCrashSimulated:
            raise
        except Exception as exc:
            # 切换已经提交（索引是密文），只是清理没做完：保留 switched 以便重试
            cleanup_pending = db.count_plain_attachments(message_id) == 0
            db.set_migration_item_state(
                item_id, "switched" if cleanup_pending else "failed",
                error=f"清理旧明文未完成: {exc}",
            )
            return "failed"

    def _blob_verifies(self, blob, message) -> bool:
        att = self._db.query_one(
            "SELECT * FROM attachments WHERE id=?", (blob["attachment_id"],)
        )
        if att is None:
            return False
        identity = self._identity_for(att, message, blob)
        try:
            ciphertext = self._read_bytes(
                self._storage.absolute_path(str(blob["cipher_rel_path"]))
            )
            plaintext = self._cipher.decrypt(
                ciphertext, identity, str(blob["cipher_sha256"])
            )
            return sha256_hex(plaintext) == str(blob["plain_sha256"])
        except (BlobIntegrityError, OSError):
            return False

    @staticmethod
    def _identity_for(att, message, blob) -> BlobIdentity:
        return BlobIdentity(
            uidvalidity=int(message["uidvalidity"]),
            uid=int(message["uid"]),
            part_number=str(att["part_number"]),
            filename=plain_name_from_cipher(
                os.path.basename(str(blob["plain_rel_path"]))
            ),
            plain_sha256=str(blob["plain_sha256"]),
            plain_size=int(blob["plain_size"]),
        )

    def _repair_blob(self, blob, message) -> bool:
        """用仍在的旧明文重建被损坏/替换的密文，并更新索引摘要（短事务）。"""
        db = self._db
        att = db.query_one("SELECT * FROM attachments WHERE id=?",
                           (blob["attachment_id"],))
        if att is None:
            return False
        plain_rel = str(blob["plain_rel_path"])
        if not os.path.isfile(self._storage.absolute_path(plain_rel)):
            return False
        try:
            with self._gate.read():
                plaintext = self._read_bytes(self._storage.absolute_path(plain_rel))
            if sha256_hex(plaintext) != str(blob["plain_sha256"]):
                return False
            identity = BlobIdentity(
                uidvalidity=int(message["uidvalidity"]), uid=int(message["uid"]),
                part_number=str(att["part_number"]),
                filename=plain_name_from_cipher(os.path.basename(plain_rel)),
                plain_sha256=str(blob["plain_sha256"]),
                plain_size=int(blob["plain_size"]),
            )
            ciphertext = self._cipher.encrypt(plaintext, identity)
            final_abs = self._storage.absolute_path(str(blob["cipher_rel_path"]))
            tmp = final_abs + ".repair.part"
            with open(tmp, "wb") as fh:
                fh.write(ciphertext)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, final_abs)
            self._fsync_dir(os.path.dirname(final_abs))
            new_sha = sha256_hex(ciphertext)
        except (OSError, BlobIntegrityError):
            return False

        conn = db.begin()
        try:
            conn.execute(
                "UPDATE migration_blobs SET cipher_sha256=?, cipher_size=? "
                "WHERE id=?", (new_sha, len(ciphertext), int(blob["id"])),
            )
            conn.execute(
                "UPDATE attachments SET cipher_sha256=? WHERE id=? "
                "AND storage_state='cipher'",
                (new_sha, int(blob["attachment_id"])),
            )
            db.commit()
        except Exception:
            db.rollback()
            return False
        return True

    # ---------------------------------------------------------------- 演示故障
    def _maybe_inject_switch_fault(self, item_id: int) -> None:
        job = self._db.get_migration_job(
            int(self._db.get_migration_item_by_id(item_id)["job_id"])
        )
        if job is None or not int(job["fail_first_switch"]):
            return
        item = self._db.get_migration_item_by_id(item_id)
        if item is None or int(item["switch_fault_done"]):
            return
        # 故障标记持久化在库中：每个邮件项只在第一次切换时失败
        with self._db.lock:
            self._db._conn.execute(
                "UPDATE migration_items SET switch_fault_done=1 WHERE id=?",
                (item_id,),
            )
            self._db._conn.commit()
        raise MigrationFaultInjected(
            "演示故障：本次索引切换失败（事务已回滚，旧明文仍可下载）"
        )

    def _job_flag(self, job_id: int, column: str) -> bool:
        job = self._db.get_migration_job(job_id)
        return bool(job is not None and int(job[column]))

    def _clear_job_flag(self, job_id: int, column: str) -> None:
        if column not in ("crash_before_switch", "crash_after_switch"):
            raise ValueError(column)
        with self._db.lock:
            self._db._conn.execute(
                f"UPDATE migration_jobs SET {column}=0 WHERE id=?", (job_id,)
            )
            self._db._conn.commit()

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
