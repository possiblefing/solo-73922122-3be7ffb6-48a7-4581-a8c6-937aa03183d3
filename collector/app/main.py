"""FastAPI 入口：采集触发、进度查询、按来源（UIDVALIDITY + UID）下载、加密迁移。

启动后访问 /docs 可看到全部入口并在线试用。

下载地址在加密前后保持不变（``/api/messages/attachments/{id}/download``、
``/api/sources/{uv}/{uid}/download``）：识别程序仍按原地址取件，
接口总是返回解密后的原 PDF。
"""
from __future__ import annotations

import os
import threading
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field

from .collector import Collector
from .config import load_settings
from .crypto import BlobCipher, CryptoError, MigrationKeyMismatchError
from .database import Database
from .downloader import BlobGate, BlobUnavailableError, DownloadService
from .migration import (MigrationBusyError, MigrationConfigError,
                        MigrationCrashSimulated, MigrationManager)
from .process_lock import CollectionBusyError
from .storage import Storage


# ---- 响应模型（/docs 中展示结构）----
class AttachmentOut(BaseModel):
    id: int
    part_number: str
    filename: str
    content_type: str
    size_bytes: int
    storage_state: str
    download_url: str


class MessageOut(BaseModel):
    id: int
    uidvalidity: int
    uid: int
    status: str
    failure_reason: Optional[str]
    message_size: Optional[int]
    subject: Optional[str]
    from_header: Optional[str]
    message_id_hdr: Optional[str]
    collected_at: Optional[str]
    attachment_count: int
    attachments: list[AttachmentOut] = Field(default_factory=list)


class EpochOut(BaseModel):
    id: int
    uidvalidity: int
    mailbox: str
    observed_at: str
    total: int
    done: int
    failed: int
    oversize: int
    attachments: int


class RunOut(BaseModel):
    id: int
    uidvalidity: Optional[int]
    started_at: str
    finished_at: Optional[str]
    status: str
    total_seen: int
    processed_ok: int
    failed: int
    oversize: int
    skipped_terminal: int
    attachments_saved: int
    note: Optional[str]


class CollectResponse(BaseModel):
    run_id: int
    status: str
    abort_reason: Optional[str]
    counters: dict


class MigrationItemOut(BaseModel):
    id: int
    job_id: int
    message_id: int
    uidvalidity: int
    uid: int
    subject: Optional[str]
    status: str
    total_attachments: int
    encrypted_attachments: int
    error: Optional[str]
    updated_at: str
    completed_at: Optional[str]


class MigrationJobOut(BaseModel):
    id: int
    status: str
    started_at: str
    finished_at: Optional[str]
    total_messages: int
    note: Optional[str]
    counts: dict
    crash_before_switch: bool
    crash_after_switch: bool
    fail_first_switch: bool
    items: list[MigrationItemOut] = Field(default_factory=list)


class MigrationTriggerOut(BaseModel):
    job_id: int
    created: bool
    status: str
    counts: dict


state: dict = {}


def _startup_migration_resume() -> None:
    manager: MigrationManager = state["migration"]
    try:
        result = manager.startup_reconcile()
    except Exception as exc:  # 续办失败不能阻止 API 启动
        result = {"error": f"启动续办异常: {exc!r}"}
    state["startup_migration"] = result


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = load_settings()
    db = Database(settings.db_path)
    # 密钥必须在数据目录之外、以只读方式加载；加载失败直接拒绝启动，
    # 避免服务带着错误密钥产生无法解密的密文
    cipher = BlobCipher.from_file(settings.key_file, settings.data_dir)
    storage = Storage(
        settings.blob_root, settings.staging_dir,
        os.path.join(settings.data_dir, "migration-staging"), cipher,
    )
    gate = BlobGate()
    removed = storage.cleanup_stale_staging()
    state["settings"] = settings
    state["db"] = db
    state["storage"] = storage
    state["cipher"] = cipher
    state["gate"] = gate
    state["stale_staging_cleaned"] = removed
    state["collector"] = Collector(settings, db, storage)
    state["migration"] = MigrationManager(settings, db, storage, cipher, gate)
    state["download"] = DownloadService(db, storage, cipher, gate)
    state["startup_migration"] = {"status": "resuming"}
    # 后台线程：清理崩溃遗留的迁移暂存，并按需续办上次中断的迁移；
    # API 立即可用，迁移按封续做，不阻塞启动。
    if settings.migration_auto_resume:
        threading.Thread(target=_startup_migration_resume, daemon=True).start()
    else:
        state["startup_migration"] = state["migration"].reconcile_status_only()
    yield
    db.close()


app = FastAPI(
    title="共享收票邮箱 PDF 采集 API（原件加密）",
    description=(
        "从固定 IMAP 邮箱以 UID 采集发票 PDF 原件。\n\n"
        "- 只读 EXAMINE + BODY.PEEK，不改变邮件已读状态；\n"
        "- 每封 ≤ 8MiB，提取全部 application/pdf，按 MIME 部分序号区分同名附件；\n"
        "- 新采集的暂存文件与正式文件均为 AES-256-GCM 密文；\n"
        "- 历史明文按邮件迁移：密文就绪后整封切换索引，切换成功才清理旧明文；\n"
        "- 下载地址不变，单件与 ZIP 下载始终返回解密后的原 PDF；"
        "密文损坏/被替换时拒绝下载，不返回部分 ZIP。"
    ),
    version="1.1.0",
    lifespan=lifespan,
)


def _db() -> Database:
    return state["db"]


def _storage() -> Storage:
    return state["storage"]


def _attachment_out(row) -> AttachmentOut:
    return AttachmentOut(
        id=row["id"], part_number=row["part_number"], filename=row["filename"],
        content_type=row["content_type"], size_bytes=row["size_bytes"],
        storage_state=row["storage_state"],
        download_url=f"/api/messages/attachments/{row['id']}/download",
    )


def _message_out(row, attachments: Optional[list] = None) -> MessageOut:
    if attachments is None:
        attachments = _db().list_attachments(row["id"])
    return MessageOut(
        id=row["id"], uidvalidity=row["uidvalidity"], uid=row["uid"],
        status=row["status"], failure_reason=row["failure_reason"],
        message_size=row["message_size"], subject=row["subject"],
        from_header=row["from_header"], message_id_hdr=row["message_id_hdr"],
        collected_at=row["collected_at"], attachment_count=len(attachments),
        attachments=[_attachment_out(a) for a in attachments],
    )


def _migration_item_out(row) -> MigrationItemOut:
    return MigrationItemOut(
        id=row["id"], job_id=row["job_id"], message_id=row["message_id"],
        uidvalidity=row["uidvalidity"], uid=row["uid"], subject=row["subject"],
        status=row["status"], total_attachments=row["total_attachments"],
        encrypted_attachments=row["encrypted_attachments"],
        error=row["error"], updated_at=row["updated_at"],
        completed_at=row["completed_at"],
    )


def _migration_job_out(job, include_items: bool = True) -> MigrationJobOut:
    return MigrationJobOut(
        id=job["id"], status=job["status"], started_at=job["started_at"],
        finished_at=job["finished_at"], total_messages=job["total_messages"],
        note=job["note"], counts=_db().migration_item_counts(int(job["id"])),
        crash_before_switch=bool(job["crash_before_switch"]),
        crash_after_switch=bool(job["crash_after_switch"]),
        fail_first_switch=bool(job["fail_first_switch"]),
        items=[_migration_item_out(i)
               for i in _db().list_migration_items(job_id=int(job["id"]))]
        if include_items else [],
    )


# ---------------------------------------------------------------- 健康检查
@app.get("/health", tags=["系统"], summary="健康检查（含密钥指纹与迁移续办状态）")
def health() -> dict:
    return {
        "status": "ok",
        "stale_staging_cleaned_on_boot": state.get("stale_staging_cleaned", 0),
        "startup_migration": state.get("startup_migration", {}),
        "key_id": state["cipher"].key_id,
        "key_file": state["settings"].key_file,
    }


# ---------------------------------------------------------------- 采集触发
@app.post("/api/collect", response_model=CollectResponse, tags=["采集"],
          summary="触发一轮采集（全进程唯一，并发触发返回 409）")
def trigger_collect() -> CollectResponse:
    collector: Collector = state["collector"]
    try:
        result = collector.run_collection()
    except CollectionBusyError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return CollectResponse(**result)


@app.get("/api/runs", response_model=list[RunOut], tags=["采集"],
         summary="历史采集运行记录")
def list_runs(limit: int = 50) -> list[RunOut]:
    return [RunOut(**dict(r)) for r in _db().list_runs(limit)]


# ---------------------------------------------------------------- 进度 / 代际
@app.get("/api/progress", response_model=list[EpochOut], tags=["进度"],
         summary="各 UIDVALIDITY 代际的采集进度（含邮箱重建后的新代际）")
def progress() -> list[EpochOut]:
    result = []
    for epoch in _db().list_epochs():
        p = _db().progress_for_epoch(epoch["id"])
        result.append(EpochOut(
            id=epoch["id"], uidvalidity=epoch["uidvalidity"],
            mailbox=epoch["mailbox"], observed_at=epoch["observed_at"],
            total=p["total"] or 0, done=p["done"] or 0,
            failed=p["failed"] or 0, oversize=p["oversize"] or 0,
            attachments=p["attachments"] or 0,
        ))
    return result


@app.get("/api/epochs", response_model=list[EpochOut], tags=["进度"],
         summary="邮箱代际列表（每次 UIDVALIDITY 变化一条）")
def list_epochs() -> list[EpochOut]:
    return progress()


# ---------------------------------------------------------------- 邮件与来源
@app.get("/api/messages", response_model=list[MessageOut], tags=["来源查询"],
         summary="已采集邮件列表，可按 UIDVALIDITY 代际/状态过滤")
def list_messages(uidvalidity: Optional[int] = None,
                  status: Optional[str] = None,
                  limit: int = 200) -> list[MessageOut]:
    epoch_id = None
    if uidvalidity is not None:
        epoch = _db().query_one(
            "SELECT id FROM mailbox_epochs WHERE uidvalidity=?", (uidvalidity,)
        )
        if epoch is None:
            return []
        epoch_id = epoch["id"]
    rows = _db().list_messages(epoch_id=epoch_id, status=status, limit=limit)
    return [_message_out(r) for r in rows]


@app.get("/api/messages/{message_pk}", response_model=MessageOut,
         tags=["来源查询"], summary="按内部 ID 查询单封邮件及其附件来源")
def get_message(message_pk: int) -> MessageOut:
    row = _db().get_message_with_epoch(message_pk)
    if row is None:
        raise HTTPException(404, "邮件记录不存在")
    return _message_out(row)


@app.get("/api/sources/{uidvalidity}/{uid}", response_model=MessageOut,
         tags=["来源查询"], summary="按来源（UIDVALIDITY + UID）定位邮件")
def get_source(uidvalidity: int, uid: int) -> MessageOut:
    epoch = _db().query_one(
        "SELECT id FROM mailbox_epochs WHERE uidvalidity=?", (uidvalidity,)
    )
    if epoch is None:
        raise HTTPException(404, f"UIDVALIDITY={uidvalidity} 代际不存在")
    row = _db().get_message(epoch["id"], uid)
    if row is None:
        raise HTTPException(404, f"UIDVALIDITY={uidvalidity}, UID={uid} 无记录")
    full = _db().get_message_with_epoch(row["id"])
    return _message_out(full)


# ---------------------------------------------------------------- 下载
@app.get("/api/messages/attachments/{attachment_pk}/download",
         tags=["下载"],
         summary="按附件 ID 下载 PDF 原件（地址不变，密文解密后返回原 PDF）")
def download_attachment(attachment_pk: int):
    service: DownloadService = state["download"]
    try:
        filename, payload = service.attachment_pdf(attachment_pk)
    except KeyError:
        raise HTTPException(404, "附件不存在")
    except BlobUnavailableError as exc:
        # 密文损坏/被替换：拒绝下载，绝不返回部分内容
        raise HTTPException(
            status_code=409, detail=f"原件完整性校验失败，拒绝下载: {exc}"
        )
    return Response(
        content=payload,
        media_type="application/pdf",
        headers={
            "Content-Disposition":
                f'attachment; filename="{_ascii_filename(filename)}"'
        },
    )


@app.get("/api/sources/{uidvalidity}/{uid}/download", tags=["下载"],
         summary="按来源（UIDVALIDITY + UID）下载该封全部 PDF（ZIP 打包）")
def download_source_bundle(uidvalidity: int, uid: int):
    service: DownloadService = state["download"]
    try:
        payload = service.source_bundle_zip(uidvalidity, uid)
    except KeyError as exc:
        raise HTTPException(404, str(exc.args[0]) if exc.args else "来源不存在")
    except BlobUnavailableError as exc:
        # 任一附件不可信：整包拒绝，绝不返回部分 ZIP
        raise HTTPException(
            status_code=409,
            detail=f"原件完整性校验失败，拒绝打包下载: {exc}",
        )
    return Response(
        content=payload,
        media_type="application/zip",
        headers={
            "Content-Disposition":
                f'attachment; filename="uv-{uidvalidity}-uid-{uid}.zip"'
        },
    )


@app.get("/api/messages/{message_pk}/verify-attachments", tags=["下载"],
         summary="逐附件校验密文完整性（不可解密时 ok=false）")
def verify_message_attachments(message_pk: int) -> dict:
    if _db().get_message_with_epoch(message_pk) is None:
        raise HTTPException(404, "邮件记录不存在")
    service: DownloadService = state["download"]
    return service.verify_message_attachments(message_pk)


def _ascii_filename(name: str) -> str:
    return name.encode("ascii", errors="replace").decode("ascii").replace('"', "_")


# ---------------------------------------------------------------- 加密迁移
@app.post("/api/migrations", response_model=MigrationTriggerOut,
          tags=["加密迁移"],
          summary="迁移历史明文为密文（按邮件；可续办指定任务）")
def trigger_migration(
    job_id: Optional[int] = None,
    crash_before_switch: bool = False,
    crash_after_switch: bool = False,
    fail_first_switch: bool = False,
    background: bool = False,
) -> MigrationTriggerOut:
    """新建或续办迁移。

    - ``job_id``：续办已有任务；不填则新建（只包含仍有明文的邮件）。
    - ``fail_first_switch``：演示用，让该封第一次切换失败并回滚，
      验证"切换失败旧明文仍可下载、可重试"。
    - ``crash_before_switch`` / ``crash_after_switch``：演示用，在该封
      "密文全部就绪"或"索引已切换"之后立刻终止进程（``os._exit``，模拟 kill）。
      容器按 restart 策略重启后，启动时自动续办该任务。这两个参数与
      ``background`` 互斥，因为进程会退出，接口不会返回正常响应。
    - ``background=true``：后台执行，接口立即返回；进度用 GET 查询。
    """
    manager: MigrationManager = state["migration"]
    settings = state["settings"]
    demo_exit = crash_before_switch or crash_after_switch
    if demo_exit and not settings.migration_allow_demo_fault:
        raise HTTPException(409, "演示故障注入已禁用（MIGRATION_ALLOW_DEMO_FAULT=0）")
    if demo_exit and background:
        # 进程退出会丢掉后台任务，二者必须互斥
        raise HTTPException(400, "crash_* 演示不支持 background=true")
    if demo_exit and job_id is not None:
        raise HTTPException(400, "crash_* 演示只用于新建任务，不用于续办已有任务")

    demo_faults = {
        "crash_before_switch": crash_before_switch,
        "crash_after_switch": crash_after_switch,
        "fail_first_switch": fail_first_switch,
    }

    def _run() -> dict:
        return manager.run_migration(job_id=job_id, demo_faults=demo_faults)

    if background:
        try:
            # 先建任务拿到 ID，再放到后台执行，避免并发创建两个任务
            created = job_id is None
            if created:
                job_id = manager.create_job(demo_faults)
            target_id = job_id

            def _bg() -> None:
                try:
                    manager.run_migration(job_id=target_id)
                except Exception:
                    pass

            threading.Thread(target=_bg, daemon=True).start()
            job = _db().get_migration_job(target_id)
            return MigrationTriggerOut(
                job_id=target_id, created=created,
                status=str(job["status"]) if job else "running",
                counts=_db().migration_item_counts(target_id),
            )
        except MigrationBusyError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except (MigrationConfigError, CryptoError) as exc:
            raise HTTPException(status_code=409, detail=str(exc))

    try:
        result = _run()
    except MigrationCrashSimulated as exc:
        # 演示：状态已持久化（该封 ready 或 switched），进程即将退出；
        # 容器重启后 startup_reconcile 会自动续办，不丢原件、不混淆明密文。
        _terminate_for_demo(str(exc))
        raise HTTPException(status_code=503, detail=str(exc))
    except MigrationBusyError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except (MigrationConfigError, MigrationKeyMismatchError) as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except CryptoError as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return MigrationTriggerOut(
        job_id=int(result["job_id"]),
        created=bool(result.get("created")),
        status=str(result["status"]),
        counts=result.get("counts", {}),
    )


def _terminate_for_demo(reason: str) -> None:
    """演示"进程退出"：同步刷新日志后立刻退出，模拟被 kill。"""
    import logging
    import sys

    logging.getLogger("uvicorn.error").warning(
        "演示进程退出：%s；容器重启后将自动续办迁移", reason
    )
    for handler in logging.getLogger().handlers:
        try:
            handler.flush()
        except Exception:
            pass
    sys.stdout.flush()
    sys.stderr.flush()
    # 非零退出码更贴近"被 kill"；compose 的 restart: always 会立即拉起
    os._exit(1)


@app.get("/api/migrations", response_model=list[MigrationJobOut],
         tags=["加密迁移"], summary="迁移任务列表（含逐邮件状态）")
def list_migrations(limit: int = 20, include_items: bool = True
                    ) -> list[MigrationJobOut]:
    return [_migration_job_out(j, include_items)
            for j in _db().list_migration_jobs(limit)]


@app.get("/api/migrations/{job_id}", response_model=MigrationJobOut,
         tags=["加密迁移"], summary="单个迁移任务与逐邮件状态")
def get_migration(job_id: int) -> MigrationJobOut:
    job = _db().get_migration_job(job_id)
    if job is None:
        raise HTTPException(404, "迁移任务不存在")
    return _migration_job_out(job)


@app.get("/api/migrations/{job_id}/items", response_model=list[MigrationItemOut],
         tags=["加密迁移"], summary="逐邮件迁移状态（可按状态过滤）")
def get_migration_items(job_id: int, status: Optional[str] = None,
                        limit: int = 500) -> list[MigrationItemOut]:
    if _db().get_migration_job(job_id) is None:
        raise HTTPException(404, "迁移任务不存在")
    rows = _db().list_migration_items(job_id=job_id, status=status, limit=limit)
    return [_migration_item_out(r) for r in rows]


@app.get("/api/migrations/{job_id}/verify", tags=["加密迁移"],
         summary="只读巡检该任务全部密文是否仍可解密（损坏/被替换时 all_ok=false）")
def verify_migration_job(job_id: int) -> dict:
    if _db().get_migration_job(job_id) is None:
        raise HTTPException(404, "迁移任务不存在")
    manager: MigrationManager = state["migration"]
    return manager.verify_job_ciphertexts(job_id)


@app.get("/api/migrations/{job_id}/items/{item_id}/verify",
         tags=["加密迁移"],
         summary="逐附件校验该封密文（不可解密时返回 ok=false）")
def verify_migration_item(job_id: int, item_id: int) -> dict:
    item = _db().get_migration_item_by_id(item_id)
    if item is None or int(item["job_id"]) != job_id:
        raise HTTPException(404, "迁移项不存在")
    if _db().get_message_with_epoch(int(item["message_id"])) is None:
        raise HTTPException(404, "邮件记录不存在")
    service: DownloadService = state["download"]
    result = service.verify_message_attachments(int(item["message_id"]))
    return {"job_id": job_id, "item_id": item_id, **result}
