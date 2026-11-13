"""采集服务配置：IMAP 连接信息、邮箱名及存储路径全部由环境变量固定。"""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    # ---- IMAP（地址、账号、邮箱名由配置固定）----
    imap_host: str
    imap_port: int
    imap_user: str
    imap_password: str
    imap_mailbox: str
    socket_timeout: int

    # ---- 业务限制 ----
    max_message_bytes: int  # 每封邮件上限，默认 8 MiB

    # ---- 本地存储 ----
    data_dir: str           # SQLite 与原件根目录
    db_path: str
    blob_root: str          # PDF 原件根目录
    staging_dir: str        # 半封附件的临时落盘区（对外不可见）
    lock_path: str          # 单采集进程文件锁

    # ---- 原件加密 / 存量迁移 ----
    key_file: str           # AES-256 密钥文件；必须位于 data_dir 之外，只读加载
    migration_lock_path: str  # 单迁移进程文件锁
    migration_auto_resume: bool  # 重启后自动续办未完成迁移
    migration_allow_demo_fault: bool  # 是否允许 /docs 触发"切换前/后退出"演示故障


def _env(key: str, default: str) -> str:
    value = os.environ.get(key)
    return value if value not in (None, "") else default


def _env_bool(key: str, default: bool) -> bool:
    value = os.environ.get(key)
    if value in (None, ""):
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def load_settings() -> Settings:
    data_dir = _env("DATA_DIR", "/data")
    # 密钥文件默认放在 data_dir 的兄弟目录：数据目录打包/备份时不会带上密钥
    default_key = os.path.join(
        os.path.dirname(os.path.abspath(data_dir)), "secrets", "blob.key"
    )
    return Settings(
        imap_host=_env("IMAP_HOST", "imap"),
        imap_port=int(_env("IMAP_PORT", "143")),
        imap_user=_env("IMAP_USER", "invoicing@example.com"),
        imap_password=_env("IMAP_PASSWORD", "invoice-pass"),
        imap_mailbox=_env("IMAP_MAILBOX", "INBOX"),
        socket_timeout=int(_env("IMAP_SOCKET_TIMEOUT", "30")),
        max_message_bytes=int(_env("MAX_MESSAGE_BYTES", str(8 * 1024 * 1024))),
        data_dir=data_dir,
        db_path=os.path.join(data_dir, "collector.db"),
        blob_root=os.path.join(data_dir, "blobs"),
        staging_dir=os.path.join(data_dir, "staging"),
        lock_path=os.path.join(data_dir, "collect.lock"),
        key_file=_env("BLOB_KEY_FILE", default_key),
        migration_lock_path=os.path.join(data_dir, "migrate.lock"),
        migration_auto_resume=_env_bool("MIGRATION_AUTO_RESUME", True),
        migration_allow_demo_fault=_env_bool("MIGRATION_ALLOW_DEMO_FAULT", True),
    )
