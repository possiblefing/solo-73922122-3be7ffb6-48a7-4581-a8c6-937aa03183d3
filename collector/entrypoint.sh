#!/bin/sh
# 容器入口：先确保数据目录存在，再以单进程启动 API。
# 密钥由独立的 keygen 一次性任务写入 /secrets（只读挂载），此处只做存在性检查。
set -e

DATA_DIR="${DATA_DIR:-/data}"
mkdir -p "$DATA_DIR"

if [ ! -f "${BLOB_KEY_FILE:-/secrets/blob.key}" ]; then
  echo "错误：未找到密钥文件 ${BLOB_KEY_FILE:-/secrets/blob.key}" >&2
  echo "请先运行一次性任务：docker compose run --rm keygen" >&2
  exit 1
fi

exec "$@"
