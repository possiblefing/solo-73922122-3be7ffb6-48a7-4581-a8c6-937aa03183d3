#!/usr/bin/env bash
# 原件加密迁移端到端演示（Docker Compose）。
#
# 前置：docker compose up -d --build
#
# 覆盖场景：
#   1) 历史明文按邮件迁移为密文，附件 ID/来源/下载地址保持不变
#   2) 迁移期间照常下载：单件与 ZIP 都返回原 PDF
#   3) 切换前进程退出 -> 容器重启 -> 自动续办，旧件始终可下载
#   4) 切换后进程退出 -> 重启续办清理，不丢原件、不混淆明密文
#   5) 切换失败 -> 旧明文保留可下载 -> 重试成功
#   6) 密文损坏 / 被其它附件密文替换 -> 拒绝下载，不返回部分 ZIP
#   7) 每封全部密文就绪才切换索引；清完旧明文和暂存才报迁移完成
set -euo pipefail

BASE="${BASE:-http://localhost:8000}"
COMPOSE=(docker compose)
LEGACY_BASE="${LEGACY_BASE:-0}"

line() { printf '\n==================== %s ====================\n' "$1"; }
json() { python3 -m json.tool; }
api_get() { curl -sS --max-time 30 "$BASE$1"; }
api_post() { curl -sS --max-time 120 -X POST "$BASE$1"; }

wait_api() {
  for _ in $(seq 1 90); do
    if curl -sS --max-time 2 "$BASE/health" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "API 未就绪" >&2
  return 1
}

seed_legacy() {
  LEGACY_BASE=$((LEGACY_BASE + 1000))
  "${COMPOSE[@]}" exec -T collector \
    python -m app.legacy --data-dir /data --uidvalidity-base "$LEGACY_BASE"
}

latest_job() {
  api_get "/api/migrations?include_items=false&limit=1" \
    | python3 -c 'import json,sys;print(json.load(sys.stdin)[0]["id"])'
}

# 磁盘上非密文文件数（迁移完成的硬指标之一：必须为 0）
non_cipher_files() {
  "${COMPOSE[@]}" exec -T collector sh -c \
    'find /data/blobs -type f ! -name "*.enc" | wc -l | tr -d "[:space:]"'
}

staging_summary() {
  "${COMPOSE[@]}" exec -T collector sh -c \
    'echo "staging=$(ls -A /data/staging | wc -l) migration-staging=$(ls -A /data/migration-staging 2>/dev/null | wc -l)"'
}

# 取第一封含指定状态附件的 (uidvalidity, uid, 附件ID)
first_source() {
  local want="$1"
  api_get "/api/messages" | WANT="$want" python3 -c '
import json, os, sys
want = os.environ["WANT"]
for m in json.load(sys.stdin):
    for a in m["attachments"]:
        if a["storage_state"] == want:
            print(m["uidvalidity"], m["uid"], a["id"]); raise SystemExit
raise SystemExit(1)
'
}

verify_zip() {
  local url="$1" out="$2" expect="$3"
  curl -sS -o "$out" -w "ZIP 下载 HTTP=%{http_code} 字节=%{size_download}\n" "$url"
  python3 - "$out" "$expect" <<'PY'
import sys, zipfile
path, expect = sys.argv[1], sys.argv[2]
if expect == "ok":
    z = zipfile.ZipFile(path)
    names = z.namelist()
    assert names, "空 ZIP"
    assert all(z.read(n).startswith(b"%PDF") for n in names), "ZIP 内不是 PDF"
    print("ZIP:", names)
else:
    try:
        zipfile.ZipFile(path)
        raise SystemExit("意外：损坏时仍返回了 ZIP")
    except SystemExit:
        raise
    except Exception:
        print("确认：未返回部分 ZIP")
PY
}

line "0. 健康检查（密钥只从数据目录之外的只读密钥卷加载）"
wait_api
api_get /health | json

line "1. 写入历史明文库（模拟加密上线前的原件目录）"
seed_legacy
api_get "/api/messages" | python3 -c '
import json,sys
rows=[m for m in json.load(sys.stdin) if m["attachments"]]
print("含附件的邮件:", len(rows))
for m in rows:
    print(f"  UIDVALIDITY={m[\"uidvalidity\"]} UID={m[\"uid\"]} "
          f"附件ID={[a[\"id\"] for a in m[\"attachments\"]]} "
          f"状态={[a[\"storage_state\"] for a in m[\"attachments\"]]}")
'
echo "--- 迁移前磁盘上的明文原件（部分）:"
"${COMPOSE[@]}" exec -T collector sh -c \
  'find /data/blobs -type f ! -name "*.enc" | sort | head -n 4'

line "2. 迁移历史明文（按邮件；每封密文全部就绪才切换索引）"
api_post "/api/migrations" | json
JOB=$(latest_job)
api_get "/api/migrations/$JOB" | python3 -c '
import json,sys
j=json.load(sys.stdin)
print("任务状态:", j["status"], "计数:", j["counts"])
for i in j["items"]:
    print(f"  UIDVALIDITY={i[\"uidvalidity\"]} UID={i[\"uid\"]} -> {i[\"status\"]}"
          f"（密文 {i[\"encrypted_attachments\"]}/{i[\"total_attachments\"]}）")
'
echo "--- 完成条件：非密文文件数应为 0；暂存应为空:"
echo "非密文文件数: $(non_cipher_files)"
staging_summary

line "3. 下载地址不变：单件与 ZIP 都返回解密后的原 PDF"
read -r UV UID_ ATT_ID <<<"$(first_source cipher)"
curl -sS -o /tmp/enc-single.pdf -w "单件下载 HTTP=%{http_code} 字节=%{size_download}\n" \
  "$BASE/api/messages/attachments/$ATT_ID/download"
head -c 8 /tmp/enc-single.pdf; echo
verify_zip "$BASE/api/sources/$UV/$UID_/download" /tmp/enc-bundle.zip ok

line "4. 切换前进程退出：密文就绪但索引未切换，旧件可下载；重启自动续办"
seed_legacy
echo "--- 触发迁移，第一封切换前 exit（连接会被断开，属预期）:"
curl -sS --max-time 15 -X POST "$BASE/api/migrations?crash_before_switch=true" || true
sleep 1
wait_api
api_get /health | python3 -c 'import json,sys;d=json.load(sys.stdin)
print("startup_migration:", json.dumps(d["startup_migration"], ensure_ascii=False))'
JOB=$(latest_job)
api_get "/api/migrations/$JOB" | python3 -c '
import json,sys
j=json.load(sys.stdin)
print("任务状态:", j["status"], "计数:", j["counts"])'
echo "非密文文件数: $(non_cipher_files)"

line "5. 切换后进程退出：索引已是密文、旧明文待清理；重启续办清理"
seed_legacy
echo "--- 触发迁移，第一封切换索引后 exit:"
curl -sS --max-time 15 -X POST "$BASE/api/migrations?crash_after_switch=true" || true
sleep 1
echo "--- 进程退出瞬间：该封索引已密文，旧明文仍在（尚未清理）:"
"${COMPOSE[@]}" exec -T collector python - <<'PY'
import sqlite3
c = sqlite3.connect("/data/collector.db"); c.row_factory = sqlite3.Row
job = c.execute("SELECT * FROM migration_jobs ORDER BY id DESC LIMIT 1").fetchone()
rows = c.execute(
    "SELECT i.status AS item_status, a.id, a.storage_state, a.storage_path "
    "FROM migration_items i JOIN attachments a ON a.message_id=i.message_id "
    "WHERE i.job_id=? ORDER BY i.id, a.id", (job["id"],)).fetchall()
print("任务状态:", job["status"])
for r in rows[:3]:
    print("  item=", r["item_status"], "att=", r["id"], r["storage_state"], r["storage_path"])
PY
wait_api
api_get /health | python3 -c 'import json,sys;d=json.load(sys.stdin)
print("startup_migration:", json.dumps(d["startup_migration"], ensure_ascii=False))'
JOB=$(latest_job)
api_get "/api/migrations/$JOB" | python3 -c '
import json,sys
j=json.load(sys.stdin)
print("重启续办后:", j["status"], j["counts"])'
echo "非密文文件数: $(non_cipher_files)"

line "6. 切换失败：旧明文保留仍可下载，重试后完成"
seed_legacy
api_post "/api/migrations?fail_first_switch=true" | json
JOB=$(latest_job)
api_get "/api/migrations/$JOB" | python3 -c '
import json,sys
j=json.load(sys.stdin)
print("第一次:", j["status"])
for i in j["items"]:
    print(f"  {i[\"uidvalidity\"]}/{i[\"uid\"]}: {i[\"status\"]} | {i[\"error\"]}")
'
PLAIN_ID=$(api_get "/api/messages" | python3 -c 'import json,sys
for m in json.load(sys.stdin):
    for a in m["attachments"]:
        if a["storage_state"]=="plain":
            print(a["id"]); raise SystemExit')
curl -sS -o /dev/null -w "切换失败期间：明文附件 $PLAIN_ID 下载 HTTP=%{http_code}\n" \
  "$BASE/api/messages/attachments/$PLAIN_ID/download"
echo "--- 重试同一任务:"
api_post "/api/migrations?job_id=$JOB" | json

line "7. 迁移期间照常采集，且下载不被迁移阻塞"
api_post "/api/collect" | json
read -r UV UID_ ATT_ID <<<"$(first_source cipher)"
for _ in $(seq 1 20); do
  code=$(curl -sS -o /dev/null -w "%{http_code}" "$BASE/api/messages/attachments/$ATT_ID/download")
  [ "$code" = "200" ] || { echo "下载失败: HTTP $code"; exit 1; }
done
echo "连续 20 次下载全部 200"

line "8. 密文损坏 / 被替换：拒绝下载，不返回部分 ZIP"
read -r UV UID_ ATT_ID <<<"$(first_source cipher)"
"${COMPOSE[@]}" exec -T collector python - "$ATT_ID" <<'PY'
import sqlite3, sys
att_id = int(sys.argv[1])
c = sqlite3.connect("/data/collector.db")
path = "/data/blobs/" + c.execute(
    "SELECT storage_path FROM attachments WHERE id=?", (att_id,)
).fetchone()[0]
data = open(path, "rb").read()
open(path, "wb").write(data[: len(data) // 2])
print("已截断密文:", path)
PY
curl -sS -o /dev/null -w "单件下载（应 409）HTTP=%{http_code}\n" \
  "$BASE/api/messages/attachments/$ATT_ID/download"
verify_zip "$BASE/api/sources/$UV/$UID_/download" /tmp/enc-bad.zip bad
echo "--- 被另一附件的合法密文替换（AAD 身份不匹配，同样拒绝）:"
"${COMPOSE[@]}" exec -T collector python - "$ATT_ID" <<'PY'
import sqlite3, sys
att_id = int(sys.argv[1])
c = sqlite3.connect("/data/collector.db")
rows = c.execute("SELECT id, storage_path FROM attachments "
                 "WHERE storage_state='cipher' AND id<>? LIMIT 1", (att_id,)).fetchall()
dst = "/data/blobs/" + c.execute("SELECT storage_path FROM attachments WHERE id=?",
                                 (att_id,)).fetchone()[0]
src = "/data/blobs/" + rows[0]["storage_path"]
open(dst, "wb").write(open(src, "rb").read())
print(f"已把附件 {rows[0]['id']} 的密文替换到附件 {att_id}")
PY
curl -sS -o /dev/null -w "替换后单件下载（应 409）HTTP=%{http_code}\n" \
  "$BASE/api/messages/attachments/$ATT_ID/download"
verify_zip "$BASE/api/sources/$UV/$UID_/download" /tmp/enc-swapped.zip bad
echo "--- 逐附件校验接口如实报告:"
MSG_PK=$(api_get "/api/messages" | python3 -c 'import json,sys
for m in json.load(sys.stdin):
    if any(a["id"]=='"$ATT_ID"' for a in m["attachments"]):
        print(m["id"]); break')
api_get "/api/messages/$MSG_PK/verify-attachments" | json

line "完成。打开 $BASE/docs 可触发迁移、查逐邮件状态、在线下载"
