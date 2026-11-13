# 共享收票邮箱 PDF 采集服务（原件加密）

从固定配置的共享收票邮箱（IMAP）归集发票 PDF 原件，供后续发票识别入仓。
技术栈：**FastAPI + SQLite + 本地文件存储**，并附带一个零第三方依赖的**本地 IMAP 演示服务**。

收票原件目录中的 PDF **一律以 AES-256-GCM 密文存放**；历史明文按邮件迁移为密文，
下载地址与识别程序取件方式保持不变（单件与 ZIP 下载始终返回解密后的原 PDF）。

## 能力与约束对照

| 需求 | 实现 |
| --- | --- |
| IMAP 地址/账号/INBOX 配置固定 | `collector/app/config.py`，全部来自环境变量，`docker-compose.yml` 固定注入 |
| 以 UID 取信 | 全程 `UID SEARCH` / `UID FETCH`，不依赖邮件序号 |
| 不改变已读状态 | `SELECT ... (readonly)` 实际发送 `EXAMINE`，正文用 `BODY.PEEK[]`，无任何 STORE/EXPUNGE |
| 每封最多 8 MiB | 先查 `RFC822.SIZE` 预校验，拉到原文再按实际字节二次校验；超限标记 `oversize`、不拉/不留正文 |
| 提取全部 `application/pdf` | 深度遍历 MIME 树，非 PDF 附件忽略，不按文件名或 Message-ID 去重 |
| 同名附件区分 | 按 IMAP MIME 部分序号（如 `1.2`、`1.3`）编号，落盘文件名 `1.2__invoice.pdf.enc` |
| SQLite 记录 UIDVALIDITY/UID/进度 | `mailbox_epochs` / `messages` / `attachments` / `collection_runs` |
| 邮箱重建后从新 UID 空间重采 | UIDVALIDITY 变化即建立新代际（epoch），新旧代际独立，旧原件与来源仍可查询下载 |
| 附件全部落盘后索引与进度一起提交 | 先写 staging，整封原子 `rename` 发布，再在**单个 SQLite 事务**内写索引+进度 |
| 断流/落盘失败/进程退出不暴露半封 | 半封只存在于 `staging/`（API 只索引 `blobs/`）；失败 `finally` 清理，启动时清理崩溃遗留；该封不写进度 |
| 重启续采不重复 | 已落库邮件（done/oversize/failed）按 (UIDVALIDITY, UID) 跳过；断流/落盘失败等未落库邮件才重采；正式路径由 UIDVALIDITY/UID/部分序号确定，重试幂等 |
| 仅一个采集进程，并发不并行 | `fcntl` 排他文件锁（跨进程）+ 线程锁（同进程并发立即 409，不排队） |
| 原件目录不含明文 PDF | 新采集在内存加密后落盘；staging 与 `blobs/` 里只有 `*.enc` 密文 |
| AES-256-GCM + cryptography | `collector/app/crypto.py`：12 字节随机 nonce、16 字节 GCM tag、AAD 绑定附件身份 |
| 密钥从数据目录外的只读文件加载 | `BLOB_KEY_FILE` 指向独立密钥卷；启动时校验"不在 `DATA_DIR` 内"，只读打开，不满足即拒绝启动 |
| 单 API 进程 | 单 worker，采集锁与迁移锁均为进程级排他锁 |
| 迁移按邮件进行 | `migration_items` 逐邮件一项；每封的全部密文验证通过后才切换该封索引 |
| 迁移保留附件 ID/来源/下载地址 | 只改 `attachments.storage_path` 等列，`id`、`message_id`、`part_number` 不动，下载路由不变 |
| 迁移期间照常采集与下载 | 迁移锁与采集锁分离；下载持读锁、迁移清理持写锁，文件读写全程不持 SQLite 写锁 |
| 已获准的下载完整结束 | 下载在读锁内把整份 PDF 读入内存并解密后才放行响应，清理旧明文不会截断已开始的响应 |
| 每封密文全部就绪才切换索引 | `_prepare_item` 全部成功 → `ready`；切换是单事务，全封附件一起变成 `cipher` |
| 切换失败保留旧件可重试 | 切换事务回滚，索引仍指向明文文件；该封项标记 `failed` 并记录原因，可再次 POST 续办 |
| 切换前后进程退出可续办 | 状态全部落库；启动时 `startup_reconcile` 自动续办（`MIGRATION_AUTO_RESUME=1`） |
| 清完旧明文和暂存才报完成 | 切密文 → 逐份校验 → 删除旧明文与迁移暂存 → 复核该封已无明文索引 → 置 `completed` |
| 密文损坏/被替换拒绝下载 | 文件 sha256 + GCM tag + AAD 三重校验；任一失败返回 `409`，ZIP 整包拒绝，绝不返回部分内容 |

## 加密与迁移设计

### 密文格式

```
MAGIC(10="INVPDFGCM") | VERSION(1) | NONCE(12) | CIPHERTEXT + GCM TAG(16)
```

AES-GCM 的 AAD 绑定 `UIDVALIDITY / UID / MIME 部分序号 / 落盘文件名 / 明文 sha256 / 明文长度`。
因此把**另一个附件的密文**搬到本附件路径会因 AAD 不匹配而解密失败；
数据库还保存整份密文的 `cipher_sha256`，文件被截断/改动会在解密前就被拒绝。

### 迁移单封邮件的三个阶段

| 阶段 | 做什么 | 进程在此退出会怎样 |
| --- | --- | --- |
| `pending → ready` | 事务外读明文、加密、写迁移暂存、fsync + 原子 rename 发布 `.enc`、解密验证；全部通过后短事务置 `ready` | 索引仍指向明文，旧件可下载；重启后幂等重做（已存在的合法密文直接复用） |
| `ready → switched` | **单个短事务**把该封全部附件索引切到密文（`storage_path`/`plain_sha256`/`cipher_sha256`/`key_id`） | 事务未提交：仍是明文索引，可下载、可重试；事务已提交：索引全是密文，不再出现明密文混用 |
| `switched → completed` | 逐份再校验密文 → 持写锁删除该封旧明文与迁移暂存 → 复核 `count(plain)=0` → 置 `completed` | 索引已是密文，旧明文多留一会儿；重启后续办清理 |

**只有 `completed` 才表示"该封迁移完成"**。任务状态 `completed` 表示全部邮件均已完成，
`completed_with_failures` 表示有邮件项失败（其旧明文保留、可下载、可重试）。

### 锁与并发

| 操作 | 文件锁 | SQLite |
| --- | --- | --- |
| 采集 `POST /api/collect` | `collect.lock`（排他，进程级） | 仅在"索引+进度"提交时短事务 |
| 迁移 `POST /api/migrations` | `migrate.lock`（排他，与采集锁不同） | 仅为状态转换开短事务 |
| 下载 | `BlobGate` 读锁 | 只读查询 |
| 迁移删除旧明文 | `BlobGate` 写锁 | 无 |

`BlobGate` 写者优先：迁移清理不会被持续下载饿死；下载在读锁内完成"读索引 + 读文件 +
解密"再放行响应，所以已获准的下载一定完整结束。

### 密钥

```bash
# compose 中由一次性任务生成到独立密钥卷 /secrets，权限 0400
docker compose run --rm keygen
# 本地开发
python -m collector.app.keygen --path /path/outside/data/blob.key
# 允许 32 字节原始密钥，或 64 位十六进制文本
```

启动时若有以下任一情况会**拒绝启动**：密钥文件不存在、长度不合法、
位于 `DATA_DIR` 之内。库里已有密文而当前密钥指纹不匹配时，迁移接口返回 `409`，
避免用新密钥产生新旧混用的密文。迁移完成后可用 `GET /api/migrations/{job_id}/verify`
随时只读巡检密文是否仍可解密。

## 目录结构

```
.
├── docker-compose.yml          # 一键启动 imap + 播种 + collector
├── collector/                  # FastAPI + SQLite 采集服务
│   ├── Dockerfile
│   ├── entrypoint.sh           # 校验密钥存在后单进程启动
│   ├── requirements.txt
│   └── app/
│       ├── main.py             # API 入口（/docs）
│       ├── collector.py        # 采集流水线与事务/故障边界
│       ├── imap_client.py      # 只读 IMAP（EXAMINE + UID + BODY.PEEK）
│       ├── pdf_extract.py      # MIME 遍历、PDF 提取、部分序号
│       ├── storage.py          # staging -> 加密 -> 原子发布 -> blobs
│       ├── crypto.py           # AES-256-GCM、AAD 绑定、密钥加载
│       ├── migration.py        # 历史明文按邮件迁移（准备/切换/清理/续办）
│       ├── downloader.py       # 解密下载、完整性拒绝、BlobGate 读写门
│       ├── keygen.py           # 一次性生成 256 位密钥（数据目录之外）
│       ├── legacy.py           # 构造历史明文演示数据
│       ├── database.py         # SQLite 持久层（含迁移状态机）
│       ├── process_lock.py     # 单采集/单迁移进程文件锁
│       └── config.py
├── imap_server/                # 本地 IMAP 演示服务（纯标准库 asyncio）
│   ├── Dockerfile
│   └── imapdemo/
│       ├── server.py           # IMAP4rev1 只读子集 + 断流注入
│       ├── state.py            # 邮箱状态（删信/重建/断流开关）
│       ├── seed.py             # 5 封演示邮件播种
│       └── control.py          # 邮箱控制 CLI
├── tests/test_encryption_migration.py  # 加密/迁移单元与集成测试
└── tools/
    ├── demo.sh                 # 采集侧端到端演示
    ├── demo_encryption.sh      # 加密迁移端到端演示（含切换前后退出）
    └── make_legacy.py          # 宿主机构造历史明文数据
```

## 快速开始

```bash
docker compose up -d --build
# 浏览器打开
#   http://localhost:8000/docs      采集/进度/下载 Swagger 文档
#   IMAP 演示端口 127.0.0.1:1430
```

启动后 `imap-seed` 一次性任务会写入 5 封演示邮件：

| UID | 内容 | 预期 |
| --- | --- | --- |
| 1 | 单个 PDF | done，1 附件 |
| 2 | 两个**同名** PDF + 一个 txt | done，2 附件，序号 1.2 / 1.3 |
| 3 | 多附件大邮件（约 6.7 MiB） | 断流演示目标 |
| 4 | 约 8.3 MiB 超限邮件 | oversize，不拉正文 |
| 5 | 无附件纯文本 | done，0 附件 |

## API 入口（详见 /docs）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/collect` | 触发一轮采集；并发触发返回 `409` |
| GET  | `/api/progress` | 各 UIDVALIDITY 代际的采集进度 |
| GET  | `/api/epochs` | 邮箱代际列表（每次重建一条） |
| GET  | `/api/runs` | 历史采集运行记录（含 aborted 原因） |
| GET  | `/api/messages` | 邮件与附件来源列表，可按 `uidvalidity`/`status` 过滤（含 `storage_state`） |
| GET  | `/api/messages/{id}` | 单封邮件及附件来源 |
| GET  | `/api/sources/{uidvalidity}/{uid}` | **按来源（UIDVALIDITY+UID）** 定位 |
| GET  | `/api/messages/attachments/{id}/download` | 下载单个 PDF 原件（密文解密后返回，地址不变） |
| GET  | `/api/sources/{uidvalidity}/{uid}/download` | 按来源 ZIP 打包下载该封全部 PDF（地址不变） |
| GET  | `/api/messages/{id}/verify-attachments` | 逐附件校验密文完整性 |
| POST | `/api/migrations` | **触发/续办加密迁移**：`job_id` 续办，`crash_before_switch`/`crash_after_switch`/`fail_first_switch` 演示故障，`background=true` 后台执行 |
| GET  | `/api/migrations` | 迁移任务列表（含逐邮件状态） |
| GET  | `/api/migrations/{job_id}` | 单个任务与逐邮件状态 |
| GET  | `/api/migrations/{job_id}/items` | 逐邮件迁移状态（可按 `status` 过滤） |
| GET  | `/api/migrations/{job_id}/verify` | 只读巡检该任务全部密文（损坏/被替换时 `all_ok=false`） |
| GET  | `/api/migrations/{job_id}/items/{item_id}/verify` | 校验该封密文，返回逐附件 `ok` |

迁移项状态：`pending`（待处理）→ `ready`（该封密文全部就绪、索引未切换）→
`switched`（索引已切到密文、旧明文待清理）→ `completed`（旧明文与暂存已清理）；
失败为 `failed`（旧明文保留、仍可下载、可重试）。

## 加密迁移演示

```bash
docker compose up -d --build
bash tools/demo_encryption.sh      # 全流程；或只看下面的手工命令
```

手工示例：

```bash
# 1) 写入"加密上线前"的历史明文数据
docker compose exec -T collector python -m app.legacy --data-dir /data

# 2) 查看当前为明文索引，下载正常
curl -s http://localhost:8000/api/messages | python3 -m json.tool

# 3) 迁移
curl -X POST http://localhost:8000/api/migrations | python3 -m json.tool
curl -s http://localhost:8000/api/migrations/1 | python3 -m json.tool
docker compose exec -T collector sh -c 'find /data/blobs -type f'   # 只剩 *.enc

# 4) 下载地址不变，返回原 PDF
curl -o /tmp/a.pdf http://localhost:8000/api/messages/attachments/1/download
curl -o /tmp/all.zip http://localhost:8000/api/sources/1000/2/download

# 5) 切换前进程退出（进程 exit，容器 restart:always 拉起并自动续办）
curl -X POST 'http://localhost:8000/api/migrations?crash_before_switch=true' || true
# 6) 切换后进程退出（索引已密文，重启后继续清理旧明文）
curl -X POST 'http://localhost:8000/api/migrations?crash_after_switch=true' || true
# 7) 切换失败：旧明文保留可下载，再次 POST ?job_id=<id> 重试即成功
curl -X POST 'http://localhost:8000/api/migrations?fail_first_switch=true'
curl -X POST 'http://localhost:8000/api/migrations?job_id=4'
```

## 演示三个关键场景

### 1) 多附件中途断流

```bash
# 让 UID3 的正文 FETCH 发送一半字节后断开
docker compose exec imap python -m imapdemo.control --data-dir /maildata flaky 3
curl -X POST http://localhost:8000/api/collect     # aborted，UID3 不推进、无半封
docker compose exec collector ls -A /data/staging  # 为空
# 恢复后续采，UID3 完整入库且不重复
docker compose exec imap python -m imapdemo.control --data-dir /maildata flaky-off
curl -X POST http://localhost:8000/api/collect
```

### 2) 删除前信导致序号变化

```bash
docker compose exec imap python -m imapdemo.control --data-dir /maildata delete-before 1
# 序号前移但 UID 不变；采集以 UID 定位，已采集邮件幂等跳过
```

### 3) 邮箱重建（UIDVALIDITY 变化）

```bash
docker compose exec imap python -m imapdemo.control --data-dir /maildata rebuild
docker compose run --rm --entrypoint \
  "python -m imapdemo.seed --data-dir /maildata --rebuild" imap-seed
curl -X POST http://localhost:8000/api/collect
curl http://localhost:8000/api/progress   # 出现两个 UIDVALIDITY 代际，旧原件仍可下载
```

一键全流程演示：`bash tools/demo.sh`。

## 存储布局

```
/data                              # 数据卷 collectordata
├── collector.db                   # SQLite（WAL）
├── collect.lock                   # 单采集进程排他锁
├── migrate.lock                   # 单迁移进程排他锁（与采集锁分离）
├── staging/tmp-<uuid>/            # 采集半封临时区（只含密文），成功或失败后即清空
├── migration-staging/job-<id>/    # 迁移密文暂存区，每封完成或失败后清空
└── blobs/
    └── uidvalidity-<UIDVALIDITY>/
        └── uid-<UID>/
            ├── 1.2__invoice.pdf.enc   # <MIME 部分序号>__<原文件名>.enc（AES-256-GCM）
            └── 1.3__invoice.pdf.enc
/secrets                           # 独立密钥卷 blobkey（只读挂载进 collector）
└── blob.key                       # 32 字节密钥，权限 0400，绝不放进数据卷
```

迁移期间上述目录会短暂同时出现 `1.2__invoice.pdf`（待清理的旧明文）与
`1.2__invoice.pdf.enc`（新密文）：索引在同一事务内整体切换，API 永远不会同时
对外提供两种形态；切换成功后旧明文随即删除，只有 `completed` 才算迁移完成。

## 测试

```bash
python3 -m unittest -v tests.test_encryption_migration
```

覆盖：密钥必须在数据目录之外、AES-GCM 往返与 AAD 身份绑定、截断/替换拒绝、
按邮件迁移与下载不变、损坏时单件与 ZIP 均拒绝、切换失败保留旧明文并可重试、
切换前/后退出后续办、旧库自动升级为 `plain`、迁移不会饿死下载。

## 本地开发（无 Docker）

```bash
pip install -r collector/requirements.txt
python -m collector.app.keygen --path /tmp/blobkey/blob.key   # 数据目录之外
# 历史明文数据（可选，用于迁移演示）
python -m tools.make_legacy --data-dir ./_data
# 采集服务
DATA_DIR=./_data BLOB_KEY_FILE=/tmp/blobkey/blob.key \
IMAP_HOST=127.0.0.1 IMAP_PORT=1430 \
  uvicorn app.main:app --reload --app-dir collector

# IMAP 演示服务（纯标准库）
PYTHONPATH=imap_server MAIL_DATA_DIR=./_mail IMAP_BIND_PORT=1430 \
  python -m imapdemo
PYTHONPATH=imap_server python -m imapdemo.seed --data-dir ./_mail
```
