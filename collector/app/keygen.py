"""一次性密钥生成任务：在数据目录之外的独立卷中创建 AES-256 密钥。

- 已存在则原样保留（幂等，绝不轮换密钥）；
- 文件权限 0400，collector 以只读方式挂载 /secrets；
- 密钥卷与数据卷分离，备份数据目录不会带上密钥。

用法（容器内）：python -m app.keygen --path /secrets/blob.key
"""
from __future__ import annotations

import argparse
import os
import sys

# 数据目录在不同部署中可能由 root 创建而容器以非 root 运行；
# 密钥只需"数据目录之外 + 只读"，权限固定 0400 即可。
os.umask(0o077)


def main() -> None:
    parser = argparse.ArgumentParser(description="生成原件加密密钥")
    parser.add_argument("--path", required=True)
    # compose 覆盖 entrypoint 时镜像 CMD 可能作为多余参数传入，忽略即可
    args, _unknown = parser.parse_known_args()
    path = args.path
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        if os.path.getsize(path) not in (32, 64):
            sys.exit(f"已存在的密钥文件长度异常: {os.path.getsize(path)} 字节")
        print(f"密钥已存在，保持不变: {path}")
        return
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o400)
    try:
        os.write(fd, os.urandom(32))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    print(f"已生成 256 位密钥: {path}")


if __name__ == "__main__":
    main()
