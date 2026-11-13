"""构造"历史明文"库：模拟加密功能上线前的数据目录，用于迁移演示与测试。

与 collector/app/legacy.py 等价，供宿主机直接（不经过 Docker）调用：
  python -m tools.make_legacy --data-dir /tmp/legacy-data
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from collector.app.legacy import seed_legacy_plaintext  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", required=True)
    args = parser.parse_args()
    os.makedirs(args.data_dir, exist_ok=True)
    created = seed_legacy_plaintext(os.path.abspath(args.data_dir))
    print(f"历史明文库已生成: {args.data_dir}（新增 {created} 封）")


if __name__ == "__main__":
    main()
