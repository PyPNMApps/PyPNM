#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import argparse
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
SRC_DIR = PROJECT_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


def _default_write_path() -> str:
    from pypnm.support.worker_profile import default_profile_env_path

    return str(default_profile_env_path())


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Seed PyPNM FastAPI worker defaults from host CPU and RAM.",
    )
    parser.add_argument(
        "--write",
        default=_default_write_path(),
        help=f"Env file path to write (default: {_default_write_path()})",
    )
    parser.add_argument(
        "--cpu-count",
        type=int,
        default=None,
        help="Override detected CPU count (testing and controlled installs).",
    )
    parser.add_argument(
        "--memory-gib",
        type=float,
        default=None,
        help="Override detected total memory in GiB (testing and controlled installs).",
    )
    parser.add_argument(
        "--print-only",
        action="store_true",
        help="Print the env content to stdout instead of writing a file.",
    )
    return parser


def main() -> int:
    from pypnm.support.worker_profile import (
        build_worker_profile,
        detect_cpu_count,
        detect_total_memory_bytes,
        profile_to_env_lines,
    )

    args = _build_parser().parse_args()

    cpu_count = max(1, int(args.cpu_count)) if args.cpu_count is not None else detect_cpu_count()
    if args.memory_gib is not None:
        total_memory_gib = float(args.memory_gib)
    else:
        total_memory_gib = detect_total_memory_bytes() / float(1024**3)

    profile = build_worker_profile(cpu_count=cpu_count, total_memory_gib=total_memory_gib)
    content = "\n".join(profile_to_env_lines(profile)) + "\n"

    if args.print_only:
        print(content, end="")
        return 0

    output_path = Path(args.write)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content)
    print(f"Wrote PyPNM worker profile to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
