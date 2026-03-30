#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_OUTPUT_PATH = ".data/runtime/pypnm-serve.env"


@dataclass(frozen=True)
class WorkerProfile:
    cpu_count: int
    total_memory_gib: float
    workers: int
    limit_max_requests: int


def _detect_cpu_count() -> int:
    return max(1, int(os.cpu_count() or 1))


def _detect_total_memory_bytes() -> int:
    if hasattr(os, "sysconf"):
        try:
            page_size = int(os.sysconf("SC_PAGE_SIZE"))
            page_count = int(os.sysconf("SC_PHYS_PAGES"))
            if page_size > 0 and page_count > 0:
                return page_size * page_count
        except (OSError, ValueError):
            pass

    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        for line in meminfo.read_text().splitlines():
            if line.startswith("MemTotal:"):
                parts = line.split()
                if len(parts) >= 2:
                    return int(parts[1]) * 1024

    raise RuntimeError("Unable to determine total system memory")


def _memory_cap_workers(total_memory_gib: float) -> int:
    if total_memory_gib < 6.0:
        return 1
    if total_memory_gib < 12.0:
        return 2
    if total_memory_gib < 24.0:
        return 4
    return 8


def build_worker_profile(cpu_count: int, total_memory_gib: float) -> WorkerProfile:
    cpu_target = min(4, max(1, cpu_count))
    memory_target = _memory_cap_workers(total_memory_gib)
    workers = max(1, min(cpu_target, memory_target))

    if total_memory_gib < 12.0:
        limit_max_requests = 1000
    elif total_memory_gib >= 64.0 and cpu_count >= 8:
        limit_max_requests = 4000
    else:
        limit_max_requests = 2000

    return WorkerProfile(
        cpu_count=cpu_count,
        total_memory_gib=round(total_memory_gib, 2),
        workers=workers,
        limit_max_requests=limit_max_requests,
    )


def _profile_to_env_lines(profile: WorkerProfile) -> list[str]:
    return [
        f"PYPNM_SERVE_CPU_COUNT={profile.cpu_count}",
        f"PYPNM_SERVE_TOTAL_MEMORY_GIB={profile.total_memory_gib}",
        f"PYPNM_SERVE_WORKERS={profile.workers}",
        f"PYPNM_SERVE_LIMIT_MAX_REQUESTS={profile.limit_max_requests}",
    ]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Seed PyPNM FastAPI worker defaults from host CPU and RAM.",
    )
    parser.add_argument(
        "--write",
        default=DEFAULT_OUTPUT_PATH,
        help=f"Env file path to write (default: {DEFAULT_OUTPUT_PATH})",
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
    args = _build_parser().parse_args()

    cpu_count = max(1, int(args.cpu_count)) if args.cpu_count is not None else _detect_cpu_count()
    if args.memory_gib is not None:
        total_memory_gib = float(args.memory_gib)
    else:
        total_memory_gib = _detect_total_memory_bytes() / float(1024**3)

    profile = build_worker_profile(cpu_count=cpu_count, total_memory_gib=total_memory_gib)
    content = "\n".join(_profile_to_env_lines(profile)) + "\n"

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
