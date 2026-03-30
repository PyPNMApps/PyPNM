# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from pypnm.config.config_manager import ConfigManager

DEFAULT_RUNTIME_DIR = ".data/runtime"
DEFAULT_PROFILE_ENV_FILENAME = "pypnm-serve.env"


@dataclass(frozen=True)
class WorkerProfile:
    cpu_count: int
    total_memory_gib: float
    workers: int
    limit_max_requests: int


def default_profile_env_path() -> Path:
    config = ConfigManager()
    runtime_dir = config.get("PnmFileRetrieval", "runtime_dir")
    if not isinstance(runtime_dir, str) or runtime_dir.strip() == "":
        runtime_dir = DEFAULT_RUNTIME_DIR
    return Path(runtime_dir) / DEFAULT_PROFILE_ENV_FILENAME


def detect_cpu_count() -> int:
    return max(1, int(os.cpu_count() or 1))


def detect_total_memory_bytes() -> int:
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
        for line in meminfo.read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                parts = line.split()
                if len(parts) >= 2:
                    return int(parts[1]) * 1024

    raise RuntimeError("Unable to determine total system memory")


def memory_cap_workers(total_memory_gib: float) -> int:
    if total_memory_gib < 6.0:
        return 1
    if total_memory_gib < 12.0:
        return 2
    if total_memory_gib < 24.0:
        return 4
    return 8


def build_worker_profile(cpu_count: int, total_memory_gib: float) -> WorkerProfile:
    cpu_target = min(4, max(1, cpu_count))
    memory_target = memory_cap_workers(total_memory_gib)
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


def detect_worker_profile() -> WorkerProfile:
    return build_worker_profile(
        cpu_count=detect_cpu_count(),
        total_memory_gib=detect_total_memory_bytes() / float(1024**3),
    )


def profile_to_env_lines(profile: WorkerProfile) -> list[str]:
    return [
        f"PYPNM_SERVE_CPU_COUNT={profile.cpu_count}",
        f"PYPNM_SERVE_TOTAL_MEMORY_GIB={profile.total_memory_gib}",
        f"PYPNM_SERVE_WORKERS={profile.workers}",
        f"PYPNM_SERVE_LIMIT_MAX_REQUESTS={profile.limit_max_requests}",
    ]


def parse_env_file(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}

    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line == "" or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def parse_int(value: str | None) -> int | None:
    if value is None or value.strip() == "":
        return None
    return int(value)


def parse_float(value: str | None) -> float | None:
    if value is None or value.strip() == "":
        return None
    return float(value)


def load_seeded_profile(path: Path) -> WorkerProfile | None:
    values = parse_env_file(path)
    workers = parse_int(values.get("PYPNM_SERVE_WORKERS"))
    limit_max_requests = parse_int(values.get("PYPNM_SERVE_LIMIT_MAX_REQUESTS"))
    cpu_count = parse_int(values.get("PYPNM_SERVE_CPU_COUNT"))
    total_memory_gib = parse_float(values.get("PYPNM_SERVE_TOTAL_MEMORY_GIB"))

    if workers is None or limit_max_requests is None or cpu_count is None or total_memory_gib is None:
        return None

    return WorkerProfile(
        cpu_count=cpu_count,
        total_memory_gib=total_memory_gib,
        workers=workers,
        limit_max_requests=limit_max_requests,
    )
