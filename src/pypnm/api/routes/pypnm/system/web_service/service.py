# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import os
from pathlib import Path

from pypnm.api.routes.pypnm.system.web_service.schemas import (
    PyPnmWebServiceRuntimeProfileModel,
)

DEFAULT_PROFILE_ENV_PATH = ".data/runtime/pypnm-serve.env"


class PyPnmSystemWebServiceService:
    @staticmethod
    def _profile_env_path() -> Path:
        return Path(os.environ.get("PYPNM_SERVE_ENV_FILE", DEFAULT_PROFILE_ENV_PATH))

    @staticmethod
    def _parse_env_file(path: Path) -> dict[str, str]:
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

    @staticmethod
    def _parse_int(value: str | None) -> int | None:
        if value is None or value.strip() == "":
            return None
        return int(value)

    @staticmethod
    def _parse_float(value: str | None) -> float | None:
        if value is None or value.strip() == "":
            return None
        return float(value)

    @classmethod
    def get_runtime_profile(cls) -> PyPnmWebServiceRuntimeProfileModel:
        profile_path = cls._profile_env_path()
        seeded = cls._parse_env_file(profile_path)

        return PyPnmWebServiceRuntimeProfileModel(
            profile_env_path=str(profile_path),
            profile_exists=profile_path.is_file(),
            detected_cpu_count=cls._parse_int(seeded.get("PYPNM_SERVE_CPU_COUNT")),
            detected_total_memory_gib=cls._parse_float(seeded.get("PYPNM_SERVE_TOTAL_MEMORY_GIB")),
            seeded_workers=cls._parse_int(seeded.get("PYPNM_SERVE_WORKERS")),
            seeded_limit_max_requests=cls._parse_int(seeded.get("PYPNM_SERVE_LIMIT_MAX_REQUESTS")),
            active_workers=cls._parse_int(os.environ.get("PYPNM_ACTIVE_WORKERS")),
            active_limit_max_requests=cls._parse_int(os.environ.get("PYPNM_ACTIVE_LIMIT_MAX_REQUESTS")),
            active_source=os.environ.get("PYPNM_ACTIVE_RUNTIME_SOURCE", ""),
        )
