# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import os
from pathlib import Path

from pypnm.api.routes.pypnm.system.web_service.schemas import (
    PyPnmWebServiceRuntimeProfileModel,
)
from pypnm.support.worker_profile import (
    default_profile_env_path,
    parse_env_file,
    parse_float,
    parse_int,
)


class PyPnmSystemWebServiceService:
    @staticmethod
    def _profile_env_path() -> Path:
        return Path(os.environ.get("PYPNM_SERVE_ENV_FILE", str(default_profile_env_path())))

    @classmethod
    def get_runtime_profile(cls) -> PyPnmWebServiceRuntimeProfileModel:
        profile_path = cls._profile_env_path()
        seeded = parse_env_file(profile_path)

        return PyPnmWebServiceRuntimeProfileModel(
            profile_env_path=str(profile_path),
            profile_exists=profile_path.is_file(),
            detected_cpu_count=parse_int(seeded.get("PYPNM_SERVE_CPU_COUNT")),
            detected_total_memory_gib=parse_float(seeded.get("PYPNM_SERVE_TOTAL_MEMORY_GIB")),
            seeded_workers=parse_int(seeded.get("PYPNM_SERVE_WORKERS")),
            seeded_limit_max_requests=parse_int(seeded.get("PYPNM_SERVE_LIMIT_MAX_REQUESTS")),
            active_workers=parse_int(os.environ.get("PYPNM_ACTIVE_WORKERS")),
            active_limit_max_requests=parse_int(os.environ.get("PYPNM_ACTIVE_LIMIT_MAX_REQUESTS")),
            active_source=os.environ.get("PYPNM_ACTIVE_RUNTIME_SOURCE", ""),
        )
