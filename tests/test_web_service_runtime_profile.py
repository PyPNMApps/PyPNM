# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

from pypnm.api.routes.pypnm.system.web_service.service import (
    PyPnmSystemWebServiceService,
)


def test_get_runtime_profile_reads_seeded_and_active_values(monkeypatch, tmp_path: Path) -> None:
    profile_path = tmp_path / "pypnm-serve.env"
    profile_path.write_text(
        "PYPNM_SERVE_CPU_COUNT=8\n"
        "PYPNM_SERVE_TOTAL_MEMORY_GIB=16.0\n"
        "PYPNM_SERVE_WORKERS=4\n"
        "PYPNM_SERVE_LIMIT_MAX_REQUESTS=2000\n",
    )

    monkeypatch.setenv("PYPNM_SERVE_ENV_FILE", str(profile_path))
    monkeypatch.setenv("PYPNM_ACTIVE_RUNTIME_SOURCE", "seeded_profile")
    monkeypatch.setenv("PYPNM_ACTIVE_WORKERS", "4")
    monkeypatch.setenv("PYPNM_ACTIVE_LIMIT_MAX_REQUESTS", "2000")

    profile = PyPnmSystemWebServiceService.get_runtime_profile()

    assert profile.profile_env_path == str(profile_path)
    assert profile.profile_exists is True
    assert profile.detected_cpu_count == 8
    assert profile.detected_total_memory_gib == 16.0
    assert profile.seeded_workers == 4
    assert profile.seeded_limit_max_requests == 2000
    assert profile.active_workers == 4
    assert profile.active_limit_max_requests == 2000
    assert profile.active_source == "seeded_profile"
