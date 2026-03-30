# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from pypnm.startup import startup as startup_module
from pypnm.startup.startup import StartUp


@pytest.fixture(autouse=True)
def _reset_startup_scheduler() -> None:
    StartUp._tmp_cache_scheduler = None


def test_log_service_start_once_uses_shared_marker(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setenv("PYPNM_SERVE_SESSION_ID", "session-1")
    monkeypatch.setattr(startup_module.SystemConfigSettings, "runtime_dir", lambda: str(tmp_path))

    with caplog.at_level(logging.INFO):
        StartUp._log_service_start_once()
        StartUp._log_service_start_once()

    assert caplog.text.count("==== PyPNM REST API Starting ====") == 1
    assert (tmp_path / ".startup-banner-session-1.marker").is_file()


def test_log_worker_start_includes_pid_and_session(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setenv("PYPNM_SERVE_SESSION_ID", "session-2")
    monkeypatch.setattr("os.getpid", lambda: 4321)

    with caplog.at_level(logging.INFO, logger="StartUp"):
        StartUp._log_worker_start()

    assert "FastAPI worker started: pid=4321 session=session-2" in caplog.text
