# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

from pypnm.api import main as api_main
from pypnm.version import __version__


def test_health_includes_uptime(monkeypatch) -> None:
    monkeypatch.setattr(api_main, "API_START_MONOTONIC", 100.0)
    monkeypatch.setattr(api_main, "API_START_EPOCH", 1_741_709_200)
    monkeypatch.setattr(api_main, "SERVICE_NAME", "pypnm-docsis")
    monkeypatch.setattr(api_main, "_data_root_path", lambda: Path(".data"))
    monkeypatch.setattr(api_main, "_folder_size_bytes", lambda _: 4096)
    monkeypatch.setattr(api_main, "_first_level_directory_sizes", lambda _: {"pnm": 1024, "json": 2048})
    monkeypatch.setattr(api_main, "monotonic", lambda: 165.9)

    response = api_main.health()

    assert response == {
        "status": "ok",
        "service": {
            "name": "pypnm-docsis",
            "version": __version__,
        },
        "uptime": {
            "starttime": 1_741_709_200,
            "uptime": 65,
        },
        "data": {
            "path": ".data",
            "size_bytes": 4096,
            "directories": {
                "pnm": 1024,
                "json": 2048,
            },
        },
    }
