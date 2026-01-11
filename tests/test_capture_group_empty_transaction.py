# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pypnm.api.routes.common.classes.file_capture.capture_group import CaptureGroup
from pypnm.config.system_config_settings import SystemConfigSettings


def _configure_capture_group_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    db_path = tmp_path / "capture_group.json"
    monkeypatch.setattr(
        SystemConfigSettings,
        "capture_group_db",
        classmethod(lambda cls: str(db_path)),
    )
    return db_path


def test_add_transaction_skips_empty_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_capture_group_db(tmp_path, monkeypatch)
    capture_group = CaptureGroup()
    group_id = capture_group.create_group()

    capture_group.add_transaction("")
    capture_group.add_transaction("   ")
    capture_group.add_transaction("txn-1")

    with db_path.open("r", encoding="utf-8") as handle:
        db = json.load(handle)

    transactions = db[group_id]["transactions"]
    assert transactions == ["txn-1"]
