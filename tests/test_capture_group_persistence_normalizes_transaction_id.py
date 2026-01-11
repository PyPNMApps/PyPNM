# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pypnm.api.routes.common.classes.file_capture.capture_group import CaptureGroup
from pypnm.api.routes.common.classes.file_capture.pnm_file_opearation import (
    OperationCaptureGroupResolver,
)
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.types import GroupId, TransactionId


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


def test_capture_group_skips_whitespace_transaction_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    db_path = _configure_capture_group_db(tmp_path, monkeypatch)
    caplog.set_level("WARNING")
    group = CaptureGroup()
    group_id = group.create_group()

    group.add_transaction("   ")

    with db_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    assert data[str(group_id)]["transactions"] == []
    assert "Skipping empty transaction_id persistence" in caplog.text


def test_resolver_filters_whitespace_transaction_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_capture_group_db(tmp_path, monkeypatch)
    group_id = GroupId("group-1")
    payload = {
        str(group_id): {
            "created": 1,
            "transactions": ["", "   ", "txn123"],
        }
    }
    db_path.write_text(json.dumps(payload), encoding="utf-8")

    resolver = OperationCaptureGroupResolver()
    txns = resolver.get_transaction_ids_for_capture_group(group_id)

    assert txns == [TransactionId("txn123")]
