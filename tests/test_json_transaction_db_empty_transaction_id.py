# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pypnm.config.pnm_config_manager import SystemConfigSettings
from pypnm.lib.db.json_transaction import JsonTransactionDb
from pypnm.lib.types import TransactionId
from pypnm.lib.utils import Generate


def _configure_json_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path]:
    json_dir = tmp_path / "json"
    json_dir.mkdir(parents=True, exist_ok=True)
    json_db = tmp_path / "transactions.json"
    monkeypatch.setattr(
        SystemConfigSettings,
        "json_db",
        classmethod(lambda cls: str(json_db)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "json_dir",
        classmethod(lambda cls: str(json_dir)),
    )
    return json_db, json_dir


@pytest.mark.parametrize("raw_id", ["", "   "])
def test_write_json_skips_empty_transaction_id(
    raw_id: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    json_db, json_dir = _configure_json_paths(tmp_path, monkeypatch)
    monkeypatch.setattr(
        Generate,
        "transaction_id",
        staticmethod(lambda seed=None, length=24: TransactionId(raw_id)),
    )

    db = JsonTransactionDb()
    caplog.set_level("WARNING")
    model = db.write_json({"alpha": 1}, "payload")

    assert not (json_dir / "payload").exists()
    assert model.records == {}
    assert "Skipping DB insert for empty transaction_id" in caplog.text

    if json_db.exists():
        with json_db.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        assert data == {}


def test_write_json_persists_valid_transaction_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    json_db, json_dir = _configure_json_paths(tmp_path, monkeypatch)
    monkeypatch.setattr(
        Generate,
        "transaction_id",
        staticmethod(lambda seed=None, length=24: TransactionId("txn-1")),
    )

    db = JsonTransactionDb()
    model = db.write_json({"alpha": 1}, "payload")

    payload_path = json_dir / "payload"
    assert payload_path.exists()
    assert "txn-1" in {str(tx_id) for tx_id in model.records}

    with json_db.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    assert "txn-1" in data
