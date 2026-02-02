# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.types import FileNameStr, TransactionId


def _patch_transaction_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    db_path = tmp_path / "transactions.json"

    def _fake_transaction_db(cls: type[SystemConfigSettings]) -> str:
        return str(db_path)

    monkeypatch.setattr(
        SystemConfigSettings,
        "transaction_db",
        classmethod(_fake_transaction_db),
        raising=False,
    )

    return db_path


def test_get_record_by_filename_matches_raw(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = _patch_transaction_db(tmp_path, monkeypatch)
    records = {
        "tx-raw": {
            "filename": "raw.bin",
        },
    }
    db_path.write_text(json.dumps(records))

    txn = PnmFileTransaction()
    result = txn.get_record_by_filename(FileNameStr("raw.bin"))

    assert result is not None
    transaction_id, record = result
    assert transaction_id == TransactionId("tx-raw")
    assert record.get("filename") == "raw.bin"


def test_get_record_by_filename_matches_compressed_base(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = _patch_transaction_db(tmp_path, monkeypatch)
    records = {
        "tx-comp": {
            "filename": "capture.bin.zst",
            "compression": {
                "is_compressed": True,
                "codec": "zstd",
                "level": 3,
                "size_before": 10,
                "size_after": 5,
            },
        },
    }
    db_path.write_text(json.dumps(records))

    txn = PnmFileTransaction()
    result = txn.get_record_by_filename(FileNameStr("capture.bin"))

    assert result is not None
    transaction_id, record = result
    assert transaction_id == TransactionId("tx-comp")
    assert record.get("filename") == "capture.bin.zst"
