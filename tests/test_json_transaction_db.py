# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from pypnm.config.pnm_config_manager import SystemConfigSettings
from pypnm.lib.db.json_transaction import JsonTransactionDb
from pypnm.lib.db.model.json_trans_model import (
    JsonReturnModel,
    JsonTransactionDbModel,
    JsonTransactionRecordModel,
)
from pypnm.lib.types import HashStr, TimeStamp, TransactionId

# ────────────────────────────────────────────────────────────────────────────────
# Model Tests
# ────────────────────────────────────────────────────────────────────────────────

def test_json_transaction_record_model_valid() -> None:
    timestamp: TimeStamp = TimeStamp(1_700_000_000)
    filename:  str       = "example.json"
    byte_size: int       = 128
    sha256:    HashStr   = HashStr("a" * 64)

    record = JsonTransactionRecordModel(
        timestamp=timestamp,
        filename=filename,
        byte_size=byte_size,
        sha256=sha256,
    )

    assert record.timestamp == timestamp
    assert record.filename  == filename
    assert record.byte_size == byte_size
    assert record.sha256    == sha256


def test_json_transaction_db_model_add_and_access() -> None:
    tx_id: TransactionId = TransactionId("tx-123")
    record = JsonTransactionRecordModel(
        timestamp=TimeStamp(1_700_000_001),
        filename="payload.json",
        byte_size=256,
        sha256=HashStr("b" * 64),
    )

    db_model = JsonTransactionDbModel()
    db_model.records[tx_id] = record

    assert tx_id in db_model.records
    assert db_model.records[tx_id].filename == "payload.json"


def test_json_return_model_inherits_metadata_and_adds_data() -> None:
    base_record = JsonTransactionRecordModel(
        timestamp=TimeStamp(1_700_000_002),
        filename="payload.json",
        byte_size=512,
        sha256=HashStr("c" * 64),
    )

    payload_text: str = '{"key": "value"}'
    ret_model = JsonReturnModel(
        timestamp=base_record.timestamp,
        filename=base_record.filename,
        byte_size=base_record.byte_size,
        sha256=base_record.sha256,
        data=payload_text,
    )

    assert ret_model.timestamp == base_record.timestamp
    assert ret_model.filename  == base_record.filename
    assert ret_model.byte_size == base_record.byte_size
    assert ret_model.sha256    == base_record.sha256
    assert ret_model.data      == payload_text


# ────────────────────────────────────────────────────────────────────────────────
# JsonTransactionDb Tests
# ────────────────────────────────────────────────────────────────────────────────

def _make_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> JsonTransactionDb:
    """
    Helper To Construct JsonTransactionDb With A Temporary Filesystem Root.

    The DB file is placed directly under tmp_path as 'transactions.json' and
    the json_dir is tmp_path / 'json' to keep payloads under a dedicated
    directory for tests.
    """
    json_dir: Path = tmp_path / "json"
    json_dir.mkdir(parents=True, exist_ok=True)

    db_path: Path = tmp_path / "transactions.json"

    def _fake_json_db(cls: type[SystemConfigSettings]) -> str:
        return str(db_path)

    def _fake_json_dir(cls: type[SystemConfigSettings]) -> str:
        return str(json_dir)

    monkeypatch.setattr(
        SystemConfigSettings,
        "json_db",
        classmethod(_fake_json_db),
        raising=False,
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "json_dir",
        classmethod(_fake_json_dir),
        raising=False,
    )

    db = JsonTransactionDb()
    return db


def test_write_json_creates_payload_and_updates_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixed_time: TimeStamp = TimeStamp(1_700_000_010)

    monkeypatch.setattr(
        "pypnm.lib.db.json_transaction.time.time",
        lambda: int(fixed_time),
    )

    db: JsonTransactionDb = _make_db(tmp_path, monkeypatch)

    payload: Mapping[str, Any] = {"foo": "bar", "value": 42}

    updated_db: JsonTransactionDbModel = db.write_json(payload, fname="payload", extension="json")
    assert isinstance(updated_db, JsonTransactionDbModel)
    assert len(updated_db.records) == 1

    tx_id, record = next(iter(updated_db.records.items()))

    db_path: Path      = tmp_path / "transactions.json"
    payload_path: Path = tmp_path / "json" / str(record.filename)

    assert isinstance(tx_id, str)
    assert payload_path.exists()
    assert db_path.exists()

    assert record.byte_size == payload_path.stat().st_size
    assert record.timestamp == fixed_time

    digest = hashlib.sha256()
    with open(payload_path, "rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    digest.update(str(int(fixed_time)).encode("utf-8"))
    expected_hash: HashStr = HashStr(digest.hexdigest())

    assert record.sha256 == expected_hash

    db_text: str = db_path.read_text(encoding="utf-8")
    db_json: dict[str, Any] = json.loads(db_text)
    assert list(db_json.keys()) == [tx_id]


def test_read_json_roundtrip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixed_time: TimeStamp = TimeStamp(1_700_000_020)
    monkeypatch.setattr(
        "pypnm.lib.db.json_transaction.time.time",
        lambda: int(fixed_time),
    )

    db: JsonTransactionDb = _make_db(tmp_path, monkeypatch)

    payload: Mapping[str, Any] = {"alpha": 1, "beta": True, "gamma": "text"}
    updated_db: JsonTransactionDbModel = db.write_json(payload, fname="roundtrip", extension="json")

    tx_id, record = next(iter(updated_db.records.items()))

    result: JsonReturnModel = db.read_json(tx_id)
    assert isinstance(result, JsonReturnModel)

    assert result.timestamp == record.timestamp
    assert result.filename  == str(record.filename)
    assert result.byte_size == record.byte_size
    assert result.sha256    == record.sha256

    parsed_payload: dict[str, Any] = json.loads(result.data)
    assert parsed_payload == dict(payload)


def test_read_json_missing_transaction_returns_empty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db: JsonTransactionDb = _make_db(tmp_path, monkeypatch)

    missing_id: TransactionId = TransactionId("non-existent-transaction-id")
    result: JsonReturnModel   = db.read_json(missing_id)

    assert result.timestamp == TimeStamp(0)
    assert result.filename  == ""
    assert result.byte_size == 0
    assert result.sha256    == HashStr("")
    assert result.data      == ""


def test_read_json_hash_mismatch_returns_empty_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixed_time: TimeStamp = TimeStamp(1_700_000_030)
    monkeypatch.setattr(
        "pypnm.lib.db.json_transaction.time.time",
        lambda: int(fixed_time),
    )

    db: JsonTransactionDb = _make_db(tmp_path, monkeypatch)

    payload: Mapping[str, Any] = {"key": "original"}
    updated_db: JsonTransactionDbModel = db.write_json(payload, fname="corrupt_me", extension="json")

    tx_id, record = next(iter(updated_db.records.items()))
    payload_path: Path = tmp_path / "json" / str(record.filename)

    with open(payload_path, "ab") as handle:
        handle.write(b"\nCORRUPTED")

    result: JsonReturnModel = db.read_json(tx_id)

    assert result.timestamp == record.timestamp
    assert result.filename  == str(record.filename)
    assert result.byte_size == record.byte_size
    assert result.sha256    == record.sha256
    assert result.data      == ""


def test_write_json_raises_on_non_serializable_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db: JsonTransactionDb = _make_db(tmp_path, monkeypatch)

    class _NonSerializable:
        ...

    bad_payload: Mapping[str, Any] = {"obj": _NonSerializable()}

    with pytest.raises(ValueError):
        db.write_json(bad_payload, fname="bad", extension="json")
