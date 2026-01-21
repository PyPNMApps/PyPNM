# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.db.transaction_repository import TransactionRepository
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    FileName,
    TransactionId,
)
from pypnm.tools.migrate_transactions import TransactionMigrator

DEFAULT_TIMESTAMP: int = 12
PNM_TEST_TYPE: str = "DS_RXMER"
SYS_DESCR: dict[str, str] = {
    "HW_REV": "1.0",
    "VENDOR": "LANCity",
    "BOOTR": "NONE",
    "SW_REV": "1.0.0",
    "MODEL": "LCPET-3",
}
DEVICE_DETAILS: dict[str, object] = {"system_description": SYS_DESCR}
DEFAULT_FILENAME = FileName("rxmer.bin")
DEFAULT_MAC = MacAddress("aa:bb:cc:dd:ee:ff")


def _configure_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    db_path = tmp_path / "pypnm.sqlite3"
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_backend",
        classmethod(lambda cls: DatabaseBackend.SQLITE),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_sqlite_path",
        classmethod(lambda cls: DatabasePath(str(db_path))),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_postgres_dsn",
        classmethod(lambda cls: DatabaseDsn("")),
    )
    DatabaseSchemaManager.from_system_config().initialize_schema()
    return db_path


def _make_payload(transaction_ids: list[str]) -> dict[str, object]:
    payload: dict[str, object] = {}
    for index, transaction_id in enumerate(transaction_ids, start=1):
        payload[transaction_id] = {
            "timestamp": DEFAULT_TIMESTAMP + index,
            "mac_address": str(DEFAULT_MAC),
            "pnm_test_type": PNM_TEST_TYPE,
            "filename": str(DEFAULT_FILENAME),
            "device_details": DEVICE_DETAILS,
        }
    return payload


def test_transaction_migrator_imports_legacy_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_db(tmp_path, monkeypatch)
    legacy_path = tmp_path / "transactions.json"
    legacy_payload = _make_payload(["txn-1", "txn-2"])
    legacy_path.write_text(json.dumps(legacy_payload), encoding="utf-8")

    exit_code = TransactionMigrator().run(["--input", str(legacy_path)])

    assert exit_code == TransactionMigrator.EXIT_OK

    repo = TransactionRepository.from_system_config()
    records = repo.list_all_transactions()
    assert {record.transaction_id for record in records} == {
        TransactionId("txn-1"),
        TransactionId("txn-2"),
    }


def test_transaction_migrator_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_db(tmp_path, monkeypatch)
    legacy_path = tmp_path / "transactions.json"
    legacy_payload = _make_payload(["txn-1", "txn-2"])
    legacy_path.write_text(json.dumps(legacy_payload), encoding="utf-8")

    migrator = TransactionMigrator()
    assert migrator.run(["--input", str(legacy_path)]) == TransactionMigrator.EXIT_OK
    assert migrator.run(["--input", str(legacy_path)]) == TransactionMigrator.EXIT_OK

    repo = TransactionRepository.from_system_config()
    records = repo.list_all_transactions()
    assert len(records) == 2


def test_transaction_migrator_missing_file_is_noop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _configure_db(tmp_path, monkeypatch)
    legacy_path = tmp_path / "transactions.json"

    exit_code = TransactionMigrator().run(["--input", str(legacy_path)])

    assert exit_code == TransactionMigrator.EXIT_OK
    assert "Legacy transactions.json not found" in caplog.text


def test_transaction_migrator_rejects_invalid_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_db(tmp_path, monkeypatch)
    legacy_path = tmp_path / "transactions.json"
    legacy_path.write_text("{", encoding="utf-8")

    exit_code = TransactionMigrator().run(["--input", str(legacy_path)])

    assert exit_code == TransactionMigrator.EXIT_FAILURE


def test_transaction_migrator_skips_invalid_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_db(tmp_path, monkeypatch)
    legacy_path = tmp_path / "transactions.json"
    legacy_payload = _make_payload(["txn-1"])
    legacy_payload["txn-missing"] = {"mac_address": str(DEFAULT_MAC)}
    legacy_path.write_text(json.dumps(legacy_payload), encoding="utf-8")

    exit_code = TransactionMigrator().run(["--input", str(legacy_path)])

    assert exit_code == TransactionMigrator.EXIT_OK
    repo = TransactionRepository.from_system_config()
    records = repo.list_all_transactions()
    assert {record.transaction_id for record in records} == {TransactionId("txn-1")}
