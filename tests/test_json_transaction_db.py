# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from pathlib import Path

import pytest

from pypnm.config.pnm_config_manager import SystemConfigSettings
from pypnm.lib.db.artifact_repository import ROLE_JSON_EXPORT
from pypnm.lib.db.db_schema_manager import (
    JSON_ARTIFACT_STORE_NAME,
    DatabaseSchemaManager,
)
from pypnm.lib.db.json_transaction import JsonTransactionDb
from pypnm.lib.db.transaction_repository import (
    DeviceDetailsRepository,
    SystemDescriptionRepository,
    TransactionRepository,
)
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    FileName,
    HashStr,
    TimestampSec,
    TransactionId,
)

SYS_DESCR: dict[str, str] = {
    "HW_REV": "1.0",
    "VENDOR": "LANCity",
    "BOOTR": "NONE",
    "SW_REV": "1.0.0",
    "MODEL": "LCPET-3",
}
DEVICE_DETAILS: dict[str, object] = {"system_description": SYS_DESCR}
DEFAULT_MAC = MacAddress("aa:bb:cc:dd:ee:ff")
DEFAULT_TEST_TYPE = "DS_RXMER"


def _configure_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    db_path = tmp_path / "pypnm.sqlite3"
    json_dir = tmp_path / "json"
    json_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(
        SystemConfigSettings,
        "pnm_dir",
        classmethod(lambda cls: str(tmp_path / "pnm")),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "json_dir",
        classmethod(lambda cls: str(json_dir)),
    )
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
    return db_path, json_dir


def _seed_transaction(db_path: Path, transaction_id: TransactionId) -> None:
    sqlite_path = DatabasePath(str(db_path))
    postgres_dsn = DatabaseDsn("")
    sys_repo = SystemDescriptionRepository.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )
    device_repo = DeviceDetailsRepository.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )
    txn_repo = TransactionRepository.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )
    sysdescr_id = sys_repo.get_or_create_sysdescr_id(SYS_DESCR)
    device_detail_id = device_repo.get_or_create_device_detail_id(
        DEVICE_DETAILS, sysdescr_id
    )
    txn_repo.insert_transaction(
        transaction_id=transaction_id,
        timestamp_epoch=TimestampSec(1234),
        mac_address=DEFAULT_MAC,
        pnm_test_type=DEFAULT_TEST_TYPE,
        filename=FileName("rxmer.bin"),
        device_detail_id=device_detail_id,
    )


def test_write_json_registers_json_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path, json_dir = _configure_db(tmp_path, monkeypatch)
    payload: Mapping[str, object] = {"foo": "bar", "value": 42}

    db = JsonTransactionDb()
    path = db.write_json(payload, fname="payload", extension="json")

    assert path.exists()
    assert path.parent == json_dir

    with sqlite3.connect(db_path) as conn:
        cursor = conn.execute(
            "SELECT store_id FROM artifact_stores WHERE store_name = ?;",
            (JSON_ARTIFACT_STORE_NAME,),
        )
        row = cursor.fetchone()
        assert row is not None
        store_id = int(row[0])

        cursor = conn.execute(
            "SELECT filename, relative_path, sha256 FROM file_artifacts WHERE store_id = ?;",
            (store_id,),
        )
        artifact_row = cursor.fetchone()
        assert artifact_row is not None
        filename, relative_path, sha256 = artifact_row
        assert filename == path.name
        assert relative_path.endswith(path.name)
        assert isinstance(sha256, str)
        assert len(sha256) == len(HashStr("a" * 64))


def test_write_json_links_transaction_artifact_when_provided(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path, _ = _configure_db(tmp_path, monkeypatch)
    transaction_id = TransactionId("txn-json-export")
    _seed_transaction(db_path, transaction_id)

    db = JsonTransactionDb()
    db.write_json(
        {"alpha": 1},
        fname="payload",
        extension="json",
        transaction_id=transaction_id,
    )

    with sqlite3.connect(db_path) as conn:
        cursor = conn.execute(
            "SELECT role FROM transaction_artifacts WHERE transaction_id = ?;",
            (str(transaction_id),),
        )
        row = cursor.fetchone()
        assert row is not None
        assert row[0] == ROLE_JSON_EXPORT


def test_write_json_raises_on_non_serializable_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_db(tmp_path, monkeypatch)
    db = JsonTransactionDb()

    class _NonSerializable: ...

    bad_payload: Mapping[str, object] = {"obj": _NonSerializable()}

    with pytest.raises(ValueError):
        db.write_json(bad_payload, fname="bad", extension="json")
