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
from pypnm.lib.db.capture_group_repository import CaptureGroupRepository
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
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
    GroupId,
    TimestampSec,
    TransactionId,
)

DEFAULT_CREATED_EPOCH: int = 1
DEFAULT_TIMESTAMP: int = 1
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


def _configure_capture_group_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
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


def _insert_transaction(db_path: Path, transaction_id: str) -> None:
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
        transaction_id=TransactionId(transaction_id),
        timestamp_epoch=TimestampSec(DEFAULT_TIMESTAMP),
        mac_address=DEFAULT_MAC,
        pnm_test_type=PNM_TEST_TYPE,
        filename=DEFAULT_FILENAME,
        device_detail_id=device_detail_id,
    )


def test_capture_group_skips_whitespace_transaction_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _configure_capture_group_db(tmp_path, monkeypatch)
    caplog.set_level("WARNING")
    group = CaptureGroup()
    group_id = group.create_group()

    group.add_transaction("   ")

    repo = CaptureGroupRepository.from_system_config()
    assert repo.list_transactions(group_id) == []
    assert "Skipping empty transaction_id persistence" in caplog.text


def test_resolver_filters_whitespace_transaction_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_capture_group_db(tmp_path, monkeypatch)
    _insert_transaction(db_path, "txn123")
    group_id = GroupId("group-1")
    json_path = tmp_path / "capture_group.json"
    monkeypatch.setattr(
        SystemConfigSettings,
        "capture_group_db",
        classmethod(lambda cls: str(json_path)),
    )
    payload = {
        str(group_id): {
            "created": DEFAULT_CREATED_EPOCH,
            "transactions": ["", "   ", "txn123"],
        }
    }
    json_path.write_text(json.dumps(payload), encoding="utf-8")

    resolver = OperationCaptureGroupResolver()
    txns = resolver.get_transaction_ids_for_capture_group(group_id)

    assert txns == [TransactionId("txn123")]
    repo = CaptureGroupRepository.from_system_config()
    assert repo.list_transactions(group_id) == [TransactionId("txn123")]


def test_resolver_prefers_db_transaction_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_capture_group_db(tmp_path, monkeypatch)
    group_id = GroupId("group-db")
    repo = CaptureGroupRepository.from_system_config()
    repo.get_or_create_capture_group(group_id, TimestampSec(DEFAULT_CREATED_EPOCH))
    _insert_transaction(db_path, "txn-b")
    _insert_transaction(db_path, "txn-a")
    repo.add_transaction(group_id, TransactionId("txn-b"), TimestampSec(2))
    repo.add_transaction(group_id, TransactionId("txn-a"), TimestampSec(3))

    resolver = OperationCaptureGroupResolver()
    txns = resolver.get_transaction_ids_for_capture_group(group_id)

    assert txns == [TransactionId("txn-b"), TransactionId("txn-a")]
