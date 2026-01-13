# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import os
import sqlite3
import uuid
from pathlib import Path

import pytest

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

DEFAULT_CREATED_EPOCH: int = 10
DEFAULT_ADDED_EPOCH: int = 11
DEFAULT_ADDED_EPOCH_NEXT: int = 12
DEFAULT_TIMESTAMP: int = 13
POSITION_FIRST: int = 0
POSITION_SECOND: int = 1
UNIQUE_SUFFIX_LEN: int = 8
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


def _unique_suffix() -> str:
    return uuid.uuid4().hex[:UNIQUE_SUFFIX_LEN]


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


def _configure_capture_group_postgres(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, dsn: DatabaseDsn
) -> DatabasePath:
    sqlite_placeholder = DatabasePath(str(tmp_path / "unused.sqlite3"))
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_backend",
        classmethod(lambda cls: DatabaseBackend.POSTGRES),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_sqlite_path",
        classmethod(lambda cls: sqlite_placeholder),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_postgres_dsn",
        classmethod(lambda cls: dsn),
    )
    DatabaseSchemaManager.from_system_config().initialize_schema()
    return sqlite_placeholder


def _insert_transaction_sqlite(db_path: Path, transaction_id: str) -> None:
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


def _insert_transaction_postgres(
    dsn: DatabaseDsn, sqlite_path: DatabasePath, transaction_id: str
) -> None:
    sys_repo = SystemDescriptionRepository.from_overrides(
        DatabaseBackend.POSTGRES, sqlite_path, dsn
    )
    device_repo = DeviceDetailsRepository.from_overrides(
        DatabaseBackend.POSTGRES, sqlite_path, dsn
    )
    txn_repo = TransactionRepository.from_overrides(
        DatabaseBackend.POSTGRES, sqlite_path, dsn
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


def test_capture_group_repository_orders_by_position(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_capture_group_db(tmp_path, monkeypatch)
    _insert_transaction_sqlite(db_path, "txn-b")
    _insert_transaction_sqlite(db_path, "txn-a")
    repo = CaptureGroupRepository.from_system_config()
    group_id = GroupId("cg-1")
    repo.create_capture_group(group_id, TimestampSec(DEFAULT_CREATED_EPOCH))
    repo.add_transaction(
        group_id,
        TransactionId("txn-b"),
        POSITION_FIRST,
        TimestampSec(DEFAULT_ADDED_EPOCH),
    )
    repo.add_transaction(
        group_id,
        TransactionId("txn-a"),
        POSITION_SECOND,
        TimestampSec(DEFAULT_ADDED_EPOCH_NEXT),
    )

    assert repo.list_transactions(group_id) == [
        TransactionId("txn-b"),
        TransactionId("txn-a"),
    ]


def test_capture_group_repository_ignores_duplicate_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_capture_group_db(tmp_path, monkeypatch)
    _insert_transaction_sqlite(db_path, "txn-dup")
    repo = CaptureGroupRepository.from_system_config()
    group_id = GroupId("cg-dup")
    repo.create_capture_group(group_id, TimestampSec(DEFAULT_CREATED_EPOCH))
    repo.add_transaction(
        group_id,
        TransactionId("txn-dup"),
        POSITION_FIRST,
        TimestampSec(DEFAULT_ADDED_EPOCH),
    )
    repo.add_transaction(
        group_id,
        TransactionId("txn-dup"),
        POSITION_SECOND,
        TimestampSec(DEFAULT_ADDED_EPOCH_NEXT),
    )

    assert repo.list_transactions(group_id) == [TransactionId("txn-dup")]


def test_capture_group_repository_retries_position_collision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_capture_group_db(tmp_path, monkeypatch)
    _insert_transaction_sqlite(db_path, "txn-retry-a")
    _insert_transaction_sqlite(db_path, "txn-retry-b")
    repo = CaptureGroupRepository.from_system_config()
    group_id = GroupId("cg-retry")
    repo.create_capture_group(group_id, TimestampSec(DEFAULT_CREATED_EPOCH))
    repo.add_transaction(
        group_id,
        TransactionId("txn-retry-a"),
        POSITION_FIRST,
        TimestampSec(DEFAULT_ADDED_EPOCH),
    )
    positions = [POSITION_FIRST, POSITION_SECOND]

    def _next_position(_: object, __: GroupId) -> int:
        return positions.pop(0)

    monkeypatch.setattr(repo, "_get_next_position_conn", _next_position)

    repo.add_transaction_next_position(
        group_id, TransactionId("txn-retry-b"), TimestampSec(DEFAULT_ADDED_EPOCH_NEXT)
    )

    assert repo.list_transactions(group_id) == [
        TransactionId("txn-retry-a"),
        TransactionId("txn-retry-b"),
    ]


def test_capture_group_repository_rejects_duplicate_position(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_capture_group_db(tmp_path, monkeypatch)
    _insert_transaction_sqlite(db_path, "txn-1")
    _insert_transaction_sqlite(db_path, "txn-2")
    repo = CaptureGroupRepository.from_system_config()
    group_id = GroupId("cg-pos")
    repo.create_capture_group(group_id, TimestampSec(DEFAULT_CREATED_EPOCH))
    repo.add_transaction(
        group_id,
        TransactionId("txn-1"),
        POSITION_FIRST,
        TimestampSec(DEFAULT_ADDED_EPOCH),
    )

    with pytest.raises(sqlite3.IntegrityError):
        repo.add_transaction(
            group_id,
            TransactionId("txn-2"),
            POSITION_FIRST,
            TimestampSec(DEFAULT_ADDED_EPOCH_NEXT),
        )


def test_capture_group_repository_enforces_fk_integrity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_capture_group_db(tmp_path, monkeypatch)
    repo = CaptureGroupRepository.from_system_config()
    group_id = GroupId("cg-fk")
    repo.create_capture_group(group_id, TimestampSec(DEFAULT_CREATED_EPOCH))

    with pytest.raises(sqlite3.IntegrityError):
        repo.add_transaction(
            group_id,
            TransactionId("missing-txn"),
            POSITION_FIRST,
            TimestampSec(DEFAULT_ADDED_EPOCH),
        )

    _insert_transaction_sqlite(db_path, "missing-txn")
    repo.add_transaction(
        group_id,
        TransactionId("missing-txn"),
        POSITION_FIRST,
        TimestampSec(DEFAULT_ADDED_EPOCH),
    )

    assert repo.list_transactions(group_id) == [TransactionId("missing-txn")]


def test_capture_group_repository_enforces_fk_integrity_postgres(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dsn_env = os.environ.get("PYPNM_DB_POSTGRES_DSN", "")
    if not dsn_env:
        pytest.skip("PYPNM_DB_POSTGRES_DSN not set")
    try:
        import psycopg
    except ImportError:
        pytest.skip("psycopg not installed")

    postgres_dsn = DatabaseDsn(dsn_env)
    sqlite_placeholder = _configure_capture_group_postgres(
        tmp_path, monkeypatch, postgres_dsn
    )
    suffix = _unique_suffix()
    group_id = GroupId(f"cg-pg-fk-{suffix}")
    missing_txn = f"missing-txn-{suffix}"

    repo = CaptureGroupRepository.from_system_config()
    repo.create_capture_group(group_id, TimestampSec(DEFAULT_CREATED_EPOCH))

    with pytest.raises(psycopg.IntegrityError):
        repo.add_transaction(
            group_id,
            TransactionId(missing_txn),
            POSITION_FIRST,
            TimestampSec(DEFAULT_ADDED_EPOCH),
        )

    _insert_transaction_postgres(postgres_dsn, sqlite_placeholder, missing_txn)
    repo.add_transaction(
        group_id,
        TransactionId(missing_txn),
        POSITION_FIRST,
        TimestampSec(DEFAULT_ADDED_EPOCH),
    )

    assert repo.list_transactions(group_id) == [TransactionId(missing_txn)]


def test_capture_group_repository_rejects_duplicate_position_postgres(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dsn_env = os.environ.get("PYPNM_DB_POSTGRES_DSN", "")
    if not dsn_env:
        pytest.skip("PYPNM_DB_POSTGRES_DSN not set")
    try:
        import psycopg
    except ImportError:
        pytest.skip("psycopg not installed")

    postgres_dsn = DatabaseDsn(dsn_env)
    sqlite_placeholder = _configure_capture_group_postgres(
        tmp_path, monkeypatch, postgres_dsn
    )
    suffix = _unique_suffix()
    group_id = GroupId(f"cg-pg-pos-{suffix}")
    txn_one = f"txn-pos-{suffix}-a"
    txn_two = f"txn-pos-{suffix}-b"

    repo = CaptureGroupRepository.from_system_config()
    repo.create_capture_group(group_id, TimestampSec(DEFAULT_CREATED_EPOCH))
    _insert_transaction_postgres(postgres_dsn, sqlite_placeholder, txn_one)
    _insert_transaction_postgres(postgres_dsn, sqlite_placeholder, txn_two)

    repo.add_transaction(
        group_id,
        TransactionId(txn_one),
        POSITION_FIRST,
        TimestampSec(DEFAULT_ADDED_EPOCH),
    )

    with pytest.raises(psycopg.IntegrityError):
        repo.add_transaction(
            group_id,
            TransactionId(txn_two),
            POSITION_FIRST,
            TimestampSec(DEFAULT_ADDED_EPOCH_NEXT),
        )
