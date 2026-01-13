## Agent Review Bundle Summary
- Goal: Make the Postgres FK test collision-proof using unique IDs per run.
- Changes: Added uuid-based suffix generation and used unique session/transaction IDs in the Postgres FK integrity test.
- Files: tests/test_session_group_repository.py.
- Tests: python3 -m compileall src; ruff check src; ruff format --check .; pytest -q (591 passed, 5 skipped).
- Notes: Skips: PNM_CM_IT hardware integration (3), PYPNM_DB_POSTGRES_DSN not set (2).

# FILE: tests/test_session_group_repository.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import os
import sqlite3
import uuid
from pathlib import Path

import pytest

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.db.session_group_repository import SessionGroupRepository
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


def _configure_session_group_db(
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


def _insert_transaction_postgres(
    dsn: DatabaseDsn,
    sqlite_path: DatabasePath,
    transaction_id: str,
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


def test_session_group_repository_ordering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_session_group_db(tmp_path, monkeypatch)
    _insert_transaction(db_path, "txn-b")
    _insert_transaction(db_path, "txn-a")
    repo = SessionGroupRepository.from_system_config()
    session_id = GroupId("session-1")
    repo.create_session_group(session_id, TimestampSec(DEFAULT_CREATED_EPOCH))
    repo.add_transaction(
        session_id,
        TransactionId("txn-b"),
        TimestampSec(DEFAULT_ADDED_EPOCH),
    )
    repo.add_transaction(
        session_id,
        TransactionId("txn-a"),
        TimestampSec(DEFAULT_ADDED_EPOCH + 1),
    )

    assert repo.list_transactions(session_id) == [
        TransactionId("txn-b"),
        TransactionId("txn-a"),
    ]


def test_session_group_repository_ignores_duplicate_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_session_group_db(tmp_path, monkeypatch)
    _insert_transaction(db_path, "txn-1")
    repo = SessionGroupRepository.from_system_config()
    session_id = GroupId("session-dup")
    repo.create_session_group(session_id, TimestampSec(DEFAULT_CREATED_EPOCH))
    repo.add_transaction(
        session_id,
        TransactionId("txn-1"),
        TimestampSec(DEFAULT_ADDED_EPOCH),
    )
    repo.add_transaction(
        session_id,
        TransactionId("txn-1"),
        TimestampSec(DEFAULT_ADDED_EPOCH + 1),
    )

    assert repo.list_transactions(session_id) == [TransactionId("txn-1")]


def test_session_group_repository_enforces_fk_integrity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_session_group_db(tmp_path, monkeypatch)
    repo = SessionGroupRepository.from_system_config()
    session_id = GroupId("session-fk")
    repo.create_session_group(session_id, TimestampSec(DEFAULT_CREATED_EPOCH))

    with pytest.raises(sqlite3.IntegrityError):
        repo.add_transaction(
            session_id,
            TransactionId("missing-txn"),
            TimestampSec(DEFAULT_ADDED_EPOCH),
        )

    _insert_transaction(db_path, "missing-txn")
    repo.add_transaction(
        session_id,
        TransactionId("missing-txn"),
        TimestampSec(DEFAULT_ADDED_EPOCH),
    )

    assert repo.list_transactions(session_id) == [TransactionId("missing-txn")]


def test_session_group_repository_enforces_fk_integrity_postgres(
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
    sqlite_placeholder = DatabasePath(str(tmp_path / "unused.sqlite3"))
    suffix = uuid.uuid4().hex[:8]
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
        classmethod(lambda cls: postgres_dsn),
    )
    DatabaseSchemaManager.from_system_config().initialize_schema()

    repo = SessionGroupRepository.from_system_config()
    session_id = GroupId(f"session-fk-postgres-{suffix}")
    repo.create_session_group(session_id, TimestampSec(DEFAULT_CREATED_EPOCH))
    missing_txn = f"missing-txn-{suffix}"

    with pytest.raises(psycopg.IntegrityError):
        repo.add_transaction(
            session_id,
            TransactionId(missing_txn),
            TimestampSec(DEFAULT_ADDED_EPOCH),
        )

    _insert_transaction_postgres(postgres_dsn, sqlite_placeholder, missing_txn)
    repo.add_transaction(
        session_id,
        TransactionId(missing_txn),
        TimestampSec(DEFAULT_ADDED_EPOCH),
    )

    assert repo.list_transactions(session_id) == [TransactionId(missing_txn)]

