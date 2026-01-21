# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from tests.postgres_test_utils import require_postgres

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.artifact_repository import (
    ROLE_PNM_RAW,
    ROLE_PNM_UPLOADED_RAW,
    ArtifactRepository,
)
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
    TimestampSec,
    TransactionId,
)

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
        "pnm_dir",
        classmethod(lambda cls: str(tmp_path)),
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
    return db_path


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
        timestamp_epoch=TimestampSec(DEFAULT_TIMESTAMP),
        mac_address=DEFAULT_MAC,
        pnm_test_type=PNM_TEST_TYPE,
        filename=DEFAULT_FILENAME,
        device_detail_id=device_detail_id,
    )


def test_artifact_repository_resolves_role_preference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    transaction_id = TransactionId("txn-role-preference")
    db_path = _configure_db(tmp_path, monkeypatch)
    _seed_transaction(db_path, transaction_id)

    raw_path = tmp_path / "raw.bin"
    uploaded_path = tmp_path / "uploaded.bin"
    raw_path.write_bytes(b"raw")
    uploaded_path.write_bytes(b"upload")

    sqlite_path = DatabasePath(str(db_path))
    postgres_dsn = DatabaseDsn("")
    repo = ArtifactRepository.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )
    repo.register_transaction_artifact(
        transaction_id=transaction_id,
        file_path=uploaded_path,
        role=ROLE_PNM_UPLOADED_RAW,
        created_epoch=TimestampSec(DEFAULT_TIMESTAMP),
    )
    repo.register_transaction_artifact(
        transaction_id=transaction_id,
        file_path=raw_path,
        role=ROLE_PNM_RAW,
        created_epoch=TimestampSec(DEFAULT_TIMESTAMP),
    )

    resolved = repo.resolve_transaction_artifact_path(transaction_id)
    assert resolved == raw_path


def test_postgres_transaction_artifact_resolution_optional(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    postgres_dsn, _ = require_postgres()
    sqlite_path = DatabasePath(str(tmp_path / "unused.sqlite3"))

    json_dir = tmp_path / "json"
    json_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(
        SystemConfigSettings,
        "pnm_dir",
        classmethod(lambda cls: str(tmp_path)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "json_dir",
        classmethod(lambda cls: str(json_dir)),
    )

    manager = DatabaseSchemaManager.from_overrides(
        DatabaseBackend.POSTGRES, sqlite_path, postgres_dsn
    )
    manager.initialize_schema()

    transaction_id = TransactionId(uuid.uuid4().hex)
    sys_repo = SystemDescriptionRepository.from_overrides(
        DatabaseBackend.POSTGRES, sqlite_path, postgres_dsn
    )
    device_repo = DeviceDetailsRepository.from_overrides(
        DatabaseBackend.POSTGRES, sqlite_path, postgres_dsn
    )
    txn_repo = TransactionRepository.from_overrides(
        DatabaseBackend.POSTGRES, sqlite_path, postgres_dsn
    )
    sysdescr_id = sys_repo.get_or_create_sysdescr_id(SYS_DESCR)
    device_detail_id = device_repo.get_or_create_device_detail_id(
        DEVICE_DETAILS, sysdescr_id
    )
    txn_repo.insert_transaction(
        transaction_id=transaction_id,
        timestamp_epoch=TimestampSec(DEFAULT_TIMESTAMP),
        mac_address=DEFAULT_MAC,
        pnm_test_type=PNM_TEST_TYPE,
        filename=DEFAULT_FILENAME,
        device_detail_id=device_detail_id,
    )

    file_path = tmp_path / DEFAULT_FILENAME
    file_path.write_bytes(b"postgres")

    repo = ArtifactRepository.from_overrides(
        DatabaseBackend.POSTGRES, sqlite_path, postgres_dsn
    )
    repo.register_transaction_artifact(
        transaction_id=transaction_id,
        file_path=file_path,
        role=ROLE_PNM_RAW,
        created_epoch=TimestampSec(DEFAULT_TIMESTAMP),
    )

    resolved = repo.resolve_transaction_artifact_path(transaction_id)
    assert resolved == file_path
