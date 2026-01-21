# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import HTTPException

from pypnm.api.routes.docs.pnm.files.service import PnmFileService
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.artifact_repository import ROLE_PNM_RAW, ArtifactRepository
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
DEFAULT_FILENAME = FileName("test_pnm_file.bin")
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


def _register_artifact(
    db_path: Path, transaction_id: TransactionId, file_path: Path
) -> None:
    sqlite_path = DatabasePath(str(db_path))
    postgres_dsn = DatabaseDsn("")
    repo = ArtifactRepository.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )
    repo.register_transaction_artifact(
        transaction_id=transaction_id,
        file_path=file_path,
        role=ROLE_PNM_RAW,
        created_epoch=TimestampSec(DEFAULT_TIMESTAMP),
    )


@pytest.mark.pnm
def test_hexdump_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Verify that get_hexdump_by_transaction_id returns a structured HexDumpResponse
    for a valid transaction with an on-disk PNM file.
    """
    transaction_id: TransactionId = TransactionId("8f17fcdd4c0138ef")
    db_path = _configure_db(tmp_path, monkeypatch)
    _seed_transaction(db_path, transaction_id)

    file_path = tmp_path / DEFAULT_FILENAME
    payload = bytes(range(32))
    file_path.write_bytes(payload)

    _register_artifact(db_path, transaction_id, file_path)

    service = PnmFileService()
    bytes_per_line = 16

    rsp = service.get_hexdump_by_transaction_id(
        transaction_id=transaction_id,
        bytes_per_line=bytes_per_line,
    )

    assert rsp.transaction_id == transaction_id
    assert rsp.bytes_per_line == bytes_per_line
    assert isinstance(rsp.lines, list)
    assert len(rsp.lines) > 0
    assert rsp.lines[0].startswith("00000000")


@pytest.mark.pnm
def test_hexdump_missing_transaction_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Ensure that a missing transaction ID results in an HTTP 404 error.
    """
    transaction_id: TransactionId = TransactionId("deadbeefdeadbeef")
    _configure_db(tmp_path, monkeypatch)

    service = PnmFileService()

    with pytest.raises(HTTPException) as excinfo:
        service.get_hexdump_by_transaction_id(
            transaction_id=transaction_id,
            bytes_per_line=16,
        )

    err = excinfo.value
    assert err.status_code == 404
    assert "Transaction ID not found" in str(err.detail)
