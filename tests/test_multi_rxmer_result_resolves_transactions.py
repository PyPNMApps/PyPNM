# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from pypnm.api.routes.advance.common.operation_registry import OperationRegistry
from pypnm.api.routes.advance.ds.ofdm.rxmer.multi.router import router
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.constants import OperationExecutionState
from pypnm.lib.db.capture_group_repository import CaptureGroupRepository
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.db.operation_capture_repository import OperationCaptureRepository
from pypnm.lib.db.transaction_repository import (
    DeviceDetailsRepository,
    SystemDescriptionRepository,
    TransactionRepository,
)
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.operations.operation_store import OperationStore
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    FileName,
    GroupId,
    OperationId,
    TimestampSec,
    TransactionId,
)


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


PNM_TEST_TYPE: str = "DS_OFDM_RXMER_PER_SUBCAR"
DEFAULT_CREATED_EPOCH: int = 1
DEFAULT_TIMESTAMP: int = 1
POSITION_START: int = 0
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


class _DbFixture:
    @staticmethod
    def initialize(db_path: Path) -> None:
        sqlite_path = DatabasePath(str(db_path))
        postgres_dsn = DatabaseDsn("")
        manager = DatabaseSchemaManager.from_overrides(
            DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
        )
        manager.initialize_schema()

    @staticmethod
    def insert_transaction(db_path: Path, transaction_id: str) -> None:
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

    @staticmethod
    def bind_operation(
        db_path: Path,
        operation_id: OperationId,
        capture_group_id: GroupId,
        transaction_ids: list[str],
    ) -> None:
        sqlite_path = DatabasePath(str(db_path))
        postgres_dsn = DatabaseDsn("")
        capture_repo = CaptureGroupRepository.from_overrides(
            DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
        )
        operation_repo = OperationCaptureRepository.from_overrides(
            DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
        )
        capture_repo.get_or_create_capture_group(
            capture_group_id, TimestampSec(DEFAULT_CREATED_EPOCH)
        )
        for position, transaction_id in enumerate(
            transaction_ids, start=POSITION_START
        ):
            capture_repo.add_transaction(
                capture_group_id,
                TransactionId(transaction_id),
                position,
                TimestampSec(DEFAULT_CREATED_EPOCH),
            )
        operation_repo.create_operation_capture(
            operation_id,
            capture_group_id,
            TimestampSec(DEFAULT_CREATED_EPOCH),
        )


def _configure_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> dict[str, Path]:
    base_dir = tmp_path / ".data"
    pnm_dir = base_dir / "pnm"
    db_dir = base_dir / "db"
    pnm_dir.mkdir(parents=True, exist_ok=True)
    db_dir.mkdir(parents=True, exist_ok=True)

    sqlite_db = db_dir / "pypnm.sqlite3"

    monkeypatch.setattr(
        SystemConfigSettings,
        "pnm_dir",
        classmethod(lambda cls: str(pnm_dir)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_backend",
        classmethod(lambda cls: DatabaseBackend.SQLITE),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_sqlite_path",
        classmethod(lambda cls: DatabasePath(str(sqlite_db))),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_postgres_dsn",
        classmethod(lambda cls: DatabaseDsn("")),
    )
    _DbFixture.initialize(sqlite_db)

    return {
        "database_sqlite_path": sqlite_db,
    }


def test_result_resolves_transactions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _configure_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())
    operation_id = OperationId("op-123")
    capture_group_id = GroupId("group-123")
    transaction_id_one = "txn-123-a"
    transaction_id_two = "txn-123-b"

    _DbFixture.insert_transaction(paths["database_sqlite_path"], transaction_id_one)
    _DbFixture.insert_transaction(paths["database_sqlite_path"], transaction_id_two)
    _DbFixture.bind_operation(
        paths["database_sqlite_path"],
        operation_id,
        capture_group_id,
        [transaction_id_two, transaction_id_one],
    )

    store = OperationStore()
    store.create_operation(operation_id, progress_total=1, message="Operation created")
    store.update_operation(
        operation_id=operation_id,
        state=OperationExecutionState.COMPLETED,
        progress_current=1,
        progress_total=1,
        message="Operation completed",
        error=None,
        artifact_paths=None,
    )

    response = client.post(
        "/advance/ds/ofdm/rxmer/multi/result",
        json={"operation_id": str(operation_id)},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["capture_group_id"] == capture_group_id
    assert payload["transactions"]
    assert payload["transactions"][0]["transaction_id"] == transaction_id_two
    assert payload["transactions"][1]["transaction_id"] == transaction_id_one
    OperationRegistry.unregister(operation_id)


def test_result_rejects_when_no_transactions_resolve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _configure_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())

    operation_id = OperationId("op-124")
    capture_group_id = GroupId("group-124")
    _DbFixture.bind_operation(
        paths["database_sqlite_path"],
        operation_id,
        capture_group_id,
        [],
    )

    store = OperationStore()
    store.create_operation(operation_id, progress_total=1, message="Operation created")
    store.update_operation(
        operation_id=operation_id,
        state=OperationExecutionState.COMPLETED,
        progress_current=1,
        progress_total=1,
        message="Operation completed",
        error=None,
        artifact_paths=None,
    )

    response = client.post(
        "/advance/ds/ofdm/rxmer/multi/result",
        json={"operation_id": str(operation_id)},
    )

    assert response.status_code == 404
    assert "No transaction records found" in response.json()["detail"]


def test_result_resolves_transactions_without_json_ledgers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _configure_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())

    operation_id = OperationId("op-125")
    capture_group_id = GroupId("group-125")
    transaction_id = "txn125"

    _DbFixture.insert_transaction(paths["database_sqlite_path"], transaction_id)
    _DbFixture.bind_operation(
        paths["database_sqlite_path"],
        operation_id,
        capture_group_id,
        [transaction_id],
    )

    store = OperationStore()
    store.create_operation(operation_id, progress_total=1, message="Operation created")
    store.update_operation(
        operation_id=operation_id,
        state=OperationExecutionState.COMPLETED,
        progress_current=1,
        progress_total=1,
        message="Operation completed",
        error=None,
        artifact_paths=None,
    )

    response = client.post(
        "/advance/ds/ofdm/rxmer/multi/result",
        json={"operation_id": str(operation_id)},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["capture_group_id"] == capture_group_id
    assert payload["transactions"][0]["transaction_id"] == transaction_id
