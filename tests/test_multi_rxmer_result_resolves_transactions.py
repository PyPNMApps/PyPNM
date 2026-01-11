# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from pypnm.api.routes.advance.common.operation_registry import OperationRegistry
from pypnm.api.routes.advance.ds.ofdm.rxmer.multi.router import router
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.constants import OperationExecutionState
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
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
    OperationId,
    TimestampSec,
    TransactionId,
)


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


PNM_TEST_TYPE: str = "DS_OFDM_RXMER_PER_SUBCAR"
DEFAULT_TIMESTAMP: int = 1
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


def _configure_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> dict[str, Path]:
    base_dir = tmp_path / ".data"
    pnm_dir = base_dir / "pnm"
    db_dir = base_dir / "db"
    pnm_dir.mkdir(parents=True, exist_ok=True)
    db_dir.mkdir(parents=True, exist_ok=True)

    capture_group_db = db_dir / "capture_group.json"
    operation_db = db_dir / "operation_capture.json"
    sqlite_db = db_dir / "pypnm.sqlite3"

    monkeypatch.setattr(
        SystemConfigSettings,
        "pnm_dir",
        classmethod(lambda cls: str(pnm_dir)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "capture_group_db",
        classmethod(lambda cls: str(capture_group_db)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "operation_db",
        classmethod(lambda cls: str(operation_db)),
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
        "capture_group_db": capture_group_db,
        "operation_db": operation_db,
        "database_sqlite_path": sqlite_db,
    }


def test_result_resolves_transactions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    paths = _configure_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())
    caplog.set_level("WARNING")

    operation_id = OperationId("op-123")
    capture_group_id = "group-123"
    transaction_id = "txn123"
    missing_transaction_id = "txn-missing"

    paths["operation_db"].write_text(
        json.dumps(
            {
                str(operation_id): {
                    "capture_group_id": capture_group_id,
                    "created": 1,
                }
            }
        ),
        encoding="utf-8",
    )
    paths["capture_group_db"].write_text(
        json.dumps(
            {
                capture_group_id: {
                    "created": 1,
                    "transactions": [transaction_id, missing_transaction_id],
                }
            }
        ),
        encoding="utf-8",
    )
    _DbFixture.insert_transaction(paths["database_sqlite_path"], transaction_id)

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
    assert payload["transactions"][0]["transaction_id"] == transaction_id
    assert "Missing transaction record for transaction_id" in caplog.text
    OperationRegistry.unregister(operation_id)


def test_result_rejects_when_no_transactions_resolve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _configure_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())

    operation_id = OperationId("op-124")
    capture_group_id = "group-124"
    transaction_id = "txn-missing"

    paths["operation_db"].write_text(
        json.dumps(
            {
                str(operation_id): {
                    "capture_group_id": capture_group_id,
                    "created": 1,
                }
            }
        ),
        encoding="utf-8",
    )
    paths["capture_group_db"].write_text(
        json.dumps(
            {
                capture_group_id: {
                    "created": 1,
                    "transactions": [transaction_id],
                }
            }
        ),
        encoding="utf-8",
    )
    # No transaction records seeded.

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


def test_result_resolves_transactions_with_legacy_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _configure_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())

    operation_id = OperationId("op-125")
    capture_group_id = "group-125"
    transaction_id = "txn125"

    paths["operation_db"].write_text(
        json.dumps(
            {
                str(operation_id): {
                    "capture_group": capture_group_id,
                    "created": 1,
                }
            }
        ),
        encoding="utf-8",
    )
    paths["capture_group_db"].write_text(
        json.dumps(
            {
                capture_group_id: {
                    "created": 1,
                    "transactions": [transaction_id],
                }
            }
        ),
        encoding="utf-8",
    )
    _DbFixture.insert_transaction(paths["database_sqlite_path"], transaction_id)

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
