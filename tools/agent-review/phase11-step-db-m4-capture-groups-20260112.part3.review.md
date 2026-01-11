### Summary
Shifted capture-group and operation linkage persistence to DB-backed repositories with JSON fallback/backfill, aligned schema assets, and updated tests to seed DB transactions for capture group linking while keeping existing API shapes stable. Added a brief FAQ entry for the legacy operation_capture key handling, recorded a TODO to confirm the FAQ update, and documented the multi-part bundle line cap.

### Modified Files
- AGENTS.md
- docs/design/db/database-backend-burndown.md
- docs/design/db/database-backend.md
- docs/design/db/schema_postgres.sql
- docs/design/db/schema_sqlite.sql
- docs/issues/index.md
- docs/todo/todo.md
- src/pypnm/api/routes/advance/common/operation_manager.py
- src/pypnm/api/routes/common/classes/file_capture/capture_group.py
- src/pypnm/api/routes/common/classes/file_capture/pnm_file_opearation.py
- src/pypnm/api/routes/common/classes/file_capture/pnm_file_transaction.py
- src/pypnm/api/routes/docs/pnm/files/service.py
- src/pypnm/lib/db/capture_group_repository.py
- src/pypnm/lib/db/db_schema_manager.py
- src/pypnm/lib/db/transaction_repository.py
- src/pypnm/startup/startup.py
- tests/test_capture_group_empty_transaction.py
- tests/test_capture_group_persistence_normalizes_transaction_id.py
- tests/test_db_schema_manager.py
- tests/test_multi_channel_estimation_result.py
- tests/test_multi_channel_estimation_start_and_analysis.py
- tests/test_multi_rxmer_result_resolves_transactions.py
- tests/test_multi_rxmer_start_returns_operation_and_group.py
- tests/test_operation_manager_capture_group_id.py
- tests/test_operation_manager_get_capture_group.py
- tests/test_operation_workflow.py
- tests/test_transaction_id_persistence_guards.py
- tests/test_transaction_repository.py

### Commands Executed And Results
- `python3 -m compileall src` → pass
- `ruff check .` → pass
- `ruff format --check .` → pass (375 files already formatted)
- `pytest -q` → pass (585 passed, 4 skipped)

### Tests
- `pytest -q` → pass (585 passed, 4 skipped)
- `ruff check .` → pass
- `ruff format --check .` → pass

### Notes / Warnings
- pytest skips: `PNM_CM_IT` not set (3 tests), `PYPNM_DB_POSTGRES_DSN` not set (1 test)

### Remaining TODOs / Follow-Ups
- Confirm the FAQ entry for legacy operation_capture capture_group fallback is published.

# FILE: tests/test_capture_group_empty_transaction.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest

from pypnm.api.routes.common.classes.file_capture.capture_group import CaptureGroup
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
    TimestampSec,
    TransactionId,
)

PNM_TEST_TYPE: str = "DS_RXMER"
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
TRANSACTION_ID: str = "txn-1"


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


def test_add_transaction_skips_empty_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_capture_group_db(tmp_path, monkeypatch)
    _insert_transaction(db_path, TRANSACTION_ID)
    capture_group = CaptureGroup()
    group_id = capture_group.create_group()

    capture_group.add_transaction("")
    capture_group.add_transaction("   ")
    capture_group.add_transaction(TRANSACTION_ID)

    repo = CaptureGroupRepository.from_system_config()
    transactions = repo.list_transactions(group_id)
    assert transactions == [TransactionId(TRANSACTION_ID)]

# FILE: tests/test_capture_group_persistence_normalizes_transaction_id.py
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

# FILE: tests/test_db_schema_manager.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import cast

import pytest

from pypnm.lib.db.db_schema_manager import (
    BEGIN_STATEMENT,
    COMMIT_STATEMENT,
    DEFAULT_ARTIFACT_STORE_NAME,
    SCHEMA_VERSION,
    SQLITE_BUSY_TIMEOUT_MS,
    SQLITE_JOURNAL_MODE,
    UNKNOWN_SYSDESCR_HASH,
    DatabaseSchemaManager,
)
from pypnm.lib.types import DatabaseBackend, DatabaseDsn, DatabasePath

SCHEMA_META_ID: int = 1
EXPECTED_UNKNOWN_COUNT: int = 1
EXPECTED_SCHEMA_STATEMENTS_MIN: int = 1
EXPECTED_SQLITE_JOURNAL_MODE: str = SQLITE_JOURNAL_MODE.lower()
UNSUPPORTED_SCHEMA_VERSION: int = SCHEMA_VERSION + 1


def test_sqlite_schema_init_and_health(tmp_path: Path) -> None:
    db_path = tmp_path / "pypnm_schema.sqlite3"
    sqlite_path = cast(DatabasePath, str(db_path))
    postgres_dsn = cast(DatabaseDsn, "")
    manager = DatabaseSchemaManager.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )

    manager.initialize_schema()
    manager.initialize_schema()

    health = manager.health_check()
    assert health.ok is True
    assert health.schema_version == SCHEMA_VERSION
    assert health.missing_tables == []
    assert health.unknown_sysdescr_present is True
    assert health.default_artifact_store_present is True

    connection = sqlite3.connect(db_path)
    try:
        cursor = connection.execute(
            "SELECT schema_version FROM schema_meta WHERE schema_meta_id = ?;",
            (SCHEMA_META_ID,),
        )
        row = cursor.fetchone()
        assert row is not None
        assert int(row[0]) == SCHEMA_VERSION

        cursor = connection.execute(
            "SELECT COUNT(1) FROM system_description_dim WHERE sysdescr_hash = ?;",
            (UNKNOWN_SYSDESCR_HASH,),
        )
        row = cursor.fetchone()
        assert row is not None
        assert int(row[0]) == EXPECTED_UNKNOWN_COUNT

        cursor = connection.execute(
            "SELECT root_path FROM artifact_stores WHERE store_name = ?;",
            (DEFAULT_ARTIFACT_STORE_NAME,),
        )
        row = cursor.fetchone()
        assert row is not None
        assert str(row[0]).strip() != ""
    finally:
        connection.close()


def test_sqlite_pragmas_applied(tmp_path: Path) -> None:
    db_path = tmp_path / "pypnm_schema.sqlite3"
    sqlite_path = cast(DatabasePath, str(db_path))
    postgres_dsn = cast(DatabaseDsn, "")
    manager = DatabaseSchemaManager.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )

    connection = manager.connect()
    try:
        cursor = connection.execute("PRAGMA journal_mode;")
        row = cursor.fetchone()
        assert row is not None
        assert str(row[0]).lower() == EXPECTED_SQLITE_JOURNAL_MODE

        cursor = connection.execute("PRAGMA busy_timeout;")
        row = cursor.fetchone()
        assert row is not None
        assert int(row[0]) == SQLITE_BUSY_TIMEOUT_MS
    finally:
        connection.close()


def test_schema_version_mismatch_raises(tmp_path: Path) -> None:
    db_path = tmp_path / "pypnm_schema.sqlite3"
    sqlite_path = cast(DatabasePath, str(db_path))
    postgres_dsn = cast(DatabaseDsn, "")
    manager = DatabaseSchemaManager.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )

    manager.initialize_schema()

    connection = sqlite3.connect(db_path)
    try:
        connection.execute(
            "UPDATE schema_meta SET schema_version = ? WHERE schema_meta_id = ?;",
            (UNSUPPORTED_SCHEMA_VERSION, SCHEMA_META_ID),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(RuntimeError, match="Unsupported schema_version"):
        manager.initialize_schema()


def test_split_sql_statements_handles_quotes_and_comments() -> None:
    sql = (
        "CREATE TABLE t (v text CHECK (v ~* '^([0-9a-f]{2}:){5}[0-9a-f]{2}$'));\n"
        "-- Comment with ; should not split\n"
        "INSERT INTO t (v) VALUES ('{}'::jsonb);\n"
        "/* Block comment ; still in comment */\n"
        "SELECT $$a; b$$;\n"
    )
    statements = DatabaseSchemaManager._split_sql_statements(sql)
    assert len(statements) == 3


def test_split_sql_statements_filters_begin_commit() -> None:
    sql = "BEGIN; CREATE TABLE demo (id int); COMMIT;"
    statements = DatabaseSchemaManager._split_sql_statements(sql)
    normalized = {stmt.strip().strip(";").upper() for stmt in statements}
    assert BEGIN_STATEMENT in normalized
    assert COMMIT_STATEMENT in normalized
    assert "CREATE TABLE DEMO (ID INT)" in normalized
    assert DatabaseSchemaManager._should_skip_statement("BEGIN") is True
    assert DatabaseSchemaManager._should_skip_statement("BEGIN TRANSACTION") is True
    assert DatabaseSchemaManager._should_skip_statement("COMMIT") is True
    assert DatabaseSchemaManager._should_skip_statement("COMMIT WORK") is True
    assert DatabaseSchemaManager._should_skip_statement("ROLLBACK") is True
    assert DatabaseSchemaManager._should_skip_statement("ROLLBACK WORK") is True


def test_split_sql_statements_handles_escaped_single_quotes() -> None:
    sql = "INSERT INTO t (v) VALUES ('a''b; still string'); SELECT 1;"
    statements = DatabaseSchemaManager._split_sql_statements(sql)
    assert len(statements) == 2


def test_split_sql_statements_handles_valid_dollar_tag() -> None:
    sql = "SELECT $tag$a; b$tag$; SELECT 2;"
    statements = DatabaseSchemaManager._split_sql_statements(sql)
    assert len(statements) == 2


def test_split_sql_statements_rejects_invalid_dollar_tag() -> None:
    sql = "SELECT $a$b$; SELECT 2;"
    statements = DatabaseSchemaManager._split_sql_statements(sql)
    assert len(statements) == 2


def test_split_schema_postgres_contains_schema_meta() -> None:
    ddl_path = Path("docs/design/db/schema_postgres.sql")
    ddl_sql = ddl_path.read_text(encoding="utf-8")
    statements = DatabaseSchemaManager._split_sql_statements(ddl_sql)
    assert len(statements) >= EXPECTED_SCHEMA_STATEMENTS_MIN
    joined = "\n".join(statements)
    assert "CREATE TABLE IF NOT EXISTS schema_meta" in joined


def test_postgres_schema_init_optional() -> None:
    dsn = os.environ.get("PYPNM_DB_POSTGRES_DSN", "")
    if not dsn:
        pytest.skip("PYPNM_DB_POSTGRES_DSN not set")
    postgres_dsn = cast(DatabaseDsn, dsn)
    sqlite_path = cast(DatabasePath, ".data/db/pypnm.sqlite3")
    manager = DatabaseSchemaManager.from_overrides(
        DatabaseBackend.POSTGRES, sqlite_path, postgres_dsn
    )
    manager.initialize_schema()
    health = manager.health_check()
    assert health.ok is True

# FILE: tests/test_multi_channel_estimation_result.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from pypnm.api.routes.advance.multi_ds_chan_est.router import router
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


PNM_TEST_TYPE: str = "DS_OFDM_CHAN_EST_COEF"
DEFAULT_TIMESTAMP: int = 1
SYS_DESCR: dict[str, str] = {
    "HW_REV": "1.0",
    "VENDOR": "LANCity",
    "BOOTR": "NONE",
    "SW_REV": "1.0.0",
    "MODEL": "LCPET-3",
}
DEVICE_DETAILS: dict[str, object] = {"system_description": SYS_DESCR}
DEFAULT_FILENAME = FileName("chan_est.bin")
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


def _seed_operation(
    operation_id: OperationId, capture_group_id: str, paths: dict[str, Path]
) -> None:
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


def _seed_transaction_db(transaction_id: str, paths: dict[str, Path]) -> None:
    _DbFixture.insert_transaction(paths["database_sqlite_path"], transaction_id)


def _seed_capture_group(
    capture_group_id: str, transaction_ids: list[str], paths: dict[str, Path]
) -> None:
    paths["capture_group_db"].write_text(
        json.dumps(
            {
                capture_group_id: {
                    "created": 1,
                    "transactions": transaction_ids,
                }
            }
        ),
        encoding="utf-8",
    )


def _complete_operation(operation_id: OperationId) -> None:
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


def test_multi_channel_estimation_result_skips_missing_records_and_returns_200(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    paths = _configure_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())
    caplog.set_level("WARNING")

    operation_id = OperationId("op-300")
    capture_group_id = "group-300"
    txn_ok = "txn-ok"
    txn_missing = "txn-missing"

    _seed_operation(operation_id, capture_group_id, paths)
    _seed_capture_group(capture_group_id, [txn_ok, txn_missing], paths)
    _seed_transaction_db(txn_ok, paths)
    _complete_operation(operation_id)

    response = client.post(
        "/advance/multiChannelEstimation/result",
        json={"operation_id": str(operation_id)},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["capture_group_id"] == capture_group_id
    assert len(payload["transactions"]) == 1
    assert payload["transactions"][0]["transaction_id"] == txn_ok
    assert "Missing transaction record for transaction_id" in caplog.text


def test_multi_channel_estimation_result_returns_404_when_none_resolve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _configure_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())

    operation_id = OperationId("op-301")
    capture_group_id = "group-301"
    txn_missing = "txn-missing"

    _seed_operation(operation_id, capture_group_id, paths)
    _seed_capture_group(capture_group_id, [txn_missing], paths)
    # No transaction records seeded.
    _complete_operation(operation_id)

    response = client.post(
        "/advance/multiChannelEstimation/result",
        json={"operation_id": str(operation_id)},
    )

    assert response.status_code == 404
    assert "No transaction records found" in response.json()["detail"]


def test_multi_channel_estimation_result_accepts_legacy_capture_group_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _configure_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())

    operation_id = OperationId("op-302")
    capture_group_id = "group-302"
    txn_ok = "txn-ok-302"

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
    _seed_capture_group(capture_group_id, [txn_ok], paths)
    _seed_transaction_db(txn_ok, paths)
    _complete_operation(operation_id)

    response = client.post(
        "/advance/multiChannelEstimation/result",
        json={"operation_id": str(operation_id)},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["capture_group_id"] == capture_group_id
    assert payload["transactions"][0]["transaction_id"] == txn_ok

# FILE: tests/test_multi_channel_estimation_start_and_analysis.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import pypnm.api.routes.advance.multi_ds_chan_est.router as ds_router
from pypnm.api.routes.advance.common.operation_registry import OperationRegistry
from pypnm.api.routes.advance.multi_ds_chan_est.router import router
from pypnm.api.routes.advance.multi_ds_chan_est.service import (
    MultiChannelEstimationService,
)
from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.types import DatabaseBackend, DatabaseDsn, DatabasePath, OperationId

_TEST_TIME_REMAINING: int = 123


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


def _configure_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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
    DatabaseSchemaManager.from_system_config().initialize_schema()


def _start_request_payload() -> dict[str, object]:
    return {
        "cable_modem": {
            "mac_address": "aa:bb:cc:dd:ee:ff",
            "ip_address": "192.168.0.100",
            "pnm_parameters": {
                "tftp": {
                    "ipv4": None,
                    "ipv6": None,
                },
                "capture": {
                    "channel_ids": None,
                },
            },
            "snmp": {
                "snmp_v2c": {
                    "community": "public",
                }
            },
        },
        "capture": {
            "parameters": {
                "measurement_duration": 1,
                "sample_interval": 1,
            }
        },
    }


@pytest.mark.asyncio
async def test_start_returns_success_status_and_group_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)

    async def _fake_precheck(
        self: CableModemServicePreCheck,
    ) -> tuple[ServiceStatusCode, str]:
        return ServiceStatusCode.SUCCESS, "ok"

    async def _fake_capture(self: MultiChannelEstimationService) -> MessageResponse:
        return MessageResponse(ServiceStatusCode.SUCCESS, payload=[])

    monkeypatch.setattr(CableModemServicePreCheck, "run_precheck", _fake_precheck)
    monkeypatch.setattr(
        MultiChannelEstimationService, "_capture_message_response", _fake_capture
    )

    client = TestClient(_build_app())
    response = client.post(
        "/advance/multiChannelEstimation/start",
        json=_start_request_payload(),
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == ServiceStatusCode.SUCCESS
    assert payload["operation_id"]
    assert payload["capture_group_id"]
    assert payload["group_id"] == payload["capture_group_id"]
    assert payload["operation_state"] == "running"
    OperationRegistry.unregister(OperationId(payload["operation_id"]))


def test_analysis_returns_capture_group_not_found_when_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)
    db_path = Path(SystemConfigSettings.operation_db())
    db_path.write_text(json.dumps({}), encoding="utf-8")

    client = TestClient(_build_app())
    response = client.post(
        "/advance/multiChannelEstimation/analysis",
        json={"operation_id": "op-missing"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == ServiceStatusCode.CAPTURE_GROUP_NOT_FOUND
    assert "No capture group found for operation" in payload["message"]


class _StubMac:
    mac_address = "aa:bb:cc:dd:ee:ff"


class _StubCm:
    get_mac_address = _StubMac()


class _StubService:
    def __init__(self) -> None:
        self.cm = _StubCm()
        self._state = "running"

    def status(self, operation_id: OperationId) -> dict[str, object]:
        return {
            "state": self._state,
            "collected": 0,
            "time_remaining": 0,
        }

    def stop(self, operation_id: OperationId) -> None:
        self._state = "stopped"


def test_status_endpoint_uses_service_status_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)
    stub = _StubService()
    monkeypatch.setattr(
        ds_router.MultiDsChanEstRouter,
        "getService",
        lambda self, operation_id: stub,
    )

    client = TestClient(_build_app())
    response = client.get("/advance/multiChannelEstimation/status/op-500")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == ServiceStatusCode.SUCCESS
    assert payload["operation"]["operation_id"] == "op-500"


def test_stop_endpoint_uses_service_status_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)
    stub = _StubService()
    monkeypatch.setattr(
        ds_router.MultiDsChanEstRouter,
        "getService",
        lambda self, operation_id: stub,
    )

    client = TestClient(_build_app())
    response = client.delete("/advance/multiChannelEstimation/stop/op-501")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == ServiceStatusCode.SUCCESS
    assert payload["operation"]["state"] == "stopped"


def test_registry_status_endpoint_returns_dual_status_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)

    def _fake_status(operation_id: OperationId) -> object:
        return {
            "operation_id": str(operation_id),
            "state": "running",
            "created_ts": 1,
            "updated_ts": 1,
            "progress_current": 0,
            "progress_total": 1,
            "message": "Operation running",
            "error": None,
            "artifact_paths": None,
        }

    monkeypatch.setattr(
        ds_router.OperationWorkflowService,
        "get_status",
        staticmethod(_fake_status),
    )

    client = TestClient(_build_app())
    response = client.post(
        "/advance/multiChannelEstimation/status",
        json={"operation_id": "op-600"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "success"
    assert payload["service_status"] == ServiceStatusCode.SUCCESS


def test_registry_status_endpoint_uses_service_time_remaining(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)

    class _StubService:
        def status(self, operation_id: OperationId) -> dict[str, int]:
            return {"time_remaining": _TEST_TIME_REMAINING}

    def _fake_status(operation_id: OperationId) -> object:
        return {
            "operation_id": str(operation_id),
            "state": "running",
            "created_ts": 1,
            "updated_ts": 1,
            "progress_current": 0,
            "progress_total": 1,
            "message": "Operation running",
            "error": None,
            "artifact_paths": None,
        }

    monkeypatch.setattr(
        ds_router.OperationWorkflowService,
        "get_status",
        staticmethod(_fake_status),
    )
    monkeypatch.setattr(
        OperationRegistry,
        "get",
        staticmethod(lambda operation_id: _StubService()),
    )

    client = TestClient(_build_app())
    response = client.post(
        "/advance/multiChannelEstimation/status",
        json={"operation_id": "op-602"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["time_remaining"] == _TEST_TIME_REMAINING


def test_registry_status_endpoint_uses_default_time_remaining_when_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)

    def _fake_status(operation_id: OperationId) -> object:
        return {
            "operation_id": str(operation_id),
            "state": "running",
            "created_ts": 1,
            "updated_ts": 1,
            "progress_current": 0,
            "progress_total": 1,
            "message": "Operation running",
            "error": None,
            "artifact_paths": None,
        }

    monkeypatch.setattr(
        ds_router.OperationWorkflowService,
        "get_status",
        staticmethod(_fake_status),
    )
    monkeypatch.setattr(
        OperationRegistry,
        "get",
        staticmethod(lambda operation_id: None),
    )

    client = TestClient(_build_app())
    response = client.post(
        "/advance/multiChannelEstimation/status",
        json={"operation_id": "op-603"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert (
        payload["time_remaining"]
        == ds_router.MultiDsChanEstRouter._DEFAULT_TIME_REMAINING
    )


def test_registry_cancel_endpoint_returns_dual_status_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)

    def _fake_cancel(
        operation_id: OperationId, service: object | None = None
    ) -> object:
        return {
            "operation_id": str(operation_id),
            "state": "canceled",
            "created_ts": 1,
            "updated_ts": 2,
            "progress_current": 1,
            "progress_total": 1,
            "message": "Operation canceled",
            "error": None,
            "artifact_paths": None,
        }

    monkeypatch.setattr(
        ds_router.OperationWorkflowService,
        "cancel",
        staticmethod(_fake_cancel),
    )

    client = TestClient(_build_app())
    response = client.post(
        "/advance/multiChannelEstimation/cancel",
        json={"operation_id": "op-601"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "success"
    assert payload["service_status"] == ServiceStatusCode.SUCCESS

# FILE: tests/test_multi_rxmer_result_resolves_transactions.py
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

# FILE: tests/test_multi_rxmer_start_returns_operation_and_group.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from pypnm.api.routes.advance.common.operation_registry import OperationRegistry
from pypnm.api.routes.advance.ds.ofdm.rxmer.multi.router import router
from pypnm.api.routes.advance.multi_rxmer.service import MultiRxMerService
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.types import DatabaseBackend, DatabaseDsn, DatabasePath, OperationId


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


def _configure_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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
    DatabaseSchemaManager.from_system_config().initialize_schema()


@pytest.mark.asyncio
async def test_start_returns_operation_and_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)

    async def _fake_capture(self: MultiRxMerService) -> MessageResponse:
        return MessageResponse(ServiceStatusCode.SUCCESS, payload=[])

    monkeypatch.setattr(MultiRxMerService, "_capture_message_response", _fake_capture)

    client = TestClient(_build_app())
    response = client.post(
        "/advance/ds/ofdm/rxmer/multi/start",
        json={
            "mac_address": "aa:bb:cc:dd:ee:ff",
            "ip_address": "192.168.0.100",
            "duration": 0,
            "interval": 0,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["operation_id"]
    assert payload["capture_group_id"]
    OperationRegistry.unregister(OperationId(payload["operation_id"]))

# FILE: tests/test_operation_manager_capture_group_id.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest

from pypnm.api.routes.advance.common.operation_manager import OperationManager
from pypnm.api.routes.common.classes.file_capture.capture_group import CaptureGroup
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.capture_group_repository import OperationCaptureRepository
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.types import DatabaseBackend, DatabaseDsn, DatabasePath


def _configure_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    base_dir = tmp_path / ".data"
    db_dir = base_dir / "db"
    db_dir.mkdir(parents=True, exist_ok=True)

    capture_group_db = db_dir / "capture_group.json"
    operation_db = db_dir / "operation_capture.json"
    sqlite_db = db_dir / "pypnm.sqlite3"

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
    DatabaseSchemaManager.from_system_config().initialize_schema()

    return operation_db


def test_operation_manager_writes_capture_group_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)
    group = CaptureGroup()
    group_id = group.create_group()

    manager = OperationManager(capture_group_id=group_id)
    operation_id = manager.register()

    operation_repo = OperationCaptureRepository.from_system_config()
    resolved = operation_repo.get_capture_group_id(operation_id)
    assert resolved == group_id

# FILE: tests/test_operation_manager_get_capture_group.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pypnm.api.routes.advance.common.operation_manager import OperationManager
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.capture_group_repository import (
    CaptureGroupRepository,
    OperationCaptureRepository,
)
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    GroupId,
    OperationId,
    TimestampSec,
)

DEFAULT_CREATED_EPOCH: int = 1


def _configure_operation_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    base_dir = tmp_path / ".data"
    db_dir = base_dir / "db"
    db_dir.mkdir(parents=True, exist_ok=True)

    operation_db = db_dir / "operation_capture.json"
    sqlite_db = db_dir / "pypnm.sqlite3"
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
    DatabaseSchemaManager.from_system_config().initialize_schema()
    return operation_db


def test_get_capture_group_prefers_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_db(tmp_path, monkeypatch)
    operation_id = OperationId("op-199")
    capture_group_id = GroupId("group-199")

    capture_repo = CaptureGroupRepository.from_system_config()
    capture_repo.get_or_create_capture_group(
        capture_group_id, TimestampSec(DEFAULT_CREATED_EPOCH)
    )
    operation_repo = OperationCaptureRepository.from_system_config()
    operation_repo.upsert_operation_capture(
        operation_id, capture_group_id, TimestampSec(DEFAULT_CREATED_EPOCH)
    )

    resolved = OperationManager.get_capture_group(operation_id)
    assert resolved == capture_group_id
    operation_repo = OperationCaptureRepository.from_system_config()
    assert operation_repo.get_capture_group_id(operation_id) == capture_group_id


def test_get_capture_group_returns_group_id_for_canonical_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    operation_db = _configure_operation_db(tmp_path, monkeypatch)
    operation_id = OperationId("op-200")
    capture_group_id = GroupId("group-200")

    operation_db.write_text(
        json.dumps(
            {
                str(operation_id): {
                    "capture_group_id": str(capture_group_id),
                    "created": DEFAULT_CREATED_EPOCH,
                }
            }
        ),
        encoding="utf-8",
    )

    resolved = OperationManager.get_capture_group(operation_id)
    assert resolved == capture_group_id
    operation_repo = OperationCaptureRepository.from_system_config()
    assert operation_repo.get_capture_group_id(operation_id) == capture_group_id


def test_get_capture_group_returns_group_id_for_legacy_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    operation_db = _configure_operation_db(tmp_path, monkeypatch)
    operation_id = OperationId("op-201")
    capture_group_id = GroupId("group-201")

    operation_db.write_text(
        json.dumps(
            {
                str(operation_id): {
                    "capture_group": str(capture_group_id),
                    "created": DEFAULT_CREATED_EPOCH,
                }
            }
        ),
        encoding="utf-8",
    )

    resolved = OperationManager.get_capture_group(operation_id)
    assert resolved == capture_group_id


def test_get_capture_group_returns_none_when_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_db(tmp_path, monkeypatch)
    operation_id = OperationId("op-202")

    resolved = OperationManager.get_capture_group(operation_id)
    assert resolved is None

# FILE: tests/test_operation_workflow.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from pypnm.api.routes.advance.common.capture_service import AbstractCaptureService
from pypnm.api.routes.advance.common.operation_workflow_service import (
    OperationWorkflowService,
)
from pypnm.api.routes.common.extended.common_messaging_service import (
    MessageResponse,
    MessageResponseType,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.constants import OperationExecutionState
from pypnm.lib.db.capture_group_repository import CaptureGroupRepository
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.operations.operation_store import OperationStore
from pypnm.lib.types import DatabaseBackend, DatabaseDsn, DatabasePath, OperationId


class _FakeCaptureService(AbstractCaptureService):
    async def _capture_message_response(self) -> MessageResponse:
        return MessageResponse(ServiceStatusCode.SUCCESS, payload=[])


class _FakeCaptureServiceEmptyTxn(AbstractCaptureService):
    async def _capture_message_response(self) -> MessageResponse:
        payload = [
            {
                "status": ServiceStatusCode.SUCCESS.name,
                "message_type": MessageResponseType.PNM_FILE_TRANSACTION.name,
                "message": {
                    "transaction_id": "",
                    "filename": "rxmer.bin",
                },
            }
        ]
        return MessageResponse(ServiceStatusCode.SUCCESS, payload=payload)


class _FakeCaptureServiceWhitespaceTxn(AbstractCaptureService):
    async def _capture_message_response(self) -> MessageResponse:
        payload = [
            {
                "status": ServiceStatusCode.SUCCESS.name,
                "message_type": MessageResponseType.PNM_FILE_TRANSACTION.name,
                "message": {
                    "transaction_id": "   ",
                    "filename": "rxmer.bin",
                },
            }
        ]
        return MessageResponse(ServiceStatusCode.SUCCESS, payload=payload)


def _configure_operation_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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
    DatabaseSchemaManager.from_system_config().initialize_schema()


@pytest.mark.asyncio
async def test_start_creates_running_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_paths(tmp_path, monkeypatch)
    service = _FakeCaptureService(duration=0, interval=1)
    _, operation_id = await service.start()

    store = OperationStore()
    status = store.get_operation(operation_id)
    assert status is not None
    assert status.state == OperationExecutionState.RUNNING

    await asyncio.sleep(0)
    completed = store.get_operation(operation_id)
    assert completed is not None
    assert completed.state == OperationExecutionState.COMPLETED
    assert completed.progress_current >= 1


@pytest.mark.asyncio
async def test_cancel_marks_canceled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_paths(tmp_path, monkeypatch)
    service = _FakeCaptureService(duration=1, interval=0)
    _, operation_id = await service.start()

    canceled = OperationWorkflowService.cancel(operation_id, service)
    assert canceled.state == OperationExecutionState.CANCELED

    await asyncio.sleep(0)
    store = OperationStore()
    status = store.get_operation(operation_id)
    assert status is not None
    assert status.state == OperationExecutionState.CANCELED


def test_result_requires_completed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_paths(tmp_path, monkeypatch)
    store = OperationStore()
    operation_id = OperationId("op-test-1")
    store.create_operation(operation_id, progress_total=1, message="Operation created")
    store.update_operation(
        operation_id=operation_id,
        state=OperationExecutionState.RUNNING,
        progress_current=0,
        progress_total=1,
        message="Operation running",
        error=None,
        artifact_paths=None,
    )

    with pytest.raises(ValueError):
        OperationWorkflowService.get_result(operation_id)

    store.update_operation(
        operation_id=operation_id,
        state=OperationExecutionState.COMPLETED,
        progress_current=1,
        progress_total=1,
        message="Operation completed",
        error=None,
        artifact_paths=None,
    )
    status = OperationWorkflowService.get_result(operation_id)
    assert status.state == OperationExecutionState.COMPLETED


@pytest.mark.asyncio
async def test_capture_service_skips_empty_transaction_id_linking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _configure_operation_paths(tmp_path, monkeypatch)
    caplog.set_level("WARNING")
    service = _FakeCaptureServiceEmptyTxn(duration=0, interval=0)
    group_id, _ = await service.start()

    await asyncio.sleep(0)

    repo = CaptureGroupRepository.from_system_config()
    assert repo.list_transactions(group_id) == []
    assert "Skipping capture_group link for empty transaction_id" in caplog.text


@pytest.mark.asyncio
async def test_capture_service_skips_whitespace_transaction_id_linking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _configure_operation_paths(tmp_path, monkeypatch)
    caplog.set_level("WARNING")
    service = _FakeCaptureServiceWhitespaceTxn(duration=0, interval=0)
    group_id, _ = await service.start()

    await asyncio.sleep(0)

    repo = CaptureGroupRepository.from_system_config()
    assert repo.list_transactions(group_id) == []
    assert "Skipping capture_group link for empty transaction_id" in caplog.text

# FILE: tests/test_transaction_id_persistence_guards.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.api.routes.common.classes.file_capture.session_group import SessionGroup
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cable_modem import CableModem
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import DatabaseBackend, DatabaseDsn, DatabasePath
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest


def _configure_transaction_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
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


def _configure_session_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    db_path = tmp_path / "session_group.json"
    monkeypatch.setattr(
        SystemConfigSettings,
        "session_group_db",
        classmethod(lambda cls: str(db_path)),
    )
    return db_path


def _empty_sha256() -> object:
    class _Hasher:
        def update(self, _data: bytes) -> None:
            return None

        def hexdigest(self) -> str:
            return ""

    return _Hasher()


def test_session_group_skips_empty_transaction_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    db_path = _configure_session_db(tmp_path, monkeypatch)
    caplog.set_level("WARNING")
    group = SessionGroup()
    session_id = group.create_session()

    group.add_transaction("")
    group.add_transaction("   ")
    group.add_transaction("txn-1")

    with db_path.open("r", encoding="utf-8") as handle:
        db = json.load(handle)
    assert db[session_id]["transactions"] == ["txn-1"]
    assert (
        "Skipping empty transaction_id persistence in session_group_db" in caplog.text
    )


def test_pnm_file_transaction_skips_empty_transaction_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    db_path = _configure_transaction_db(tmp_path, monkeypatch)
    caplog.set_level("WARNING")
    monkeypatch.setattr(
        "pypnm.api.routes.common.classes.file_capture.pnm_file_transaction.hashlib.sha256",
        lambda _data=None: _empty_sha256(),
    )

    txn_store = PnmFileTransaction()
    cm = CableModem(
        mac_address=MacAddress("aa:bb:cc:dd:ee:ff"),
        inet=Inet("192.168.0.100"),
        write_community="public",
    )
    txn_id = txn_store._insert_generic(
        mac_address=cm.get_mac_address,
        pnm_test_type=DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR,
        filename="rxmer.bin",
    )

    assert str(txn_id) == ""
    assert "Skipping transaction insert for empty transaction_id" in caplog.text

    connection = sqlite3.connect(db_path)
    try:
        cursor = connection.execute("SELECT COUNT(1) FROM transaction_records;")
        row = cursor.fetchone()
        assert row is not None
        assert int(row[0]) == 0
    finally:
        connection.close()


def test_pnm_file_transaction_persists_valid_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_transaction_db(tmp_path, monkeypatch)
    txn_store = PnmFileTransaction()
    cm = CableModem(
        mac_address=MacAddress("aa:bb:cc:dd:ee:ff"),
        inet=Inet("192.168.0.100"),
        write_community="public",
    )
    txn_id = txn_store._insert_generic(
        mac_address=cm.get_mac_address,
        pnm_test_type=DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR,
        filename="rxmer.bin",
    )

    connection = sqlite3.connect(db_path)
    try:
        cursor = connection.execute(
            "SELECT COUNT(1) FROM transaction_records WHERE transaction_id = ?;",
            (str(txn_id),),
        )
        row = cursor.fetchone()
        assert row is not None
        assert int(row[0]) == 1
    finally:
        connection.close()

# FILE: tests/test_transaction_repository.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import cast

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

PNM_TEST_TYPE: str = "DS_RXMER"

SYS_DESCR: dict[str, str] = {
    "HW_REV": "1.0",
    "VENDOR": "ACME",
    "BOOTR": "1.1",
    "SW_REV": "2.0.1",
    "MODEL": "ACME-123",
}

MAC_ONE = MacAddress("aa:bb:cc:dd:ee:ff")
MAC_TWO = MacAddress("11:22:33:44:55:66")

TRANSACTION_ONE = TransactionId("aaaaaaaaaaaaaaaa")
TRANSACTION_TWO = TransactionId("bbbbbbbbbbbbbbbb")
TRANSACTION_THREE = TransactionId("cccccccccccccccc")

FILENAME_ONE = FileName("rxmer_one.bin")
FILENAME_TWO = FileName("rxmer_two.bin")
FILENAME_THREE = FileName("rxmer_three.bin")

TIMESTAMP_ONE: int = 1700000000
TIMESTAMP_TWO: int = 1700000100

EXPECTED_SYS_DESCR_COUNT: int = 1
EXPECTED_DEVICE_DETAILS_COUNT: int = 1
EXPECTED_DISTINCT_MACS: int = 2


class _RepoFixture:
    @staticmethod
    def build(
        tmp_path: Path,
    ) -> tuple[
        SystemDescriptionRepository,
        DeviceDetailsRepository,
        TransactionRepository,
        Path,
    ]:
        db_path = tmp_path / "pypnm.sqlite3"
        sqlite_path = cast(DatabasePath, str(db_path))
        postgres_dsn = cast(DatabaseDsn, "")

        manager = DatabaseSchemaManager.from_overrides(
            DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
        )
        manager.initialize_schema()

        sys_repo = SystemDescriptionRepository.from_overrides(
            DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
        )
        device_repo = DeviceDetailsRepository.from_overrides(
            DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
        )
        txn_repo = TransactionRepository.from_overrides(
            DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
        )

        return sys_repo, device_repo, txn_repo, db_path

    @staticmethod
    def insert_transaction(
        sys_repo: SystemDescriptionRepository,
        device_repo: DeviceDetailsRepository,
        txn_repo: TransactionRepository,
        transaction_id: TransactionId,
        timestamp_epoch: int,
        mac_address: MacAddress,
        filename: FileName,
        sysdescr: dict[str, str],
    ) -> None:
        sysdescr_id = sys_repo.get_or_create_sysdescr_id(sysdescr)
        device_details: dict[str, object] = {"system_description": sysdescr}
        device_detail_id = device_repo.get_or_create_device_detail_id(
            device_details, sysdescr_id
        )
        txn_repo.insert_transaction(
            transaction_id=transaction_id,
            timestamp_epoch=TimestampSec(timestamp_epoch),
            mac_address=mac_address,
            pnm_test_type=PNM_TEST_TYPE,
            filename=filename,
            device_detail_id=device_detail_id,
        )


def test_sysdescr_dedup(tmp_path: Path) -> None:
    sys_repo, device_repo, txn_repo, db_path = _RepoFixture.build(tmp_path)

    _RepoFixture.insert_transaction(
        sys_repo,
        device_repo,
        txn_repo,
        TRANSACTION_ONE,
        TIMESTAMP_ONE,
        MAC_ONE,
        FILENAME_ONE,
        SYS_DESCR,
    )
    _RepoFixture.insert_transaction(
        sys_repo,
        device_repo,
        txn_repo,
        TRANSACTION_TWO,
        TIMESTAMP_TWO,
        MAC_ONE,
        FILENAME_TWO,
        SYS_DESCR,
    )

    connection = sqlite3.connect(db_path)
    try:
        cursor = connection.execute(
            "SELECT COUNT(1) FROM system_description_dim WHERE is_unknown = 0;"
        )
        row = cursor.fetchone()
        assert row is not None
        assert int(row[0]) == EXPECTED_SYS_DESCR_COUNT
    finally:
        connection.close()


def test_device_details_dedup(tmp_path: Path) -> None:
    sys_repo, device_repo, txn_repo, db_path = _RepoFixture.build(tmp_path)

    _RepoFixture.insert_transaction(
        sys_repo,
        device_repo,
        txn_repo,
        TRANSACTION_ONE,
        TIMESTAMP_ONE,
        MAC_ONE,
        FILENAME_ONE,
        SYS_DESCR,
    )
    _RepoFixture.insert_transaction(
        sys_repo,
        device_repo,
        txn_repo,
        TRANSACTION_TWO,
        TIMESTAMP_TWO,
        MAC_TWO,
        FILENAME_TWO,
        SYS_DESCR,
    )

    connection = sqlite3.connect(db_path)
    try:
        cursor = connection.execute("SELECT COUNT(1) FROM device_details;")
        row = cursor.fetchone()
        assert row is not None
        assert int(row[0]) == EXPECTED_DEVICE_DETAILS_COUNT
    finally:
        connection.close()


def test_list_macs_returns_distinct(tmp_path: Path) -> None:
    sys_repo, device_repo, txn_repo, _db_path = _RepoFixture.build(tmp_path)

    _RepoFixture.insert_transaction(
        sys_repo,
        device_repo,
        txn_repo,
        TRANSACTION_ONE,
        TIMESTAMP_ONE,
        MAC_ONE,
        FILENAME_ONE,
        SYS_DESCR,
    )
    _RepoFixture.insert_transaction(
        sys_repo,
        device_repo,
        txn_repo,
        TRANSACTION_TWO,
        TIMESTAMP_TWO,
        MAC_ONE,
        FILENAME_TWO,
        SYS_DESCR,
    )
    _RepoFixture.insert_transaction(
        sys_repo,
        device_repo,
        txn_repo,
        TRANSACTION_THREE,
        TIMESTAMP_TWO,
        MAC_TWO,
        FILENAME_THREE,
        SYS_DESCR,
    )

    mac_entries = txn_repo.list_macs()
    assert len(mac_entries) == EXPECTED_DISTINCT_MACS
    macs = {entry.mac_address for entry in mac_entries}
    assert str(MAC_ONE) in macs
    assert str(MAC_TWO) in macs


def test_list_transactions_for_mac_orders_by_timestamp(tmp_path: Path) -> None:
    sys_repo, device_repo, txn_repo, _db_path = _RepoFixture.build(tmp_path)

    _RepoFixture.insert_transaction(
        sys_repo,
        device_repo,
        txn_repo,
        TRANSACTION_ONE,
        TIMESTAMP_TWO,
        MAC_ONE,
        FILENAME_ONE,
        SYS_DESCR,
    )
    _RepoFixture.insert_transaction(
        sys_repo,
        device_repo,
        txn_repo,
        TRANSACTION_TWO,
        TIMESTAMP_ONE,
        MAC_ONE,
        FILENAME_TWO,
        SYS_DESCR,
    )

    records = txn_repo.list_transactions_for_mac(MAC_ONE)
    timestamps = [int(record.timestamp_epoch) for record in records]
    assert timestamps == [TIMESTAMP_ONE, TIMESTAMP_TWO]
