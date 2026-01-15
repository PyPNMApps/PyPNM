## Agent Review Bundle Summary
- Goal: Close M2 open items by aligning the Postgres DSN fail-fast contract, optional psycopg policy, packaging verification, and shared Postgres test gating.
- Changes: Added a shared Postgres gating helper for integration-style tests; added package-data schema SQL load test and DSN fail-fast test; moved psycopg to an optional extra; updated design docs to reflect fail-fast schema manager behavior and optional Postgres driver.
- Files: pyproject.toml, tests/postgres_test_utils.py, tests/test_db_schema_manager.py, tests/test_capture_group_repository.py, tests/test_operation_capture_repository.py, tests/test_session_group_repository.py, docs/design/db/database-backend.md, docs/design/db/bootstrap-contract.md.
- Tests: python3 -m compileall src; ruff check .; ruff format --check .; pytest -q.
- Notes: Postgres DSN contract is fail-fast in DatabaseSchemaManager; psycopg is now optional via the `postgres` extra. pytest skips include PNM_CM_IT and PYPNM_TEST_POSTGRES-gated integration tests.

# FILE: pyproject.toml
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name            = "pypnm-docsis"
version         = "1.0.20.0"
description     = "DOCSIS 3.x/4.0 Proactive Network Maintenance Toolkit"
readme          = "README.md"
requires-python = ">=3.10"
license         = "Apache-2.0"

authors = [
  { name = "Maurice Garcia", email = "mgarcia01752@outlook.com" }
]

classifiers = [
  "Programming Language :: Python :: 3",
  "Programming Language :: Python :: 3 :: Only",
  "Programming Language :: Python :: 3.10",
  "Programming Language :: Python :: 3.11",
  "Programming Language :: Python :: 3.12",
  "Programming Language :: Python :: 3.13",
  "Operating System :: OS Independent",
  "Framework :: FastAPI",
  "Topic :: System :: Networking",
  "Typing :: Typed",
]

license-files = ["LICENSE", "NOTICE"]

dependencies = [
  "fastapi==0.115.12",
  "uvicorn[standard]==0.34.2",
  "python-multipart>=0.0.20",
  "numpy==2.2.6",
  "scipy==1.15.1",
  "pydantic>=2.12.4,<2.13",
  "pysmi==1.6.1",
  "pysnmp==7.1.17",
  "python-dotenv>=1.0.0",
  "requests==2.32.3",
  "pandas==2.2.3",
  "paramiko==3.5.1",
  "tftpy==0.8.5",
  "matplotlib==3.10.8",
  "typing-extensions>=4.10.0",
]

[project.optional-dependencies]
dev = [
  "pytest>=8.0.0",
  "pytest-cov>=5.0.0",
  "pytest-asyncio>=0.23.5",
  "black>=24.0.0",
  "pydantic-settings>=2.6.0",
  "pylint>=4.0.4",
  "ruff>=0.14.7",
  "pycycle>=0.0.8",
  "pyright>=1.1.407",
  "pyyaml>=6.0.2",
]
postgres = [
  "psycopg[binary]==3.2.3",
]
docs = [
  "mkdocs>=1.6",
  "mkdocs-material>=9.5",
  "pymdown-extensions>=10.8",
]
reports = []

[project.urls]
Homepage    = "https://www.pypnm.io"
Repository  = "https://github.com/PyPNMApps/PyPNM"
Bug-Tracker = "https://github.com/PyPNMApps/PyPNM/issues"
Documentation = "https://www.pypnm.io"

[project.scripts]
pypnm      = "pypnm.cli:main"
docs-serve = "mkdocs.__main__:serve"
docs-build = "mkdocs.__main__:build"
pypnm-software-qa-checker  = "pypnm.tools.qa_checker:main"

[tool.setuptools]
package-dir = { "" = "src" }
include-package-data = true

[tool.setuptools.packages.find]
where   = ["src"]
include = ["pypnm*"]

[tool.setuptools.package-data]
"pypnm" = [
  "db/schema/sql/*.sql",
  "settings/*.json",
  "py.typed",
]

[tool.pytest.ini_options]
minversion   = "8.0"
pythonpath   = ["src"]
testpaths    = ["tests"]
addopts      = "-ra -q --strict-markers --tb=short -m 'not cm_it'"
asyncio_mode = "auto"
log_cli = true
log_cli_level = "INFO"
log_cli_format = "%(levelname)s %(name)s:%(lineno)d | %(message)s"
log_cli_date_format = "%H:%M:%S"
markers = [
  "asyncio: mark test as asyncio-based (requires pytest-asyncio)",
  "cm_it: cable modem integration tests (enable with -m cm_it)",
  "slow: slow tests",
  "net: network-required tests",
  "pnm: PNM file parsing tests",
]
filterwarnings = [
  "ignore:getReadersFromUrls is deprecated:DeprecationWarning:pysnmp",
  "ignore:smiV1Relaxed is deprecated:DeprecationWarning:pysnmp",
  "ignore:.*getReadersFromUrls.*:DeprecationWarning:pysmi.reader.url",
  "ignore:.*addSources.*:DeprecationWarning:pysnmp.smi.compiler",
  "ignore:.*addSearchers.*:DeprecationWarning:pysnmp.smi.compiler",
  "ignore:.*addBorrowers.*:DeprecationWarning:pysnmp.smi.compiler",
]

[tool.coverage.run]
branch = true
source = ["pypnm"]

[tool.coverage.report]
show_missing = true
skip_covered = true

[tool.black]
line-length = 100
target-version = ["py310"]

[tool.ruff]
src            = ["src"]
target-version = "py310"
exclude        = [
  "tools",
  "src/pypnm/lib/matplot/manager.py",
  "src/pypnm/lib/csv/manager.py",
  "src/pypnm/api/routes/common/extended/common_messaging_service.py",
  "src/pypnm/api/routes/common/extended/common_measure_service.py",
  "src/pypnm/examples/",
]

[tool.ruff.lint]
# Common, high-signal rulesets:
# F   = Pyflakes (real errors)
# E,W = pycodestyle
# I   = import sorting
# B   = flake8-bugbear
# UP  = pyupgrade
#
# Ignore:
# E501 - https://docs.astral.sh/ruff/rules/line-too-long/
# B006 - https://docs.astral.sh/ruff/rules/mutable-argument-default/
#
# ---------------------------------------------------------------------------
# Ruff Roadmap (do NOT enable by default; turn on gradually when ready)
# ---------------------------------------------------------------------------
# Phase 1 (current):
#   - Focus on correctness + core style only.
#   - Enabled rule families:
#       F, E, W, I, B, UP
#
# Phase 2 (optional): Naming rules
#   - Add N (pep8-naming) when public API naming is stable.
#   - This enforces conventional names for functions, classes, etc.
#   - Example change (for later, DO NOT UNCOMMENT YET):
#       select = ["F", "E", "W", "I", "B", "UP", "N"]
#
# Phase 3 (optional): Type-annotation rules
#   - Add ANN to enforce more consistent type hints once F/E/W noise is low.
#   - You can selectively ignore strict ANN codes if needed (e.g., ANN101/ANN102).
#   - Example (for later):
#       select = ["F", "E", "W", "I", "B", "UP", "ANN"]
#       ignore = ["E501", "B006", "ANN101", "ANN102"]
#
# Phase 4 (optional): Simplification & performance hints
#   - Enable SIM (flake8-simplify) to flag redundant or over-complicated logic.
#   - Enable PERF to catch obvious performance footguns in hot paths.
#   - Recommended approach:
#       - First, run ad-hoc from CLI without adding to select:
#           ruff check src --select SIM,PERF
#       - Fix only the diagnostics you agree with.
#   - If you like the results, you can later extend select:
#       select = ["F", "E", "W", "I", "B", "UP", "N", "ANN", "SIM", "PERF"]
#
# Packs to generally avoid for PyPNM (unless explicitly desired later):
#   - D (pydocstyle): conflicts with custom docstring rules.
#   - C90 / PL (mccabe / pylint families): very noisy, low signal for this project.

select = ["F", "E", "W", "I", "B", "UP", "ANN", "SIM", "PERF"]
ignore = [
  "E501",
  "B006"
]

[tool.pyright]
pythonVersion = "3.10"
pythonPlatform = "Linux"

include = ["src"]
exclude = [
  "tools",
  "src/pypnm/examples/",
  "**/__pycache__",
]

# VSCode + .env venv
venvPath = "."
venv = ".env"

reportMissingImports = "warning"
reportMissingTypeStubs = "warning"
typeCheckingMode = "basic"

# FILE: tests/postgres_test_utils.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import os
from types import ModuleType

import pytest

from pypnm.lib.types import DatabaseDsn


def require_postgres() -> tuple[DatabaseDsn, ModuleType]:
    if os.environ.get("PYPNM_TEST_POSTGRES", "").strip() != "1":
        pytest.skip("PYPNM_TEST_POSTGRES not set")
    dsn = os.environ.get("PYPNM_DB_POSTGRES_DSN", "").strip()
    if dsn == "":
        pytest.skip("PYPNM_DB_POSTGRES_DSN not set")
    try:
        import psycopg
    except ImportError:
        pytest.skip("psycopg not installed")
    return DatabaseDsn(dsn), psycopg

# FILE: tests/test_db_schema_manager.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import sqlite3
from importlib import resources
from pathlib import Path
from typing import cast

import pytest
from tests.postgres_test_utils import require_postgres

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
INDEX_CG_TX_TABLE: str = "capture_group_transactions"
INDEX_OPERATION_CAPTURES_TABLE: str = "operation_captures"
INDEX_CG_TX_CAPTURE_GROUP_POSITION: str = "idx_cg_tx_capture_group_position"
INDEX_OPERATION_CAPTURES_OPERATION_ID: str = "idx_operation_captures_operation_id"
EXPECTED_CG_TX_COLUMNS: tuple[str, str] = ("capture_group_id", "position")
EXPECTED_OPERATION_COLUMNS: tuple[str, ...] = ("operation_id",)


def _sqlite_index_columns(
    connection: sqlite3.Connection, table_name: str, index_name: str
) -> list[str]:
    cursor = connection.execute(f"PRAGMA index_list('{table_name}');")
    rows = cursor.fetchall()
    index_names = {str(row[1]) for row in rows}
    assert index_name in index_names
    cursor = connection.execute(f"PRAGMA index_info('{index_name}');")
    rows = cursor.fetchall()
    return [str(row[2]) for row in rows]


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


def test_sqlite_capture_group_indexes_present(tmp_path: Path) -> None:
    db_path = tmp_path / "pypnm_schema.sqlite3"
    sqlite_path = cast(DatabasePath, str(db_path))
    postgres_dsn = cast(DatabaseDsn, "")
    manager = DatabaseSchemaManager.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )

    manager.initialize_schema()

    connection = sqlite3.connect(db_path)
    try:
        columns = _sqlite_index_columns(
            connection, INDEX_CG_TX_TABLE, INDEX_CG_TX_CAPTURE_GROUP_POSITION
        )
        assert columns == list(EXPECTED_CG_TX_COLUMNS)
        columns = _sqlite_index_columns(
            connection,
            INDEX_OPERATION_CAPTURES_TABLE,
            INDEX_OPERATION_CAPTURES_OPERATION_ID,
        )
        assert columns == list(EXPECTED_OPERATION_COLUMNS)
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
    ddl_path = resources.files("pypnm.db.schema.sql").joinpath("schema_postgres.sql")
    ddl_sql = ddl_path.read_text(encoding="utf-8")
    statements = DatabaseSchemaManager._split_sql_statements(ddl_sql)
    assert len(statements) >= EXPECTED_SCHEMA_STATEMENTS_MIN
    joined = "\n".join(statements)
    assert "CREATE TABLE IF NOT EXISTS schema_meta" in joined


def test_schema_sql_assets_load_from_package() -> None:
    sqlite_sql = (
        resources.files("pypnm.db.schema.sql")
        .joinpath("schema_sqlite.sql")
        .read_text(encoding="utf-8")
    )
    postgres_sql = (
        resources.files("pypnm.db.schema.sql")
        .joinpath("schema_postgres.sql")
        .read_text(encoding="utf-8")
    )
    assert "CREATE TABLE IF NOT EXISTS schema_meta" in sqlite_sql
    assert "CREATE TABLE IF NOT EXISTS schema_meta" in postgres_sql


def test_postgres_schema_init_requires_dsn(tmp_path: Path) -> None:
    sqlite_path = cast(DatabasePath, str(tmp_path / "unused.sqlite3"))
    postgres_dsn = cast(DatabaseDsn, "")
    manager = DatabaseSchemaManager.from_overrides(
        DatabaseBackend.POSTGRES, sqlite_path, postgres_dsn
    )

    with pytest.raises(ValueError, match="Database.postgres.dsn cannot be blank"):
        manager.connect()


def test_postgres_schema_init_optional() -> None:
    postgres_dsn, _ = require_postgres()
    sqlite_path = cast(DatabasePath, ".data/db/pypnm.sqlite3")
    manager = DatabaseSchemaManager.from_overrides(
        DatabaseBackend.POSTGRES, sqlite_path, postgres_dsn
    )
    manager.initialize_schema()
    health = manager.health_check()
    assert health.ok is True


def test_postgres_capture_group_indexes_optional() -> None:
    postgres_dsn, _ = require_postgres()
    sqlite_path = cast(DatabasePath, ".data/db/pypnm.sqlite3")
    manager = DatabaseSchemaManager.from_overrides(
        DatabaseBackend.POSTGRES, sqlite_path, postgres_dsn
    )
    manager.initialize_schema()

    connection = manager.connect()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                ""
                "SELECT indexname FROM pg_indexes "
                "WHERE schemaname = current_schema() "
                "AND tablename = %s;",
                (INDEX_CG_TX_TABLE,),
            )
            rows = cursor.fetchall()
        index_names = {str(row[0]) for row in rows}
        assert INDEX_CG_TX_CAPTURE_GROUP_POSITION in index_names

        with connection.cursor() as cursor:
            cursor.execute(
                ""
                "SELECT indexname FROM pg_indexes "
                "WHERE schemaname = current_schema() "
                "AND tablename = %s;",
                (INDEX_OPERATION_CAPTURES_TABLE,),
            )
            rows = cursor.fetchall()
        index_names = {str(row[0]) for row in rows}
        assert INDEX_OPERATION_CAPTURES_OPERATION_ID in index_names
    finally:
        connection.close()

# FILE: tests/test_capture_group_repository.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path

import pytest
from tests.postgres_test_utils import require_postgres

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
    postgres_dsn, psycopg = require_postgres()
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
    postgres_dsn, psycopg = require_postgres()
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

# FILE: tests/test_operation_capture_repository.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path

import pytest
from tests.postgres_test_utils import require_postgres

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.capture_group_repository import CaptureGroupRepository
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.db.operation_capture_repository import OperationCaptureRepository
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    GroupId,
    OperationId,
    TimestampSec,
)

DEFAULT_CREATED_EPOCH: int = 20
UNIQUE_SUFFIX_LEN: int = 8


def _unique_suffix() -> str:
    return uuid.uuid4().hex[:UNIQUE_SUFFIX_LEN]


def _configure_operation_capture_db(
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


def _configure_operation_capture_legacy_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    db_path = tmp_path / "pypnm-legacy.sqlite3"
    connection = sqlite3.connect(db_path)
    try:
        connection.execute("PRAGMA foreign_keys = ON;")
        connection.execute(
            ""
            "CREATE TABLE IF NOT EXISTS capture_groups ("
            "    capture_group_id  TEXT    PRIMARY KEY,"
            "    created_epoch     INTEGER NOT NULL"
            ");"
        )
        connection.execute(
            ""
            "CREATE TABLE IF NOT EXISTS operation_captures ("
            "    operation_capture_id TEXT PRIMARY KEY,"
            "    capture_group_id     TEXT    NOT NULL "
            "        REFERENCES capture_groups(capture_group_id) ON DELETE RESTRICT,"
            "    created_epoch        INTEGER NOT NULL "
            "        DEFAULT (CAST(strftime('%s','now') AS INTEGER))"
            ");"
        )
        connection.commit()
    finally:
        connection.close()

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
    return db_path


def _configure_operation_capture_postgres(
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


def test_operation_capture_repository_links_and_resolves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_capture_db(tmp_path, monkeypatch)
    capture_repo = CaptureGroupRepository.from_system_config()
    operation_repo = OperationCaptureRepository.from_system_config()
    capture_group_id = GroupId("cg-op-1")
    operation_id = OperationId("op-1")

    capture_repo.create_capture_group(
        capture_group_id, TimestampSec(DEFAULT_CREATED_EPOCH)
    )
    operation_repo.create_operation_capture(
        operation_id, capture_group_id, TimestampSec(DEFAULT_CREATED_EPOCH)
    )

    resolved = operation_repo.get_capture_group_id(operation_id)
    assert resolved == capture_group_id


def test_operation_capture_repository_fk_enforced_on_missing_capture_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_capture_db(tmp_path, monkeypatch)
    operation_repo = OperationCaptureRepository.from_system_config()
    capture_group_id = GroupId("cg-missing")
    operation_id = OperationId("op-missing")

    with pytest.raises(sqlite3.IntegrityError):
        operation_repo.create_operation_capture(
            operation_id, capture_group_id, TimestampSec(DEFAULT_CREATED_EPOCH)
        )


def test_operation_capture_repository_legacy_column_detection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_operation_capture_legacy_db(tmp_path, monkeypatch)
    connection = sqlite3.connect(db_path)
    try:
        connection.execute("PRAGMA foreign_keys = ON;")
        connection.execute(
            "INSERT INTO capture_groups (capture_group_id, created_epoch) VALUES (?, ?);",
            ("cg-legacy", DEFAULT_CREATED_EPOCH),
        )
        connection.commit()
    finally:
        connection.close()

    operation_repo = OperationCaptureRepository.from_system_config()
    capture_group_id = GroupId("cg-legacy")
    operation_id = OperationId("op-legacy")
    operation_repo.create_operation_capture(
        operation_id, capture_group_id, TimestampSec(DEFAULT_CREATED_EPOCH)
    )

    assert operation_repo.get_capture_group_id(operation_id) == capture_group_id
    assert operation_repo._operation_id_column == "operation_capture_id"


def test_operation_capture_repository_fk_enforced_on_missing_capture_group_postgres(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    postgres_dsn, psycopg = require_postgres()
    _configure_operation_capture_postgres(tmp_path, monkeypatch, postgres_dsn)
    suffix = _unique_suffix()
    capture_group_id = GroupId(f"cg-op-missing-{suffix}")
    operation_id = OperationId(f"op-missing-{suffix}")

    operation_repo = OperationCaptureRepository.from_system_config()
    with pytest.raises(psycopg.IntegrityError):
        operation_repo.create_operation_capture(
            operation_id, capture_group_id, TimestampSec(DEFAULT_CREATED_EPOCH)
        )

# FILE: tests/test_session_group_repository.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path

import pytest
from tests.postgres_test_utils import require_postgres

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
    postgres_dsn, psycopg = require_postgres()
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

# FILE: docs/design/db/database-backend.md
# PyPNM Database Backend Design

## Table Of Contents

- [0. Status Snapshot (2026-01-11)](#0-status-snapshot-2026-01-11)
- [1. Purpose](#1-purpose)
- [2. Scope](#2-scope)
- [3. Non-Goals](#3-non-goals)
- [4. Design Requirements](#4-design-requirements)
- [5. Terminology](#5-terminology)
- [6. Target Operating Model](#6-target-operating-model)
  - [6.1 DB Responsibility Contract](#61-db-responsibility-contract)
  - [6.2 What Stays On Disk](#62-what-stays-on-disk)
  - [6.3 What Moves Into The DB](#63-what-moves-into-the-db)
- [7. Backend Selection And Installation Contract](#7-backend-selection-and-installation-contract)
  - [7.1 install.sh Flags And Interactive Prompt](#71-installsh-flags-and-interactive-prompt)
  - [7.2 Configuration Keys](#72-configuration-keys)
  - [7.3 DB Location Policy](#73-db-location-policy)
  - [7.4 PostgreSQL Authentication And Secrets](#74-postgresql-authentication-and-secrets)
  - [7.5 Adapter Contract And Bootstrap](#75-adapter-contract-and-bootstrap)
- [8. Release Hygiene Requirements](#8-release-hygiene-requirements)
  - [8.1 Git Ignore And Packaging Exclusions](#81-git-ignore-and-packaging-exclusions)
  - [8.2 Docker And Container Image Hygiene](#82-docker-and-container-image-hygiene)
- [9. Target Schema (Planned)](#9-target-schema-planned)
  - [9.1 Dimensions](#91-dimensions)
  - [9.2 Fact Tables](#92-fact-tables)
  - [9.3 Grouping Constructs](#93-grouping-constructs)
  - [9.4 Artifact Linkage](#94-artifact-linkage)
  - [9.5 Constraints And Indexing](#95-constraints-and-indexing)
  - [9.6 UNKNOWN sysDescr Seed Row](#96-unknown-sysdescr-seed-row)
- [10. Path Contract And Portability](#10-path-contract-and-portability)
  - [10.1 Portable Paths](#101-portable-paths)
  - [10.2 Absolute Path Construction](#102-absolute-path-construction)
  - [10.3 Demo Isolation](#103-demo-isolation)
- [11. Endpoint Compatibility Requirements](#11-endpoint-compatibility-requirements)
  - [11.1 Current File Manager Endpoints](#111-current-file-manager-endpoints)
  - [11.2 DB Queries Needed By Each Endpoint](#112-db-queries-needed-by-each-endpoint)
  - [11.3 Artifact Resolution Rules](#113-artifact-resolution-rules)
- [12. Workflows](#12-workflows)
  - [12.1 Upload Flow](#121-upload-flow)
  - [12.2 Download By Transaction ID](#122-download-by-transaction-id)
  - [12.3 Search Files By MAC](#123-search-files-by-mac)
  - [12.4 Download By MAC (ZIP)](#124-download-by-mac-zip)
  - [12.5 Download By Operation ID (ZIP)](#125-download-by-operation-id-zip)
- [13. Documentation And Tooling Updates](#13-documentation-and-tooling-updates)
  - [13.1 Remove Ledger JSON Design From Docs](#131-remove-ledger-json-design-from-docs)
  - [13.2 Add Mermaid Support To MkDocs And pyproject](#132-add-mermaid-support-to-mkdocs-and-pyproject)
- [14. Migration Strategy](#14-migration-strategy)
  - [14.1 Cutover Philosophy](#141-cutover-philosophy)
  - [14.2 Legacy Ledger Data](#142-legacy-ledger-data)
  - [14.3 Implementation Milestones And Cutover Moment](#143-implementation-milestones-and-cutover-moment)
- [15. Testing Requirements](#15-testing-requirements)
  - [15.1 CI And GitHub Workflow Considerations](#151-ci-and-github-workflow-considerations)
- [16. Concurrency Model And Backend Guidance](#16-concurrency-model-and-backend-guidance)
  - [16.1 SQLite Concurrency Limits](#161-sqlite-concurrency-limits)
  - [16.2 PostgreSQL Recommendation Guidance](#162-postgresql-recommendation-guidance)
- [17. Appendix A: Mermaid ER Diagram](#17-appendix-a-mermaid-er-diagram)
- [18. Appendix B: PostgreSQL DDL](#18-appendix-b-postgresql-ddl)
- [19. Appendix C: SQLite DDL](#19-appendix-c-sqlite-ddl)

## 0. Status Snapshot (2026-01-11)

This section is a working marker so you can see progress against the design while the DB cutover is in-flight.

Work completed toward the DB bootstrap contract:

- Unified operation workflow payload shape across newer registry-style endpoints:
  - Dual-status support (legacy `status` string plus canonical `service_status`)
  - Shared `time_remaining` contract on registry status endpoints, including safe coercion and default fallback behavior
- Multi-capture registry status endpoints aligned to the shared `time_remaining` contract:
  - Multi-RxMER `/advance/multiRxMer/status` (POST)
  - Multi-ChannelEstimation `/advance/multiChannelEstimation/status` (POST)
- Test coverage added to lock in the above contract behavior and keep the validation gate green.

Bootstrap status:

- The adapter contract and schema bootstrap readiness check are implemented.
- The full schema and data migrations remain planned work.

## 1. Purpose

PyPNM historically persisted transaction metadata using JSON “ledger” files under `.data/db/`. The DB backend is
being introduced incrementally; the JSON ledgers are deprecated, but the DB is not yet authoritative for
transactions, capture groups, or operations. This design defines the target state for replacing the ledger with a
relational database while preserving PyPNM’s operational model
(filesystem-based binary artifacts plus lightweight metadata persistence).

This document is authoritative for:

- PyPNM (authoritative engine and persistence owner)
- PyPNM-CMTS (consumer of PyPNM; inherits PyPNM’s backend choice)

The current implementation only provides a minimal bootstrap contract; see [Bootstrap Contract](bootstrap-contract.md)
for implemented behavior. The schema and workflow sections below are forward-looking until later phases land.

## 2. Scope

In scope:

- Install-time DB backend selection owned by PyPNM (`sqlite` or `postgres`)
- A normalized relational schema for transaction metadata and grouping constructs (capture groups and operations)
- A durable, explicit way to link transactions to one-or-more files on disk (raw capture binaries and future derived artifacts)
- Demo mode isolation using the same schema with different data roots and or a different DB target
- Release hygiene rules to guarantee no runtime DB/data is shipped in sdists wheels images
- Documentation updates to remove ledger JSON design and replace it with DB-backed persistence
- Endpoint compatibility for the existing PNM File Manager API routes (no JSON ledger traversal at runtime)
- CI viability for both backends (SQLite as baseline, Postgres as service-backed integration in CI when enabled)

Out of scope:

- Security sanitization pipeline refactor (tracked as a later work item, but design constraints are captured here)
- Any change to PNM binary formats
- Any separate persistence mechanism in PyPNM-CMTS

## 3. Non-Goals

- No database-specific business logic in PyPNM-CMTS
- No separate DB selection logic in PyPNM-CMTS
- No database embedded in the Python package directory (no `.sqlite3` inside `src/pypnm/...`)
- No requirement for Kubernetes APIs or a K8 operator

## 4. Design Requirements

1) PyPNM owns persistence  
   PyPNM selects the backend and initializes schema. PyPNM-CMTS must use PyPNM APIs only and inherit the same backend.

2) Epoch timestamps  
   All stored timestamps remain epoch seconds.

3) Explicit artifact linkage  
   A transaction must reference one-or-more on-disk artifacts (raw binary capture, uploads, derived artifacts, archives).

4) SysDescr de-duplication  
   `system_description` values are normalized. A special `UNKNOWN` row exists for user uploads lacking sysDescr.

5) Demo mode uses the same schema  
   Same code path, same tables. Only data differs (dataset root and DB target).

6) Paths stored in DB are portable  
   No user-specific absolute paths are stored (for example `/home/dev01/...`). Store repo app-root relative strings.

7) Backward-facing endpoint shapes remain stable  
   The FastAPI file manager endpoints must continue to function with the same request response models (or minimally invasive
   changes), while switching persistence from JSON ledgers to DB.

8) Release artifacts must never ship runtime DB or data  
   Sdists, wheels, and container images must not contain `.data/`, `demo/.data/`, SQLite DB files, or captured artifacts.

9) DB must be capable of resolving a transaction to a binary without legacy settings JSON linkage  
   The DB must provide sufficient metadata to locate the authoritative binary on disk for download, analysis, and hexdump.

10) DB backend guidance must be explicit for multi-worker deployments  
   SQLite is acceptable for single-writer or small deployments. Postgres is recommended for multi-worker service deployments,
   especially when running PyPNM-CMTS on top of PyPNM.

11) Schema version compatibility is enforced  
   PyPNM must persist a schema version (via `schema_meta`) and must fail fast with a clear error if the DB schema version
   is unsupported. No silent or destructive migrations are permitted in normal runtime flows.

## 5. Terminology

- app_root: The runtime root directory resolved by PyPNM (repo root in dev, container path like `/app` in Docker).
- artifact store: A named root directory relative to app_root (for example `.data/pnm`).
- artifact: A file on disk referenced by the DB (raw PNM binary or a derived packaged artifact).
- transaction: A logical capture event (one PNM binary and its metadata).
- capture group: A grouping of multiple transactions captured together.
- operation capture: A higher-level operation identifier that points to a capture group.
- role: A transaction to artifact linkage label that indicates which file is authoritative for a given purpose (for example `pnm_raw`).

## 6. Target Operating Model

### 6.1 DB Responsibility Contract

PyPNM is the persistence owner:

- Selects backend at install time
- Initializes schema (idempotent)
- Enforces schema version compatibility (fail fast on mismatch)
- Provides repository service APIs that hide backend differences
- Owns all queries required by the file manager endpoints

Initialization ownership contract:

- `install.sh` is responsible for selecting the backend and generating settings that describe it.
- PyPNM runtime is responsible for idempotent schema ensurement:
  - SQLite: create directory and DB file under configured `.data/` root when missing.
  - Postgres: validate connectivity, ensure schema exists, and validate `schema_meta.schema_version`.
- PyPNM runtime must never “silently downgrade” or “auto-migrate” a schema across major versions. If schema version is not
  supported, PyPNM must raise a clear, actionable error with remediation steps.

PyPNM-CMTS is a consumer:

- Never selects a different backend
- Never embeds its own schema or persistence logic for PyPNM transaction metadata
- Calls PyPNM APIs for file transaction resolution

### 6.2 What Stays On Disk

Binary artifacts remain filesystem-based:

- Raw PNM binaries captured via SNMP TFTP HTTP and saved into `.data/pnm/` (or demo equivalent)
- Derived files (CSV JSON PNG PDF ZIP) remain in `.data/<type>/` directories as currently designed
- Archives (ZIP) remain under `.data/archive/`

The DB stores metadata and references to those artifacts.

### 6.3 What Moves Into The DB

Planned changes for later phases:

- Transaction metadata
- Capture group membership and ordering
- Operation capture linkage
- Artifact store roots and artifact file linkage

## 7. Backend Selection And Installation Contract

### 7.1 install.sh Flags And Interactive Prompt

PyPNM’s `install.sh` must support:

- `--db-install-sqlite` (default if not specified)
- `--db-install-postgres`

If neither flag is provided, the installer must prompt:

- Question: choose `sqlite` or `postgres`
- Default: `sqlite`

Selection is written into the generated settings file (for example `settings/system.json`), and PyPNM uses it at runtime.

Implementation status (2026-01-10):

- Flags and interactive selection have been implemented, and selection occurs before pytest so the suite runs against the chosen backend contract.
- Postgres DSN capture supports password redaction and recommends env var injection rather than plaintext persistence.

### 7.2 Configuration Keys

A single configuration contract, applicable to both prod and demo datasets:

```json
{
  "Database": {
    "backend": "sqlite",
    "sqlite": {
      "path": ".data/db/pypnm.sqlite3"
    },
    "postgres": {
      "dsn": ""
    }
  }
}
```

Notes:

- Postgres must accept a DSN at minimum. Discrete fields may exist, but DSN is the lowest common denominator.
- Demo mode may point to `demo/.data/db/pypnm.sqlite3` and the demo artifact root via artifact store seeding.
- Secret handling: the DSN may be supplied via environment variables in service deployments to avoid plaintext passwords in
  tracked configuration files.

DSN resolution order (contract):

1) Environment variable override (if set)
2) Settings file value (`Database.postgres.dsn`)
3) Installer-generated discrete fields (if implemented) composed into a DSN

Recommended environment variable keys (contract):

- `PYPNM_DB_BACKEND` (optional override for dev and CI)
- `PYPNM_DB_POSTGRES_DSN` (preferred secret injection mechanism for Postgres DSN)

Implementation note:

- The template and SystemConfigSettings accessors align to this contract; installer output preserves the same keys.

### 7.3 DB Location Policy

The DB is runtime state and must live under `.data/` roots, not inside the package directory.

Recommended defaults (repo app-root relative):

- SQLite: `.data/db/pypnm.sqlite3`
- Demo SQLite: `demo/.data/db/pypnm.sqlite3`
- Postgres: external service; no local DB file

### 7.4 PostgreSQL Authentication And Secrets

Development defaults may use `pypnm` / `pypnm` for local containers or CI service containers, but the design requires:

- No credentials hardcoded in source code
- DSN or discrete connection fields populated via:
  - settings file generated by `install.sh`, and or
  - environment variables or secret injection in container deployments
- CI should use a service-container (or equivalent) and pass DSN through env vars
- Documentation must include an example DSN pattern without embedding real customer credentials

Credential guidance contract:

- Local dev and CI may use the well-known defaults:
  - user: `pypnm`
  - password: `pypnm`
  - db: `pypnm`
- Production documentation must explicitly warn that the above defaults are not acceptable for production environments.
- If a password is present in `settings/system.json`, it must only be present because the user explicitly chose to keep it there
  during `install.sh`. In all other cases, prefer DSN injection using `PYPNM_DB_POSTGRES_DSN` and avoid plaintext secrets.

Example DSN pattern (documentation-only example):

- `postgresql://pypnm:${PYPNM_DB_POSTGRES_PASSWORD}@localhost:5432/pypnm`

PyPNM must treat DSN strings as secrets:

- Do not log full DSNs at INFO level (mask or omit password portion).
- If diagnostics need to report connectivity, log only host, port, dbname, user, and SSL mode.
- Postgres driver support is optional and provided by the `postgres` extra (install with `pypnm-docsis[postgres]`).

### 7.5 Adapter Contract And Bootstrap

The DB adapter contract provides a minimal lifecycle interface: `connect`, `apply_schema`, `healthcheck`, and `close`.
Adapters must remain policy-neutral and focused on the bootstrap path only.

Backend selection precedence (contract):

1) Environment overrides (`PYPNM_DB_BACKEND`, `PYPNM_DB_POSTGRES_DSN`)
2) Configuration file values (`Database.backend`, `Database.postgres.dsn`)
3) Defaults (SQLite)

DatabaseManager selection may fall back to SQLite without raising if the Postgres DSN is invalid or blank. The
schema manager is fail-fast: when backend is postgres and the DSN is invalid or blank, it raises a clear error.

Schema bootstrap scope (current phase):

- `schema_meta` exists solely to verify minimal DB readiness.
- `initialize()` connects, applies the schema seed if empty, and checks health.
- `close()` tears down the adapter and clears the cached instance for re-selection.
- Schema DDL assets are loaded from package data (via importlib.resources); docs copies are reference-only.

## 8. Release Hygiene Requirements

When building releases (sdist, wheel, container images):

- Never ship `.data/` or `demo/.data/` content
- Never ship any `.sqlite3` or `.db` files
- Never ship customer binary captures or derived artifacts

### 8.1 Git Ignore And Packaging Exclusions

Concrete safeguards:

- `.gitignore` includes `.data/` and `demo/.data/`
- Packaging config excludes `.data/**` and `demo/.data/**`
- Any demo dataset DB file is also excluded (`demo/.data/db/pypnm.sqlite3`)

### 8.2 Docker And Container Image Hygiene

- `.dockerignore` includes `.data/`, `demo/.data/`, `*.sqlite3`, `*.db`
- Dockerfiles do not `COPY` `.data/` or demo datasets into image layers (data must come from runtime volumes)

## 9. Target Schema (Planned)

This section describes the planned target schema and workflow contracts. It is not implemented yet beyond the
bootstrap table used for readiness checks.

### 9.1 Dimensions

system_description_dim:

- Normalized sysDescr fields
- Unique by `sysdescr_hash`
- Includes `UNKNOWN` row

device_details:

- References system_description_dim
- Stores device details JSON (extensible)
- Unique by `device_details_hash`

### 9.2 Fact Tables

transaction_records:

- One row per transaction
- Includes transaction_id, timestamp_epoch, mac_address, pnm_test_type, filename (legacy convenience)
- References device_details via device_detail_id

### 9.3 Grouping Constructs

capture_groups:

- One row per capture group id

capture_group_transactions:

- Join table linking capture groups to transactions
- Stores ordering via `position`
- Position assignment uses `MAX(position) + 1` with bounded retries on collisions

operation_captures:

- One row per operation id
- References capture group id
- DB-backed mapping is authoritative; JSON ledgers are deprecated

### 9.4 Artifact Linkage

artifact_stores:

- Named store roots relative to app_root (for example `.data/pnm`, `demo/.data/pnm`)

file_artifacts:

- One row per file artifact
- Unique by `(store_id, relative_path)` and by `sha256`

transaction_artifacts:

- Join table linking transactions to file artifacts
- Includes `role` (for example `pnm_raw`, `pnm_uploaded_raw`, `analysis_zip`, `analysis_json`)

### 9.5 Constraints And Indexing

- MAC address format enforced via CHECK constraints
- Unique constraints on dimension hashes and artifact uniqueness
- Indices on timestamp, mac_address, pnm_test_type, FK columns

### 9.6 UNKNOWN sysDescr Seed Row

The schema seeds a canonical UNKNOWN sysDescr row, used when:

- A file is uploaded by the user and sysDescr cannot be derived
- A capture flow fails to collect sysDescr but still persists a transaction record

Canonical sysDescr JSON example (normal case, not UNKNOWN):

```json
{"HW_REV":"1.0","VENDOR":"LANCity","BOOTR":"NONE","SW_REV":"1.0.0","MODEL":"LCPET-3"}
```

## 10. Path Contract And Portability

### 10.1 Portable Paths

Store only repo app-root relative paths:

- artifact_stores.root_path: store root (for example `.data/pnm`, `demo/.data/pnm`)
- file_artifacts.relative_path: path relative to store root (often a filename, may be nested)

### 10.2 Absolute Path Construction

At runtime:

`absolute_path = Path(app_root) / artifact_stores.root_path / file_artifacts.relative_path`

No absolute paths are stored in the DB.

### 10.3 Demo Isolation

Demo uses:

- Separate DB target (recommended): `demo/.data/db/pypnm.sqlite3`
- Separate artifact store root: `demo/.data/pnm`

Prod uses:

- `.data/db/pypnm.sqlite3`
- `.data/pnm`

Same schema, different data.

## 11. Endpoint Compatibility Requirements

### 11.1 Current File Manager Endpoints

The following endpoints (existing shapes) must remain functionally equivalent:

- `GET /docs/pnm/files/getMacAddresses/`
- `GET /docs/pnm/files/searchFiles/{mac_address}`
- `GET /docs/pnm/files/download/transactionID/{transaction_id}`
- `GET /docs/pnm/files/download/macAddress/{mac_address}`
- `GET /docs/pnm/files/download/operationID/{operation_id}`
- `POST /docs/pnm/files/upload`
- `POST /docs/pnm/files/getAnalysis`
- `GET /docs/pnm/files/getHexdump/transactionID/{transaction_id}`

### 11.2 DB Queries Needed By Each Endpoint

1) getMacAddresses  
   Query: distinct MACs from transaction_records with latest timestamp per MAC, include best-effort system_description derived
   from joined device_details system_description_dim.

2) searchFiles/{mac}  
   Query: transaction_records filtered by mac_address, sorted by timestamp, returning `transaction_id`, `filename`, `pnm_test_type`,
   `timestamp_epoch`, and system_description.

3) download/transactionID/{transaction_id}  
   Query: resolve transaction -> artifact by role (prefer `pnm_raw` then `pnm_uploaded_raw`); construct absolute path; serve file.

4) download/macAddress/{mac}  
   Query: list transactions for MAC; resolve artifacts per transaction; zip.

5) download/operationID/{operation_id}  
   Query: operation -> capture_group -> ordered tx list; resolve artifacts; zip.

6) upload  
   Insert: create transaction record with UNKNOWN sysDescr device_details if necessary; insert artifact and link as `pnm_uploaded_raw`.

7) getAnalysis  
   Resolve file as in download; analysis logic continues as-is once a filesystem path is available.

8) getHexdump  
   Resolve file as in download; hexdump logic continues as-is.

### 11.3 Artifact Resolution Rules

When resolving the on-disk file for a transaction:

- First choice role: `pnm_raw` (captured file)
- Second choice role: `pnm_uploaded_raw` (uploaded file)
- If neither exists, treat as missing file (404)

## 12. Workflows

### 12.1 Upload Flow

```mermaid
flowchart TD
    A[Client POST /upload] --> B[Write file to artifact store root]
    B --> C[Parse PNM header to find file_type and mac_address]
    C --> D[Upsert system_description_dim (or UNKNOWN)]
    D --> E[Upsert device_details]
    E --> F[Insert transaction_records]
    F --> G[Insert file_artifacts (sha256, size_bytes)]
    G --> H[Insert transaction_artifacts role=pnm_uploaded_raw]
    H --> I[Return transaction_id + filename + mac]
```

### 12.2 Download By Transaction ID

```mermaid
flowchart TD
    A[Client GET /download/transactionID/{transaction_id}] --> B[Select artifact by role pnm_raw or pnm_uploaded_raw]
    B --> C[Resolve absolute path from app_root + store_root + relative_path]
    C --> D{File exists?}
    D -->|Yes| E[Return FileResponse]
    D -->|No| F[404 File not found on disk]
```

### 12.3 Search Files By MAC

```mermaid
flowchart TD
    A[Client GET /searchFiles/{mac}] --> B[Select transaction_records where mac_address = mac]
    B --> C[Join device_details + system_description_dim]
    C --> D[Return list of FileEntry objects]
```

### 12.4 Download By MAC (ZIP)

```mermaid
flowchart TD
    A[Client GET /download/macAddress/{mac}] --> B[List transactions for mac]
    B --> C[Resolve artifact path for each tx]
    C --> D[Zip existing files]
    D --> E{Any files?}
    E -->|Yes| F[Return zip FileResponse]
    E -->|No| G[404 No files on disk]
```

### 12.5 Download By Operation ID (ZIP)

```mermaid
flowchart TD
    A[Client GET /download/operationID/{op_id}] --> B[Resolve op_id -> capture_group_id]
    B --> C[Get ordered tx list for group]
    C --> D[Resolve artifact path for each tx]
    D --> E[Zip existing files]
    E --> F[Return zip FileResponse]
```

## 13. Documentation And Tooling Updates

### 13.1 Remove Ledger JSON Design From Docs

Documentation changes required (planned, not yet complete):

- Remove or clearly mark deprecated any documentation that describes JSON ledger persistence as the design
- When the DB becomes authoritative (Phase 3+), update file manager docs to state: transactions capture groups operations are DB-backed; binaries remain on disk
- Update any docs that still imply JSON ledger authority for transaction/group/operation metadata
- Ensure examples and diagrams in docs reflect DB-backed persistence and artifact linkage

### 13.2 Add Mermaid Support To MkDocs And pyproject

Your docs now include Mermaid diagrams. Ensure the docs build supports Mermaid.

Implementation expectations:

- Add Mermaid support in your MkDocs configuration (Material approach is typical):
  - enable `pymdownx.superfences` with mermaid fences, and or
  - add a Mermaid plugin appropriate for your MkDocs stack
- Add the required docs dependency to `pyproject.toml` so `pip install .[docs]` enables Mermaid rendering

Candidate dependency (Codex must verify what your docs stack already uses):

- `mkdocs-mermaid2-plugin`

If your current docs stack already supports Mermaid via existing extensions, treat this as a configuration-only change and do not add redundant dependencies.

## 14. Migration Strategy

### 14.1 Cutover Philosophy

- Introduce schema + DB API first (SQLite path fully testable)
- Migrate write paths to DB, then migrate read paths used by endpoints
- Remove JSON ledger code after DB-backed implementation is verified by tests

Schema versioning posture:

- The initial DB-backed release is `schema_meta.schema_version = 1`.
- PyPNM is permitted to perform idempotent initialization (create tables, seed rows) but is not permitted to perform
  destructive migrations at runtime.
- If a future schema change is required, it must be implemented as an explicit migration step (CLI tool or install-time
  action) with a clear upgrade path and release notes.

### 14.2 Legacy Ledger Data

If you want to preserve legacy ledger data:

- Provide an optional one-time migrator tool that reads old JSON ledgers and inserts DB rows
- Keep it out of normal runtime flow
- Do not ship any populated DB in releases

If you do not need legacy migration, remove the ledgers and start fresh for new installs.

### 14.3 Implementation Milestones And Cutover Moment

Milestone mapping to the burndown:

- Phase 1: Installer/config contract is complete (backend selection, template keys, settings accessors).
- Phase 2: DB abstraction exists and schema init is idempotent for SQLite and wired for Postgres.
- Phase 3: Transactions write and read paths are DB-backed (ledger is no longer authoritative for transactions).
- Phase 4: Capture group and operation persistence is DB-backed (ledger group and operation files are no longer authoritative).
- Phase 5: Artifact linkage exists and file resolution is DB-driven (DB becomes authoritative for locating binaries).
- Phase 6: Ledger JSON code paths and config keys are removed and docs are updated accordingly.

Cutover definition (authoritative):

- PyPNM is considered “DB-only” only after Phase 3 through Phase 6 are complete.
- Until then, any DB work is preparatory and must not introduce behavior that depends on ledgers being present, except for optional offline migration tooling.

## 15. Testing Requirements

- SQLite: unit tests must validate schema init and CRUD without external services
- Postgres: integration is optional, but code paths must be wired and guarded
- Endpoint-level tests (FastAPI TestClient) must validate that the file manager endpoints resolve transactions to paths
  through DB-backed repositories (no JSON file reads)
- Tests must not require live SNMP or CMTS access
- Clean up any pytest coverage that was explicitly validating the JSON-ledger persistence model

### 15.1 CI And GitHub Workflow Considerations

CI contract:

- SQLite must run in all CI jobs (no external dependencies, deterministic).
- Postgres integration must be supported by CI when enabled by the project (recommended once Postgres backend is implemented):
  - a GitHub Actions job using a Postgres service container
  - schema init performed as part of the test setup
  - DSN passed via environment variables (no committed secrets)

Recommended CI Postgres service defaults:

- `POSTGRES_USER=pypnm`
- `POSTGRES_PASSWORD=pypnm`
- `POSTGRES_DB=pypnm`

Recommended DSN injection:

- `PYPNM_DB_POSTGRES_DSN=postgresql://pypnm:pypnm@localhost:5432/pypnm`

Minimum CI validation expectations:

- Schema init applies cleanly and seeds `schema_meta` + `UNKNOWN` sysDescr + default artifact store.
- A minimal CRUD test suite passes for Postgres (create transaction, link artifact, resolve path).
- Endpoint-level tests continue to use SQLite by default unless an explicit Postgres job is running.

## 16. Concurrency Model And Backend Guidance

### 16.1 SQLite Concurrency Limits

SQLite is appropriate for:

- Standalone PyPNM usage
- Lab environments
- Small deployments with limited concurrent writes

Operational considerations:

- SQLite is single-writer (concurrent reads are fine, concurrent writes serialize).
- Multi-process deployments (multiple Uvicorn workers) increase contention risk.
- For best behavior, enable WAL mode and set a reasonable busy timeout in the SQLite connection layer.
- For containers: SQLite requires a persistent volume mount and is not suitable for horizontal scaling with multiple replicas
  writing to the same DB file.
- SQLite must be treated as a single-writer backend when PyPNM is deployed as a service.

### 16.2 PostgreSQL Recommendation Guidance

Postgres is recommended for:

- Production deployments with high concurrency
- Any deployment where PyPNM-CMTS runs as a service with multiple workers and frequent reads writes
- Scenarios where multiple PyPNM processes (or containers) may touch the same persistence layer

Guidance statement to include in docs:

- For PyPNM standalone use, SQLite is fine and is the default for minimal-risk installs.
- For PyPNM-CMTS or any multi-worker service mode, Postgres is recommended.

## 17. Appendix A: Mermaid ER Diagram

```mermaid
erDiagram
    SCHEMA_META {
        INT        schema_meta_id PK
        INT        schema_version
        BIGINT     applied_epoch
    }

    SYSTEM_DESCRIPTION_DIM {
        BIGINT     sysdescr_id PK
        TEXT       hw_rev
        TEXT       vendor
        TEXT       bootr
        TEXT       sw_rev
        TEXT       model
        JSON        sysdescr_json
        TEXT       sysdescr_hash UK
        BOOLEAN    is_unknown
        BIGINT     created_epoch
    }

    DEVICE_DETAILS {
        BIGINT     device_detail_id PK
        BIGINT     sysdescr_id FK
        JSON       device_details_json
        TEXT       device_details_hash UK
        BIGINT     created_epoch
    }

    TRANSACTION_RECORDS {
        TEXT       transaction_id PK
        BIGINT     timestamp_epoch
        TEXT       mac_address
        TEXT       pnm_test_type
        TEXT       filename
        BIGINT     device_detail_id FK
        BIGINT     created_epoch
    }

    CAPTURE_GROUPS {
        TEXT       capture_group_id PK
        BIGINT     created_epoch
    }

    CAPTURE_GROUP_TRANSACTIONS {
        BIGINT     capture_group_transaction_id PK
        TEXT       capture_group_id FK
        TEXT       transaction_id FK
        INT        position
        BIGINT     added_epoch
    }

    OPERATION_CAPTURES {
        TEXT       operation_id PK
        TEXT       capture_group_id FK
        BIGINT     created_epoch
    }

    ARTIFACT_STORES {
        BIGINT     store_id PK
        TEXT       store_name UK
        TEXT       root_path
        BIGINT     created_epoch
    }

    FILE_ARTIFACTS {
        BIGINT     artifact_id PK
        BIGINT     store_id FK
        TEXT       relative_path
        TEXT       filename
        TEXT       sha256 UK
        BIGINT     size_bytes
        TEXT       mime_type
        BIGINT     created_epoch
    }

    TRANSACTION_ARTIFACTS {
        BIGINT     transaction_artifact_id PK
        TEXT       transaction_id FK
        BIGINT     artifact_id FK
        TEXT       role
        BIGINT     created_epoch
    }

    SYSTEM_DESCRIPTION_DIM ||--o{ DEVICE_DETAILS : "1_to_many"
    DEVICE_DETAILS        ||--o{ TRANSACTION_RECORDS : "1_to_many"

    CAPTURE_GROUPS        ||--o{ CAPTURE_GROUP_TRANSACTIONS : "1_to_many"
    TRANSACTION_RECORDS   ||--o{ CAPTURE_GROUP_TRANSACTIONS : "1_to_many"
    CAPTURE_GROUPS        ||--o{ OPERATION_CAPTURES : "1_to_many"

    ARTIFACT_STORES       ||--o{ FILE_ARTIFACTS : "1_to_many"
    FILE_ARTIFACTS        ||--o{ TRANSACTION_ARTIFACTS : "1_to_many"
    TRANSACTION_RECORDS   ||--o{ TRANSACTION_ARTIFACTS : "1_to_many"
```

## 18. Appendix B: PostgreSQL DDL

Authoritative DDL is maintained in the schema_*.sql files.

```sql
BEGIN;

CREATE TABLE IF NOT EXISTS schema_meta (
    schema_meta_id  SMALLINT PRIMARY KEY,
    schema_version  INTEGER  NOT NULL,
    applied_epoch   BIGINT   NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),

    CONSTRAINT ck_schema_meta_single_row CHECK (schema_meta_id = 1),
    CONSTRAINT ck_schema_version_positive CHECK (schema_version >= 1)
);

INSERT INTO schema_meta (schema_meta_id, schema_version)
VALUES (1, 1)
ON CONFLICT (schema_meta_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS system_description_dim (
    sysdescr_id    BIGSERIAL PRIMARY KEY,
    hw_rev         TEXT      NOT NULL,
    vendor         TEXT      NOT NULL,
    bootr          TEXT      NOT NULL,
    sw_rev         TEXT      NOT NULL,
    model          TEXT      NOT NULL,
    sysdescr_json  JSONB     NOT NULL DEFAULT '{}'::jsonb,
    sysdescr_hash  TEXT      NOT NULL UNIQUE,
    is_unknown     BOOLEAN   NOT NULL DEFAULT FALSE,
    created_epoch  BIGINT    NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),

    CONSTRAINT ck_sysdescr_unknown_consistency CHECK (
        (is_unknown = TRUE  AND sysdescr_json = '{}'::jsonb AND hw_rev = 'UNKNOWN' AND vendor = 'UNKNOWN' AND bootr = 'UNKNOWN' AND sw_rev = 'UNKNOWN' AND model = 'UNKNOWN')
     OR (is_unknown = FALSE AND sysdescr_json <> '{}'::jsonb)
    )
);

CREATE INDEX IF NOT EXISTS idx_system_description_hash
ON system_description_dim (sysdescr_hash);

CREATE TABLE IF NOT EXISTS device_details (
    device_detail_id     BIGSERIAL PRIMARY KEY,
    sysdescr_id          BIGINT   NOT NULL REFERENCES system_description_dim(sysdescr_id) ON DELETE RESTRICT,
    device_details_json  JSONB    NOT NULL DEFAULT '{}'::jsonb,
    device_details_hash  TEXT     NOT NULL UNIQUE,
    created_epoch        BIGINT   NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
);

CREATE INDEX IF NOT EXISTS idx_device_details_sysdescr_id
ON device_details (sysdescr_id);

CREATE INDEX IF NOT EXISTS idx_device_details_hash
ON device_details (device_details_hash);

CREATE TABLE IF NOT EXISTS transaction_records (
    transaction_id    TEXT    PRIMARY KEY,
    timestamp_epoch   BIGINT  NOT NULL,
    mac_address       TEXT    NOT NULL,
    pnm_test_type     TEXT    NOT NULL,
    filename          TEXT    NOT NULL,
    device_detail_id  BIGINT  NOT NULL REFERENCES device_details(device_detail_id) ON DELETE RESTRICT,
    created_epoch     BIGINT  NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),

    CONSTRAINT ck_transaction_mac_format CHECK (
        mac_address ~* '^([0-9a-f]{2}:){5}[0-9a-f]{2}$'
    )
);

CREATE INDEX IF NOT EXISTS idx_transaction_timestamp_epoch
ON transaction_records (timestamp_epoch);

CREATE INDEX IF NOT EXISTS idx_transaction_mac_address
ON transaction_records (mac_address);

CREATE INDEX IF NOT EXISTS idx_transaction_pnm_test_type
ON transaction_records (pnm_test_type);

CREATE INDEX IF NOT EXISTS idx_transaction_device_detail_id
ON transaction_records (device_detail_id);

CREATE TABLE IF NOT EXISTS capture_groups (
    capture_group_id  TEXT   PRIMARY KEY,
    created_epoch     BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
);

CREATE INDEX IF NOT EXISTS idx_capture_groups_created_epoch
ON capture_groups (created_epoch);

CREATE TABLE IF NOT EXISTS capture_group_transactions (
    capture_group_transaction_id  BIGSERIAL PRIMARY KEY,
    capture_group_id              TEXT     NOT NULL REFERENCES capture_groups(capture_group_id) ON DELETE CASCADE,
    transaction_id                TEXT     NOT NULL REFERENCES transaction_records(transaction_id) ON DELETE CASCADE,
    position                      INTEGER  NOT NULL,
    added_epoch                   BIGINT   NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),

    CONSTRAINT uq_capture_group_position UNIQUE (capture_group_id, position),
    CONSTRAINT uq_capture_group_transaction UNIQUE (capture_group_id, transaction_id)
);

CREATE INDEX IF NOT EXISTS idx_cg_tx_capture_group_id
ON capture_group_transactions (capture_group_id);

CREATE INDEX IF NOT EXISTS idx_cg_tx_capture_group_position
ON capture_group_transactions (capture_group_id, position);

CREATE INDEX IF NOT EXISTS idx_cg_tx_transaction_id
ON capture_group_transactions (transaction_id);

CREATE TABLE IF NOT EXISTS operation_captures (
    operation_id     TEXT   PRIMARY KEY,
    capture_group_id TEXT   NOT NULL REFERENCES capture_groups(capture_group_id) ON DELETE RESTRICT,
    created_epoch    BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
);

CREATE INDEX IF NOT EXISTS idx_operation_captures_capture_group_id
ON operation_captures (capture_group_id);

CREATE INDEX IF NOT EXISTS idx_operation_captures_operation_id
ON operation_captures (operation_id);

CREATE TABLE IF NOT EXISTS artifact_stores (
    store_id      BIGSERIAL PRIMARY KEY,
    store_name    TEXT      NOT NULL UNIQUE,
    root_path     TEXT      NOT NULL,
    created_epoch BIGINT    NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
);

CREATE TABLE IF NOT EXISTS file_artifacts (
    artifact_id    BIGSERIAL PRIMARY KEY,
    store_id       BIGINT   NOT NULL REFERENCES artifact_stores(store_id) ON DELETE RESTRICT,
    relative_path  TEXT     NOT NULL,
    filename       TEXT     NOT NULL,
    sha256         TEXT     NOT NULL,
    size_bytes     BIGINT   NOT NULL DEFAULT 0,
    mime_type      TEXT     NOT NULL DEFAULT '',
    created_epoch  BIGINT   NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),

    CONSTRAINT uq_artifact_store_path UNIQUE (store_id, relative_path),
    CONSTRAINT uq_artifact_sha256 UNIQUE (sha256)
);

CREATE INDEX IF NOT EXISTS idx_file_artifacts_store_id
ON file_artifacts (store_id);

CREATE INDEX IF NOT EXISTS idx_file_artifacts_sha256
ON file_artifacts (sha256);

CREATE TABLE IF NOT EXISTS transaction_artifacts (
    transaction_artifact_id  BIGSERIAL PRIMARY KEY,
    transaction_id           TEXT    NOT NULL REFERENCES transaction_records(transaction_id) ON DELETE CASCADE,
    artifact_id              BIGINT  NOT NULL REFERENCES file_artifacts(artifact_id) ON DELETE RESTRICT,
    role                     TEXT    NOT NULL,
    created_epoch            BIGINT   NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),

    CONSTRAINT uq_tx_role UNIQUE (transaction_id, role),
    CONSTRAINT uq_tx_artifact UNIQUE (transaction_id, artifact_id)
);

CREATE INDEX IF NOT EXISTS idx_transaction_artifacts_tx
ON transaction_artifacts (transaction_id);

CREATE INDEX IF NOT EXISTS idx_transaction_artifacts_artifact
ON transaction_artifacts (artifact_id);

INSERT INTO system_description_dim (
    hw_rev, vendor, bootr, sw_rev, model,
    sysdescr_json, sysdescr_hash, is_unknown
)
VALUES (
    'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN',
    '{}'::jsonb, 'UNKNOWN', TRUE
)
ON CONFLICT (sysdescr_hash) DO NOTHING;

COMMIT;
```

## 19. Appendix C: SQLite DDL

Authoritative DDL is maintained in the schema_*.sql files.

```sql
PRAGMA foreign_keys = ON;

BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS schema_meta (
    schema_meta_id  INTEGER PRIMARY KEY,
    schema_version  INTEGER NOT NULL,
    applied_epoch   INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),

    CHECK (schema_meta_id = 1),
    CHECK (schema_version >= 1)
);

INSERT OR IGNORE INTO schema_meta (schema_meta_id, schema_version)
VALUES (1, 1);

CREATE TABLE IF NOT EXISTS system_description_dim (
    sysdescr_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    hw_rev         TEXT    NOT NULL,
    vendor         TEXT    NOT NULL,
    bootr          TEXT    NOT NULL,
    sw_rev         TEXT    NOT NULL,
    model          TEXT    NOT NULL,
    sysdescr_json  TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(sysdescr_json)),
    sysdescr_hash  TEXT    NOT NULL UNIQUE,
    is_unknown     INTEGER NOT NULL DEFAULT 0 CHECK (is_unknown IN (0, 1)),
    created_epoch  INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),

    CHECK (
        (is_unknown = 1 AND sysdescr_json = '{}' AND hw_rev = 'UNKNOWN' AND vendor = 'UNKNOWN' AND bootr = 'UNKNOWN' AND sw_rev = 'UNKNOWN' AND model = 'UNKNOWN')
     OR (is_unknown = 0 AND sysdescr_json <> '{}')
    )
);

CREATE INDEX IF NOT EXISTS idx_system_description_hash
ON system_description_dim (sysdescr_hash);

CREATE TABLE IF NOT EXISTS device_details (
    device_detail_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    sysdescr_id          INTEGER NOT NULL REFERENCES system_description_dim(sysdescr_id) ON DELETE RESTRICT,
    device_details_json  TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(device_details_json)),
    device_details_hash  TEXT    NOT NULL UNIQUE,
    created_epoch        INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER))
);

CREATE INDEX IF NOT EXISTS idx_device_details_sysdescr_id
ON device_details (sysdescr_id);

CREATE INDEX IF NOT EXISTS idx_device_details_hash
ON device_details (device_details_hash);

CREATE TABLE IF NOT EXISTS transaction_records (
    transaction_id    TEXT    PRIMARY KEY,
    timestamp_epoch   INTEGER NOT NULL,
    mac_address       TEXT    NOT NULL,
    pnm_test_type     TEXT    NOT NULL,
    filename          TEXT    NOT NULL,
    device_detail_id  INTEGER NOT NULL REFERENCES device_details(device_detail_id) ON DELETE RESTRICT,
    created_epoch     INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),

    CHECK (
        length(mac_address) = 17
        AND mac_address GLOB
            '[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]'
    )
);

CREATE INDEX IF NOT EXISTS idx_transaction_timestamp_epoch
ON transaction_records (timestamp_epoch);

CREATE INDEX IF NOT EXISTS idx_transaction_mac_address
ON transaction_records (mac_address);

CREATE INDEX IF NOT EXISTS idx_transaction_pnm_test_type
ON transaction_records (pnm_test_type);

CREATE INDEX IF NOT EXISTS idx_transaction_device_detail_id
ON transaction_records (device_detail_id);

CREATE TABLE IF NOT EXISTS capture_groups (
    capture_group_id  TEXT    PRIMARY KEY,
    created_epoch     INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER))
);

CREATE INDEX IF NOT EXISTS idx_capture_groups_created_epoch
ON capture_groups (created_epoch);

CREATE TABLE IF NOT EXISTS capture_group_transactions (
    capture_group_transaction_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_group_id              TEXT    NOT NULL REFERENCES capture_groups(capture_group_id) ON DELETE CASCADE,
    transaction_id                TEXT    NOT NULL REFERENCES transaction_records(transaction_id) ON DELETE CASCADE,
    position                      INTEGER NOT NULL,
    added_epoch                   INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),

    UNIQUE (capture_group_id, position),
    UNIQUE (capture_group_id, transaction_id)
);

CREATE INDEX IF NOT EXISTS idx_cg_tx_capture_group_id
ON capture_group_transactions (capture_group_id);

CREATE INDEX IF NOT EXISTS idx_cg_tx_capture_group_position
ON capture_group_transactions (capture_group_id, position);

CREATE INDEX IF NOT EXISTS idx_cg_tx_transaction_id
ON capture_group_transactions (transaction_id);

CREATE TABLE IF NOT EXISTS operation_captures (
    operation_id     TEXT    PRIMARY KEY,
    capture_group_id TEXT    NOT NULL REFERENCES capture_groups(capture_group_id) ON DELETE RESTRICT,
    created_epoch    INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER))
);

CREATE INDEX IF NOT EXISTS idx_operation_captures_capture_group_id
ON operation_captures (capture_group_id);

CREATE INDEX IF NOT EXISTS idx_operation_captures_operation_id
ON operation_captures (operation_id);

CREATE TABLE IF NOT EXISTS artifact_stores (
    store_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    store_name    TEXT    NOT NULL UNIQUE,
    root_path     TEXT    NOT NULL,
    created_epoch INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER))
);

CREATE TABLE IF NOT EXISTS file_artifacts (
    artifact_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    store_id       INTEGER NOT NULL REFERENCES artifact_stores(store_id) ON DELETE RESTRICT,
    relative_path  TEXT    NOT NULL,
    filename       TEXT    NOT NULL,
    sha256         TEXT    NOT NULL,
    size_bytes     INTEGER NOT NULL DEFAULT 0,
    mime_type      TEXT    NOT NULL DEFAULT '',
    created_epoch  INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),

    UNIQUE (store_id, relative_path),
    UNIQUE (sha256)
);

CREATE INDEX IF NOT EXISTS idx_file_artifacts_store_id
ON file_artifacts (store_id);

CREATE INDEX IF NOT EXISTS idx_file_artifacts_sha256
ON file_artifacts (sha256);

CREATE TABLE IF NOT EXISTS transaction_artifacts (
    transaction_artifact_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    transaction_id           TEXT    NOT NULL REFERENCES transaction_records(transaction_id) ON DELETE CASCADE,
    artifact_id              INTEGER NOT NULL REFERENCES file_artifacts(artifact_id) ON DELETE RESTRICT,
    role                     TEXT    NOT NULL,
    created_epoch            INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),

    UNIQUE (transaction_id, role),
    UNIQUE (transaction_id, artifact_id)
);

CREATE INDEX IF NOT EXISTS idx_transaction_artifacts_tx
ON transaction_artifacts (transaction_id);

CREATE INDEX IF NOT EXISTS idx_transaction_artifacts_artifact
ON transaction_artifacts (artifact_id);

INSERT OR IGNORE INTO system_description_dim (
    hw_rev, vendor, bootr, sw_rev, model,
    sysdescr_json, sysdescr_hash, is_unknown
)
VALUES (
    'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN',
    '{}', 'UNKNOWN', 1
);

COMMIT;
```

# FILE: docs/design/db/bootstrap-contract.md
# DB Bootstrap Contract (Implemented)

## Purpose

This document describes the implemented DB bootstrap contract for Phase 2. It covers adapter lifecycle, backend
selection precedence, and the current schema scope (bootstrap-only).

Implemented vs planned:

- Implemented: adapter lifecycle and schema bootstrap readiness checks.
- Planned: full schema and migrations for transactions, capture groups, operations, and artifacts.

## Adapter Contract

Adapters implement a minimal lifecycle interface:

- connect
- apply_schema
- healthcheck
- close

Adapters must remain policy-neutral and focused on bootstrap readiness only.

## Backend Selection Precedence

Backend selection is deterministic and follows this order:

1) Environment overrides (`PYPNM_DB_BACKEND`, `PYPNM_DB_POSTGRES_DSN`)
2) Configuration file values (`Database.backend`, `Database.postgres.dsn`)
3) Defaults (SQLite)

If Postgres is selected but the DSN is invalid or blank, DatabaseManager selection falls back to SQLite without
raising from get_adapter. Direct configuration validation may still raise ValidationError. The schema manager is
fail-fast when backend is postgres and the DSN is invalid or blank.

## Schema Bootstrap Scope

The bootstrap schema is limited to `schema_meta`:

- `apply_schema` ensures `schema_meta` exists and is seeded once.
- No other tables are created in this phase.
- Runtime does not perform destructive migrations.
- Schema DDL assets are loaded from package data via importlib.resources; docs copies are reference-only.

Postgres driver support is optional and provided by the `postgres` extra (install with `pypnm-docsis[postgres]`).

## Lifecycle Usage

`initialize()` performs connect, applies the bootstrap schema, and checks health. `close()` shuts down the adapter and
clears the cached instance so selection can be re-evaluated.

## Mermaid Support

Documentation builds expect Mermaid diagrams to render through the MkDocs Material pipeline with Mermaid JS enabled.
