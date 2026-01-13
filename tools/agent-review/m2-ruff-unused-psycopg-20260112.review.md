## Agent Review Bundle Summary
- Goal: Resolve ruff unused import in Postgres-gated schema test.
- Changes: Swapped psycopg import check to importlib.util.find_spec to avoid unused import.
- Files: tests/test_db_schema_manager.py
- Tests: Not run (user ran ruff check --fix and reported error).
- Notes: None.

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


def test_postgres_capture_group_indexes_optional() -> None:
    dsn = os.environ.get("PYPNM_DB_POSTGRES_DSN", "")
    if not dsn:
        pytest.skip("PYPNM_DB_POSTGRES_DSN not set")
    try:
        from importlib.util import find_spec
    except ImportError:
        pytest.skip("importlib.util not available")
    if find_spec("psycopg") is None:
        pytest.skip("psycopg not installed")

    postgres_dsn = cast(DatabaseDsn, dsn)
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
