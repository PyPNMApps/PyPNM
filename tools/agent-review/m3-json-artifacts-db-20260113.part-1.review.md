## Agent Review Bundle Summary
- Goal: Remove JSON ledger references, track JSON exports in DB, and add deprecated config warnings while keeping runtime DB-backed behavior.
- Changes: Seeded a JSON artifact store, added JSON export artifact registration, updated JsonTransactionDb to register artifacts in DB, added deprecation warnings for legacy keys, and linked JSON exports to transactions where available.
- Files: src/pypnm/lib/db/db_schema_manager.py; src/pypnm/lib/db/artifact_repository.py; src/pypnm/lib/db/json_transaction.py; src/pypnm/config/system_config_settings.py; src/pypnm/api/routes/advance/analysis/report/multi_analysis_rpt.py.
- Tests: python3 -m compileall src; ruff check src; ruff format --check .; pytest -q (596 passed, 9 skipped).
- Notes: Postgres-gated tests skipped (PYPNM_DB_POSTGRES_DSN unset) and PNM_CM_IT integration tests skipped; initial pytest run timed out at 10s and was re-run with a longer timeout.

# FILE: src/pypnm/lib/db/db_schema_manager.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING, TypeAlias

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.model.db_health_model import DatabaseHealthModel
from pypnm.lib.types import DatabaseBackend, DatabaseDsn, DatabasePath

if TYPE_CHECKING:
    from psycopg import Connection as PsycopgConnection
else:
    PsycopgConnection = object

DbConnection: TypeAlias = sqlite3.Connection | PsycopgConnection

SCHEMA_VERSION: int = 1
SCHEMA_META_ID: int = 1
UNKNOWN_SYSDESCR_HASH: str = "UNKNOWN"
DEFAULT_ARTIFACT_STORE_NAME: str = "default"
JSON_ARTIFACT_STORE_NAME: str = "json"
DEFAULT_ARTIFACT_STORE_ROOT: str = ".data/pnm"
SQLITE_JOURNAL_MODE: str = "WAL"
SQLITE_BUSY_TIMEOUT_MS: int = 5000

BEGIN_STATEMENT: str = "BEGIN"
COMMIT_STATEMENT: str = "COMMIT"

_SQLITE_DDL_FILE: str = "schema_sqlite.sql"
_POSTGRES_DDL_FILE: str = "schema_postgres.sql"

_REQUIRED_TABLES: tuple[str, ...] = (
    "schema_meta",
    "system_description_dim",
    "device_details",
    "transaction_records",
    "capture_groups",
    "capture_group_transactions",
    "operation_captures",
    "session_groups",
    "session_group_transactions",
    "artifact_stores",
    "file_artifacts",
    "transaction_artifacts",
)


class DatabaseSchemaManager:
    """
    Initialize and validate the DB schema for the selected backend.
    """

    def __init__(
        self,
        backend: DatabaseBackend,
        sqlite_path: DatabasePath,
        postgres_dsn: DatabaseDsn,
    ) -> None:
        self._backend = backend
        self._sqlite_path = sqlite_path
        self._postgres_dsn = postgres_dsn
        self.logger = logging.getLogger(f"{self.__class__.__name__}")

    @classmethod
    def from_system_config(cls) -> DatabaseSchemaManager:
        """
        Build a schema manager using SystemConfigSettings.
        """
        return cls(
            SystemConfigSettings.database_backend(),
            SystemConfigSettings.database_sqlite_path(),
            SystemConfigSettings.database_postgres_dsn(),
        )

    @classmethod
    def from_overrides(
        cls,
        backend: DatabaseBackend,
        sqlite_path: DatabasePath,
        postgres_dsn: DatabaseDsn,
    ) -> DatabaseSchemaManager:
        """
        Build a schema manager using explicit backend overrides.
        """
        return cls(backend, sqlite_path, postgres_dsn)

    def connect(self) -> DbConnection:
        """
        Open a DB connection for the configured backend.
        """
        match self._backend:
            case DatabaseBackend.SQLITE:
                return self._connect_sqlite()
            case DatabaseBackend.POSTGRES:
                return self._connect_postgres()
        raise ValueError(f"Unsupported Database backend: {self._backend}")

    def initialize_schema(self) -> None:
        """
        Apply schema DDL and seed required rows idempotently.
        """
        connection = self.connect()
        try:
            self._apply_schema(connection)
            self._seed_unknown_sysdescr(connection)
            self._seed_default_artifact_store(connection)
            self._seed_json_artifact_store(connection)
            self._ensure_schema_version(connection)
        finally:
            connection.close()

    def health_check(self) -> DatabaseHealthModel:
        """
        Run a schema health check and return a diagnostic model.
        """
        connection = self.connect()
        try:
            table_names = self._fetch_table_names(connection)
            missing_tables = [
                table for table in _REQUIRED_TABLES if table not in table_names
            ]
            schema_version = self._fetch_schema_version(connection)
            unknown_sysdescr_present = self._has_unknown_sysdescr(connection)
            default_store_present = self._has_default_artifact_store(connection)
            ok = (
                not missing_tables
                and schema_version == SCHEMA_VERSION
                and unknown_sysdescr_present
                and default_store_present
            )
            details = self._health_details(
                schema_version,
                missing_tables,
                unknown_sysdescr_present,
                default_store_present,
            )
            return DatabaseHealthModel(
                backend=self._backend,
                schema_version=schema_version,
                missing_tables=missing_tables,
                unknown_sysdescr_present=unknown_sysdescr_present,
                default_artifact_store_present=default_store_present,
                ok=ok,
                details=details,
            )
        finally:
            connection.close()

    def _connect_sqlite(self) -> sqlite3.Connection:
        db_path = self._resolve_sqlite_db_path()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(db_path)
        connection.execute(f"PRAGMA journal_mode = {SQLITE_JOURNAL_MODE};")
        connection.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS};")
        connection.execute("PRAGMA foreign_keys = ON;")
        return connection

    def _connect_postgres(self) -> PsycopgConnection:
        dsn = str(self._postgres_dsn).strip()
        if not dsn:
            raise ValueError("Database.postgres.dsn cannot be blank")
        try:
            import psycopg
        except ImportError as exc:
            raise RuntimeError(
                "psycopg is required for Postgres backend support"
            ) from exc
        return psycopg.connect(dsn)

    def _apply_schema(self, connection: DbConnection) -> None:
        ddl_sql = self._load_schema_sql()
        match self._backend:
            case DatabaseBackend.SQLITE:
                sqlite_conn = connection
                sqlite_conn.executescript(ddl_sql)
                sqlite_conn.commit()
            case DatabaseBackend.POSTGRES:
                pg_conn = connection
                statements = self._split_sql_statements(ddl_sql)
                current_idx = 0
                try:
                    with pg_conn.cursor() as cursor:
                        for idx, statement in enumerate(statements, start=1):
                            current_idx = idx
                            if self._should_skip_statement(statement):
                                continue
                            cursor.execute(statement)
                    pg_conn.commit()
                except Exception as exc:
                    pg_conn.rollback()
                    raise RuntimeError(
                        f"Failed to apply Postgres schema at statement {current_idx}"
                    ) from exc

    def _seed_unknown_sysdescr(self, connection: DbConnection) -> None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                sqlite_conn = connection
                sqlite_conn.execute(
                    """
                    INSERT OR IGNORE INTO system_description_dim (
                        hw_rev, vendor, bootr, sw_rev, model,
                        sysdescr_json, sysdescr_hash, is_unknown
                    )
                    VALUES (
                        'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN',
                        '{}', ?, 1
                    );
                    """,
                    (UNKNOWN_SYSDESCR_HASH,),
                )
                sqlite_conn.commit()
            case DatabaseBackend.POSTGRES:
                pg_conn = connection
                with pg_conn.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO system_description_dim (
                            hw_rev, vendor, bootr, sw_rev, model,
                            sysdescr_json, sysdescr_hash, is_unknown
                        )
                        VALUES (
                            'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN',
                            '{}'::jsonb, %s, TRUE
                        )
                        ON CONFLICT (sysdescr_hash) DO NOTHING;
                        """,
                        (UNKNOWN_SYSDESCR_HASH,),
                    )
                pg_conn.commit()

    def _seed_default_artifact_store(self, connection: DbConnection) -> None:
        root_path = self._normalize_root_path(SystemConfigSettings.pnm_dir())
        match self._backend:
            case DatabaseBackend.SQLITE:
                sqlite_conn = connection
                sqlite_conn.execute(
                    """
                    INSERT OR IGNORE INTO artifact_stores (store_name, root_path)
                    VALUES (?, ?);
                    """,
                    (DEFAULT_ARTIFACT_STORE_NAME, root_path),
                )
                sqlite_conn.commit()
            case DatabaseBackend.POSTGRES:
                pg_conn = connection
                with pg_conn.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO artifact_stores (store_name, root_path)
                        VALUES (%s, %s)
                        ON CONFLICT (store_name) DO NOTHING;
                        """,
                        (DEFAULT_ARTIFACT_STORE_NAME, root_path),
                    )
                pg_conn.commit()

    def _seed_json_artifact_store(self, connection: DbConnection) -> None:
        root_path = self._normalize_root_path(SystemConfigSettings.json_dir())
        match self._backend:
            case DatabaseBackend.SQLITE:
                sqlite_conn = connection
                sqlite_conn.execute(
                    """
                    INSERT OR IGNORE INTO artifact_stores (store_name, root_path)
                    VALUES (?, ?);
                    """,
                    (JSON_ARTIFACT_STORE_NAME, root_path),
                )
                sqlite_conn.commit()
            case DatabaseBackend.POSTGRES:
                pg_conn = connection
                with pg_conn.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO artifact_stores (store_name, root_path)
                        VALUES (%s, %s)
                        ON CONFLICT (store_name) DO NOTHING;
                        """,
                        (JSON_ARTIFACT_STORE_NAME, root_path),
                    )
                pg_conn.commit()

    def _ensure_schema_version(self, connection: DbConnection) -> None:
        schema_version = self._fetch_schema_version(connection)
        if schema_version != SCHEMA_VERSION:
            raise RuntimeError(
                f"Unsupported schema_version={schema_version}; expected {SCHEMA_VERSION}"
            )

    def _fetch_table_names(self, connection: DbConnection) -> set[str]:
        match self._backend:
            case DatabaseBackend.SQLITE:
                sqlite_conn = connection
                cursor = sqlite_conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table';"
                )
                return {row[0] for row in cursor.fetchall()}
            case DatabaseBackend.POSTGRES:
                pg_conn = connection
                with pg_conn.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT table_name
                        FROM information_schema.tables
                        WHERE table_schema = 'public';
                        """
                    )
                    return {row[0] for row in cursor.fetchall()}
        return set()

    def _fetch_schema_version(self, connection: DbConnection) -> int:
        match self._backend:
            case DatabaseBackend.SQLITE:
                sqlite_conn = connection
                cursor = sqlite_conn.execute(
                    "SELECT schema_version FROM schema_meta WHERE schema_meta_id = ?;",
                    (SCHEMA_META_ID,),
                )
                row = cursor.fetchone()
                if row:
                    return int(row[0])
            case DatabaseBackend.POSTGRES:
                pg_conn = connection
                with pg_conn.cursor() as cursor:
                    cursor.execute(
                        "SELECT schema_version FROM schema_meta WHERE schema_meta_id = %s;",
                        (SCHEMA_META_ID,),
                    )
                    row = cursor.fetchone()
                    if row:
                        return int(row[0])
        return 0

    def _has_unknown_sysdescr(self, connection: DbConnection) -> bool:
        match self._backend:
            case DatabaseBackend.SQLITE:
                sqlite_conn = connection
                cursor = sqlite_conn.execute(
                    "SELECT 1 FROM system_description_dim WHERE sysdescr_hash = ?;",
                    (UNKNOWN_SYSDESCR_HASH,),
                )
                return cursor.fetchone() is not None
            case DatabaseBackend.POSTGRES:
                pg_conn = connection
                with pg_conn.cursor() as cursor:
                    cursor.execute(
                        "SELECT 1 FROM system_description_dim WHERE sysdescr_hash = %s;",
                        (UNKNOWN_SYSDESCR_HASH,),
                    )
                    return cursor.fetchone() is not None
        return False

    def _has_default_artifact_store(self, connection: DbConnection) -> bool:
        match self._backend:
            case DatabaseBackend.SQLITE:
                sqlite_conn = connection
                cursor = sqlite_conn.execute(
                    "SELECT 1 FROM artifact_stores WHERE store_name = ?;",
                    (DEFAULT_ARTIFACT_STORE_NAME,),
                )
                return cursor.fetchone() is not None
            case DatabaseBackend.POSTGRES:
                pg_conn = connection
                with pg_conn.cursor() as cursor:
                    cursor.execute(
                        "SELECT 1 FROM artifact_stores WHERE store_name = %s;",
                        (DEFAULT_ARTIFACT_STORE_NAME,),
                    )
                    return cursor.fetchone() is not None
        return False

    def _health_details(
        self,
        schema_version: int,
        missing_tables: list[str],
        unknown_sysdescr_present: bool,
        default_store_present: bool,
    ) -> str:
        if missing_tables:
            return f"Missing tables: {', '.join(missing_tables)}"
        if schema_version != SCHEMA_VERSION:
            return f"Schema version mismatch: {schema_version}"
        if not unknown_sysdescr_present:
            return "Missing UNKNOWN sysDescr seed row"
        if not default_store_present:
            return "Missing default artifact store row"
        return "Schema healthy"

    def _resolve_sqlite_db_path(self) -> Path:
        path = Path(str(self._sqlite_path))
        if path.is_absolute():
            return path
        return self._resolve_app_root() / path

    def _normalize_root_path(self, root_path: str) -> str:
        path = Path(root_path)
        if not path.is_absolute():
            return root_path
        app_root = self._resolve_app_root()
        if app_root in path.parents:
            return str(path.relative_to(app_root))
        self.logger.warning(
            "Artifact store root_path is absolute; portable paths are recommended: %s",
            root_path,
        )
        return root_path

    def _load_schema_sql(self) -> str:
        ddl_dir = self._resolve_ddl_dir()
        ddl_file = (
            _SQLITE_DDL_FILE
            if self._backend == DatabaseBackend.SQLITE
            else _POSTGRES_DDL_FILE
        )
        ddl_path = ddl_dir / ddl_file
        return ddl_path.read_text(encoding="utf-8")

    @staticmethod
    def _split_sql_statements(sql: str) -> list[str]:
        statements: list[str] = []
        buffer: list[str] = []
        in_single = False
        in_double = False
        in_line_comment = False
        in_block_comment = False
        dollar_tag: str | None = None

        idx = 0
        length = len(sql)
        while idx < length:
            ch = sql[idx]
            nxt = sql[idx + 1] if idx + 1 < length else ""

            if in_line_comment:
                buffer.append(ch)
                if ch == "\n":
                    in_line_comment = False
                idx += 1
                continue

            if in_block_comment:
                buffer.append(ch)
                if ch == "*" and nxt == "/":
                    buffer.append(nxt)
                    idx += 2
                    in_block_comment = False
                    continue
                idx += 1
                continue

            if dollar_tag is not None:
                if ch == "$" and sql.startswith(dollar_tag, idx):
                    buffer.append(dollar_tag)
                    idx += len(dollar_tag)
                    dollar_tag = None
                    continue
                buffer.append(ch)
                idx += 1
                continue

            if not in_single and not in_double:
                if ch == "-" and nxt == "-":
                    buffer.append(ch)
                    buffer.append(nxt)
                    idx += 2
                    in_line_comment = True
                    continue
                if ch == "/" and nxt == "*":
                    buffer.append(ch)
                    buffer.append(nxt)
                    idx += 2
                    in_block_comment = True
                    continue

            if not in_single and not in_double and ch == "$":
                tag_end = sql.find("$", idx + 1)
                if tag_end != -1:
                    tag = sql[idx : tag_end + 1]
                    if DatabaseSchemaManager._is_valid_dollar_tag(tag):
                        closing_idx = sql.find(tag, tag_end + 1)
                        if closing_idx == -1:
                            buffer.append(ch)
                            idx += 1
                            continue
                        dollar_tag = tag
                        buffer.append(tag)
                        idx = tag_end + 1
                        continue

            if ch == "'" and not in_double:
                if in_single and nxt == "'":
                    buffer.append(ch)
                    buffer.append(nxt)
                    idx += 2
                    continue
                in_single = not in_single
                buffer.append(ch)
                idx += 1
                continue

            if ch == '"' and not in_single:
                in_double = not in_double
                buffer.append(ch)
                idx += 1
                continue

            if ch == ";" and not in_single and not in_double and dollar_tag is None:
                statement = "".join(buffer).strip()
                if statement:
                    statements.append(statement)
                buffer = []
                idx += 1
                continue

            buffer.append(ch)
            idx += 1

        tail = "".join(buffer).strip()
        if tail:
            statements.append(tail)
        return statements

    @staticmethod
    def _should_skip_statement(statement: str) -> bool:
        normalized = " ".join(statement.strip().strip(";").split()).upper()
        return normalized in (
            BEGIN_STATEMENT,
            "BEGIN TRANSACTION",
            COMMIT_STATEMENT,
            "COMMIT WORK",
            "ROLLBACK",
            "ROLLBACK WORK",
        )

    @staticmethod
    def _is_valid_dollar_tag(tag: str) -> bool:
        if len(tag) < 2 or not tag.startswith("$") or not tag.endswith("$"):
            return False
        body = tag[1:-1]
        return all(ch_token.isalnum() or ch_token == "_" for ch_token in body)

    def _resolve_ddl_dir(self) -> Path:
        candidates = [Path(__file__).resolve(), Path.cwd().resolve()]
        for candidate in candidates:
            for parent in [candidate] + list(candidate.parents):
                ddl_dir = parent / "docs" / "design" / "db"
                if ddl_dir.is_dir():
                    return ddl_dir
        raise FileNotFoundError("Unable to locate docs/design/db for DDL assets")

    def _resolve_app_root(self) -> Path:
        cwd = Path.cwd().resolve()
        for parent in [cwd] + list(cwd.parents):
            if (parent / "pyproject.toml").is_file():
                return parent
        return cwd


def initialize_database_schema() -> None:
    """
    Initialize and validate the database schema using system configuration.
    """
    manager = DatabaseSchemaManager.from_system_config()
    manager.initialize_schema()
    health = manager.health_check()
    if not health.ok:
        raise RuntimeError(f"Database schema health check failed: {health.details}")

# FILE: src/pypnm/lib/db/artifact_repository.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from pypnm.lib.db.db_schema_manager import (
    DEFAULT_ARTIFACT_STORE_NAME,
    JSON_ARTIFACT_STORE_NAME,
    DbConnection,
)
from pypnm.lib.db.transaction_repository import _RepositoryBase
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    HashStr,
    TimestampSec,
    TransactionId,
)

ROLE_PNM_RAW: str = "pnm_raw"
ROLE_PNM_UPLOADED_RAW: str = "pnm_uploaded_raw"
ROLE_JSON_EXPORT: str = "json_export"

ROLE_PREFERENCE: tuple[str, str] = (
    ROLE_PNM_RAW,
    ROLE_PNM_UPLOADED_RAW,
)

DEFAULT_MIME_TYPE: str = ""
JSON_EXPORT_MIME_TYPE: str = "application/json"
FILE_HASH_CHUNK_BYTES: int = 1024 * 1024


@dataclass(frozen=True)
class ArtifactStoreRow:
    store_id: int
    root_path: str


class ArtifactRepository(_RepositoryBase):
    """
    Repository for artifact stores, file artifacts, and transaction artifacts.
    """

    @classmethod
    def from_system_config(cls) -> ArtifactRepository:
        """
        Build a repository using SystemConfigSettings DB overrides.
        """
        return cls._from_system_config()

    @classmethod
    def from_overrides(
        cls,
        backend: DatabaseBackend,
        sqlite_path: DatabasePath,
        postgres_dsn: DatabaseDsn,
    ) -> ArtifactRepository:
        """
        Build a repository using explicit backend overrides.
        """
        return cls(backend, sqlite_path, postgres_dsn)

    def resolve_transaction_artifact_path(
        self,
        transaction_id: TransactionId,
        roles: tuple[str, ...] = ROLE_PREFERENCE,
    ) -> Path | None:
        """
        Resolve the on-disk artifact path for a transaction, honoring role order.
        """
        connection = self._connect()
        try:
            row = self._fetch_transaction_artifact_row(
                connection, transaction_id, roles
            )
        finally:
            connection.close()

        if row is None:
            return None

        root_path, relative_path = row
        return self._build_artifact_path(root_path, relative_path)

    def register_transaction_artifact(
        self,
        transaction_id: TransactionId,
        file_path: Path,
        role: str,
        created_epoch: TimestampSec,
    ) -> None:
        """
        Insert file_artifacts + transaction_artifacts rows for an on-disk file.
        """
        connection = self._connect()
        try:
            store = self._get_default_store(connection)
            relative_path = self._normalize_relative_path(file_path, store.root_path)
            filename = file_path.name
            sha256 = self._hash_file(file_path)
            size_bytes = self._file_size_bytes(file_path)
            artifact_id = self._get_or_create_file_artifact(
                connection,
                store.store_id,
                relative_path,
                filename,
                sha256,
                size_bytes,
                DEFAULT_MIME_TYPE,
                created_epoch,
            )
            self._insert_transaction_artifact(
                connection,
                transaction_id,
                artifact_id,
                role,
                created_epoch,
            )
            connection.commit()
        finally:
            connection.close()

    def register_json_export(
        self,
        file_path: Path,
        created_epoch: TimestampSec,
        transaction_id: TransactionId | None = None,
    ) -> None:
        """
        Register a JSON export file and optionally link it to a transaction.
        """
        connection = self._connect()
        try:
            store = self._get_store_by_name(connection, JSON_ARTIFACT_STORE_NAME)
            relative_path = self._normalize_relative_path(file_path, store.root_path)
            filename = file_path.name
            sha256 = self._hash_file(file_path)
            size_bytes = self._file_size_bytes(file_path)
            artifact_id = self._get_or_create_file_artifact(
                connection,
                store.store_id,
                relative_path,
                filename,
                sha256,
                size_bytes,
                JSON_EXPORT_MIME_TYPE,
                created_epoch,
            )
            if transaction_id is not None:
                self._insert_transaction_artifact(
                    connection,
                    transaction_id,
                    artifact_id,
                    ROLE_JSON_EXPORT,
                    created_epoch,
                )
            connection.commit()
        finally:
            connection.close()

    def _get_default_store(self, connection: DbConnection) -> ArtifactStoreRow:
        return self._get_store_by_name(connection, DEFAULT_ARTIFACT_STORE_NAME)

    def _get_store_by_name(
        self, connection: DbConnection, store_name: str
    ) -> ArtifactStoreRow:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    "SELECT store_id, root_path FROM artifact_stores WHERE store_name = ?;",
                    (store_name,),
                )
                row = cursor.fetchone()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT store_id, root_path FROM artifact_stores WHERE store_name = %s;",
                        (store_name,),
                    )
                    row = cursor.fetchone()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")
        if not row:
            raise RuntimeError(f"Artifact store row is missing for '{store_name}'")
        return ArtifactStoreRow(store_id=int(row[0]), root_path=str(row[1]))

    def _normalize_relative_path(self, file_path: Path, store_root: str) -> str:
        root_path = Path(store_root)
        if not root_path.is_absolute():
            root_path = self._resolve_app_root() / root_path
        try:
            relative = file_path.relative_to(root_path)
            return relative.as_posix()
        except ValueError:
            self.logger.warning(
                "File path not under artifact store root; using filename only: %s",
                file_path,
            )
            return file_path.name

    def _get_or_create_file_artifact(
        self,
        connection: DbConnection,
        store_id: int,
        relative_path: str,
        filename: str,
        sha256: HashStr,
        size_bytes: int,
        mime_type: str,
        created_epoch: TimestampSec,
    ) -> int:
        existing = self._fetch_file_artifact_id(connection, store_id, relative_path)
        if existing is not None:
            return existing

        self._insert_file_artifact(
            connection,
            store_id,
            relative_path,
            filename,
            sha256,
            size_bytes,
            mime_type,
            created_epoch,
        )
        existing = self._fetch_file_artifact_id(connection, store_id, relative_path)
        if existing is not None:
            return existing
        existing = self._fetch_file_artifact_id_by_sha(connection, sha256)
        if existing is not None:
            return existing
        raise RuntimeError("Failed to resolve file_artifacts row after insert")

    def _fetch_file_artifact_id(
        self, connection: DbConnection, store_id: int, relative_path: str
    ) -> int | None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    "SELECT artifact_id FROM file_artifacts WHERE store_id = ? AND relative_path = ?;",
                    (store_id, relative_path),
                )
                row = cursor.fetchone()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT artifact_id FROM file_artifacts WHERE store_id = %s AND relative_path = %s;",
                        (store_id, relative_path),
                    )
                    row = cursor.fetchone()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")
        if not row:
            return None
        return int(row[0])

    def _fetch_file_artifact_id_by_sha(
        self, connection: DbConnection, sha256: HashStr
    ) -> int | None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    "SELECT artifact_id FROM file_artifacts WHERE sha256 = ?;",
                    (str(sha256),),
                )
                row = cursor.fetchone()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT artifact_id FROM file_artifacts WHERE sha256 = %s;",
                        (str(sha256),),
                    )
                    row = cursor.fetchone()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")
        if not row:
            return None
        return int(row[0])

    def _insert_file_artifact(
        self,
        connection: DbConnection,
        store_id: int,
        relative_path: str,
        filename: str,
        sha256: HashStr,
        size_bytes: int,
        mime_type: str,
        created_epoch: TimestampSec,
    ) -> None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                connection.execute(
                    ""
                    "INSERT OR IGNORE INTO file_artifacts ("
                    "    store_id, relative_path, filename, sha256, size_bytes, "
                    "    mime_type, created_epoch"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?);",
                    (
                        store_id,
                        relative_path,
                        filename,
                        str(sha256),
                        int(size_bytes),
                        mime_type,
                        int(created_epoch),
                    ),
                )
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        ""
                        "INSERT INTO file_artifacts ("
                        "    store_id, relative_path, filename, sha256, size_bytes, "
                        "    mime_type, created_epoch"
                        ") VALUES (%s, %s, %s, %s, %s, %s, %s) "
                        "ON CONFLICT DO NOTHING;",
                        (
                            store_id,
                            relative_path,
                            filename,
                            str(sha256),
                            int(size_bytes),
                            mime_type,
                            int(created_epoch),
                        ),
                    )
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")

    def _insert_transaction_artifact(
        self,
        connection: DbConnection,
        transaction_id: TransactionId,
        artifact_id: int,
        role: str,
        created_epoch: TimestampSec,
    ) -> None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                connection.execute(
                    ""
                    "INSERT OR IGNORE INTO transaction_artifacts ("
                    "    transaction_id, artifact_id, role, created_epoch"
                    ") VALUES (?, ?, ?, ?);",
                    (
                        str(transaction_id),
                        int(artifact_id),
                        role,
                        int(created_epoch),
                    ),
                )
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        ""
                        "INSERT INTO transaction_artifacts ("
                        "    transaction_id, artifact_id, role, created_epoch"
                        ") VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING;",
                        (
                            str(transaction_id),
                            int(artifact_id),
                            role,
                            int(created_epoch),
                        ),
                    )
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")

    def _fetch_transaction_artifact_row(
        self,
        connection: DbConnection,
        transaction_id: TransactionId,
        roles: tuple[str, str],
    ) -> tuple[str, str] | None:
        role_primary, role_secondary = roles
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    ""
                    "SELECT s.root_path, f.relative_path "
                    "FROM transaction_artifacts ta "
                    "JOIN file_artifacts f ON ta.artifact_id = f.artifact_id "
                    "JOIN artifact_stores s ON f.store_id = s.store_id "
                    "WHERE ta.transaction_id = ? AND ta.role IN (?, ?) "
                    "ORDER BY CASE ta.role "
                    "    WHEN ? THEN 0 "
                    "    WHEN ? THEN 1 "
                    "    ELSE 2 "
                    "END, ta.transaction_artifact_id ASC "
                    "LIMIT 1;",
                    (
                        str(transaction_id),
                        role_primary,
                        role_secondary,
                        role_primary,
                        role_secondary,
                    ),
                )
                row = cursor.fetchone()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        ""
                        "SELECT s.root_path, f.relative_path "
                        "FROM transaction_artifacts ta "
                        "JOIN file_artifacts f ON ta.artifact_id = f.artifact_id "
                        "JOIN artifact_stores s ON f.store_id = s.store_id "
                        "WHERE ta.transaction_id = %s AND ta.role IN (%s, %s) "
                        "ORDER BY CASE ta.role "
                        "    WHEN %s THEN 0 "
                        "    WHEN %s THEN 1 "
                        "    ELSE 2 "
                        "END, ta.transaction_artifact_id ASC "
                        "LIMIT 1;",
                        (
                            str(transaction_id),
                            role_primary,
                            role_secondary,
                            role_primary,
                            role_secondary,
                        ),
                    )
                    row = cursor.fetchone()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")
        if not row:
            return None
        return str(row[0]), str(row[1])

    def _build_artifact_path(self, root_path: str, relative_path: str) -> Path:
        store_root = Path(root_path)
        if not store_root.is_absolute():
            store_root = self._resolve_app_root() / store_root
        return store_root / relative_path

    def _hash_file(self, file_path: Path) -> HashStr:
        hasher = hashlib.sha256()
        with file_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(FILE_HASH_CHUNK_BYTES), b""):
                hasher.update(chunk)
        return HashStr(hasher.hexdigest())

    @staticmethod
    def _file_size_bytes(file_path: Path) -> int:
        return int(file_path.stat().st_size)

# FILE: src/pypnm/lib/db/json_transaction.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
import logging
import time
from collections.abc import Mapping
from pathlib import Path

from pypnm.config.pnm_config_manager import SystemConfigSettings
from pypnm.lib.db.artifact_repository import ArtifactRepository
from pypnm.lib.file_processor import FileProcessor
from pypnm.lib.types import PathLike, TimestampSec, TransactionId

JsonPayload = Mapping[str, object]


class JsonTransactionDb:
    """
    JSON export writer with DB-backed artifact tracking.

    The legacy JSON ledger file is no longer used. This helper writes JSON
    payloads under the configured json_dir and registers the artifact in the
    DB-backed artifact tables. When a transaction_id is supplied, the JSON
    artifact is linked via transaction_artifacts using the JSON export role.
    """

    def __init__(self) -> None:
        """
        Initialize the JSON export writer.

        Configuration comes from SystemConfigSettings.json_dir(), and artifacts
        are registered via ArtifactRepository using the configured DB backend.
        """
        self._json_dir = Path(SystemConfigSettings.json_dir())
        self._artifact_repo = ArtifactRepository.from_system_config()
        self.logger = logging.getLogger(f"{self.__class__.__name__}")

    def write_json(
        self,
        data: JsonPayload,
        fname: PathLike,
        extension: str = "",
        transaction_id: TransactionId | None = None,
    ) -> Path:
        """
        Persist a JSON payload and register the artifact in the DB.

        Parameters
        ----------
        data:
            JSON-serializable mapping representing the payload.
        fname:
            Base filename (without extension) to use for the payload file.
        extension:
            File extension to use for the payload file (default: "").
        transaction_id:
            Optional transaction identifier to link the JSON artifact to an
            existing transaction record.

        Returns
        -------
        Path
            Full path to the JSON payload file on disk.

        Raises
        ------
        ValueError
            If ``data`` cannot be serialized as JSON.
        RuntimeError
            If writing the payload file fails.
        """
        try:
            json.dumps(data)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Provided data is not JSON-serializable: {exc}") from exc

        filename = str(fname)
        if extension:
            filename = f"{filename}.{extension.lstrip('.')}"

        payload_path = self._json_dir / filename
        payload_processor = FileProcessor(payload_path)
        write_ok = payload_processor.write_file(dict(data), append=False)
        if not write_ok:
            raise RuntimeError(f"Failed to write transaction payload to {payload_path}")

        created_epoch = TimestampSec(int(time.time()))
        self._artifact_repo.register_json_export(
            file_path=payload_path,
            created_epoch=created_epoch,
            transaction_id=transaction_id,
        )

        return payload_path

# FILE: src/pypnm/config/system_config_settings.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import cast

from pydantic import ValidationError

from pypnm.config.config_manager import ConfigManager
from pypnm.config.database_settings import (
    DEFAULT_POSTGRES_DSN,
    DEFAULT_SQLITE_DB_PATH,
    POSTGRES_DSN_ENV_VAR,
    DatabaseSettings,
)
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.secret.crypto_manager import SecretCryptoError, SecretCryptoManager
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    FileNameStr,
    InetAddressStr,
    IPv4Str,
    IPv6Str,
    MacAddressStr,
    SnmpReadCommunity,
    SnmpWriteCommunity,
)


class SystemConfigSettings:
    """Provides dynamically reloaded system configuration via class properties."""

    _cfg = ConfigManager()
    _logger = logging.getLogger("SystemConfigSettings")
    _deprecated_ledger_warned: set[str] = set()

    _DEFAULT_IP_ADDRESS: InetAddressStr = cast(InetAddressStr, "192.168.0.100")
    _DEFAULT_SNMP_RETRIES: int = 5
    _DEFAULT_SNMP_TIMEOUT: int = 2
    _DEFAULT_FILE_RETRIEVAL_RETRIES: int = 5
    _DEFAULT_HTTP_PORT: int = 80
    _DEFAULT_HTTPS_PORT: int = 443
    _DEFAULT_TFTP_PORT: int = 69
    _DEFAULT_FTP_PORT: int = 21
    _DEFAULT_SFTP_PORT: int = 22
    _DEFAULT_SCP_PORT: int = 22
    _DEFAULT_LOG_LEVEL: str = "INFO"
    _DEFAULT_LOG_DIR: str = "logs"
    _DEFAULT_LOG_FILENAME: str = "pypnm.log"
    _DEFAULT_SNMP_READ_COMMUNITY: str = "public"
    _DEFAULT_SNMP_WRITE_COMMUNITY: str = ""
    _DEFAULT_PNM_DIR: str = ".data/pnm"
    _DEFAULT_CSV_DIR: str = ".data/csv"
    _DEFAULT_JSON_DIR: str = ".data/json"
    _DEFAULT_XLSX_DIR: str = ".data/xlsx"
    _DEFAULT_PNG_DIR: str = ".data/png"
    _DEFAULT_ARCHIVE_DIR: str = ".data/archive"
    _DEFAULT_MSG_RSP_DIR: str = ".data/msg_rsp"
    _DEFAULT_DB_BACKEND: DatabaseBackend = DatabaseBackend.SQLITE
    _DEFAULT_SQLITE_DB_PATH: DatabasePath = DEFAULT_SQLITE_DB_PATH
    _DEFAULT_POSTGRES_DSN: DatabaseDsn = DEFAULT_POSTGRES_DSN
    _POSTGRES_DSN_ENV_VAR: str = POSTGRES_DSN_ENV_VAR
    _DB_BACKEND_ENV_VAR: str = "PYPNM_DB_BACKEND"

    _ENCRYPTED_TOKEN_PREFIX: str = "ENC["

    _PRIMARY_RETRIEVAL_METHOD_KEY: str = "retrieval_method"
    _LEGACY_RETRIEVAL_METHOD_KEY: str = "retrival_method"

    @classmethod
    def _config_path(cls, *path: str) -> str:
        """Return dotted path for logging."""
        return ".".join(path)

    @classmethod
    def _postgres_dsn_env_override(cls) -> str:
        value = os.getenv(cls._POSTGRES_DSN_ENV_VAR, "")
        return value.strip()

    @classmethod
    def _db_backend_env_override(cls) -> str:
        value = os.getenv(cls._DB_BACKEND_ENV_VAR, "")
        normalized = value.strip().lower()
        if normalized == "":
            return ""
        if normalized in (DatabaseBackend.SQLITE.value, DatabaseBackend.POSTGRES.value):
            return normalized
        cls._logger.error(
            "Invalid %s value '%s'; expected sqlite or postgres",
            cls._DB_BACKEND_ENV_VAR,
            value,
        )
        return ""

    @classmethod
    def _peek_str(cls, *path: str) -> str:
        value = cls._cfg.get(*path)
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        return str(value)

    @classmethod
    def _peek_str_fallback(
        cls, primary: tuple[str, ...], legacy: tuple[str, ...]
    ) -> str:
        value = cls._cfg.get(*primary)
        if value is not None:
            if isinstance(value, str):
                return value
            return str(value)
        return cls._peek_str(*legacy)

    @classmethod
    def _maybe_decrypt(cls, value: str, *path: str) -> str:
        text = value.strip()
        if text == "":
            return ""
        if not text.startswith(cls._ENCRYPTED_TOKEN_PREFIX):
            return text
        try:
            return SecretCryptoManager.decrypt_password(text)
        except SecretCryptoError as exc:
            cls._logger.error(
                "Failed to decrypt configuration value for '%s': %s",
                cls._config_path(*path),
                exc,
            )
            return ""

    @classmethod
    def _get_password_value(cls, require: bool, *method_path: str) -> str:
        password_enc = cls._peek_str(*method_path, "password_enc")
        if password_enc.strip() != "":
            decrypted = cls._maybe_decrypt(password_enc, *method_path, "password_enc")
            if decrypted != "":
                return decrypted
            if require:
                return ""

        password = cls._peek_str(*method_path, "password")
        if password.strip() == "":
            if require:
                cls._logger.error(
                    "Missing configuration value for '%s'; expected password or password_enc",
                    cls._config_path(*method_path, "password"),
                )
            return ""

        cls._logger.warning(
            "Using legacy plaintext password for '%s'; prefer password_enc",
            cls._config_path(*method_path, "password"),
        )
        return cls._maybe_decrypt(password, *method_path, "password")

    @classmethod
    def _get_password_value_fallback(
        cls, require: bool, primary: tuple[str, ...], legacy: tuple[str, ...]
    ) -> str:
        password_enc = cls._peek_str_fallback(
            primary + ("password_enc",), legacy + ("password_enc",)
        )
        if password_enc.strip() != "":
            decrypted = cls._maybe_decrypt(password_enc, *(primary + ("password_enc",)))
            if decrypted != "":
                return decrypted
            if require:
                return ""

        password = cls._peek_str_fallback(
            primary + ("password",), legacy + ("password",)
        )
        if password.strip() == "":
            if require:
                cls._logger.error(
                    "Missing configuration value for '%s'; expected password or password_enc",
                    cls._config_path(*(primary + ("password",))),
                )
            return ""

        cls._logger.warning(
            "Using legacy plaintext password for '%s'; prefer password_enc",
            cls._config_path(*(primary + ("password",))),
        )
        return cls._maybe_decrypt(password, *(primary + ("password",)))

    @classmethod
    def _get_str(cls, default: str, *path: str) -> str:
        value = cls._cfg.get(*path)
        if value is None:
            cls._logger.error(
                "Missing configuration value for '%s'; using default '%s'",
                cls._config_path(*path),
                default,
            )
            return default
        if not isinstance(value, str):
            coerced = str(value)
            cls._logger.error(
                "Non-string configuration value for '%s': %r; using coerced '%s'",
                cls._config_path(*path),
                value,
                coerced,
            )
            return coerced
        if value == "":
            cls._logger.error(
                "Empty configuration value for '%s'; using default '%s'",
                cls._config_path(*path),
                default,
            )
            return default
        return value

    @classmethod
    def _get_str_fallback(
        cls, default: str, primary: tuple[str, ...], legacy: tuple[str, ...]
    ) -> str:
        value = cls._cfg.get(*primary)
        if value is not None:
            if isinstance(value, str) and value != "":
                return value
            if not isinstance(value, str):
                coerced = str(value)
                cls._logger.error(
                    "Non-string configuration value for '%s': %r; using coerced '%s'",
                    cls._config_path(*primary),
                    value,
                    coerced,
                )
                return coerced
            if value == "":
                legacy_value = cls._cfg.get(*legacy)
                if legacy_value is not None:
                    if not isinstance(legacy_value, str):
                        coerced = str(legacy_value)
                        cls._logger.error(
                            "Non-string configuration value for '%s': %r; using coerced '%s'",
                            cls._config_path(*primary),
                            legacy_value,
                            coerced,
                        )
                        return coerced
                    if legacy_value != "":
                        return legacy_value
                cls._logger.error(
                    "Empty configuration value for '%s'; using default '%s'",
                    cls._config_path(*primary),
                    default,
                )
                return default

        legacy_value = cls._cfg.get(*legacy)
        if legacy_value is None:
            cls._logger.error(
                "Missing configuration value for '%s'; using default '%s'",
                cls._config_path(*primary),
                default,
            )
            return default
        if not isinstance(legacy_value, str):
            coerced = str(legacy_value)
            cls._logger.error(
                "Non-string configuration value for '%s': %r; using coerced '%s'",
                cls._config_path(*primary),
                legacy_value,
                coerced,
            )
            return coerced
        if legacy_value == "":
            cls._logger.error(
                "Empty configuration value for '%s'; using default '%s'",
                cls._config_path(*primary),
                default,
            )
            return default
        return legacy_value

    @classmethod
    def _get_str_allow_empty(cls, default: str, *path: str) -> str:
        value = cls._cfg.get(*path)
        if value is None:
            return default
        if not isinstance(value, str):
            coerced = str(value)
            cls._logger.error(
                "Non-string configuration value for '%s': %r; using coerced '%s'",
                cls._config_path(*path),
                value,
                coerced,
            )
            return coerced
        return value

    @classmethod
    def _get_str_fallback_allow_empty(
        cls, default: str, primary: tuple[str, ...], legacy: tuple[str, ...]
    ) -> str:
        value = cls._cfg.get(*primary)
        if value is not None:
            if isinstance(value, str):
                return value
            coerced = str(value)
            cls._logger.error(
                "Non-string configuration value for '%s': %r; using coerced '%s'",
                cls._config_path(*primary),
                value,
                coerced,
            )
            return coerced

        legacy_value = cls._cfg.get(*legacy)
        if legacy_value is None:
            return default
        if not isinstance(legacy_value, str):
            coerced = str(legacy_value)
            cls._logger.error(
                "Non-string configuration value for '%s': %r; using coerced '%s'",
                cls._config_path(*primary),
                legacy_value,
                coerced,
            )
            return coerced
        return legacy_value

    @classmethod
    def _get_int(cls, default: int, *path: str) -> int:
        value = cls._cfg.get(*path)
        if value is None:
            cls._logger.error(
                "Missing configuration value for '%s'; using default %d",
                cls._config_path(*path),
                default,
            )
            return default
        try:
            return int(value)
        except (TypeError, ValueError):
            cls._logger.error(
                "Invalid integer configuration value for '%s': %r; using default %d",
                cls._config_path(*path),
                value,
                default,
            )
            return default

    @classmethod
    def _get_int_fallback(
        cls, default: int, primary: tuple[str, ...], legacy: tuple[str, ...]
    ) -> int:
        value = cls._cfg.get(*primary)
        if value is not None:
            try:
                return int(value)
            except (TypeError, ValueError):
                cls._logger.error(
                    "Invalid integer configuration value for '%s': %r; using default %d",
                    cls._config_path(*primary),
                    value,
                    default,
                )
                return default

        legacy_value = cls._cfg.get(*legacy)
        if legacy_value is None:
            cls._logger.error(
                "Missing configuration value for '%s'; using default %d",
                cls._config_path(*primary),
                default,
            )
            return default
        try:
            return int(legacy_value)
        except (TypeError, ValueError):
            cls._logger.error(
                "Invalid integer configuration value for '%s': %r; using default %d",
                cls._config_path(*primary),
                legacy_value,
                default,
            )
            return default

    @classmethod
    def _get_bool(cls, default: bool, *path: str) -> bool:
        value = cls._cfg.get(*path)
        if isinstance(value, bool):
            return value
        if value is None:
            cls._logger.error(
                "Missing configuration value for '%s'; using default %s",
                cls._config_path(*path),
                default,
            )
            return default

        text = str(value).strip().lower()
        if text in ("1", "true", "yes", "on"):
            return True
        if text in ("0", "false", "no", "off"):
            return False

        cls._logger.error(
            "Invalid boolean configuration value for '%s': %r; using default %s",
            cls._config_path(*path),
            value,
            default,
        )
        return default

    @classmethod
    def _get_bool_fallback(
        cls, default: bool, primary: tuple[str, ...], legacy: tuple[str, ...]
    ) -> bool:
        value = cls._cfg.get(*primary)
        if isinstance(value, bool):
            return value
        if value is None:
            legacy_value = cls._cfg.get(*legacy)
            if isinstance(legacy_value, bool):
                return legacy_value
            if legacy_value is None:
                cls._logger.error(
                    "Missing configuration value for '%s'; using default %s",
                    cls._config_path(*primary),
                    default,
                )
                return default
            text = str(legacy_value).strip().lower()
            if text in ("1", "true", "yes", "on"):
                return True
            if text in ("0", "false", "no", "off"):
                return False
            cls._logger.error(
                "Invalid boolean configuration value for '%s': %r; using default %s",
                cls._config_path(*primary),
                legacy_value,
                default,
            )
            return default

        text = str(value).strip().lower()
        if text in ("1", "true", "yes", "on"):
            return True
        if text in ("0", "false", "no", "off"):
            return False

        cls._logger.error(
            "Invalid boolean configuration value for '%s': %r; using default %s",
            cls._config_path(*primary),
            value,
            default,
        )
        return default

    @classmethod
    def database_settings(cls) -> DatabaseSettings:
        data: dict[str, object] = {}

        backend_value = cls._cfg.get("Database", "backend")
        if backend_value is not None:
            data["backend"] = str(backend_value).strip()
        env_backend = cls._db_backend_env_override()
        if env_backend != "":
            data["backend"] = env_backend

        sqlite_value = cls._cfg.get("Database", "sqlite", "path")
        if sqlite_value is None:
            sqlite_path = str(cls._DEFAULT_SQLITE_DB_PATH)
        else:
            sqlite_path = str(sqlite_value)
        data["sqlite"] = {"path": sqlite_path}

        postgres_value = cls._cfg.get("Database", "postgres", "dsn")
        if postgres_value is None:
            postgres_dsn = str(cls._DEFAULT_POSTGRES_DSN)
        else:
            postgres_dsn = str(postgres_value)

        env_override = cls._postgres_dsn_env_override()
        if env_override != "":
            postgres_dsn = env_override
        data["postgres"] = {"dsn": postgres_dsn}

        return DatabaseSettings.model_validate(data)

    @classmethod
    def database_backend(cls) -> DatabaseBackend:
        try:
            return cls.database_settings().backend
        except ValidationError as exc:
            cls._logger.error("Invalid Database configuration: %s", exc)
            return cls._DEFAULT_DB_BACKEND

    @classmethod
    def database_sqlite_path(cls) -> DatabasePath:
        try:
            return cls.database_settings().sqlite.path
        except ValidationError as exc:
            cls._logger.error("Invalid Database configuration: %s", exc)
            return cls._DEFAULT_SQLITE_DB_PATH

    @classmethod
    def database_postgres_dsn(cls) -> DatabaseDsn:
        try:
            return cls.database_settings().postgres.dsn
        except ValidationError as exc:
            cls._logger.error("Invalid Database configuration: %s", exc)
            return cls._DEFAULT_POSTGRES_DSN

    @classmethod
    def get_config_path(cls) -> str:
        return cls._cfg.get_config_path()

    @classmethod
    def default_mac_address(cls) -> MacAddressStr:
        mac = cls._cfg.get("FastApiRequestDefault", "mac_address")
        if not mac:
            cls._logger.error(
                "Missing configuration value for '%s'; using MacAddress.null()",
                cls._config_path("FastApiRequestDefault", "mac_address"),
            )
            return cast(MacAddressStr, MacAddress.null())
        return cast(MacAddressStr, mac)

    @classmethod
    def default_ip_address(cls) -> InetAddressStr:
        return cast(
            InetAddressStr,
            cls._get_str(
                cls._DEFAULT_IP_ADDRESS, "FastApiRequestDefault", "ip_address"
            ),
        )

    # SNMP v2 settings
    @classmethod
    def snmp_enable(cls) -> bool:
        return cls._get_bool(True, "SNMP", "version", "2c", "enable")

    @classmethod
    def snmp_retries(cls) -> int:
        return cls._get_int(
            cls._DEFAULT_SNMP_RETRIES, "SNMP", "version", "2c", "retries"
        )

    @classmethod
    def snmp_read_community(cls) -> SnmpReadCommunity:
        value = cls._cfg.get("SNMP", "version", "2c", "read_community")
        if value is not None:
            if isinstance(value, str) and value.strip() != "":
                return cast(SnmpReadCommunity, value)
            if not isinstance(value, str):
                coerced = str(value)
                cls._logger.error(
                    "Non-string configuration value for '%s': %r; using coerced '%s'",
                    cls._config_path("SNMP", "version", "2c", "read_community"),
                    value,
                    coerced,
                )
                return cast(SnmpReadCommunity, coerced)
        legacy = cls._cfg.get("SNMP", "version", "2c", "community")
        if legacy is not None:
            if isinstance(legacy, str) and legacy.strip() != "":
                return cast(SnmpReadCommunity, legacy)
            if not isinstance(legacy, str):
                coerced = str(legacy)
                cls._logger.error(
                    "Non-string configuration value for '%s': %r; using coerced '%s'",
                    cls._config_path("SNMP", "version", "2c", "community"),
                    legacy,
                    coerced,
                )
                return cast(SnmpReadCommunity, coerced)
        return cast(
            SnmpReadCommunity,
            cls._get_str(
                cls._DEFAULT_SNMP_READ_COMMUNITY,
                "SNMP",
                "version",
                "2c",
                "read_community",
            ),
        )

    @classmethod
    def snmp_write_community(cls) -> SnmpWriteCommunity:
        value = cls._cfg.get("SNMP", "version", "2c", "write_community")
        if value is not None:
            if isinstance(value, str) and value.strip() != "":
                return cast(SnmpWriteCommunity, value)
            if not isinstance(value, str):
                coerced = str(value)
                cls._logger.error(
                    "Non-string configuration value for '%s': %r; using coerced '%s'",
                    cls._config_path("SNMP", "version", "2c", "write_community"),
                    value,
                    coerced,
                )
                return cast(SnmpWriteCommunity, coerced)
        return cast(
            SnmpWriteCommunity,
            cls._get_str(
                cls._DEFAULT_SNMP_WRITE_COMMUNITY,
                "SNMP",
                "version",
                "2c",
                "write_community",
            ),
        )

    # SNMP v3 settings

    @classmethod
    def snmp_v3_enable(cls) -> bool:
        return cls._get_bool(False, "SNMP", "version", "3", "enable")

    @classmethod
    def snmp_v3_username(cls) -> str:
        if not cls.snmp_v3_enable():
            return ""
        return cls._get_str("", "SNMP", "version", "3", "username")

    @classmethod
    def snmp_v3_security_level(cls) -> str:
        if not cls.snmp_v3_enable():
            return ""
        return cls._get_str("", "SNMP", "version", "3", "securityLevel")

    @classmethod
    def snmp_v3_auth_protocol(cls) -> str:
        if not cls.snmp_v3_enable():
            return ""
        return cls._get_str("", "SNMP", "version", "3", "authProtocol")

    @classmethod
    def snmp_v3_auth_password(cls) -> str:
        if not cls.snmp_v3_enable():
            return ""
        value = cls._get_str("", "SNMP", "version", "3", "authPassword")
        return cls._maybe_decrypt(value, "SNMP", "version", "3", "authPassword")

    @classmethod
    def snmp_v3_priv_protocol(cls) -> str:
        if not cls.snmp_v3_enable():
            return ""
        return cls._get_str("", "SNMP", "version", "3", "privProtocol")

    @classmethod
    def snmp_v3_priv_password(cls) -> str:
        if not cls.snmp_v3_enable():
            return ""
        value = cls._get_str("", "SNMP", "version", "3", "privPassword")
        return cls._maybe_decrypt(value, "SNMP", "version", "3", "privPassword")

    # SNMP general settings
    @classmethod
    def snmp_timeout(cls) -> int:
        return cls._get_int(cls._DEFAULT_SNMP_TIMEOUT, "SNMP", "timeout")

    # Bulk data transfer settings
    @classmethod
    def bulk_transfer_method(cls) -> str:
        return cls._get_str("", "PnmBulkDataTransfer", "method")

    @classmethod
    def bulk_tftp_ip_v4(cls) -> IPv4Str:
        return cast(
            IPv4Str,
            cls._get_str("", "PnmBulkDataTransfer", "tftp", "ip_v4"),
        )

    @classmethod
    def bulk_tftp_ip_v6(cls) -> IPv6Str:
        return cast(
            IPv6Str,
            cls._get_str("", "PnmBulkDataTransfer", "tftp", "ip_v6"),
        )

    @classmethod
    def bulk_tftp_remote_dir(cls) -> str:
        return cls._get_str_allow_empty("", "PnmBulkDataTransfer", "tftp", "remote_dir")

    @classmethod
    def bulk_http_base_url(cls) -> str:
        return cls._get_str("", "PnmBulkDataTransfer", "http", "base_url")

    @classmethod
    def bulk_http_port(cls) -> int:
        return cls._get_int(
            cls._DEFAULT_HTTP_PORT, "PnmBulkDataTransfer", "http", "port"
        )

    @classmethod
    def bulk_https_base_url(cls) -> str:
        return cls._get_str("", "PnmBulkDataTransfer", "https", "base_url")

    @classmethod
    def bulk_https_port(cls) -> int:
        return cls._get_int(
            cls._DEFAULT_HTTPS_PORT, "PnmBulkDataTransfer", "https", "port"
        )

    # PNM file retrieval/storage settings
    @classmethod
    def save_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_PNM_DIR, "PnmFileRetrieval", "pnm_dir")

    @classmethod
    def pnm_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_PNM_DIR, "PnmFileRetrieval", "pnm_dir")

    @classmethod
    def csv_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_CSV_DIR, "PnmFileRetrieval", "csv_dir")

    @classmethod
    def json_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_JSON_DIR, "PnmFileRetrieval", "json_dir")

    @classmethod
    def xlsx_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_XLSX_DIR, "PnmFileRetrieval", "xlsx_dir")

    @classmethod
    def png_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_PNG_DIR, "PnmFileRetrieval", "png_dir")

    @classmethod
    def archive_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_ARCHIVE_DIR, "PnmFileRetrieval", "archive_dir")

    @classmethod
    def message_response_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_MSG_RSP_DIR, "PnmFileRetrieval", "msg_rsp_dir")

    @classmethod
    def transaction_db(cls) -> str:
        return cls._get_str("", "PnmFileRetrieval", "transaction_db")

    @classmethod
    def capture_group_db(cls) -> str:
        return cls._get_str("", "PnmFileRetrieval", "capture_group_db")

    @classmethod
    def session_group_db(cls) -> str:
        return cls._get_str("", "PnmFileRetrieval", "session_group_db")

    @classmethod
    def operation_db(cls) -> str:
        return cls._get_str("", "PnmFileRetrieval", "operation_db")

    @classmethod
    def json_db(cls) -> str:
        return cls._get_str("", "PnmFileRetrieval", "json_transaction_db")

    @classmethod
    def file_retrieval_retries(cls) -> int:
        return cls._get_int(
            cls._DEFAULT_FILE_RETRIEVAL_RETRIES, "PnmFileRetrieval", "retries"
        )

    @classmethod
    def retrieval_method(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "method")
        legacy = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "method")

        return cls._get_str_fallback("", primary, legacy)

    # Local method
    @classmethod
    def local_src_dir(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "local",
            "src_dir",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "local",
            "src_dir",
        )
        return cls._get_str_fallback("", primary, legacy)

    # TFTP method
    @classmethod
    def tftp_host(cls) -> InetAddressStr:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "tftp",
            "host",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "tftp",
            "host",
        )
        return InetAddressStr(cls._get_str_fallback("", primary, legacy))

    @classmethod
    def tftp_port(cls) -> int:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "tftp",
            "port",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "tftp",
            "port",
        )
        return cls._get_int_fallback(cls._DEFAULT_TFTP_PORT, primary, legacy)

    @classmethod
    def tftp_timeout(cls) -> int:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "tftp",
            "timeout",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "tftp",
            "timeout",
        )
        return cls._get_int_fallback(cls._DEFAULT_SNMP_TIMEOUT, primary, legacy)

    @classmethod
    def tftp_remote_dir(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "tftp",
            "remote_dir",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "tftp",
            "remote_dir",
        )
        return cls._get_str_fallback_allow_empty("", primary, legacy)

    # FTP method
    @classmethod
    def ftp_host(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "ftp",
            "host",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "ftp",
            "host",
        )
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def ftp_port(cls) -> int:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "ftp",
            "port",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "ftp",
            "port",
        )
        return cls._get_int_fallback(cls._DEFAULT_FTP_PORT, primary, legacy)

    @classmethod
    def ftp_use_tls(cls) -> bool:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "ftp",
            "tls",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "ftp",
            "tls",
        )
        return cls._get_bool_fallback(False, primary, legacy)

    @classmethod
    def ftp_timeout(cls) -> int:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "ftp",
            "timeout",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "ftp",
            "timeout",
        )
        return cls._get_int_fallback(cls._DEFAULT_SNMP_TIMEOUT, primary, legacy)

    @classmethod
    def ftp_user(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "ftp",
            "user",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "ftp",
            "user",
        )
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def ftp_password(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "ftp",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "ftp",
        )
        return cls._get_password_value_fallback(
            True,
            primary,
            legacy,
        )

    @classmethod
    def ftp_remote_dir(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "ftp",
            "remote_dir",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "ftp",
            "remote_dir",
        )
        return cls._get_str_fallback_allow_empty("", primary, legacy)

    # SCP method
    @classmethod
    def scp_host(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "scp",
            "host",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "scp",
            "host",
        )
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def scp_port(cls) -> int:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "scp",
            "port",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "scp",
            "port",
        )
        return cls._get_int_fallback(cls._DEFAULT_SCP_PORT, primary, legacy)

    @classmethod
    def scp_user(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "scp",
            "user",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "scp",
            "user",
        )
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def scp_password(cls) -> str:
        private_key_path_primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "scp",
            "private_key_path",
        )
        private_key_path_legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "scp",
            "private_key_path",
        )
        private_key_path = cls._peek_str_fallback(
            private_key_path_primary, private_key_path_legacy
        ).strip()
        require = private_key_path == ""

        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "scp",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "scp",
        )

        return cls._get_password_value_fallback(
            require,
            primary,
            legacy,
        )

    @classmethod
    def scp_private_key_path(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "scp",
            "private_key_path",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "scp",
            "private_key_path",
        )
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def scp_remote_dir(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "scp",
            "remote_dir",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "scp",
            "remote_dir",
        )
        return cls._get_str_fallback_allow_empty("", primary, legacy)

    # SFTP method
    @classmethod
    def sftp_host(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "sftp",
            "host",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "sftp",
            "host",
        )
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def sftp_port(cls) -> int:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "sftp",
            "port",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "sftp",
            "port",
        )
        return cls._get_int_fallback(cls._DEFAULT_SFTP_PORT, primary, legacy)

    @classmethod
    def sftp_user(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "sftp",
            "user",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "sftp",
            "user",
        )
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def sftp_password(cls) -> str:
        private_key_path_primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "sftp",
            "private_key_path",
        )
        private_key_path_legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "sftp",
            "private_key_path",
        )
        private_key_path = cls._peek_str_fallback(
            private_key_path_primary, private_key_path_legacy
        ).strip()
        require = private_key_path == ""

        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "sftp",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "sftp",
        )

        return cls._get_password_value_fallback(
            require,
            primary,
            legacy,
        )

    @classmethod
    def sftp_private_key_path(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "sftp",
            "private_key_path",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "sftp",
            "private_key_path",
        )
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def sftp_remote_dir(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "sftp",
            "remote_dir",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "sftp",
            "remote_dir",
        )
        return cls._get_str_fallback_allow_empty("", primary, legacy)

    # HTTP method
    @classmethod
    def http_base_url(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "http",
            "base_url",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "http",
            "base_url",
        )
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def http_port(cls) -> int:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "http",
            "port",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "http",
            "port",
        )
        return cls._get_int_fallback(cls._DEFAULT_HTTP_PORT, primary, legacy)

    # HTTPS method
    @classmethod
    def https_base_url(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "https",
            "base_url",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "https",
            "base_url",
        )
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def https_port(cls) -> int:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "https",
            "port",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "https",
            "port",
        )
        return cls._get_int_fallback(cls._DEFAULT_HTTPS_PORT, primary, legacy)

    # Logging
    @classmethod
    def log_level(cls) -> str:
        return cls._get_str(cls._DEFAULT_LOG_LEVEL, "logging", "log_level")

    @classmethod
    def log_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_LOG_DIR, "logging", "log_dir")

    @classmethod
    def log_filename(cls) -> FileNameStr:
        return cls._get_str(cls._DEFAULT_LOG_FILENAME, "logging", "log_filename")

    @classmethod
    def initialize_directories(cls) -> None:
        """
        Create necessary directories if they do not exist.
        """
        cls._warn_deprecated_ledger_paths()
        directories = [
            cls.pnm_dir(),
            cls.csv_dir(),
            cls.json_dir(),
            cls.xlsx_dir(),
            cls.png_dir(),
            cls.archive_dir(),
            cls.message_response_dir(),
            cls.log_dir(),
        ]
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)

    @classmethod
    def _warn_deprecated_ledger_paths(cls) -> None:
        cls._warn_deprecated_ledger_key("transaction_db")
        cls._warn_deprecated_ledger_key("json_transaction_db")

    @classmethod
    def _warn_deprecated_ledger_key(cls, key: str) -> None:
        if key in cls._deprecated_ledger_warned:
            return
        value = cls._cfg.get("PnmFileRetrieval", key)
        if value is None:
            return
        if isinstance(value, str):
            if value == "":
                return
            configured = value
        else:
            configured = str(value)
            if configured == "":
                return
        cls._logger.warning(
            "Configuration key 'PnmFileRetrieval.%s' is deprecated and ignored at runtime; remove it from system.json",
            key,
        )
        cls._deprecated_ledger_warned.add(key)

    @classmethod
    def reload(cls) -> None:
        """
        Reload the configuration settings.
        """
        cls._cfg.reload()
        cls.initialize_directories()

# FILE: src/pypnm/api/routes/advance/analysis/report/multi_analysis_rpt.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from pathlib import Path

from pydantic import BaseModel

from pypnm.api.routes.advance.common.capture_data_aggregator import (
    CaptureDataAggregator,
    TransactionCollection,
)
from pypnm.api.routes.advance.common.transactionsCollection import (
    TransactionCollectionModel,
)
from pypnm.api.routes.basic.abstract.analysis_report import AnalysisOutputModel
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.data_type.sysDescr import SystemDescriptor, SystemDescriptorModel
from pypnm.lib.archive.manager import ArchiveManager
from pypnm.lib.csv.manager import CSVManager
from pypnm.lib.db.json_transaction import JsonTransactionDb
from pypnm.lib.mac_address import MacAddress, cast
from pypnm.lib.matplot.manager import MatplotManager
from pypnm.lib.types import (
    ChannelId,
    JsonScalar,
    PathArray,
    PathLike,
    TimeStamp,
    TransactionId,
)
from pypnm.lib.utils import Generate, TimeUnit


class MultiAnalysisRpt(ABC):
    """
    Abstact Class to manage multiple captures:
     + This class will be inherited and can support single or multiple cable modems
    """

    def __init__(self, capt_data_agg: CaptureDataAggregator) -> None:
        self.logger = logging.getLogger("MultiAnalysisRpt")

        self._capt_data_agg = capt_data_agg
        self._trans_collect: TransactionCollection = capt_data_agg.collect()
        tcm: TransactionCollectionModel = (
            self._trans_collect.getTransactionCollectionModel()[0]
        )

        self._png_dir: PathLike = cast(PathLike, SystemConfigSettings.png_dir())
        self._csv_dir: PathLike = cast(PathLike, SystemConfigSettings.csv_dir())
        self._json_dir: PathLike = cast(PathLike, SystemConfigSettings.json_dir())
        self._archive_dir: PathLike = cast(PathLike, SystemConfigSettings.archive_dir())

        self._group_time: TimeStamp = Generate.time_stamp()
        self._base_filename: PathLike = ""
        self._common_analysis_model: dict[ChannelId, BaseModel] = {}

        self._mac_addresses: set[MacAddress] = set()
        self._cmts_mac_address: MacAddress = MacAddress(MacAddress.null())
        self._sys_descr_model: SystemDescriptorModel = (
            tcm.device_details.system_description
        )

        self.csv_files: list[PathLike] = []
        self.plot_files: list[PathLike] = []
        self.json_files: list[PathLike] = []

        self.logger.info(
            f"MultiAnalysisRpt: MAC: {self._mac_addresses}, "
            f"Model: {self._sys_descr_model.model_dump()}, "
            f"GroupTime: {self._group_time}"
        )

    def getMacAddresses(self) -> list[MacAddress]:
        """Return the cable-modem MAC address associated with this report session."""
        return self._trans_collect.getMacAddresses()

    def get_system_description(self) -> SystemDescriptor:
        """Return the device SystemDescriptor used for filenames and labeling."""
        return SystemDescriptor.load_from_dict(self._sys_descr_model.model_dump())

    def get_group_time(self) -> int:
        """Return the session/group timestamp used to namespace output filenames."""
        return self._group_time

    def to_output_model(self) -> AnalysisOutputModel:
        """
        Produce a serializable model of the generated artifacts (time, CSVs, plots, archive).

        Call this after `build_report()` to pass paths and metadata to API callers.
        """
        return AnalysisOutputModel(
            time=self._group_time,
            csv_files=self.csv_files,
            plot_files=self.plot_files,
            json_files=self.json_files,
            archive_file=self.archive_file,
        )

    def create_csv_fname(self, tags: list[str] = None) -> PathLike:
        """
        Build a CSV filename of the form:
            <csv_dir>/<mac>_<model>_<timestamp>[_TAGS].csv

        Example:
            fname = self.create_csv_fname(tags=["ch1", "rpt"])
        """
        if tags is None:
            tags = []
        return f"{self._csv_dir}/{self.create_generic_fname(tags=tags, ext='csv')}"

    def create_png_fname(self, tags: list[str] = None) -> PathLike:
        """
        Build a PNG filename of the form:
            <png_dir>/<mac>_<model>_<timestamp>[_TAGS].png

        Example:
            fname = self.create_png_fname(tags=["spectrum"])
        """
        if tags is None:
            tags = []
        return f"{self._png_dir}/{self.create_generic_fname(tags=tags, ext='png')}"

    def create_json_fname(self, tags: list[str] = None) -> PathLike:
        """
        Build a PNG filename of the form:
            <json_dir>/<mac>_<model>_<timestamp>[_TAGS].json

        Example:
            fname = self.create_json_fname(tags=["spectrum"])
        """
        if tags is None:
            tags = []
        return f"{self._json_dir}/{self.create_generic_fname(tags=tags, ext='json')}"

    def create_archive_fname(self, tags: list[str] = None) -> PathLike:
        """
        Build a ZIP archive filename of the form:
            <archive_dir>/<mac>_<model>_<timestamp>[_TAGS].zip

        Example:
            fname = self.create_archive_fname(tags=["bundle"])
        """
        if tags is None:
            tags = []
        return f"{self._archive_dir}/{self.create_generic_fname(tags=tags, ext='zip')}"

    def create_generic_fname(self, tags: list[str], ext: str = "") -> str:
        """
        Generate a generic filename using the current session metadata plus tags.

        Args:
            tags: Optional descriptors to append (e.g., ["ch1", "rpt"]).
            ext:  Optional file extension (e.g., "csv", ".png").

        Returns:
            The constructed filename (no directories).

        Example:
            name = self.create_generic_fname(tags=["debug"], ext="json")
        """
        return self._generate_fname(tags=tags, ext=ext)

    def csv_manager_factory(self) -> CSVManager:
        """Return a `CSVManager` instance. Subclasses may override to customize behavior."""
        return CSVManager()

    def get_base_filename(self) -> str:
        """
        Return the base filename (no extension) derived from MAC/model/time.

        Useful when emitting multiple related files for the same report run.
        """
        return self._generate_fname()

    def build_report(self) -> Path:
        """
        Run the full report pipeline: `_process()` → CSV generation → plot rendering → ZIP.

        Returns:
            The path to the created ZIP archive.

        Typical use:
            archive = report.build_report()
            return report.to_model()
        """
        self._process()

        f: PathArray = [Path("")]

        for csv_mgr in self.create_csv():
            if not csv_mgr.write():
                self.logger.error(f"Failed to write CSV: {csv_mgr.get_path_fname()}")
                continue

            self.logger.debug(f"Wrote CSV File: {csv_mgr.get_path_fname()}")
            self.csv_files.append(csv_mgr.get_path_fname())
            f.append(csv_mgr.get_path_fname())

        for matplot_mgr in self.create_matplot():
            for fn in matplot_mgr.get_png_files():
                self.logger.debug(f"Wrote Matplotlib Figure: {fn}")
                self.plot_files.append(fn)
                f.append(fn)

        if not self.json_files:
            self.logger.warning("No JSON files were registered for the report archive.")
        else:
            f.extend(self.json_files)

        try:
            self.archive_file = ArchiveManager().zip_files(
                files=f, archive_path=self.create_archive_fname()
            )

        except Exception as e:
            self.logger.error(f"Failed to create archive: {e}")

        return self.archive_file

    def _generate_fname(self, tags: list[str] = None, ext: str = "") -> str:
        """
        Construct a sanitized filename from:
          - MAC address (colon-free, lowercase)
          - device model (`system_description.model`, spaces → underscores, lowercase)
          - group timestamp
          - optional tag suffix (underscored)
          - optional extension

        Args:
            tags: Descriptive tokens to append (e.g., ["ch1", "rpt"]).
            ext:  Extension with or without leading dot.

        Returns:
            The finalized filename string (no directory).

        Example:
            self._generate_fname(tags=["ch1", "rpt"], ext="csv")
        """
        if tags is None:
            tags = []
        mac = self.getMacAddresses()[0].to_mac_format()
        model = self.get_system_description().model.replace(" ", "_").lower()
        ts = str(self.get_group_time())

        clean_tags = []
        for t in tags:
            t_clean = str(t).strip().replace(" ", "_").lower()
            if t_clean:
                clean_tags.append(t_clean)

        tag_part = f"_{'_'.join(clean_tags)}" if clean_tags else ""
        ext = ext.lstrip(".")
        ext_part = f".{ext}" if ext else ""

        return f"{mac}_{model}_{ts}{tag_part}{ext_part}"

    def getTransactionCollection(self) -> TransactionCollection:
        """Return the `TransactionCollection` instance used to collect capture files."""
        return self._trans_collect

    def register_models_for_json_archive_files(
        self,
        model: BaseModel,
        filename_tags: list[str],
        append_timestamp: bool = True,
        transaction_id: TransactionId | None = None,
    ) -> None:
        """
        Register a Pydantic model to be serialized as JSON and included in the report archive.
        """

        # model is a Pydantic BaseModel instance, but it can be any subclass
        # We need to make sure its initial derive is from BaseModel
        if not isinstance(model, BaseModel):
            raise TypeError("model must be a Pydantic BaseModel instance")

        if append_timestamp:
            filename_tags.append(str(Generate.time_stamp(TimeUnit.NANOSECONDS)))

        full_path_fname = self.create_json_fname(tags=filename_tags)

        JsonTransactionDb().write_json(
            data=model.model_dump(),
            fname=Path(full_path_fname).parts[-1],
            transaction_id=transaction_id,
        )

        self.json_files.append(full_path_fname)

    @abstractmethod
    def _process(self) -> None:
        """
        Populate per-channel report models from analysis results.

        Implement in subclasses:
            - Parse `self.get_analysis_model()` and/or `self.get_analysis_data()`.
            - Build models and register with:
                `self.register_common_analysis_model(channel_id, model)`.
        """
        pass

    @abstractmethod
    def create_csv(self, **kwargs: JsonScalar) -> list[CSVManager]:
        """
        Build one or more `CSVManager` instances ready to `write()`.

        Parameters
        ----------
        **kwargs : JsonScalar
            Optional configuration flags or scalar parameters (ints, floats,
            strings, booleans, or None) used by concrete implementations.

        Returns
        -------
        list[CSVManager]
            List of configured `CSVManager` instances ready to write.
        """
        return []

    @abstractmethod
    def create_matplot(self, **kwargs: JsonScalar) -> list[MatplotManager]:
        """
        Build one or more `MatplotManager` instances to render PNG figures.

        Parameters
        ----------
        **kwargs : JsonScalar
            Optional configuration flags or scalar parameters (ints, floats,
            strings, booleans, or None) used by concrete implementations.

        Returns
        -------
        list[MatplotManager]
            List of configured `MatplotManager` instances used to generate plots.
        """
        return []
