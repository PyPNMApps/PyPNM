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
