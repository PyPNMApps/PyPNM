## Agent Review Bundle Summary
- Goal: M3 cutover to DB-backed transactions + artifact resolution, remove runtime dependency on transactions.json, and update docs/tests.
- Changes: Added artifact repository and resolver, wired capture/upload paths to register artifacts, migrated file-manager resolution to DB artifacts, added DB-backed tests and ledger guards, updated docs to reflect DB authority.
- Files: src/pypnm/lib/db/artifact_repository.py; src/pypnm/lib/db/transaction_repository.py; src/pypnm/api/routes/common/classes/file_capture/pnm_file_transaction.py; src/pypnm/api/routes/docs/pnm/files/service.py; tests/test_artifact_repository.py; tests/test_pnm_file_hexdump.py; tests/test_pnm_file_artifact_resolution.py.
- Tests: python3 -m compileall src; ruff check src; ruff format --check .; pytest -q (603 passed, 9 skipped).
- Notes: Skips: PNM_CM_IT hardware integration and PYPNM_DB_POSTGRES_DSN-gated tests.

# FILE: src/pypnm/lib/db/artifact_repository.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from pypnm.lib.db.db_schema_manager import DEFAULT_ARTIFACT_STORE_NAME, DbConnection
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

ROLE_PREFERENCE: tuple[str, str] = (
    ROLE_PNM_RAW,
    ROLE_PNM_UPLOADED_RAW,
)

DEFAULT_MIME_TYPE: str = ""
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
        self, transaction_id: TransactionId, roles: tuple[str, str] = ROLE_PREFERENCE
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

    def _get_default_store(self, connection: DbConnection) -> ArtifactStoreRow:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    "SELECT store_id, root_path FROM artifact_stores WHERE store_name = ?;",
                    (DEFAULT_ARTIFACT_STORE_NAME,),
                )
                row = cursor.fetchone()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT store_id, root_path FROM artifact_stores WHERE store_name = %s;",
                        (DEFAULT_ARTIFACT_STORE_NAME,),
                    )
                    row = cursor.fetchone()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")
        if not row:
            raise RuntimeError("Default artifact store row is missing")
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
                        DEFAULT_MIME_TYPE,
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
                            DEFAULT_MIME_TYPE,
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

# FILE: src/pypnm/lib/db/transaction_repository.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Self
else:
    from typing_extensions import Self

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.data_type.sysDescr import SystemDescriptor
from pypnm.lib.db.db_schema_manager import (
    UNKNOWN_SYSDESCR_HASH,
    DatabaseSchemaManager,
    DbConnection,
)
from pypnm.lib.mac_address import MacAddress, MacAddressFormat
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    FileName,
    HashStr,
    MacAddressStr,
    TimestampSec,
    TransactionId,
)

_UNKNOWN_FIELD_VALUE: str = "UNKNOWN"
_EMPTY_JSON_OBJECT: str = "{}"
_IS_UNKNOWN_TRUE: int = 1
_IS_UNKNOWN_FALSE: int = 0


@dataclass(frozen=True)
class MacAddressDescriptorRow:
    mac_address: MacAddressStr
    system_description: dict[str, str] | None


@dataclass(frozen=True)
class TransactionRecordRow:
    transaction_id: TransactionId
    timestamp_epoch: TimestampSec
    mac_address: MacAddressStr
    pnm_test_type: str
    filename: FileName
    system_description: dict[str, str] | None


class _RepositoryBase:
    def __init__(
        self,
        backend: DatabaseBackend,
        sqlite_path: DatabasePath,
        postgres_dsn: DatabaseDsn,
    ) -> None:
        self._backend = backend
        self._schema_manager = DatabaseSchemaManager.from_overrides(
            backend, sqlite_path, postgres_dsn
        )
        self.logger = logging.getLogger(f"{self.__class__.__name__}")

    @classmethod
    def _from_system_config(cls) -> Self:
        return cls(
            SystemConfigSettings.database_backend(),
            SystemConfigSettings.database_sqlite_path(),
            SystemConfigSettings.database_postgres_dsn(),
        )

    def _connect(self) -> DbConnection:
        connection = self._schema_manager.connect()
        if self._backend == DatabaseBackend.SQLITE:
            connection.execute("PRAGMA foreign_keys = ON;")
            cursor = connection.execute("PRAGMA foreign_keys;")
            row = cursor.fetchone()
            if row and row[0] != 1:
                self.logger.debug(
                    "SQLite foreign_keys PRAGMA not enabled (value=%s)",
                    row[0],
                )
        return connection

    def _resolve_app_root(self) -> Path:
        return self._schema_manager._resolve_app_root()

    @staticmethod
    def _canonical_json(data: dict[str, object]) -> str:
        return json.dumps(data, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _hash_json(data: dict[str, object]) -> HashStr:
        payload = _RepositoryBase._canonical_json(data).encode("utf-8")
        return HashStr(hashlib.sha256(payload).hexdigest())

    @staticmethod
    def _load_json_value(value: object) -> dict[str, object]:
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                return {}
            if isinstance(parsed, dict):
                return parsed
        return {}


class SystemDescriptionRepository(_RepositoryBase):
    """
    Repository for the system_description_dim dimension table.
    """

    @classmethod
    def from_system_config(cls) -> SystemDescriptionRepository:
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
    ) -> SystemDescriptionRepository:
        """
        Build a repository using explicit backend overrides.
        """
        return cls(backend, sqlite_path, postgres_dsn)

    def get_or_create_sysdescr_id(self, sysdescr_json: dict[str, str] | None) -> int:
        """
        Resolve or insert a sysDescr row and return its primary key.
        """
        normalized = self._normalize_sysdescr_json(sysdescr_json)
        is_unknown = not normalized
        if is_unknown:
            sysdescr_hash = UNKNOWN_SYSDESCR_HASH
            hw_rev = _UNKNOWN_FIELD_VALUE
            vendor = _UNKNOWN_FIELD_VALUE
            bootr = _UNKNOWN_FIELD_VALUE
            sw_rev = _UNKNOWN_FIELD_VALUE
            model = _UNKNOWN_FIELD_VALUE
            sysdescr_payload = _EMPTY_JSON_OBJECT
        else:
            sysdescr_hash = str(self._hash_json(normalized))
            hw_rev = normalized.get("HW_REV", "")
            vendor = normalized.get("VENDOR", "")
            bootr = normalized.get("BOOTR", "")
            sw_rev = normalized.get("SW_REV", "")
            model = normalized.get("MODEL", "")
            sysdescr_payload = self._canonical_json(normalized)

        connection = self._connect()
        try:
            existing = self._fetch_sysdescr_id(connection, sysdescr_hash)
            if existing is not None:
                return existing
            self._insert_sysdescr(
                connection,
                hw_rev,
                vendor,
                bootr,
                sw_rev,
                model,
                sysdescr_payload,
                sysdescr_hash,
                is_unknown,
            )
            fetched = self._fetch_sysdescr_id(connection, sysdescr_hash)
            if fetched is None:
                raise RuntimeError("Failed to resolve sysdescr_id after insert")
            return fetched
        finally:
            connection.close()

    @staticmethod
    def _normalize_sysdescr_json(
        sysdescr_json: dict[str, str] | None,
    ) -> dict[str, str]:
        if not sysdescr_json:
            return {}
        cleaned = {key: str(value) for key, value in sysdescr_json.items()}
        normalized = SystemDescriptor.load_from_dict(cleaned).to_dict()
        if not any(value.strip() for value in normalized.values()):
            return {}
        return normalized

    def _fetch_sysdescr_id(
        self, connection: DbConnection, sysdescr_hash: str
    ) -> int | None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    "SELECT sysdescr_id FROM system_description_dim WHERE sysdescr_hash = ?;",
                    (sysdescr_hash,),
                )
                row = cursor.fetchone()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT sysdescr_id FROM system_description_dim WHERE sysdescr_hash = %s;",
                        (sysdescr_hash,),
                    )
                    row = cursor.fetchone()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")
        if not row:
            return None
        return int(row[0])

    def _insert_sysdescr(
        self,
        connection: DbConnection,
        hw_rev: str,
        vendor: str,
        bootr: str,
        sw_rev: str,
        model: str,
        sysdescr_json: str,
        sysdescr_hash: str,
        is_unknown: bool,
    ) -> None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO system_description_dim (
                        hw_rev, vendor, bootr, sw_rev, model,
                        sysdescr_json, sysdescr_hash, is_unknown
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        hw_rev,
                        vendor,
                        bootr,
                        sw_rev,
                        model,
                        sysdescr_json,
                        sysdescr_hash,
                        _IS_UNKNOWN_TRUE if is_unknown else _IS_UNKNOWN_FALSE,
                    ),
                )
                connection.commit()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO system_description_dim (
                            hw_rev, vendor, bootr, sw_rev, model,
                            sysdescr_json, sysdescr_hash, is_unknown
                        )
                        VALUES (%s, %s, %s, %s, %s, CAST(%s AS jsonb), %s, %s)
                        ON CONFLICT (sysdescr_hash) DO NOTHING;
                        """,
                        (
                            hw_rev,
                            vendor,
                            bootr,
                            sw_rev,
                            model,
                            sysdescr_json,
                            sysdescr_hash,
                            is_unknown,
                        ),
                    )
                connection.commit()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")


class DeviceDetailsRepository(_RepositoryBase):
    """
    Repository for the device_details dimension table.
    """

    @classmethod
    def from_system_config(cls) -> DeviceDetailsRepository:
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
    ) -> DeviceDetailsRepository:
        """
        Build a repository using explicit backend overrides.
        """
        return cls(backend, sqlite_path, postgres_dsn)

    def get_or_create_device_detail_id(
        self, device_details_json: dict[str, object], sysdescr_id: int
    ) -> int:
        """
        Resolve or insert a device_details row and return its primary key.
        """
        payload = device_details_json or {}
        device_details_hash = str(self._hash_json(payload))
        payload_json = self._canonical_json(payload)

        connection = self._connect()
        try:
            existing = self._fetch_device_detail_id(connection, device_details_hash)
            if existing is not None:
                return existing
            self._insert_device_details(
                connection, sysdescr_id, payload_json, device_details_hash
            )
            fetched = self._fetch_device_detail_id(connection, device_details_hash)
            if fetched is None:
                raise RuntimeError("Failed to resolve device_detail_id after insert")
            return fetched
        finally:
            connection.close()

    def _fetch_device_detail_id(
        self, connection: DbConnection, device_details_hash: str
    ) -> int | None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    "SELECT device_detail_id FROM device_details WHERE device_details_hash = ?;",
                    (device_details_hash,),
                )
                row = cursor.fetchone()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT device_detail_id FROM device_details WHERE device_details_hash = %s;",
                        (device_details_hash,),
                    )
                    row = cursor.fetchone()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")
        if not row:
            return None
        return int(row[0])

    def _insert_device_details(
        self,
        connection: DbConnection,
        sysdescr_id: int,
        device_details_json: str,
        device_details_hash: str,
    ) -> None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO device_details (
                        sysdescr_id, device_details_json, device_details_hash
                    )
                    VALUES (?, ?, ?);
                    """,
                    (sysdescr_id, device_details_json, device_details_hash),
                )
                connection.commit()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO device_details (
                            sysdescr_id, device_details_json, device_details_hash
                        )
                        VALUES (%s, CAST(%s AS jsonb), %s)
                        ON CONFLICT (device_details_hash) DO NOTHING;
                        """,
                        (sysdescr_id, device_details_json, device_details_hash),
                    )
                connection.commit()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")


class TransactionRepository(_RepositoryBase):
    """
    Repository for transaction_records and related queries.
    """

    @classmethod
    def from_system_config(cls) -> TransactionRepository:
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
    ) -> TransactionRepository:
        """
        Build a repository using explicit backend overrides.
        """
        return cls(backend, sqlite_path, postgres_dsn)

    def insert_transaction(
        self,
        transaction_id: TransactionId,
        timestamp_epoch: TimestampSec,
        mac_address: MacAddress | MacAddressStr | str,
        pnm_test_type: str,
        filename: FileName | str,
        device_detail_id: int,
    ) -> None:
        """
        Insert a transaction record (idempotent on transaction_id).
        """
        mac_str = self._normalize_mac(mac_address)
        connection = self._connect()
        try:
            match self._backend:
                case DatabaseBackend.SQLITE:
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO transaction_records (
                            transaction_id, timestamp_epoch, mac_address,
                            pnm_test_type, filename, device_detail_id
                        )
                        VALUES (?, ?, ?, ?, ?, ?);
                        """,
                        (
                            str(transaction_id),
                            int(timestamp_epoch),
                            mac_str,
                            pnm_test_type,
                            str(filename),
                            device_detail_id,
                        ),
                    )
                    connection.commit()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            """
                            INSERT INTO transaction_records (
                                transaction_id, timestamp_epoch, mac_address,
                                pnm_test_type, filename, device_detail_id
                            )
                            VALUES (%s, %s, %s, %s, %s, %s)
                            ON CONFLICT (transaction_id) DO NOTHING;
                            """,
                            (
                                str(transaction_id),
                                int(timestamp_epoch),
                                mac_str,
                                pnm_test_type,
                                str(filename),
                                device_detail_id,
                            ),
                        )
                    connection.commit()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
        finally:
            connection.close()

    def list_macs(self) -> list[MacAddressDescriptorRow]:
        """
        List distinct MAC addresses with best-effort system_description metadata.
        """
        connection = self._connect()
        try:
            rows = self._fetch_mac_rows(connection)
        finally:
            connection.close()

        latest_by_mac: dict[str, tuple[int, dict[str, str] | None]] = {}
        for mac_str, timestamp_epoch, device_details_json in rows:
            normalized_mac = str(mac_str).lower().strip()
            if not normalized_mac:
                continue
            system_description = self._extract_system_description(device_details_json)
            existing = latest_by_mac.get(normalized_mac)
            if existing is None:
                latest_by_mac[normalized_mac] = (timestamp_epoch, system_description)
                continue
            existing_ts, _existing_sd = existing
            if timestamp_epoch >= existing_ts:
                latest_by_mac[normalized_mac] = (timestamp_epoch, system_description)

        results: list[MacAddressDescriptorRow] = []
        for mac_str, (_ts, system_description) in sorted(
            latest_by_mac.items(), key=lambda item: item[0]
        ):
            results.append(
                MacAddressDescriptorRow(
                    mac_address=MacAddressStr(mac_str),
                    system_description=system_description,
                )
            )

        return results

    def list_transactions_for_mac(
        self, mac_address: MacAddress | MacAddressStr | str
    ) -> list[TransactionRecordRow]:
        """
        List all transactions for a MAC address ordered by timestamp.
        """
        mac_str = self._normalize_mac(mac_address)
        connection = self._connect()
        try:
            rows = self._fetch_transaction_rows_for_mac(connection, mac_str)
        finally:
            connection.close()
        return self._transaction_rows_from_query(rows)

    def list_all_transactions(self) -> list[TransactionRecordRow]:
        """
        List all transactions ordered by timestamp.
        """
        connection = self._connect()
        try:
            rows = self._fetch_all_transaction_rows(connection)
        finally:
            connection.close()
        return self._transaction_rows_from_query(rows)

    def get_transaction_record(
        self, transaction_id: TransactionId
    ) -> TransactionRecordRow | None:
        """
        Fetch a transaction record by identifier.
        """
        connection = self._connect()
        try:
            row = self._fetch_transaction_row_by_id(connection, str(transaction_id))
        finally:
            connection.close()

        if row is None:
            return None
        return self._transaction_row_from_tuple(row)

    def _fetch_mac_rows(
        self, connection: DbConnection
    ) -> list[tuple[str, int, object]]:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    """
                    SELECT t.mac_address, t.timestamp_epoch, d.device_details_json
                    FROM transaction_records t
                    JOIN device_details d ON t.device_detail_id = d.device_detail_id
                    ORDER BY t.timestamp_epoch DESC;
                    """
                )
                rows = cursor.fetchall()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT t.mac_address, t.timestamp_epoch, d.device_details_json
                        FROM transaction_records t
                        JOIN device_details d ON t.device_detail_id = d.device_detail_id
                        ORDER BY t.timestamp_epoch DESC;
                        """
                    )
                    rows = cursor.fetchall()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")

        return [(str(row[0]), int(row[1]), row[2]) for row in rows]

    def _fetch_transaction_rows_for_mac(
        self, connection: DbConnection, mac_address: str
    ) -> list[tuple[str, int, str, str, str, object]]:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    """
                    SELECT t.transaction_id, t.timestamp_epoch, t.mac_address,
                           t.pnm_test_type, t.filename, d.device_details_json
                    FROM transaction_records t
                    JOIN device_details d ON t.device_detail_id = d.device_detail_id
                    WHERE t.mac_address = ?
                    ORDER BY t.timestamp_epoch ASC, t.transaction_id ASC;
                    """,
                    (mac_address,),
                )
                rows = cursor.fetchall()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT t.transaction_id, t.timestamp_epoch, t.mac_address,
                               t.pnm_test_type, t.filename, d.device_details_json
                        FROM transaction_records t
                        JOIN device_details d ON t.device_detail_id = d.device_detail_id
                        WHERE t.mac_address = %s
                        ORDER BY t.timestamp_epoch ASC, t.transaction_id ASC;
                        """,
                        (mac_address,),
                    )
                    rows = cursor.fetchall()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")

        return [
            (
                str(row[0]),
                int(row[1]),
                str(row[2]),
                str(row[3]),
                str(row[4]),
                row[5],
            )
            for row in rows
        ]

    def _fetch_all_transaction_rows(
        self, connection: DbConnection
    ) -> list[tuple[str, int, str, str, str, object]]:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    """
                    SELECT t.transaction_id, t.timestamp_epoch, t.mac_address,
                           t.pnm_test_type, t.filename, d.device_details_json
                    FROM transaction_records t
                    JOIN device_details d ON t.device_detail_id = d.device_detail_id
                    ORDER BY t.timestamp_epoch ASC, t.transaction_id ASC;
                    """
                )
                rows = cursor.fetchall()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT t.transaction_id, t.timestamp_epoch, t.mac_address,
                               t.pnm_test_type, t.filename, d.device_details_json
                        FROM transaction_records t
                        JOIN device_details d ON t.device_detail_id = d.device_detail_id
                        ORDER BY t.timestamp_epoch ASC, t.transaction_id ASC;
                        """
                    )
                    rows = cursor.fetchall()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")

        return [
            (
                str(row[0]),
                int(row[1]),
                str(row[2]),
                str(row[3]),
                str(row[4]),
                row[5],
            )
            for row in rows
        ]

    def _fetch_transaction_row_by_id(
        self, connection: DbConnection, transaction_id: str
    ) -> tuple[str, int, str, str, str, object] | None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    """
                    SELECT t.transaction_id, t.timestamp_epoch, t.mac_address,
                           t.pnm_test_type, t.filename, d.device_details_json
                    FROM transaction_records t
                    JOIN device_details d ON t.device_detail_id = d.device_detail_id
                    WHERE t.transaction_id = ?;
                    """,
                    (transaction_id,),
                )
                row = cursor.fetchone()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT t.transaction_id, t.timestamp_epoch, t.mac_address,
                               t.pnm_test_type, t.filename, d.device_details_json
                        FROM transaction_records t
                        JOIN device_details d ON t.device_detail_id = d.device_detail_id
                        WHERE t.transaction_id = %s;
                        """,
                        (transaction_id,),
                    )
                    row = cursor.fetchone()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")

        if row is None:
            return None
        return (
            str(row[0]),
            int(row[1]),
            str(row[2]),
            str(row[3]),
            str(row[4]),
            row[5],
        )

    @staticmethod
    def _normalize_mac(mac_address: MacAddress | MacAddressStr | str) -> str:
        if isinstance(mac_address, MacAddress):
            return mac_address.to_mac_format(MacAddressFormat.COLON).lower()
        normalized = MacAddress(mac_address).to_mac_format(MacAddressFormat.COLON)
        return str(normalized).lower()

    def _transaction_rows_from_query(
        self, rows: list[tuple[str, int, str, str, str, object]]
    ) -> list[TransactionRecordRow]:
        records: list[TransactionRecordRow] = []
        for row in rows:
            record = self._transaction_row_from_tuple(row)
            records.append(record)
        return records

    def _transaction_row_from_tuple(
        self, row: tuple[str, int, str, str, str, object]
    ) -> TransactionRecordRow:
        system_description = self._extract_system_description(row[5])
        return TransactionRecordRow(
            transaction_id=TransactionId(row[0]),
            timestamp_epoch=TimestampSec(int(row[1])),
            mac_address=MacAddressStr(row[2]),
            pnm_test_type=row[3],
            filename=FileName(row[4]),
            system_description=system_description,
        )

    def _extract_system_description(
        self, device_details_json: object
    ) -> dict[str, str] | None:
        payload = self._load_json_value(device_details_json)
        if not payload:
            return None
        sysdesc = payload.get("system_description")
        if not isinstance(sysdesc, dict):
            return None
        cleaned: dict[str, str] = {}
        for key, value in sysdesc.items():
            cleaned[str(key)] = str(value)
        return cleaned or None

# FILE: src/pypnm/api/routes/common/classes/file_capture/pnm_file_transaction.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import hashlib
import logging
import time
from pathlib import Path
from typing import cast

from pypnm.lib.db.artifact_repository import (
    ROLE_PNM_UPLOADED_RAW,
    ArtifactRepository,
)

from pypnm.api.routes.common.classes.file_capture.types import (
    DeviceDetailsModel,
    TransactionRecordModel,
)
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.sysDescr import SystemDescriptor
from pypnm.lib.db.transaction_repository import (
    DeviceDetailsRepository,
    SystemDescriptionRepository,
    TransactionRecordRow,
    TransactionRepository,
)
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import FileName, TimestampSec, TransactionId
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest


class PnmFileTransaction:
    """
    Manages persistent tracking of PNM file transactions across the PyPNM system.

    Each transaction corresponds to a PNM test result file (e.g., RxMER, Spectrum Analysis),
    whether generated through automated measurements or manually uploaded by a user.

    A transaction includes:
        - A unique transaction ID (16-char SHA-256 digest)
        - Timestamp (epoch time)
        - MAC address of the cable modem
        - PNM test type (e.g., DS_RXMER, SPECTRUM_ANALYZER)
        - Filename of the associated binary data file

    Transactions are stored in the configured database backend (SQLite/Postgres)
    using the DB schema defined under docs/design/db/.

    Usage Scenarios:
        - When a measurement test completes and produces a file.
        - When a user uploads a file manually via the REST API.
        - When retrieving metadata about previously captured test files.

    Record structure mirrors the legacy JSON layout so downstream parsers stay stable:
        {
            "timestamp": int,
            "mac_address": "<cable modem mac address>",
            "pnm_test_type": "<PNM Test Type>",
            "filename": "<FileName>",
            "device_details": {
                "system_description": { ... }
            }
        }
    """

    PNM_TEST_TYPE = "pnm_test_type"
    FILE_NAME = "filename"
    DEVICE_DETAILS = "device_details"
    MAC_ADDRESS = "mac_address"

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self._sysdescr_repo = SystemDescriptionRepository.from_system_config()
        self._device_details_repo = DeviceDetailsRepository.from_system_config()
        self._transaction_repo = TransactionRepository.from_system_config()
        self._artifact_repo = ArtifactRepository.from_system_config()

    async def insert(
        self, cable_modem: CableModem, pnm_test_type: DocsPnmCmCtlTest, filename: str
    ) -> TransactionId:
        """
        Record A Transaction Initiated From An Actual Cable Modem Test.

        This method is invoked by measurement services once a PNM capture has
        successfully completed and produced a result file. It pulls the current
        system description from the cable modem, generates a new transaction
        identifier, and appends a normalized record into the transaction
        database.

        Parameters
        ----------
        cable_modem:
            Live `CableModem` instance representing the device under test. Used
            to obtain the MAC address and system description snapshot.
        pnm_test_type:
            Enumeration value describing which PNM test produced the file
            (for example, DS_RXMER, DS_OFDM_HISTOGRAM, DS_CONSTELLATION).
        filename:
            Relative or absolute path to the generated PNM binary file, as
            stored by the calling measurement service.

        Returns
        -------
        str
            Newly generated transaction identifier (16-character SHA-256
            digest prefix) suitable for later lookup (download and analysis).
        """
        sd: SystemDescriptor = await cable_modem.getSysDescr()
        mac_address_value = cable_modem.get_mac_address
        if callable(mac_address_value):
            mac_address_value = mac_address_value()
        return self._insert_generic(
            mac_address=cast(MacAddress, mac_address_value),
            pnm_test_type=pnm_test_type,
            filename=filename,
            system_description=sd.to_dict(),
        )

    @staticmethod
    def set_file_by_user(
        mac_address: MacAddress, pnm_test_type: DocsPnmCmCtlTest, filename: FileName
    ) -> TransactionId:
        """
        Record A Transaction For A Manually Supplied File (User Upload).

        This path is used when the file is not the result of an automated test
        initiated by PyPNM, but rather provided by the user (for example, a
        lab-captured PNM file uploaded via REST). The record is normalized into
        the same transaction database used for automated captures.

        Parameters
        ----------
        mac_address:
            MAC address of the cable modem associated with the uploaded file.
        pnm_test_type:
            Enumeration describing the semantic PNM test type for the file,
            allowing downstream analysis routing to behave consistently.
        filename:
            Filesystem path or name where the uploaded file has been stored on
            the server.

        Returns
        -------
        str
            Newly generated transaction identifier bound to the uploaded file.
        """
        txn = PnmFileTransaction()
        transaction_id = txn._insert_generic(
            mac_address=mac_address,
            pnm_test_type=pnm_test_type,
            filename=filename,
        )
        if str(transaction_id).strip():
            txn.register_pnm_artifact(transaction_id, filename, ROLE_PNM_UPLOADED_RAW)
        return transaction_id

    def register_pnm_artifact(
        self, transaction_id: TransactionId, filename: FileName | str, role: str
    ) -> None:
        """
        Register a stored PNM file artifact for a transaction.

        Parameters
        ----------
        transaction_id:
            Transaction identifier to bind to the artifact record.
        filename:
            File name or relative path of the stored PNM file under the
            configured artifact store root.
        role:
            Artifact role used for resolution (for example: pnm_raw or
            pnm_uploaded_raw).
        """
        if not str(transaction_id).strip():
            self.logger.warning(
                "Skipping artifact registration for empty transaction_id (filename=%s)",
                filename,
            )
            return
        file_path = self._resolve_pnm_path(filename)
        created_epoch = TimestampSec(int(time.time()))
        self._artifact_repo.register_transaction_artifact(
            transaction_id=transaction_id,
            file_path=file_path,
            role=role,
            created_epoch=created_epoch,
        )

    @staticmethod
    def _resolve_pnm_path(filename: FileName | str) -> Path:
        pnm_dir = SystemConfigSettings.pnm_dir()
        return Path(pnm_dir) / str(filename)

    def get_record(self, transaction_id: TransactionId) -> dict | None:
        """
        Fetch A Plain Dictionary Representation Of A Transaction Record.

        This method provides a minimal, schema-free view into the transaction
        database. It is intended for low-level callers that need direct access
        to the stored fields without constructing a Pydantic model.

        Parameters
        ----------
        transaction_id:
            Unique transaction identifier for the record to retrieve.

        Returns
        -------
        dict | None
            The underlying transaction record as a dictionary, or `None` when
            the identifier does not exist in the database.
        """
        record = self._transaction_repo.get_transaction_record(transaction_id)
        if record is None:
            return None
        return self._record_to_payload(record)

    def get(self, transaction_id: TransactionId) -> dict | None:
        return self.get_record(transaction_id)

    def getRecordModel(self, transaction_id: TransactionId) -> TransactionRecordModel:
        """
        Build A Canonical TransactionRecordModel For A Transaction Identifier.

        This convenience wrapper resolves the DB-backed record and constructs
        the normalized Pydantic model. If the record does not exist, a
        `null()` sentinel model is returned.

        Parameters
        ----------
        transaction_id:
            Unique transaction identifier for which a model representation is
            requested.

        Returns
        -------
        TransactionRecordModel
            Canonical, fully-normalized transaction model, or the sentinel
            `TransactionRecordModel.null()` instance for missing records.
        """
        record = self._transaction_repo.get_transaction_record(transaction_id)
        if record is None:
            return TransactionRecordModel.null()
        return self._record_to_model(record)

    def get_file_info_via_macaddress(
        self, mac_address: MacAddress
    ) -> list[TransactionRecordModel]:
        """
        Retrieve All Transaction Records Associated With A Given MAC Address.

        This method scans the transaction database and collects all entries
        whose stored `mac_address` matches the supplied cable modem MAC (case-
        insensitive). Each matching record is returned as a fully normalized
        `TransactionRecordModel`, using the same parsing logic as individual
        lookups.

        Typical usage patterns include:
        - Building a catalog of all PNM files available for a modem.
        - Populating UI tables of historical captures keyed by MAC address.
        - Providing selection lists for downstream download or analysis calls.

        Parameters
        ----------
        mac_address:
            Cable modem MAC address used as the primary lookup key. The value
            is normalized to lower-case for comparison against stored records.

        Returns
        -------
        List[TransactionRecordModel]
            List of canonical `TransactionRecordModel` instances for all
            transactions associated with the given MAC address. The list is
            empty when no matching records are found.
        """
        records = self._transaction_repo.list_transactions_for_mac(mac_address)
        models: list[TransactionRecordModel] = []
        for record in records:
            model = self._record_to_model(record)
            models.append(model)
        return models

    def get_all_record_models(self) -> list[TransactionRecordModel]:
        """
        Retrieve All Transaction Records As Canonical Models.

        This scans the transaction database and returns each record as a fully
        normalized `TransactionRecordModel`. Any per-record parse failures are
        logged and skipped so callers can still operate on partial data.

        Returns
        -------
        list[TransactionRecordModel]
            List of all transaction models currently stored in the transaction
            database. The list is empty when no records exist.
        """
        records = self._transaction_repo.list_all_transactions()
        if not records:
            return []

        models: list[TransactionRecordModel] = []
        for record in records:
            model = self._safe_record_model(record)
            if model is not None:
                models.append(model)

        return models

    def _safe_record_model(
        self, record: TransactionRecordRow
    ) -> TransactionRecordModel | None:
        try:
            return self._record_to_model(record)
        except Exception as exc:
            self.logger.warning("Skipping transaction due to parse error: %s", exc)
            return None

    # ---------------------------
    # Write helpers
    # ---------------------------

    def _insert_generic(
        self,
        mac_address: MacAddress,
        pnm_test_type: DocsPnmCmCtlTest,
        filename: str,
        system_description: dict[str, str] | None = None,
    ) -> TransactionId:
        """
        Common Logic For Creating And Persisting A Transaction Record.

        This internal helper generates a new transaction identifier, assembles
        the DB-backed record structure, and persists the transaction to the
        configured database backend.

        Parameters
        ----------
        mac_address:
            MAC address of the cable modem associated with the transaction.
        pnm_test_type:
            Enumeration describing the PNM test type that produced or owns the
            associated file.
        filename:
            Path or name of the PNM data file linked to this transaction.
        system_description:
            Optional system description snapshot dictionary, typically produced
            via `SystemDescriptor.to_dict()`. When omitted, an empty mapping is
            stored under `device_details.system_description`.

        Returns
        -------
        str
            Newly created transaction identifier associated with the record.
        """
        timestamp = int(time.time())
        hash_input = (
            f"{filename}{mac_address}{pnm_test_type.name}{time.time_ns()}"
        ).encode()
        transaction_id = TransactionId(hashlib.sha256(hash_input).hexdigest()[:16])
        tx_id = str(transaction_id)
        if not tx_id.strip():
            self.logger.warning(
                "Skipping transaction insert for empty transaction_id (filename=%s, mac=%s)",
                filename,
                mac_address,
            )
            return TransactionId("")

        normalized_sd = self._normalize_system_description(system_description)
        device_details = {"system_description": normalized_sd}
        sysdescr_payload = normalized_sd if normalized_sd else None
        sysdescr_id = self._sysdescr_repo.get_or_create_sysdescr_id(sysdescr_payload)
        device_detail_id = self._device_details_repo.get_or_create_device_detail_id(
            device_details, sysdescr_id
        )
        self._transaction_repo.insert_transaction(
            transaction_id=transaction_id,
            timestamp_epoch=TimestampSec(timestamp),
            mac_address=mac_address,
            pnm_test_type=pnm_test_type.name,
            filename=filename,
            device_detail_id=device_detail_id,
        )
        return transaction_id

    @staticmethod
    def _normalize_system_description(
        system_description: dict[str, str] | None,
    ) -> dict[str, str]:
        if not system_description:
            return {}
        return SystemDescriptor.load_from_dict(system_description).to_dict()

    def _record_to_payload(self, record: TransactionRecordRow) -> dict:
        return {
            "timestamp": int(record.timestamp_epoch),
            "mac_address": str(record.mac_address),
            "pnm_test_type": record.pnm_test_type,
            "filename": str(record.filename),
            "device_details": {
                "system_description": record.system_description or {},
            },
        }

    def _record_to_model(self, record: TransactionRecordRow) -> TransactionRecordModel:
        sysdesc = record.system_description or {}
        system_description = SystemDescriptor.load_from_dict(sysdesc).to_model()
        return TransactionRecordModel(
            transaction_id=record.transaction_id,
            timestamp=TimestampSec(int(record.timestamp_epoch)),
            mac_address=record.mac_address,
            pnm_test_type=record.pnm_test_type,
            filename=record.filename,
            device_details=DeviceDetailsModel(system_description=system_description),
        )

# FILE: src/pypnm/api/routes/docs/pnm/files/service.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import cast

from fastapi import HTTPException
from fastapi.responses import FileResponse
from pypnm.lib.db.artifact_repository import (
    ROLE_PNM_RAW,
    ROLE_PNM_UPLOADED_RAW,
    ArtifactRepository,
)

from pypnm.api.routes.basic.abstract.analysis_report import AnalysisRptMatplotConfig
from pypnm.api.routes.basic.channel_estimation_analysis_rpt import ChanEstimationReport
from pypnm.api.routes.basic.constellation_display_analysis_rpt import (
    ConstDisplayAnalysisRptMatplotConfig,
    ConstellationDisplayReport,
)
from pypnm.api.routes.basic.fec_summary_analysis_rpt import FecSummaryAnalysisReport
from pypnm.api.routes.basic.modulation_profile_analysis_rpt import (
    ModulationProfileReport,
)
from pypnm.api.routes.basic.rxmer_analysis_rpt import RxMerAnalysisReport
from pypnm.api.routes.basic.us_ofdma_pre_eq_analysis_rpt import CmUsOfdmaPreEqReport
from pypnm.api.routes.common.classes.analysis.model.schema import (
    ParserAnalysisModelReturn,
)
from pypnm.api.routes.common.classes.file_capture.file_type import FileType
from pypnm.api.routes.common.classes.file_capture.pnm_file_opearation import (
    OperationCaptureGroupResolver,
)
from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.api.routes.docs.pnm.files.schemas import (
    FileAnalysisRequest,
    FileEntry,
    FileQueryRequest,
    FileQueryResponse,
    HexDumpResponse,
    MacAddressSystemDescriptorEntry,
    MacAddressSystemDescriptorResponse,
    UploadFileResponse,
)
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.archive.manager import ArchiveManager
from pypnm.lib.constants import MediaType
from pypnm.lib.db.transaction_repository import TransactionRepository
from pypnm.lib.file_processor import FileProcessor
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import (
    FileName,
    MacAddressStr,
    OperationId,
    PathLike,
    TransactionId,
)
from pypnm.lib.utils import Generate
from pypnm.pnm.parser.model.parser_rtn_models import (
    CmDsConstDispMeasModel,
    CmDsHistModel,
    CmDsOfdmChanEstimateCoefModel,
    CmDsOfdmFecSummaryModel,
    CmDsOfdmModulationProfileModel,
    CmDsOfdmRxMerModel,
    CmUsOfdmaPreEqModel,
)
from pypnm.pnm.parser.pnm_file_type import PnmFileType
from pypnm.pnm.parser.pnm_parameter import (
    GetPnmParserAndParameters,
    PnmParserParametersModel,
    PnmParsers,
)
from pypnm.pnm.parser.pnm_type_header_mapper import PnmFileTypeMapper


class PnmFileService:
    """
    Handles file storage, metadata registration, and high-level analysis
    for PNM-related binary data pushed into the PyPNM system.

    Methods:
        - search_files: List available files by MAC.
        - get_file_by_transaction_id: Download raw PNM file by transaction ID.
        - get_file_by_operation_id: Download all files for an operation as a ZIP.
        - get_file_by_mac_address: Download all files for a MAC as a ZIP.
        - upload_file: Accepts uploaded files, saves, and registers.
        - get_analysis: Produces analysis for a stored file.
        - get_file: Serve generated CSV/JSON/ARCHIVE files.
    """

    DEFAULT_HEXDUMP_BYTES_PER_LINE: int = 16

    def __init__(self) -> None:
        self.pnm_dir: PathLike = SystemConfigSettings.pnm_dir()
        self.logger = logging.getLogger(self.__class__.__name__)
        self._artifact_repo = ArtifactRepository.from_system_config()

    def search_files(self, req: FileQueryRequest) -> FileQueryResponse:
        """
        Searches for all registered PNM files tied to a specific MAC address.
        """
        try:
            mac = MacAddress(req.mac_address)
            txn = PnmFileTransaction()
            results = txn.get_file_info_via_macaddress(mac)

            if not results:
                self.logger.warning(f"No files found for MAC: {mac}")
                return FileQueryResponse(files={str(mac): []})

            file_entries: list[FileEntry] = []

            for entry in results:
                device_details = getattr(entry, "device_details", None)

                if hasattr(device_details, "model_dump"):
                    system_description = device_details.model_dump()
                elif isinstance(device_details, dict):
                    system_description = device_details
                else:
                    system_description = None

                file_entries.append(
                    FileEntry(
                        transaction_id=entry.transaction_id,
                        filename=entry.filename,
                        pnm_test_type=entry.pnm_test_type,
                        timestamp=entry.timestamp,
                        system_description=system_description,
                    )
                )

            return FileQueryResponse(files={str(mac): file_entries})

        except Exception as e:
            self.logger.error(f"Failed to search files for MAC {req.mac_address}: {e}")
            return FileQueryResponse(files={req.mac_address: []})

    def get_file_by_transaction_id(self, transaction_id: TransactionId) -> FileResponse:
        """
        Retrieves and serves the binary file associated with the given transaction ID.
        """
        full_path = self._resolve_pnm_artifact_path(transaction_id)

        self.logger.info(
            "Retrieving file for transaction %s: %s",
            transaction_id,
            full_path,
        )

        return FileResponse(
            path=full_path,
            filename=full_path.name,
            media_type=MediaType.APPLICATION_OCTET_STREAM,
        )

    def get_file_by_operation_id(self, operation_id: OperationId) -> FileResponse:
        """
        Retrieve All PNM Files For An Operation ID As A ZIP Archive.

        Resolves the capture group associated with the supplied operation ID,
        then collects all transaction records in that group, locates their
        corresponding PNM files on disk, and packages them into a single ZIP
        archive for download.
        """
        resolver = OperationCaptureGroupResolver()
        txn_models = resolver.get_transaction_models_for_operation(operation_id)

        if not txn_models:
            raise HTTPException(
                status_code=404, detail="No transactions found for Operation ID."
            )

        files_to_archive: list[Path] = []
        for rec in txn_models:
            src_path = self._resolve_pnm_artifact_path_optional(rec.transaction_id)
            if src_path is None or not src_path.is_file():
                self.logger.warning(
                    "Skipping missing file for transaction %s at %s",
                    rec.transaction_id,
                    src_path,
                )
                continue
            files_to_archive.append(src_path)

        if not files_to_archive:
            raise HTTPException(
                status_code=404, detail="No files on disk for Operation ID."
            )

        archive_dir = Path(SystemConfigSettings.archive_dir())
        archive_dir.mkdir(parents=True, exist_ok=True)

        archive_name = f"pnm_operation_{operation_id}_{Generate.time_stamp()}.zip"
        archive_path = archive_dir / archive_name

        ArchiveManager.zip_files(
            files=files_to_archive,
            archive_path=archive_path,
            mode="w",
            compression="zipdeflated",
            preserve_tree=False,
        )

        if not archive_path.is_file():
            self.logger.error(
                "Archive creation failed for Operation ID %s at %s",
                operation_id,
                archive_path,
            )
            raise HTTPException(
                status_code=500, detail="Failed to create archive for Operation ID."
            )

        self.logger.info(
            "Returning ZIP archive for Operation ID %s: %s", operation_id, archive_path
        )

        return FileResponse(
            path=str(archive_path),
            filename=archive_name,
            media_type=MediaType.APPLICATION_ZIP,
        )

    def get_file_by_mac_address(self, mac_address: MacAddressStr) -> FileResponse:
        """
        Retrieve All PNM Files For A MAC Address As A ZIP Archive.

        Looks up all transaction records bound to the provided cable modem
        MAC address, collects their associated PNM files from the PNM
        directory, and packages them into a single ZIP archive for download.

        If no records are found, or none of the files exist on disk, a 404 is raised.
        """
        records = PnmFileTransaction().get_file_info_via_macaddress(
            MacAddress(mac_address)
        )

        if not records:
            raise HTTPException(
                status_code=404, detail="No transactions found for MAC address."
            )

        files_to_archive: list[Path] = []
        for rec in records:
            src_path = self._resolve_pnm_artifact_path_optional(rec.transaction_id)
            if src_path is None or not src_path.is_file():
                self.logger.warning(
                    "Skipping missing file for transaction %s: %s",
                    rec.transaction_id,
                    src_path,
                )
                continue
            files_to_archive.append(src_path)

        if not files_to_archive:
            raise HTTPException(
                status_code=404, detail="No files on disk for MAC address."
            )

        archive_dir = Path(SystemConfigSettings.archive_dir())
        archive_dir.mkdir(parents=True, exist_ok=True)

        safe_mac = str(MacAddress(mac_address).to_mac_format())
        archive_name = f"pnm_files_{safe_mac}_{Generate.time_stamp()}.zip"
        archive_path = archive_dir / archive_name

        ArchiveManager.zip_files(
            files=files_to_archive,
            archive_path=archive_path,
            mode="w",
            compression="zipdeflated",
            preserve_tree=False,
        )

        if not archive_path.is_file():
            self.logger.error(
                "Archive creation failed for MAC %s at %s", mac_address, archive_path
            )
            raise HTTPException(
                status_code=500, detail="Failed to create archive for MAC address."
            )

        self.logger.info(
            "Returning ZIP archive for MAC %s: %s", mac_address, archive_path
        )

        return FileResponse(
            path=str(archive_path),
            filename=archive_name,
            media_type=MediaType.APPLICATION_ZIP,
        )

    def upload_file(self, filename: FileName, data: bytes) -> UploadFileResponse:
        """
        Handle A User-Initiated Upload Of A Raw PNM Binary File.

        1. Saves the file locally to the configured directory.
        2. Inspects its header to identify the PNM file type and MAC.
        3. Maps it to a known DOCSIS test type.
        4. Registers the transaction and returns the transaction ID.
        """
        os.makedirs(self.pnm_dir, exist_ok=True)
        filepath = os.path.join(self.pnm_dir, filename)

        processor = FileProcessor(filepath)
        success = processor.write_file(data)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to write file")

        params = GetPnmParserAndParameters(processor.read_file()).to_model()
        mac_address = params.mac_address or MacAddress.null()
        pnm_file_type: PnmFileType = params.file_type

        try:
            transaction_id = PnmFileTransaction().set_file_by_user(
                mac_address=MacAddress(mac_address),
                pnm_test_type=PnmFileTypeMapper.get_test_type(pnm_file_type),
                filename=filename,
            )
        except (FileNotFoundError, RuntimeError) as exc:
            self.logger.error(
                "Failed to register uploaded file artifact for %s: %s",
                filename,
                exc,
            )
            raise HTTPException(
                status_code=500, detail="Failed to register uploaded file artifact."
            ) from exc

        return UploadFileResponse(
            mac_address=MacAddress(mac_address).mac_address,
            filename=filename,
            transaction_id=transaction_id,
        )

    def get_file(self, file_type: FileType, filename: PathLike) -> FileResponse:
        """
        Serve a generated file from its configured directory.

        Supported types:
        - CSV: returns text/csv from SystemConfigSettings.csv_dir
        - JSON: returns application/json from SystemConfigSettings.json_dir
        - ARCHIVE: returns application/zip from SystemConfigSettings.archive_dir
        """
        safe_name = Path(filename).name

        valid_extensions = [".csv", ".json", ".zip"]
        if not any(safe_name.endswith(ext) for ext in valid_extensions):
            raise HTTPException(
                status_code=400, detail=f"Invalid file extension, file: {safe_name}"
            )

        if file_type == FileType.CSV:
            base_dir = SystemConfigSettings.csv_dir()
            media_type = MediaType.TEXT_CSV

        elif file_type == FileType.JSON:
            base_dir = SystemConfigSettings.json_dir()
            media_type = MediaType.APPLICATION_JSON

        elif file_type == FileType.ARCHIVE:
            base_dir = SystemConfigSettings.archive_dir()
            media_type = MediaType.APPLICATION_ZIP

        else:
            self.logger.error(f"Unsupported file type requested: {file_type.name}")
            raise HTTPException(
                status_code=400, detail=f"Unsupported file type: {file_type.name}"
            )

        file_path = Path(base_dir) / safe_name
        if not file_path.is_file():
            self.logger.warning(f"File not found: {file_path}")
            raise HTTPException(status_code=404, detail="File not found on disk.")

        return FileResponse(
            path=str(file_path),
            filename=safe_name,
            media_type=media_type,
        )

    def get_analysis(
        self, req: FileAnalysisRequest
    ) -> tuple[ParserAnalysisModelReturn, PnmFileType]:
        """
        Returns basic analysis result for a stored PNM file identified by transaction ID.
        The analysis performed depends on the PNM file type.

        Return:
        Tuple[ParserAnalysisModelReturn, PnmFileType]
            A tuple containing the analysis model and the PNM file type.
        """
        file_path = self._resolve_pnm_artifact_path(req.search.transaction_id)
        filename = file_path.name

        self.logger.info(
            "Starting analysis for transaction ID %s on file: %s",
            req.search.transaction_id,
            file_path,
        )

        fp = FileProcessor(str(file_path)).read_file()

        # Get PnmHeader to Determine PnmFileType
        from pypnm.pnm.parser.pnm_parameter import GetPnmParserAndParameters

        parser, model = GetPnmParserAndParameters(fp).get_parser()

        self.logger.info(
            "Performing %s analysis for transaction %s on file %s",
            model.file_type.name,
            req.search.transaction_id,
            filename,
        )

        return self.__get_analysis(parser, model)

    def get_pnm_path_for_transaction(self, transaction_id: TransactionId) -> Path:
        """
        Resolve The Filesystem Path For A PNM File From A Transaction ID.

        Parameters
        ----------
        transaction_id:
            Transaction identifier associated with the PNM capture file.

        Returns
        -------
        Path
            Fully-resolved path to the PNM file on disk.

        Raises
        ------
        HTTPException
            If no artifact is linked to the transaction, or the file is not
            present on disk.
        """
        return self._resolve_pnm_artifact_path(transaction_id)

    def get_hexdump_by_transaction_id(
        self, transaction_id: TransactionId, bytes_per_line: int
    ) -> HexDumpResponse:
        """
        Generate A Structured Hexdump For A PNM File Identified By Transaction ID.

        Parameters
        ----------
        transaction_id:
            Transaction identifier associated with the PNM capture file.
        bytes_per_line:
            Number of bytes per output line in the hexdump view. Typical values
            are 8, 16, or 32. Non-positive values are coerced to the default
            configured via DEFAULT_HEXDUMP_BYTES_PER_LINE.

        Returns
        -------
        HexDumpResponse
            Structured hexdump payload including the transaction ID, the
            effective bytes-per-line setting, and formatted hexdump lines
            containing offset, hex bytes, and ASCII representation.
        """
        if bytes_per_line <= 0:
            bytes_per_line = self.DEFAULT_HEXDUMP_BYTES_PER_LINE

        file_path = self.get_pnm_path_for_transaction(transaction_id)
        processor = FileProcessor(file_path)
        lines = processor.hexdump(bytes_per_line=bytes_per_line)

        if not lines:
            self.logger.error(
                "Hexdump generation failed or produced no data for transaction %s at %s",
                transaction_id,
                file_path,
            )
            raise HTTPException(
                status_code=500, detail="Failed to generate hexdump for PNM file."
            )

        return HexDumpResponse(
            transaction_id=transaction_id,
            bytes_per_line=bytes_per_line,
            lines=lines,
        )

    def _resolve_pnm_artifact_path(self, transaction_id: TransactionId) -> Path:
        path = self._artifact_repo.resolve_transaction_artifact_path(
            transaction_id,
            roles=(ROLE_PNM_RAW, ROLE_PNM_UPLOADED_RAW),
        )
        if path is None:
            raise HTTPException(
                status_code=404,
                detail="Transaction ID not found.",
            )
        if not path.is_file():
            raise HTTPException(
                status_code=404,
                detail="File not found on disk.",
            )
        return path

    def _resolve_pnm_artifact_path_optional(
        self, transaction_id: TransactionId
    ) -> Path | None:
        try:
            return self._resolve_pnm_artifact_path(transaction_id)
        except HTTPException:
            return None

    def __get_analysis(
        self, parser: PnmParsers, model: PnmParserParametersModel
    ) -> tuple[ParserAnalysisModelReturn, PnmFileType]:
        """
        Internal method to instantiate the Analysis class with the given parser and model.
        """
        from pypnm.api.routes.common.classes.analysis.analysis import Analysis

        match model.file_type:
            case PnmFileType.RECEIVE_MODULATION_ERROR_RATIO:
                return Analysis.basic_analysis_rxmer_from_model(
                    cast(CmDsOfdmRxMerModel, parser.to_model())
                ), model.file_type

            case PnmFileType.OFDM_CHANNEL_ESTIMATE_COEFFICIENT:
                return Analysis.basic_analysis_ds_chan_est_from_model(
                    cast(CmDsOfdmChanEstimateCoefModel, parser.to_model())
                ), model.file_type

            case PnmFileType.OFDM_MODULATION_PROFILE:
                return Analysis.basic_analysis_ds_modulation_profile_from_model(
                    cast(CmDsOfdmModulationProfileModel, parser.to_model())
                ), model.file_type

            case PnmFileType.DOWNSTREAM_CONSTELLATION_DISPLAY:
                return Analysis.basic_analysis_ds_constellation_display_from_model(
                    cast(CmDsConstDispMeasModel, parser.to_model())
                ), model.file_type

            case PnmFileType.DOWNSTREAM_HISTOGRAM:
                return Analysis.basic_analysis_ds_histogram_from_model(
                    cast(CmDsHistModel, parser.to_model())
                ), model.file_type

            case PnmFileType.OFDM_FEC_SUMMARY:
                return Analysis.basic_analysis_ds_ofdm_fec_summary_from_model(
                    cast(CmDsOfdmFecSummaryModel, parser.to_model())
                ), model.file_type

            case (
                PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS
                | PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE
            ):
                return Analysis.basic_analysis_us_ofdma_pre_equalization_from_model(
                    cast(CmUsOfdmaPreEqModel, parser.to_model())
                ), model.file_type

        raise HTTPException(
            status_code=400,
            detail=f"Analysis not implemented for file type: {model.file_type.name}",
        )

    def get_archive(self, request: FileAnalysisRequest) -> FileResponse:
        rpt: Path = Path()

        theme = request.analysis.plot.ui.theme
        plot_config = AnalysisRptMatplotConfig(theme=theme)
        analysis_model, pnm_ftype = self.get_analysis(request)

        # TODO: Need to clean up circlar import at next major release
        from pypnm.api.routes.common.classes.analysis.analysis import Analysis

        analysis = Analysis.get_analysis_from_model(analysis_model)

        if pnm_ftype == PnmFileType.RECEIVE_MODULATION_ERROR_RATIO:
            analysis_rpt = RxMerAnalysisReport(analysis, plot_config)
            rpt: Path = cast(Path, analysis_rpt.build_report())

        elif pnm_ftype == PnmFileType.OFDM_CHANNEL_ESTIMATE_COEFFICIENT:
            analysis_rpt = ChanEstimationReport(analysis, plot_config)
            rpt: Path = cast(Path, analysis_rpt.build_report())

        elif pnm_ftype == PnmFileType.OFDM_MODULATION_PROFILE:
            analysis_rpt = ModulationProfileReport(analysis, plot_config)
            rpt: Path = cast(Path, analysis_rpt.build_report())

        elif pnm_ftype == PnmFileType.DOWNSTREAM_CONSTELLATION_DISPLAY:
            plot_config = ConstDisplayAnalysisRptMatplotConfig(theme=theme)
            analysis_rpt = ConstellationDisplayReport(analysis, plot_config)
            rpt: Path = cast(Path, analysis_rpt.build_report())

        elif (
            pnm_ftype == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS
            or pnm_ftype == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE
        ):
            plot_config = ConstDisplayAnalysisRptMatplotConfig(theme=theme)
            analysis_rpt = CmUsOfdmaPreEqReport(analysis)
            rpt: Path = cast(Path, analysis_rpt.build_report())

        elif pnm_ftype == PnmFileType.OFDM_FEC_SUMMARY:
            plot_config = ConstDisplayAnalysisRptMatplotConfig(theme=theme)
            analysis_rpt = FecSummaryAnalysisReport(analysis, plot_config)
            rpt: Path = cast(Path, analysis_rpt.build_report())

        return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

    def get_mac_addresses(self) -> MacAddressSystemDescriptorResponse:
        """
        Retrieve Unique MAC Addresses With Registered PNM Files.

        This scans all transaction records and returns a de-duplicated set of
        MAC addresses. When multiple records exist for the same MAC, the most
        recent record (by timestamp) is used as the source for the system
        descriptor when available.

        Parameters
        ----------
        req:
            Placeholder request model for endpoint compatibility. Currently not
            used for filtering.

        Returns
        -------
        MacAddressSystemDescriptorResponse
            Unique MAC address list with optional system descriptor per MAC.
        """
        entries = TransactionRepository.from_system_config().list_macs()
        if not entries:
            return MacAddressSystemDescriptorResponse(mac_addresses=[])

        response_entries = [
            MacAddressSystemDescriptorEntry(
                mac_address=entry.mac_address,
                system_description=entry.system_description,
            )
            for entry in entries
        ]

        return MacAddressSystemDescriptorResponse(mac_addresses=response_entries)

# FILE: tests/test_artifact_repository.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.artifact_repository import (
    ArtifactRepository,
    ROLE_PNM_RAW,
    ROLE_PNM_UPLOADED_RAW,
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

# FILE: tests/test_pnm_file_hexdump.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import HTTPException

from pypnm.api.routes.docs.pnm.files.service import PnmFileService
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.artifact_repository import ArtifactRepository, ROLE_PNM_RAW
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


def _guard_json_ledgers(monkeypatch: pytest.MonkeyPatch) -> None:
    original_open = Path.open

    def _guarded_open(
        self: Path, *args: tuple[object, ...], **kwargs: dict[str, object]
    ) -> object:
        if self.name == "transactions.json":
            raise AssertionError(f"Unexpected JSON ledger access: {self}")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", _guarded_open)


@pytest.mark.pnm
def test_hexdump_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Verify that get_hexdump_by_transaction_id returns a structured HexDumpResponse
    for a valid transaction with an on-disk PNM file.
    """
    transaction_id: TransactionId = TransactionId("8f17fcdd4c0138ef")
    db_path = _configure_db(tmp_path, monkeypatch)
    _guard_json_ledgers(monkeypatch)
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
    _guard_json_ledgers(monkeypatch)

    service = PnmFileService()

    with pytest.raises(HTTPException) as excinfo:
        service.get_hexdump_by_transaction_id(
            transaction_id=transaction_id,
            bytes_per_line=16,
        )

    err = excinfo.value
    assert err.status_code == 404
    assert "Transaction ID not found" in str(err.detail)

# FILE: tests/test_pnm_file_artifact_resolution.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest

from pypnm.api.routes.common.classes.common_endpoint_classes.common_req_resp import (
    CommonMatPlotConfigRequest,
    CommonOutput,
    CommonSingleCaptureAnalysisType,
)
from pypnm.api.routes.docs.pnm.files.schemas import (
    FileAnalysisRequest,
    FileSearchRequest,
)
from pypnm.api.routes.docs.pnm.files.service import PnmFileService
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.artifact_repository import ArtifactRepository, ROLE_PNM_RAW
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
from pypnm.pnm.parser.pnm_file_type import PnmFileType

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


def _guard_json_ledgers(monkeypatch: pytest.MonkeyPatch) -> None:
    original_open = Path.open

    def _guarded_open(
        self: Path, *args: tuple[object, ...], **kwargs: dict[str, object]
    ) -> object:
        if self.name == "transactions.json":
            raise AssertionError(f"Unexpected JSON ledger access: {self}")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", _guarded_open)


@pytest.mark.pnm
def test_get_file_by_transaction_id_uses_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    transaction_id = TransactionId("txn-1")
    db_path = _configure_db(tmp_path, monkeypatch)
    _guard_json_ledgers(monkeypatch)
    _seed_transaction(db_path, transaction_id)

    file_path = tmp_path / DEFAULT_FILENAME
    file_path.write_bytes(b"test")

    _register_artifact(db_path, transaction_id, file_path)

    service = PnmFileService()
    response = service.get_file_by_transaction_id(transaction_id)

    content_disp = response.headers.get("content-disposition")
    assert content_disp is not None
    assert DEFAULT_FILENAME in content_disp


@pytest.mark.pnm
def test_get_analysis_resolves_via_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    transaction_id = TransactionId("txn-2")
    db_path = _configure_db(tmp_path, monkeypatch)
    _guard_json_ledgers(monkeypatch)
    _seed_transaction(db_path, transaction_id)

    file_path = tmp_path / DEFAULT_FILENAME
    file_path.write_bytes(b"test")

    _register_artifact(db_path, transaction_id, file_path)

    class _FakeModel:
        file_type = PnmFileType.RECEIVE_MODULATION_ERROR_RATIO

    class _FakeParser:
        def __init__(self, _payload: bytes) -> None:
            return None

        def get_parser(self) -> tuple[object, _FakeModel]:
            return None, _FakeModel()

    monkeypatch.setattr(
        "pypnm.pnm.parser.pnm_parameter.GetPnmParserAndParameters",
        _FakeParser,
    )

    def _fake_get_analysis(
        self: PnmFileService, _parser: object, _model: _FakeModel
    ) -> tuple[object, PnmFileType]:
        return object(), PnmFileType.RECEIVE_MODULATION_ERROR_RATIO

    monkeypatch.setattr(
        PnmFileService,
        "_PnmFileService__get_analysis",
        _fake_get_analysis,
        raising=True,
    )

    request = FileAnalysisRequest(
        search=FileSearchRequest(transaction_id=transaction_id),
        analysis=CommonSingleCaptureAnalysisType(
            output=CommonOutput(),
            plot=CommonMatPlotConfigRequest(),
        ),
    )

    analysis_model, file_type = PnmFileService().get_analysis(request)
    assert file_type == PnmFileType.RECEIVE_MODULATION_ERROR_RATIO
    assert analysis_model is not None
