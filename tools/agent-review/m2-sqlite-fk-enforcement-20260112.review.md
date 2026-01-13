## Agent Review Bundle Summary
- Goal: Enforce SQLite foreign key pragmas per connection and add a regression test to prove FK integrity.
- Changes: Enable PRAGMA foreign_keys in repository base connections; added session-group FK integrity test using SQLite IntegrityError.
- Files: src/pypnm/lib/db/transaction_repository.py; tests/test_session_group_repository.py.
- Tests: python3 -m compileall src; ruff check src; ruff format --check .; pytest -q (591 passed, 4 skipped).
- Notes: Skips: PNM_CM_IT hardware integration (3), PYPNM_DB_POSTGRES_DSN not set (1).

# FILE: src/pypnm/lib/db/transaction_repository.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
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

# FILE: tests/test_session_group_repository.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

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

