## Agent Review Bundle Summary
- Goal:
- Changes:
- Files:
- Tests:
- Notes:
# FILE: .pylintrc
[MASTER]
load-plugins=pylint.extensions.magic_value

[MESSAGES CONTROL]
disable=all
enable=magic-value-comparison

[MAGIC_VALUE]
valid-magic-values="-1,0,1,__main__"

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
  "psycopg[binary]==3.2.3",
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
        return self._schema_manager.connect()

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

# FILE: src/pypnm/tools/qa_checker.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import subprocess
import sys


Command = tuple[str, list[str]]


def _run_command(label: str, cmd: list[str]) -> int:
    """
    Run A Single QA Tool Command And Stream Its Output.

    Parameters
    ----------
    label : str
        Human-readable label for the tool (e.g., "ruff", "pyright").
    cmd : Sequence[str]
        The command and arguments to execute.

    Returns
    -------
    int
        The process return code (0 on success, non-zero on failure).
    """
    print(f"\n=== [{label}] running: {' '.join(cmd)} ===", flush=True)
    try:
        proc = subprocess.run(cmd, check=False)
        if proc.returncode == 0:
            print(f"=== [{label}] OK ===", flush=True)
        else:
            print(f"=== [{label}] FAILED (exit code {proc.returncode}) ===", flush=True)
        return proc.returncode
    except FileNotFoundError:
        print(f"=== [{label}] NOT FOUND on PATH ===", flush=True)
        return 127


def _build_commands(
    include_pyright: bool, include_pylint: bool, pytest_args: list[str]
) -> list[Command]:
    """
    Build The Ordered List Of QA Commands To Run.

    Parameters
    ----------
    include_pyright : bool
        If True, include a `pyright` static type-check step after Ruff.
    pytest_args : Sequence[str]
        Additional arguments to pass through to pytest (for example, via
        the CLI separator ``--``).

    Returns
    -------
    list[Command]
        Ordered list of (label, cmd) tuples to execute.
    """
    python_cmd = sys.executable or "python"
    commands: list[Command] = [
        ("secrets", ["./tools/security/scan-secrets.sh"]),
        ("enc-secrets", [python_cmd, "./tools/security/scan-enc-secrets.py"]),
        ("macs", ["./tools/security/scan-mac-addresses.py", "--fail-on-found"]),
        ("headers", [python_cmd, "./tools/maintenance/add-required-python-headers.py"]),
        ("ruff", ["ruff", "check", "src"]),
    ]

    if include_pyright:
        # Insert Pyright after Ruff but before loop nesting and pytest for faster feedback.
        commands.append(("pyright", ["pyright"]))

    if include_pylint:
        commands.append(
            (
                "pylint",
                ["pylint", "--rcfile=.pylintrc", "src/pypnm/lib/db/transaction_repository.py"],
            )
        )

    commands.append(("loop-nesting", [python_cmd, "-m", "pypnm.tools.loop_nesting_checker", "src"]))
    commands.append(("pytest", ["pytest", *pytest_args]))

    return commands


def main() -> None:
    """
    Run The Standard PyPNM Software QA Suite.

    Default Behavior
    ----------------
    By default, this helper aggregates the core quality checks configured for
    the project:

    1) secrets             - secret scanning via ./tools/security/scan-secrets.sh
                             (gitleaks + .gitleaks.toml if available).
    2) enc-secrets         - encrypted password pattern scan (ENC[v1] + password_enc).
    3) macs                - repository scan for non-approved MAC addresses.
    4) headers             - ensure SPDX/license headers (./tools/maintenance/add-required-python-headers.py).
    5) ruff check src      - syntax, style, and common bug patterns.
    6) loop nesting        - ensure no function exceeds 3+ nested loops.
    7) pytest              - unit tests (pytest options from pyproject.toml).

    Optional Pyright
    ----------------
    To enable static type checking with Pyright, pass the flag:

        pypnm-software-qa-checker --with-pyright

    This will run an additional step:

    - pyright              - static type analysis using [tool.pyright] settings,
                             executed after Ruff but before loop nesting and pytest.

    Optional Pylint (Magic Values)
    ------------------------------
    To enable magic-value checks with Pylint, pass the flag:

        pypnm-software-qa-checker --with-pylint

    This runs the Pylint magic-value extension (R2004) using the
    .pylintrc configuration, after Ruff but before loop nesting.

    Passing Extra Pytest Arguments
    ------------------------------
    To pass additional arguments directly to pytest, use ``--`` as a separator.
    Any arguments after ``--`` are forwarded only to pytest. For example:

        pypnm-software-qa-checker --with-pyright -- -k \"fast\" --maxfail=1

    In this example, pytest will be invoked as:

        pytest -k \"fast\" --maxfail=1

    The process exit code is non-zero if any check fails.
    """
    raw_args = sys.argv[1:]

    pytest_args: list[str] = []
    qa_args: list[str] = raw_args

    if "--" in raw_args:
        sep_index = raw_args.index("--")
        qa_args = raw_args[:sep_index]
        pytest_args = raw_args[sep_index + 1 :]

    include_pyright = "--with-pyright" in qa_args
    include_pylint = "--with-pylint" in qa_args
    filtered_qa_args = [a for a in qa_args if a not in {"--with-pyright", "--with-pylint"}]

    # Preserve a minimal sys.argv for any downstream libraries that inspect it.
    sys.argv = [sys.argv[0], *filtered_qa_args]

    commands = _build_commands(
        include_pyright=include_pyright,
        include_pylint=include_pylint,
        pytest_args=pytest_args,
    )

    overall_rc = 0
    for label, cmd in commands:
        rc = _run_command(label, cmd)
        if rc != 0 and overall_rc == 0:
            overall_rc = rc

    print("\n=== PyPNM Software QA Suite Finished ===", flush=True)
    if overall_rc == 0:
        print("All checks passed.", flush=True)
    else:
        print(f"One or more checks failed (exit code {overall_rc}).", flush=True)

    sys.exit(overall_rc)


if __name__ == "__main__":
    main()
