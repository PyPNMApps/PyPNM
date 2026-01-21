## Agent Review Bundle Summary
- Goal: Make DB-only cutover guardrails enforceable (health check + test guard) and add minimal Postgres artifact coverage.
- Changes: DB schema health check now validates JSON artifact store; added Postgres-gated artifact resolution test; centralized ledger read guard for PNM-marked tests.
- Files: docs/design/db/database-backend.md; src/pypnm/lib/db/db_schema_manager.py; src/pypnm/lib/db/json_transaction.py; src/pypnm/lib/db/model/db_health_model.py; src/pypnm/tools/migrate_transactions.py; tests/ledger_guard.py; tests/test_migrate_transactions.py; tests/test_pnm_file_artifact_resolution.py; tests/test_pnm_file_hexdump.py; tests/test_artifact_repository.py; tests/test_db_schema_manager.py; tests/conftest.py
- Tests: python3 -m compileall src; ruff check .; ruff format --check .; pytest -q
- Notes: pytest skips include PYPNM_TEST_POSTGRES-gated tests and PNM_CM_IT hardware integration; planning/.pylintrc left untouched.

# FILE: tests/ledger_guard.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import builtins
from pathlib import Path

import pytest

_DEFAULT_LEDGER_FILES: tuple[str, ...] = ("transactions.json",)


def guard_legacy_ledger_reads(
    monkeypatch: pytest.MonkeyPatch,
    ledger_files: tuple[str, ...] = _DEFAULT_LEDGER_FILES,
) -> None:
    """
    Fail fast if legacy ledger files are opened or read during tests.
    """
    original_open = Path.open
    original_read_text = Path.read_text
    original_read_bytes = Path.read_bytes
    original_builtin_open = builtins.open
    blocked = {name.lower() for name in ledger_files}

    def _is_blocked(value: object) -> bool:
        if isinstance(value, Path):
            name = value.name
        elif isinstance(value, str):
            name = Path(value).name
        else:
            return False
        return name.lower() in blocked

    def _guarded_open(
        self: Path, *args: tuple[object, ...], **kwargs: dict[str, object]
    ) -> object:
        if _is_blocked(self):
            raise AssertionError(f"Unexpected JSON ledger access: {self}")
        return original_open(self, *args, **kwargs)

    def _guarded_read_text(
        self: Path, *args: tuple[object, ...], **kwargs: dict[str, object]
    ) -> str:
        if _is_blocked(self):
            raise AssertionError(f"Unexpected JSON ledger access: {self}")
        return original_read_text(self, *args, **kwargs)

    def _guarded_read_bytes(self: Path) -> bytes:
        if _is_blocked(self):
            raise AssertionError(f"Unexpected JSON ledger access: {self}")
        return original_read_bytes(self)

    def _guarded_builtin_open(
        file: object, *args: tuple[object, ...], **kwargs: dict[str, object]
    ) -> object:
        if _is_blocked(file):
            raise AssertionError(f"Unexpected JSON ledger access: {file}")
        return original_builtin_open(file, *args, **kwargs)

    monkeypatch.setattr(Path, "open", _guarded_open)
    monkeypatch.setattr(Path, "read_text", _guarded_read_text)
    monkeypatch.setattr(Path, "read_bytes", _guarded_read_bytes)
    monkeypatch.setattr(builtins, "open", _guarded_builtin_open)

# FILE: tests/test_migrate_transactions.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.db.transaction_repository import TransactionRepository
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    FileName,
    TransactionId,
)
from pypnm.tools.migrate_transactions import TransactionMigrator

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


def _make_payload(transaction_ids: list[str]) -> dict[str, object]:
    payload: dict[str, object] = {}
    for index, transaction_id in enumerate(transaction_ids, start=1):
        payload[transaction_id] = {
            "timestamp": DEFAULT_TIMESTAMP + index,
            "mac_address": str(DEFAULT_MAC),
            "pnm_test_type": PNM_TEST_TYPE,
            "filename": str(DEFAULT_FILENAME),
            "device_details": DEVICE_DETAILS,
        }
    return payload


def test_transaction_migrator_imports_legacy_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_db(tmp_path, monkeypatch)
    legacy_path = tmp_path / "transactions.json"
    legacy_payload = _make_payload(["txn-1", "txn-2"])
    legacy_path.write_text(json.dumps(legacy_payload), encoding="utf-8")

    exit_code = TransactionMigrator().run(["--input", str(legacy_path)])

    assert exit_code == TransactionMigrator.EXIT_OK

    repo = TransactionRepository.from_system_config()
    records = repo.list_all_transactions()
    assert {record.transaction_id for record in records} == {
        TransactionId("txn-1"),
        TransactionId("txn-2"),
    }


def test_transaction_migrator_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_db(tmp_path, monkeypatch)
    legacy_path = tmp_path / "transactions.json"
    legacy_payload = _make_payload(["txn-1", "txn-2"])
    legacy_path.write_text(json.dumps(legacy_payload), encoding="utf-8")

    migrator = TransactionMigrator()
    assert migrator.run(["--input", str(legacy_path)]) == TransactionMigrator.EXIT_OK
    assert migrator.run(["--input", str(legacy_path)]) == TransactionMigrator.EXIT_OK

    repo = TransactionRepository.from_system_config()
    records = repo.list_all_transactions()
    assert len(records) == 2


def test_transaction_migrator_missing_file_is_noop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _configure_db(tmp_path, monkeypatch)
    legacy_path = tmp_path / "transactions.json"

    exit_code = TransactionMigrator().run(["--input", str(legacy_path)])

    assert exit_code == TransactionMigrator.EXIT_OK
    assert "Legacy transactions.json not found" in caplog.text


def test_transaction_migrator_rejects_invalid_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_db(tmp_path, monkeypatch)
    legacy_path = tmp_path / "transactions.json"
    legacy_path.write_text("{", encoding="utf-8")

    exit_code = TransactionMigrator().run(["--input", str(legacy_path)])

    assert exit_code == TransactionMigrator.EXIT_FAILURE


def test_transaction_migrator_skips_invalid_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_db(tmp_path, monkeypatch)
    legacy_path = tmp_path / "transactions.json"
    legacy_payload = _make_payload(["txn-1"])
    legacy_payload["txn-missing"] = {"mac_address": str(DEFAULT_MAC)}
    legacy_path.write_text(json.dumps(legacy_payload), encoding="utf-8")

    exit_code = TransactionMigrator().run(["--input", str(legacy_path)])

    assert exit_code == TransactionMigrator.EXIT_OK
    repo = TransactionRepository.from_system_config()
    records = repo.list_all_transactions()
    assert {record.transaction_id for record in records} == {TransactionId("txn-1")}

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
    FileQueryRequest,
    FileSearchRequest,
)
from pypnm.api.routes.docs.pnm.files.service import PnmFileService
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.artifact_repository import ROLE_PNM_RAW, ArtifactRepository
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


@pytest.mark.pnm
def test_get_file_by_transaction_id_uses_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    transaction_id = TransactionId("txn-1")
    db_path = _configure_db(tmp_path, monkeypatch)
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


@pytest.mark.pnm
@pytest.mark.pnm
def test_search_files_uses_db_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    transaction_id = TransactionId("txn-search")
    db_path = _configure_db(tmp_path, monkeypatch)
    _seed_transaction(db_path, transaction_id)

    request = FileQueryRequest(mac_address=str(DEFAULT_MAC))
    response = PnmFileService().search_files(request)

    entries = response.files.get(str(DEFAULT_MAC), [])
    assert len(entries) == 1
    assert entries[0].transaction_id == transaction_id


@pytest.mark.pnm
def test_get_mac_addresses_uses_db_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    transaction_id = TransactionId("txn-mac")
    db_path = _configure_db(tmp_path, monkeypatch)
    _seed_transaction(db_path, transaction_id)

    response = PnmFileService().get_mac_addresses()
    assert response.mac_addresses
    assert response.mac_addresses[0].mac_address == str(DEFAULT_MAC)

# FILE: tests/test_pnm_file_hexdump.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import HTTPException

from pypnm.api.routes.docs.pnm.files.service import PnmFileService
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.artifact_repository import ROLE_PNM_RAW, ArtifactRepository
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


@pytest.mark.pnm
def test_hexdump_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Verify that get_hexdump_by_transaction_id returns a structured HexDumpResponse
    for a valid transaction with an on-disk PNM file.
    """
    transaction_id: TransactionId = TransactionId("8f17fcdd4c0138ef")
    db_path = _configure_db(tmp_path, monkeypatch)
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

    service = PnmFileService()

    with pytest.raises(HTTPException) as excinfo:
        service.get_hexdump_by_transaction_id(
            transaction_id=transaction_id,
            bytes_per_line=16,
        )

    err = excinfo.value
    assert err.status_code == 404
    assert "Transaction ID not found" in str(err.detail)

# FILE: tests/test_artifact_repository.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from tests.postgres_test_utils import require_postgres

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.artifact_repository import (
    ROLE_PNM_RAW,
    ROLE_PNM_UPLOADED_RAW,
    ArtifactRepository,
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


def test_postgres_transaction_artifact_resolution_optional(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    postgres_dsn, _ = require_postgres()
    sqlite_path = DatabasePath(str(tmp_path / "unused.sqlite3"))

    json_dir = tmp_path / "json"
    json_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(
        SystemConfigSettings,
        "pnm_dir",
        classmethod(lambda cls: str(tmp_path)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "json_dir",
        classmethod(lambda cls: str(json_dir)),
    )

    manager = DatabaseSchemaManager.from_overrides(
        DatabaseBackend.POSTGRES, sqlite_path, postgres_dsn
    )
    manager.initialize_schema()

    transaction_id = TransactionId(uuid.uuid4().hex)
    sys_repo = SystemDescriptionRepository.from_overrides(
        DatabaseBackend.POSTGRES, sqlite_path, postgres_dsn
    )
    device_repo = DeviceDetailsRepository.from_overrides(
        DatabaseBackend.POSTGRES, sqlite_path, postgres_dsn
    )
    txn_repo = TransactionRepository.from_overrides(
        DatabaseBackend.POSTGRES, sqlite_path, postgres_dsn
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

    file_path = tmp_path / DEFAULT_FILENAME
    file_path.write_bytes(b"postgres")

    repo = ArtifactRepository.from_overrides(
        DatabaseBackend.POSTGRES, sqlite_path, postgres_dsn
    )
    repo.register_transaction_artifact(
        transaction_id=transaction_id,
        file_path=file_path,
        role=ROLE_PNM_RAW,
        created_epoch=TimestampSec(DEFAULT_TIMESTAMP),
    )

    resolved = repo.resolve_transaction_artifact_path(transaction_id)
    assert resolved == file_path

# FILE: tests/test_db_schema_manager.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

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
    JSON_ARTIFACT_STORE_NAME,
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
INVALID_DSN_VALUE: str = "   "
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
    assert health.json_artifact_store_present is True

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

        cursor = connection.execute(
            "SELECT root_path FROM artifact_stores WHERE store_name = ?;",
            (JSON_ARTIFACT_STORE_NAME,),
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


def test_postgres_schema_init_requires_non_blank_dsn(tmp_path: Path) -> None:
    sqlite_path = cast(DatabasePath, str(tmp_path / "unused.sqlite3"))
    postgres_dsn = cast(DatabaseDsn, INVALID_DSN_VALUE)
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

# FILE: tests/conftest.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import pytest
from tests.ledger_guard import guard_legacy_ledger_reads


@pytest.fixture(autouse=True)
def _guard_legacy_ledgers_for_pnm_tests(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    if request.node.get_closest_marker("pnm") is None:
        return
    guard_legacy_ledger_reads(monkeypatch)
