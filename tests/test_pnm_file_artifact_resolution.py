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
