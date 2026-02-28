# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.extended.common_process_service import CommonProcessService
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.lib.types import TransactionId, TransactionRecord
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest


def _service_stub(payload: list[dict[str, object]] | None = None) -> CommonProcessService:
    service = CommonProcessService.__new__(CommonProcessService)
    service.logger = logging.getLogger("CommonProcessService")
    service._msg_rsp = MessageResponse(ServiceStatusCode.SUCCESS, payload=payload or [])
    return service


def test_update_pnm_data_from_message_response_extension_merges() -> None:
    service = _service_stub()
    transaction_id = TransactionId("abc123")
    service._msg_rsp.payload = [
        {
            "status": ServiceStatusCode.SUCCESS.name,
            "message_type": "PNM_FILE_TRANSACTION",
            "message": {
                "transaction_id": transaction_id,
                "extension": {"key": "value"},
            },
        },
    ]
    transaction_record: TransactionRecord = {"transaction_id": transaction_id}
    pnm_data = {"existing": "data"}

    updated = service._update_pnm_data_from_message_response_extension(transaction_record, pnm_data)

    assert updated == {"existing": "data", "key": "value"}
    assert transaction_record["transaction_id"] == transaction_id


def test_update_pnm_data_from_message_response_extension_missing_extension() -> None:
    service = _service_stub()
    transaction_id = TransactionId("abc123")
    service._msg_rsp.payload = [
        {
            "status": ServiceStatusCode.SUCCESS.name,
            "message_type": "PNM_FILE_TRANSACTION",
            "message": {
                "transaction_id": transaction_id,
            },
        },
    ]
    transaction_record: TransactionRecord = {"transaction_id": transaction_id}
    pnm_data = {"existing": "data"}

    updated = service._update_pnm_data_from_message_response_extension(transaction_record, pnm_data)

    assert updated == {"existing": "data"}


def test_process_prefers_ingress_file_when_present(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ingress_file = tmp_path / "ingress.bin"
    ingress_file.write_bytes(b"test")

    class _FakeArtifactStore:
        def ingress_candidate_path(self, filename: object, transaction_id: object) -> Path:
            return ingress_file

        def materialize(self, transaction_id: object, filename: object, compression: object) -> Path:
            raise AssertionError("materialize should not be called when ingress file exists")

    class _FakeParser:
        def __init__(self, binary_data: bytes) -> None:
            self.binary_data = binary_data

        def to_dict(self) -> dict[str, object]:
            return {"data": "ok"}

    service = CommonProcessService.__new__(CommonProcessService)
    service.logger = logging.getLogger("CommonProcessService")
    service._artifact_store = _FakeArtifactStore()
    service._msg_rsp = MessageResponse(ServiceStatusCode.SUCCESS, payload=[])
    service._messages = []

    transaction_record: TransactionRecord = {
        "transaction_id": TransactionId("tx-ingress"),
        "filename": "ingress.bin",
        "pnm_test_type": DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR.name,
        "device_details": {},
    }

    monkeypatch.setattr(
        "pypnm.api.routes.common.extended.common_process_service.CmDsOfdmRxMer",
        _FakeParser,
    )

    status = service._process_pnm_measure_test(transaction_record)

    assert status == ServiceStatusCode.SUCCESS


def test_process_uses_ingress_fallback_when_transaction_dir_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ingress_dir = tmp_path / "ingress" / "other-tx"
    ingress_dir.mkdir(parents=True)
    ingress_file = ingress_dir / "fallback.bin"
    ingress_file.write_bytes(b"fallback")

    class _FakeArtifactStore:
        def ingress_candidate_path(self, filename: object, transaction_id: object) -> Path:
            return tmp_path / "ingress" / "missing" / "fallback.bin"

        def find_ingress_by_filename(self, filename: object) -> Path | None:
            return ingress_file

        def materialize(self, transaction_id: object, filename: object, compression: object) -> Path:
            raise AssertionError("materialize should not be called when ingress fallback exists")

    class _FakeParser:
        def __init__(self, binary_data: bytes) -> None:
            self.binary_data = binary_data

        def to_dict(self) -> dict[str, object]:
            return {"data": "ok"}

    service = CommonProcessService.__new__(CommonProcessService)
    service.logger = logging.getLogger("CommonProcessService")
    service._artifact_store = _FakeArtifactStore()
    service._msg_rsp = MessageResponse(ServiceStatusCode.SUCCESS, payload=[])
    service._messages = []

    transaction_record: TransactionRecord = {
        "transaction_id": TransactionId("tx-fallback"),
        "filename": "fallback.bin",
        "pnm_test_type": DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR.name,
        "device_details": {},
    }

    monkeypatch.setattr(
        "pypnm.api.routes.common.extended.common_process_service.CmDsOfdmRxMer",
        _FakeParser,
    )

    status = service._process_pnm_measure_test(transaction_record)

    assert status == ServiceStatusCode.SUCCESS
