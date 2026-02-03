# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import asyncio
import logging
from types import SimpleNamespace

import pytest

from pypnm.api.routes.common.extended.common_measure_service import CommonMeasureService
from pypnm.docsis.cm_snmp_operation import DocsPnmBulkFileUploadStatus
from pypnm.lib.utils import Generate
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest


@pytest.mark.asyncio
async def test_tftp_upload_retries_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    service = CommonMeasureService.__new__(CommonMeasureService)
    service.logger = logging.getLogger("CommonMeasureService")
    service.log_prefix = "CommonMeasureService"
    service.pnm_test_type = DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR
    service.pnm_dir = ".data/pnm"
    service.cm = SimpleNamespace()

    statuses = [
        DocsPnmBulkFileUploadStatus.ERROR,
        DocsPnmBulkFileUploadStatus.UPLOAD_COMPLETED,
    ]

    async def fake_status(filename: str) -> DocsPnmBulkFileUploadStatus:
        return statuses.pop(0)

    async def fake_sleep(_: float) -> None:
        return None

    service.cm.getBulkFileUploadStatus = fake_status
    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    filename = f"unit-test-{Generate.time_stamp()}.bin"
    result = await service._check_and_wait_for_tftp_upload(filename, max_wait_count=1, retries=5)

    assert result.name == "SUCCESS"


@pytest.mark.asyncio
async def test_tftp_upload_retry_delay_caps_at_two_seconds(monkeypatch: pytest.MonkeyPatch) -> None:
    service = CommonMeasureService.__new__(CommonMeasureService)
    service.logger = logging.getLogger("CommonMeasureService")
    service.log_prefix = "CommonMeasureService"
    service.pnm_test_type = DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR
    service.pnm_dir = ".data/pnm"
    service.cm = SimpleNamespace()

    statuses = [
        DocsPnmBulkFileUploadStatus.ERROR,
        DocsPnmBulkFileUploadStatus.ERROR,
        DocsPnmBulkFileUploadStatus.ERROR,
    ]
    sleep_calls: list[float] = []

    async def fake_status(filename: str) -> DocsPnmBulkFileUploadStatus:
        return statuses.pop(0)

    async def fake_sleep(delay: float) -> None:
        sleep_calls.append(delay)

    service.cm.getBulkFileUploadStatus = fake_status
    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    filename = f"unit-test-{Generate.time_stamp()}.bin"
    result = await service._check_and_wait_for_tftp_upload(filename, max_wait_count=1, retries=3)

    assert result.name == "TFTP_PNM_FILE_UPLOAD_FAILURE"
    assert sleep_calls == [1, 2]
