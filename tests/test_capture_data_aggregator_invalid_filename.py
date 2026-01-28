# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest

from pypnm.api.routes.advance.common import capture_data_aggregator
from pypnm.api.routes.common.classes.file_capture.types import (
    DeviceDetailsModel,
    TransactionRecordModel,
)
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cm_snmp_operation import SystemDescriptor
from pypnm.lib.types import FileName, MacAddressStr, TimestampSec, TransactionId


def _record(filename: str) -> TransactionRecordModel:
    return TransactionRecordModel(
        transaction_id=TransactionId("txn1"),
        timestamp=TimestampSec(0),
        mac_address=MacAddressStr("aa:bb:cc:dd:ee:ff"),
        pnm_test_type="PNM_TEST",
        filename=FileName(filename),
        device_details=DeviceDetailsModel(system_description=SystemDescriptor.empty().to_model()),
    )


def _patch_capture_group(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeCaptureGroup:
        def __init__(self, group_id: str) -> None:
            self._group_id = group_id

        def getTransactionIds(self) -> list[TransactionId]:
            return [TransactionId("txn1")]

    monkeypatch.setattr(capture_data_aggregator, "CaptureGroup", _FakeCaptureGroup)


def _patch_transaction_record(monkeypatch: pytest.MonkeyPatch, record: TransactionRecordModel) -> None:
    class _FakePnmFileTransaction:
        def getRecordModel(self, txn_id: TransactionId) -> TransactionRecordModel:
            return record

    monkeypatch.setattr(capture_data_aggregator, "PnmFileTransaction", _FakePnmFileTransaction)


def _patch_pnm_dir(monkeypatch: pytest.MonkeyPatch, pnm_dir: Path) -> None:
    monkeypatch.setattr(SystemConfigSettings, "pnm_dir", classmethod(lambda cls: str(pnm_dir)))


def test_collect_skips_empty_filename(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _patch_capture_group(monkeypatch)
    _patch_transaction_record(monkeypatch, _record(""))
    _patch_pnm_dir(monkeypatch, tmp_path)

    aggregator = capture_data_aggregator.CaptureDataAggregator("group1")
    collection = aggregator.collect()

    assert collection.length() == 0


def test_collect_skips_directory_filename(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _patch_capture_group(monkeypatch)
    _patch_transaction_record(monkeypatch, _record("pnm_dir"))
    _patch_pnm_dir(monkeypatch, tmp_path)

    (tmp_path / "pnm_dir").mkdir(parents=True, exist_ok=True)

    aggregator = capture_data_aggregator.CaptureDataAggregator("group1")
    collection = aggregator.collect()

    assert collection.length() == 0
