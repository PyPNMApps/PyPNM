## Agent Review Bundle Summary
- Goal: Prevent CaptureDataAggregator from trying to read directories or empty filenames and add regression coverage.
- Changes: Skipped empty filenames and directory paths in capture aggregation; added tests for both cases.
- Files: src/pypnm/api/routes/advance/common/capture_data_aggregator.py; tests/test_capture_data_aggregator_invalid_filename.py.
- Tests: python3 -m compileall src; ruff check src; ruff format --check . (fails: repo drift); pytest -q.
- Notes: pytest skips due to PNM_CM_IT not set; ruff format check failed because of pre-existing formatting drift.

# FILE: src/pypnm/api/routes/advance/common/capture_data_aggregator.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from pathlib import Path

from pypnm.api.routes.advance.common.transactionsCollection import TransactionCollection
from pypnm.api.routes.advance.common.types.types import TransactionFileCollection
from pypnm.api.routes.common.classes.file_capture.capture_group import CaptureGroup
from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.api.routes.common.classes.file_capture.types import TransactionRecordModel
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.types import GroupId, TransactionId


class CaptureDataAggregator:
    """
    Collect raw capture files for a given capture group, returning (filename, bytes) pairs.

    Typical usage:
        aggregator = CaptureDataAggregator(capture_group_id)
        file_entries = aggregator.collect()
        collection = aggregator.getPnmCollection()
    """

    def __init__(self, capture_group_id: GroupId) -> None:
        """
        Parameters
        ----------
        capture_group_id : str
            Identifier for the capture group.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self._capture_group_id:GroupId = capture_group_id
        self._pnm_dir = Path(SystemConfigSettings.pnm_dir())
        self._trans_file_bin_entries: TransactionFileCollection = []
        self._trans_collection: TransactionCollection = TransactionCollection()

    # ──────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────
    def collect(self) -> TransactionCollection:
        """
        Gather all capture files for the configured group and read their contents.

        """
        capture_grp = CaptureGroup(self._capture_group_id)
        txn_ids: list[TransactionId] = capture_grp.getTransactionIds()

        if not txn_ids:
            self.logger.warning(f"No transactions found for capture_group_id='{self._capture_group_id}'")
            return TransactionCollection()

        for file_count, txn_id in enumerate(txn_ids, 1):

            record: TransactionRecordModel = PnmFileTransaction().getRecordModel(txn_id)
            if not str(record.filename).strip():
                self.logger.error(f"Capture record missing filename: txn={txn_id}")
                continue

            file_path = self._safe_join(self._pnm_dir, record.filename)
            if file_path.is_dir():
                self.logger.error(f"Capture file path is a directory: {file_path}")
                continue

            try:
                bin:bytes = file_path.read_bytes()
                self.logger.debug(f'Reading capture - count={file_count},  txn={txn_id},  file={file_path.name}, size={len(bin)}')

            except FileNotFoundError:
                self.logger.error(f'Capture file not found: {file_path}')
                raise

            except Exception as exc:
                self.logger.error(f'Error reading file {file_path}: {exc}')
                continue

            if not self._trans_collection.add(record, bin):
                self.logger.error(f'Unable to add [{record.filename}] to Transaction Collection')
                continue

        return self._trans_collection

    # ──────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────
    def _safe_join(self, base_dir: Path, user_filename: str) -> Path:
        """
        Safely join `user_filename` under `base_dir`, preventing absolute-path override
        and directory traversal.

        Rules:
        - If you *do not* need subdirectories: only allow basename component.
        - If you *do* need subdirectories under base_dir: set allow_subdirs=True below.

        Returns a path that is guaranteed to remain within `base_dir`.
        """
        allow_subdirs = False  # flip to True if legitimate subfolders are expected

        fname = str(user_filename)

        # Option A (default): collapse to basename (blocks any subdir usage).
        candidate = base_dir / Path(fname).name

        # Option B (if allow_subdirs is True): use full user path under base_dir
        if allow_subdirs:
            candidate = base_dir / fname

        # Resolve without touching filesystem; verify it stays within base_dir
        base_resolved = base_dir.resolve(strict=False)
        file_path = candidate.resolve(strict=False)

        try:
            file_path.relative_to(base_resolved)
        except ValueError:
            # Outside of base_dir → reject
            self.logger.error(
                "Rejected filename outside save_dir; group_id=%s base=%s filename=%r resolved=%s",
                self._capture_group_id, base_resolved, fname, file_path)

            return base_resolved / "__invalid__"

        return file_path


# FILE: tests/test_capture_data_aggregator_invalid_filename.py
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
