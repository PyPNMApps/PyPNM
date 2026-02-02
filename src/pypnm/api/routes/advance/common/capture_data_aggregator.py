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
from pypnm.lib.types import FileNameStr, GroupId, TransactionId
from pypnm.pnm.lib.pnm_artifact_store import PnmArtifactStore


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
        self._artifact_store = PnmArtifactStore(pnm_dir=self._pnm_dir)

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

            try:
                compression = record.compression.model_dump() if record.compression else None
                bin:bytes = self._artifact_store.read_bytes(
                    record.transaction_id,
                    FileNameStr(str(record.filename)),
                    compression,
                )
                self.logger.debug(f'Reading capture - count={file_count},  txn={txn_id},  file={record.filename}, size={len(bin)}')

            except FileNotFoundError:
                self.logger.error(f'Capture file not found: {record.filename}')
                raise

            except Exception as exc:
                self.logger.error(f'Error reading file {record.filename}: {exc}')
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
