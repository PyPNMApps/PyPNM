# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import io
import logging
import os
import zipfile

from fastapi import HTTPException
from fastapi.responses import StreamingResponse

from pypnm.api.routes.advance.common.abstract.service import AbstractService
from pypnm.api.routes.advance.common.capture_service import AbstractCaptureService
from pypnm.api.routes.advance.common.operation_manager import OperationManager
from pypnm.api.routes.common.classes.file_capture.capture_group import CaptureGroup
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.types import GroupId, OperationId


class AbstractMultiCaptureRouter(AbstractService):
    """
    Shared helper base for multi-capture routers.

    Provides common route orchestration helpers for:
    - operation/service lookup with HTTP 404 translation
    - operation_id -> capture_group_id lookup normalization
    - ZIP download response assembly from capture samples
    """

    def __init__(self) -> None:
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)

    def _get_service_or_404(self, operation_id: OperationId) -> AbstractCaptureService:
        """Return an in-memory capture service instance or raise HTTP 404."""
        try:
            return self.getService(operation_id)
        except KeyError as err:
            raise HTTPException(status_code=404, detail="Operation not found") from err

    def _get_capture_group_or_none(self, operation_id: OperationId) -> GroupId | None:
        """
        Resolve a capture group for an operation id.

        Normalizes the current OperationManager behavior, which may return an empty string
        rather than raising when an operation cannot be found.
        """
        capture_group_id = OperationManager.get_capture_group(operation_id)
        if not str(capture_group_id).strip():
            return None
        return capture_group_id

    def _build_results_zip_response(self, operation_id: OperationId, filename_prefix: str) -> StreamingResponse:
        """
        Build a ZIP streaming response for files associated with an in-memory capture service.

        Missing files are skipped with warnings.
        """
        service = self._get_service_or_404(operation_id)
        samples = service.results(operation_id)

        pnm_dir = str(SystemConfigSettings.pnm_dir())
        cm = getattr(service, "cm", None)
        mac = getattr(getattr(cm, "get_mac_address", None), "mac_address", "unknown")

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zipf:
            for sample in samples:
                filename = getattr(sample, "filename", "")
                if not str(filename).strip():
                    continue

                file_path = os.path.join(pnm_dir, str(filename))
                arcname = os.path.basename(str(filename))
                try:
                    zipf.write(file_path, arcname=arcname)
                except FileNotFoundError:
                    self.logger.warning("File not found, skipping: %s", file_path)
                except Exception as exc:
                    self.logger.warning("Skipping %s: %s", file_path, exc)

        buf.seek(0)
        headers = {"Content-Disposition": f"attachment; filename={filename_prefix}_{mac}_{operation_id}.zip"}
        return StreamingResponse(buf, media_type="application/zip", headers=headers)

    def _repair_capture_group_from_service_samples(self, operation_id: OperationId, capture_group_id: GroupId) -> int:
        """
        Backfill capture-group transaction IDs from in-memory service samples.

        This is a no-op when the operation service is not available in memory.
        Returns the number of transaction IDs added to the capture-group DB.
        """
        try:
            service = self.getService(operation_id)
        except Exception:
            return 0

        txn_ids: list[str] = []
        for sample in service.results(operation_id):
            txn_id = getattr(sample, "transaction_id", "")
            if str(txn_id).strip():
                txn_ids.append(str(txn_id))

        if not txn_ids:
            return 0

        try:
            cg = CaptureGroup(capture_group_id)
            existing = set(str(txn) for txn in cg.getTransactionIds())
            added = 0
            for txn_id in txn_ids:
                if txn_id in existing:
                    continue
                cg.add_transaction(txn_id)
                existing.add(txn_id)
                added += 1
            if added > 0:
                self.logger.warning(
                    "Repaired capture group %s for op %s by adding %d transaction IDs from in-memory samples.",
                    capture_group_id,
                    operation_id,
                    added,
                )
            return added
        except Exception as exc:
            self.logger.warning(
                "Capture-group repair failed for op %s group %s: %s",
                operation_id,
                capture_group_id,
                exc,
            )
            return 0
