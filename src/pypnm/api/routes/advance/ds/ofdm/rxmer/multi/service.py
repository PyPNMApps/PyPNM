# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging

from pypnm.api.routes.advance.common.operation_workflow_service import (
    OperationWorkflowService,
)
from pypnm.api.routes.advance.ds.ofdm.rxmer.multi.schemas import (
    MultiRxMerResultRequest,
    MultiRxMerResultResponse,
    MultiRxMerStartRequest,
    MultiRxMerStartResponse,
)
from pypnm.api.routes.advance.multi_rxmer.service import MultiRxMerService
from pypnm.api.routes.common.classes.file_capture.pnm_file_opearation import (
    OperationCaptureGroupResolver,
)
from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.api.routes.common.classes.file_capture.types import TransactionRecordModel
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.docsis.cable_modem import CableModem
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress


class MultiRxMerWorkflowService:
    """
    Start and result helpers for multi-RxMER capture workflows.
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)

    async def start(self, request: MultiRxMerStartRequest) -> MultiRxMerStartResponse:
        cm = CableModem(
            mac_address=MacAddress(request.mac_address),
            inet=Inet(request.ip_address),
        )
        service = MultiRxMerService(
            cm=cm,
            duration=request.duration,
            interval=request.interval,
        )
        group_id, operation_id = await service.start()
        return MultiRxMerStartResponse(
            mac_address=request.mac_address,
            status=ServiceStatusCode.SUCCESS,
            message="Operation started",
            operation_id=operation_id,
            capture_group_id=group_id,
        )

    def result(self, request: MultiRxMerResultRequest) -> MultiRxMerResultResponse:
        status = OperationWorkflowService.get_result(request.operation_id)
        resolver = OperationCaptureGroupResolver()
        capture_group_id = resolver.get_capture_group_id(request.operation_id)
        if not capture_group_id:
            raise KeyError(
                f"Capture group not found for operation: {request.operation_id}"
            )
        txn_ids = resolver.get_transaction_ids_for_capture_group(capture_group_id)
        txn_store = PnmFileTransaction()
        transactions: list[TransactionRecordModel] = []
        for txn_id in txn_ids:
            model = txn_store.getRecordModel(txn_id)
            tx_id = str(getattr(model, "transaction_id", "")).strip()
            if tx_id:
                transactions.append(model)
                continue
            self.logger.warning(
                "Missing transaction record for transaction_id=%s", txn_id
            )
        if not transactions:
            raise KeyError(
                f"No transaction records found for capture_group_id={capture_group_id}"
            )
        return MultiRxMerResultResponse(
            mac_address=MacAddress.null(),
            status=ServiceStatusCode.SUCCESS,
            message=None,
            operation=status,
            capture_group_id=capture_group_id,
            transactions=transactions,
            artifact_paths=status.artifact_paths,
        )


__all__ = ["MultiRxMerWorkflowService"]
