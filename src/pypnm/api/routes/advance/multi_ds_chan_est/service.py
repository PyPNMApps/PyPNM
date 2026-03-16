# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
from __future__ import annotations

import logging

from pypnm.api.routes.advance.common.capture_service import AbstractCaptureService
from pypnm.api.routes.advance.common.operation_kind import MultiCaptureOperation
from pypnm.api.routes.common.extended.common_measure_schema import (
    DownstreamOfdmParameters,
)
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.ds.ofdm.chan_est_coeff.service import (
    CmDsOfdmChanEstCoefService,
)
from pypnm.docsis.cable_modem import CableModem, PnmConfigManager
from pypnm.lib.inet import Inet


class MultiChannelEstimationService(AbstractCaptureService):
    """
    Service to trigger a Cable Modem's ChannelEstimation capture via SNMP/TFTP and
    collect corresponding file-transfer transactions as CaptureSample objects.

    Each invocation of _capture_sample will:
      1. Send SNMP command to start ChannelEstimation capture and TFTP transfer.
      2. Await MessageResponse payload containing transaction entries.
      3. For each payload entry of type PNM_FILE_TRANSACTION with SUCCESS status:
         - Lookup the transaction record for filename retrieval.
         - Yield a CaptureSample(timestamp, transaction_id, filename).
      4. On SNMP/TFTP error or no valid entries, return a single CaptureSample
         with the appropriate error message.

    Inherited:
      - duration: total measurement duration in seconds.
      - interval: interval between captures in seconds.
    """
    OPERATION_NAME = MultiCaptureOperation.MULTI_DS_CHANNEL_ESTIMATION
    MEASURE_MODE = "standard"

    def __init__(self, cm: CableModem,
                tftp_servers: tuple[Inet, Inet] = PnmConfigManager.get_tftp_servers(),
                tftp_path: str = PnmConfigManager.get_tftp_path(),
                 duration: float = 1, interval: float = 1,
                 interface_parameters: DownstreamOfdmParameters | None = None,
                 system_description: dict[str, str] | None = None,) -> None:
        """
        Initialize the MultiChannelEstimationService.

        Args:
            cm: Configured CableModem instance for SNMP/TFTP operations.
            tftp_servers: Tuple of Inet objects representing TFTP servers.
            tftp_path: Path on the TFTP server for file storage.
            duration: Total duration (seconds) to run periodic captures.
            interval: Time (seconds) between successive captures.
        """
        super().__init__(duration, interval, system_description=system_description)
        self.cm = cm
        self.tftp_servers = tftp_servers
        self.tftp_path = tftp_path
        self.logger = logging.getLogger(__name__)
        self._interface_parameters = interface_parameters

    async def _capture_message_response(self) -> MessageResponse:
        """
        Perform one ChannelEstimation capture cycle.

        Returns:
            A list of CaptureSample objects. On success, one per file-transfer
            transaction; on error, a single Sample with error filled.

        Error handling:
            - Catches exceptions from SNMP/TFTP invocation.
            - Validates payload type and entry contents.
        """
        try:
            msg_rsp: MessageResponse = await CmDsOfdmChanEstCoefService(
                self.cm,
                self.tftp_servers,
                self.tftp_path,
                system_description=self.get_system_description(),
            ).set_and_go(interface_parameters=self._interface_parameters)

        except Exception as exc:
            err_msg = f"Exception during ChannelEstimation SNMP/TFTP operation: {exc}"
            self.logger.error(err_msg, exc_info=True)
            return MessageResponse(ServiceStatusCode.DS_OFDM_CHAN_EST_NOT_AVAILABLE)

        if msg_rsp.status != ServiceStatusCode.SUCCESS:
            err_msg = f"SNMP/TFTP failure: status={msg_rsp.status}"
            self.logger.error(err_msg)
            return MessageResponse(ServiceStatusCode.DS_OFDM_CHAN_EST_NOT_AVAILABLE)

        return msg_rsp
