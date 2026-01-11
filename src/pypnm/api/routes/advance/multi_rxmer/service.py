# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
import math
from typing import cast

from pypnm.api.routes.advance.common.capture_service import AbstractCaptureService
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.ds.ofdm.fec_summary.service import (
    CmDsOfdmFecSummaryService,
)
from pypnm.api.routes.docs.pnm.ds.ofdm.modulation_profile.service import (
    CmDsOfdmModProfileService,
)
from pypnm.api.routes.docs.pnm.ds.ofdm.rxmer.service import CmDsOfdmRxMerService
from pypnm.docsis.cable_modem import CableModem, PnmConfigManager
from pypnm.docsis.cm_snmp_operation import FecSummaryType
from pypnm.lib.inet import Inet


class MultiRxMerService(AbstractCaptureService):
    """
    Service to trigger a Cable Modem's RxMER capture via SNMP/TFTP and
    collect corresponding file-transfer transactions as CaptureSample objects.

    Each invocation of _capture_sample will:
      1. Send SNMP command to start RxMER capture and TFTP transfer.
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

    def __init__(
        self,
        cm: CableModem,
        duration: float,
        interval: float,
        tftp_servers: tuple[Inet, Inet] = PnmConfigManager.get_tftp_servers(),
        tftp_path: str = PnmConfigManager.get_tftp_path(),
    ) -> None:
        """
        Initialize the MultiRxMerService.

        Args:
            cm: Configured CableModem instance for SNMP/TFTP operations.
            duration: Total duration (seconds) to run periodic captures.
            interval: Time (seconds) between successive captures.
        """
        super().__init__(duration, interval)
        self.cm = cm
        self.tftp_servers = tftp_servers
        self.tftp_path = tftp_path
        self.logger = logging.getLogger(self.__class__.__name__)

    async def _capture_message_response(self) -> MessageResponse:
        """
        Perform one RxMER capture cycle.

        Returns:
            A list of CaptureSample objects. On success, one per file-transfer
            transaction; on error, a single Sample with error filled.

        Error handling:
            - Catches exceptions from SNMP/TFTP invocation.
            - Validates payload type and entry contents.
        """
        try:
            msg_rsp: MessageResponse = await CmDsOfdmRxMerService(
                self.cm, self.tftp_servers, self.tftp_path
            ).set_and_go()

        except Exception as exc:
            err_msg = f"Exception during RxMER SNMP/TFTP operation: {exc}"
            self.logger.error(err_msg, exc_info=True)
            return MessageResponse(ServiceStatusCode.DS_OFDM_RXMER_NOT_AVAILABLE)

        if msg_rsp.status != ServiceStatusCode.SUCCESS:
            err_msg = f"SNMP/TFTP failure: status={msg_rsp.status}"
            self.logger.error(err_msg)
            return MessageResponse(ServiceStatusCode.DS_OFDM_RXMER_NOT_AVAILABLE)

        return msg_rsp


class MultiRxMer_Ofdm_Performance_1_Service(AbstractCaptureService):
    """
    Service to trigger a Cable Modem's RxMER capture via SNMP/TFTP and
    collect corresponding file-transfer transactions as CaptureSample objects.

    Each invocation of _capture_sample will:
      1. Send SNMP command to start RxMER capture and TFTP transfer.
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

    def __init__(
        self,
        cm: CableModem,
        tftp_servers: tuple[Inet, Inet] = PnmConfigManager.get_tftp_servers(),
        tftp_path: str = PnmConfigManager.get_tftp_path(),
        duration: float = 1,
        interval: float = 1,
    ) -> None:
        """
        Initialize the MultiRxMerService.

        Args:
            cm: Configured CableModem instance for SNMP/TFTP operations.
            duration: Total duration (seconds) to run periodic captures.
            interval: Time (seconds) between successive captures.
        """
        super().__init__(duration, interval)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.cm = cm
        self.tftp_servers = tftp_servers
        self.tftp_path = tftp_path
        self._half_life = math.ceil(self.duration / 2)
        self._mod_profile_done = False

        MIN_10 = 600
        self._fec_thresholds = list(range(int(self.duration), -1, -MIN_10))
        self._handled_fec_thresholds = set()

    async def _capture_message_response(self) -> MessageResponse:
        """
        Operation:
        -----------------------
        * Collect a series of RxMER
        * Collect at least 1 Modualtion Profile at 50% duration
        * Collect a Fec Summary at:
            - 1 FecSummary every 10 Min (10 Min provides sec-by-sec accounting)
            - At end of the test

        OFDM_PROFILE_MEASUREMENT_1
        --------------------------
        * Calculate the Avg RxMER of the series
        * Calculate Shannon for each subcarrier
        * Compare each Modualtion Profile against the RxMER Average
        * Calculate the percentage of subcarries that are outside a given profile
        * Provide total FEC Stats for each profile over the time of the capture.

        Returns:
            A list of CaptureSample objects. On success, one per file-transfer
            transaction; on error, a single Sample with error filled.

        Error handling:
            - Catches exceptions from SNMP/TFTP invocation.
            - Validates payload type and entry contents.
        """
        operation_id = self.getOperationID()
        self.logger.debug(f"OperationID: {operation_id}")
        operation = self.getOperation(operation_id)
        time_remaining = cast(int, operation["time_remaining"])

        # First, perform the primary RxMER capture
        try:
            msg_rsp: MessageResponse = await CmDsOfdmRxMerService(
                self.cm, self.tftp_servers, self.tftp_path
            ).set_and_go()
        except Exception as exc:
            self.logger.error(f"Exception during RxMER capture: {exc}", exc_info=True)
            return MessageResponse(ServiceStatusCode.DS_OFDM_RXMER_NOT_AVAILABLE)

        # 50%‐time modulation profile (only once)
        if not self._mod_profile_done and time_remaining <= self._half_life:
            self._mod_profile_done = True

            self.logger.info(f"Collecting a Modulation Profile @ {time_remaining}s")
            try:
                msg_rsp = await CmDsOfdmModProfileService(
                    self.cm, self.tftp_servers, self.tftp_path
                ).set_and_go()

            except Exception as exc:
                self.logger.error(
                    f"Exception during ModProfile capture: {exc}", exc_info=True
                )
                return MessageResponse(
                    ServiceStatusCode.DS_OFDM_MOD_PROFILE_NOT_AVALAIBLE
                )

            if msg_rsp.status != ServiceStatusCode.SUCCESS:
                self.logger.error(
                    f"Unable to get OFDM Modualtion Profile, status={msg_rsp.status.name}"
                )
                return MessageResponse(
                    ServiceStatusCode.DS_OFDM_MOD_PROFILE_NOT_AVALAIBLE
                )

        # Every 10 min/600 seconds (and once at end), FEC summary
        self.logger.info(f"Checking FEC Summary @ TimeRemaining={time_remaining}s")

        for thresh in self._fec_thresholds:
            self.logger.info(
                f"INSIDE-THRESH-LOOP({thresh}): Checking FEC Summary @ TimeRemaining={time_remaining}s - Thresholds: {self._fec_thresholds}"
            )
            self.logger.info(
                f"Final-Invovcation: {self.getOperationFinalInvocation(operation_id)}"
            )

            if (
                self.getOperationFinalInvocation(operation_id)
                or (time_remaining <= thresh)
                and (thresh not in self._handled_fec_thresholds)
            ):
                self._handled_fec_thresholds.add(thresh)
                self.logger.info(
                    f"Collecting a FEC Summary @ TimeRemaining={time_remaining}s (threshold={thresh})"
                )

                try:
                    msg_rsp = await CmDsOfdmFecSummaryService(
                        self.cm,
                        FecSummaryType.TEN_MIN,
                        tftp_servers=self.tftp_servers,
                        tftp_path=self.tftp_path,
                    ).set_and_go()

                except Exception as exc:
                    self.logger.error(
                        f"Exception during FEC summary: {exc}", exc_info=True
                    )
                    return MessageResponse(
                        ServiceStatusCode.DS_OFDM_FEC_SUMMARY_NOT_AVALIABLE
                    )

                if msg_rsp.status != ServiceStatusCode.SUCCESS:
                    self.logger.error(
                        f"Unable to get last FecSummary, status={msg_rsp.status.name}"
                    )
                    return MessageResponse(
                        ServiceStatusCode.DS_OFDM_FEC_SUMMARY_NOT_AVALIABLE
                    )

                break

        return msg_rsp
