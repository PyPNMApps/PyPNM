# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging

from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.api.routes.common.extended.common_messaging_service import (
    CommonMessagingService,
    MessageResponse,
    MessageResponseType,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.file_processor import FileProcessor
from pypnm.lib.types import MacAddressStr
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest
from pypnm.pnm.parser.CmDsConstDispMeas import CmDsConstDispMeas
from pypnm.pnm.parser.CmDsHist import CmDsHist
from pypnm.pnm.parser.CmDsOfdmChanEstimateCoef import CmDsOfdmChanEstimateCoef
from pypnm.pnm.parser.CmDsOfdmFecSummary import CmDsOfdmFecSummary
from pypnm.pnm.parser.CmDsOfdmModulationProfile import CmDsOfdmModulationProfile
from pypnm.pnm.parser.CmDsOfdmRxMer import CmDsOfdmRxMer
from pypnm.pnm.parser.CmSpectrumAnalysis import CmSpectrumAnalysis
from pypnm.pnm.parser.CmSpectrumAnalysisSnmp import CmSpectrumAnalysisSnmp
from pypnm.pnm.parser.CmUsOfdmaPreEq import CmUsOfdmaPreEq


class CommonProcessService(CommonMessagingService):
    def __init__(
        self, message_response: MessageResponse, **extra_options: object
    ) -> None:
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.pnm_file_dir = self.config_mgr = SystemConfigSettings.pnm_dir()
        self._msg_rsp = message_response
        self.logger.debug(f"CommonProcessService: {self._msg_rsp}")

    def process(self) -> MessageResponse:
        """
        Processes each item in the MessageResponse payload.

        Expected payload format:
            {
                "payload": [
                    {
                        "status": "SUCCESS",
                        "message_type": "PNM_FILE_TRANSACTION",
                        "message": {
                            "transaction_id": "275de83146e904d7",
                            "filename": "ds_ofdm_rxmer_per_subcar_00:50:f1:12:e2:63_954000000_1746501260.bin"
                        }
                    },
                    ...
                ]
            }

        Returns:
            MessageResponse: A success message if all payloads are processed,
                            or an error message if a transaction record is missing.
        """
        for payload in self._msg_rsp.payload:
            status, message_type, message = MessageResponse.get_payload_msg(payload)

            self.logger.debug(
                f"CommonProcessService.MessageResponse: MSG-TYPE: {message_type}"
            )

            if status != ServiceStatusCode.SUCCESS.name:
                self.logger.error(f"Status Error: {status}")
                continue

            if message_type == MessageResponseType.PNM_FILE_TRANSACTION.name:
                transaction_id = message.get("transaction_id")
                transaction_record = PnmFileTransaction().get_record(transaction_id)

                if not transaction_record:
                    self.build_msg(ServiceStatusCode.TRANSACTION_RECORD_GET_FAILED)
                    pass

                self._process_pnm_measure_test(transaction_record)

            elif message_type == MessageResponseType.SNMP_DATA_RTN_SPEC_ANALYSIS.name:
                transaction_id = message.get("transaction_id")
                self.logger.debug(f"process() -> Found TransactionID: {transaction_id}")

                transaction_record = PnmFileTransaction().get_record(transaction_id)
                self._process_pnm_measure_test(transaction_record)

        return self.send_msg()

    def _process_pnm_measure_test(self, transaction_record: dict) -> ServiceStatusCode:
        """
        Processes the provided PNM transaction record based on its test type.

        Args:
            transaction_record (dict): The transaction metadata including test type and filename.

        Returns:
            ServiceStatusCode: The result of the operation, indicating success or error type.
        """
        pnm_test_type = transaction_record[PnmFileTransaction().PNM_TEST_TYPE]

        if not pnm_test_type:
            self.logger.error("PNM test type is missing in the transaction record.")
            return ServiceStatusCode.MISSING_PNM_TEST_TYPE

        self.logger.debug(f"Processing PNM test type: {pnm_test_type}")
        if not transaction_record.get(PnmFileTransaction.FILE_NAME):
            self.logger.error("Filename is missing in the transaction record.")
            return ServiceStatusCode.MISSING_PNM_FILENAME

        # Check to make sure the pnm_test_type is in the DocsPnmCmCtlTest enum
        if pnm_test_type not in DocsPnmCmCtlTest.__members__:
            self.logger.error(f"Unsupported PNM test type: {pnm_test_type}")
            return ServiceStatusCode.UNSUPPORTED_TEST_TYPE

        file_name_dst = (
            f"{self.pnm_file_dir}/{transaction_record[PnmFileTransaction.FILE_NAME]}"
        )
        device_details: dict[str, str] = transaction_record[
            PnmFileTransaction.DEVICE_DETAILS
        ]
        pnm_data = FileProcessor(file_name_dst).read_file()

        if pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR.name:
            pnm_dict = self._add_device_details(
                CmDsOfdmRxMer(binary_data=pnm_data).to_dict(), device_details
            )
            self.build_msg(ServiceStatusCode.SUCCESS, pnm_dict)

        elif pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_CODEWORD_ERROR_RATE.name:
            pnm_dict = self._add_device_details(
                CmDsOfdmFecSummary(binary_data=pnm_data).to_dict(), device_details
            )
            self.build_msg(ServiceStatusCode.SUCCESS, pnm_dict)

        elif pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_CHAN_EST_COEF.name:
            pnm_dict = self._add_device_details(
                CmDsOfdmChanEstimateCoef(binary_data=pnm_data).to_dict(), device_details
            )
            self.build_msg(ServiceStatusCode.SUCCESS, pnm_dict)

        elif pnm_test_type == DocsPnmCmCtlTest.DS_CONSTELLATION_DISP.name:
            pnm_dict = self._add_device_details(
                CmDsConstDispMeas(binary_data=pnm_data).to_dict(), device_details
            )
            self.build_msg(ServiceStatusCode.SUCCESS, pnm_dict)

        elif pnm_test_type == DocsPnmCmCtlTest.DS_HISTOGRAM.name:
            pnm_dict = self._add_device_details(
                CmDsHist(binary_data=pnm_data).to_dict(), device_details
            )
            self.build_msg(ServiceStatusCode.SUCCESS, pnm_dict)

        elif pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_MODULATION_PROFILE.name:
            pnm_dict = self._add_device_details(
                CmDsOfdmModulationProfile(binary_data=pnm_data).to_dict(),
                device_details,
            )
            self.build_msg(ServiceStatusCode.SUCCESS, pnm_dict)

        elif pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER.name:
            self.logger.debug("Processing DS_SPECTRUM_ANALYZER PNM data")
            pnm_dict = self._add_device_details(
                CmSpectrumAnalysis(pnm_data).to_dict(), device_details
            )
            self.build_msg(ServiceStatusCode.SUCCESS, pnm_dict)

        elif pnm_test_type == DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF.name:
            self.logger.debug(f"Processing {pnm_test_type} PNM data")
            pnm_dict = self._add_device_details(
                CmUsOfdmaPreEq(binary_data=pnm_data).to_dict(), device_details
            )
            self.build_msg(ServiceStatusCode.SUCCESS, pnm_dict)

        elif pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA.name:
            self.logger.info(f"Processing {pnm_test_type} PNM data")
            pnm_dict = self._add_device_details(
                CmSpectrumAnalysisSnmp(pnm_data).to_dict(), device_details
            )
            pnm_dict["mac_address"] = MacAddressStr(
                transaction_record[PnmFileTransaction.MAC_ADDRESS]
            )
            self.build_msg(ServiceStatusCode.SUCCESS, pnm_dict)

        else:
            self.logger.error(f"Unsupported PNM test type: {pnm_test_type}")
            return ServiceStatusCode.UNSUPPORTED_TEST_TYPE

        return ServiceStatusCode.SUCCESS

    def _add_device_details(
        self, pnm_data: dict, device_details: dict[str, str]
    ) -> dict:
        """
        Adds device details to the PNM data dictionary.

        Args:
            pnm_data (dict): The PNM data dictionary.
            device_details (Dict[str, str]): Device details to be added.

        Returns:
            dict: Updated PNM data dictionary with device details.
        """
        if PnmFileTransaction.DEVICE_DETAILS not in pnm_data:
            pnm_data[PnmFileTransaction.DEVICE_DETAILS] = {}
        pnm_data[PnmFileTransaction.DEVICE_DETAILS].update(device_details)
        return pnm_data
