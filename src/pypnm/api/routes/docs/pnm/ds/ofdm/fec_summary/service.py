# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging

from pypnm.api.routes.common.extended.common_measure_service import CommonMeasureService
from pypnm.config.pnm_config_manager import PnmConfigManager
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.cm_snmp_operation import FecSummaryType
from pypnm.lib.inet import Inet
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest


class CmDsOfdmFecSummaryService(CommonMeasureService):
    """
    Service class for handling downstream OFDM FEC Summary operations.

    This class initiates a PNM test to retrieve Forward Error Correction (FEC) summary statistics
    for downstream OFDM channels over a specified time window (e.g., 10 minutes or 24 hours).

    Parameters:
        cable_modem (CableModem): The target cable modem to run the FEC summary test on.
        fec_summary_type (FecSummaryType): The FEC summary interval type (e.g., TEN_MIN, ONE_DAY).
        tftp_server_inet (Inet): The IP address of the TFTP server used for result file retrieval.
        tftp_path (str, optional): The path on the TFTP server where test results are stored. Defaults to "".
        snmp_write_community (str, optional): The SNMP write community string. Defaults to "private".
    """
    def __init__(self, cable_modem: CableModem,
                 fec_summary_type: FecSummaryType,
                 tftp_servers: tuple[Inet, Inet] = PnmConfigManager.get_tftp_servers(),
                 tftp_path: str = PnmConfigManager.get_tftp_path(),
                 system_description: dict[str, str] | None = None) -> None:
        super().__init__(DocsPnmCmCtlTest.DS_OFDM_CODEWORD_ERROR_RATE,
                        cable_modem,
                        tftp_servers,
                        tftp_path,
                        cable_modem.getWriteCommunity(),
                        fec_summary_type=fec_summary_type,
                        system_description=system_description)
        self.logger = logging.getLogger(self.__class__.__name__)
