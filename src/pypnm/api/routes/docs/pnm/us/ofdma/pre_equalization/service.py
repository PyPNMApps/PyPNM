
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
import logging

from pypnm.api.routes.common.extended.common_measure_service import CommonMeasureService
from pypnm.config.pnm_config_manager import PnmConfigManager
from pypnm.docsis.cable_modem import CableModem
from pypnm.lib.inet import Inet
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest


class CmUsOfdmaPreEqService(CommonMeasureService):
    """
    Service for performing Upstream OFDMA Pre-Equalization analysis on a DOCSIS 3.1 cable modem.

    This class initiates a PNM (Proactive Network Maintenance) test to collect and analyze
    pre-equalization coefficients from the upstream OFDMA channel. The collected data helps
    diagnose issues such as group delay, in-channel frequency response (ICFR) impairments,
    or common path distortions (CPD).

    Attributes:
        cable_modem (CableModem): The target cable modem instance for the test.
        tftp_servers (Tuple[Inet, Inet]): Tuple of primary and secondary TFTP servers used
            for file transfers during test execution.
        tftp_path (str): The remote TFTP path where result files will be stored.
        logger (logging.Logger): Logger instance for service-level logging and diagnostics.

    Inherits:
        CommonMeasureService: Provides core functionality for initiating tests,
        retrieving results, and performing SNMP or file-based operations.
    """
    def __init__(
        self,
        cable_modem: CableModem,
        tftp_servers: tuple[Inet, Inet] = PnmConfigManager.get_tftp_servers(),
        tftp_path: str = PnmConfigManager.get_tftp_path(),
        system_description: dict[str, str] | None = None,
    ) -> None:
        super().__init__(
            DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF,
            cable_modem,
            tftp_servers,
            tftp_path,
            cable_modem.getWriteCommunity(),
            system_description=system_description,
        )
        self.logger = logging.getLogger(self.__class__.__name__)
