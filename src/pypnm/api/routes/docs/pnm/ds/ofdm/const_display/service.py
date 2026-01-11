# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging

from pypnm.api.routes.common.extended.common_measure_service import CommonMeasureService
from pypnm.config.pnm_config_manager import PnmConfigManager
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.DsCmConstDisplay import (
    CmDsConstellationDisplayConst as ConstelDisplayConst,
)
from pypnm.lib.inet import Inet
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest


class CmDsOfdmConstDisplayService(CommonMeasureService):
    """
    Service for triggering and retrieving DOCSIS 3.1 Downstream OFDM Constellation Display measurements.

    This class orchestrates a Proactive Network Maintenance (PNM) control test on a cable modem
    to capture constellation data from downstream OFDM channels. The test results are transferred
    via TFTP and typically visualized to evaluate symbol demodulation quality, such as detecting
    phase noise, symbol dispersion, or signal degradation.

    The constellation display provides a two-dimensional scatter plot of I/Q symbol points,
    helping diagnose modulation fidelity and in-channel interference.

    Parameters:
        cable_modem (CableModem): Target cable modem instance on which to perform the test.
        modulation_order_offset (int, optional): Offset used to align modulation constellation with expected resolution.
        number_sample_symbol (int, optional): Number of OFDM symbols to capture (default: 8192).
        tftp_servers (Tuple[Inet, Inet], optional): IPv4 and IPv6 TFTP server IPs (default: from config).
        tftp_path (str, optional): Destination path on the TFTP server for result files (default: from config).

    Inherits:
        CommonMeasureService: Base class for SNMP-controlled PNM measurement orchestration.

    Usage:
        service = CmDsOfdmConstDisplayService(cable_modem)

    See Also:
        - CmDsConstDispMeas: Class used to parse and visualize the retrieved constellation data.
        - CommonMeasureService: Provides core test initiation and file retrieval logic.
    """

    def __init__(
        self,
        cable_modem: CableModem,
        modulation_order_offset: int = ConstelDisplayConst.MODULATION_OFFSET.value,
        number_sample_symbol: int = ConstelDisplayConst.NUM_SAMPLE_SYMBOL.value,
        tftp_servers: tuple[Inet, Inet] = PnmConfigManager.get_tftp_servers(),
        tftp_path: str = PnmConfigManager.get_tftp_path(),
    ) -> None:
        super().__init__(
            DocsPnmCmCtlTest.DS_CONSTELLATION_DISP,
            cable_modem,
            tftp_servers,
            tftp_path,
            cable_modem.getWriteCommunity(),
            modulation_order_offset=modulation_order_offset,
            number_sample_symbol=number_sample_symbol,
        )
        self.logger = logging.getLogger(self.__class__.__name__)
