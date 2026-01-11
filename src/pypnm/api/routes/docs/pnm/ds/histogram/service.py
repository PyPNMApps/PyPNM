# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging

from pypnm.api.routes.common.extended.common_measure_service import CommonMeasureService
from pypnm.config.pnm_config_manager import PnmConfigManager
from pypnm.docsis.cable_modem import CableModem
from pypnm.lib.inet import Inet
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest


class CmDsHistogramService(CommonMeasureService):
    """
    Service for initiating and managing DOCSIS Downstream Histogram measurements on a cable modem.

    This class leverages SNMP to configure and control the measurement process, and uses TFTP
    for offloading histogram capture results.

    Functionality:
    - Sets up histogram capture on the modem.
    - Configures capture timeout via `docsPnmCmDsHistTimeOut`.
    - Initiates capture using `docsPnmCmDsHistEnable`.
    - Stores the resulting data file to a TFTP server using `docsPnmCmDsHistFileName`.
    - Monitors capture status through `docsPnmCmDsHistMeasStatus`.

    SNMP Behavior:
    - `docsPnmCmDsHistTimeOut` defines the timeout in seconds for capture (0 = indefinite).
      Changing this while capture is active restarts the timer.
    - Capture begins only when `docsPnmCmDsHistEnable` is set to true.
    - When capture ends (either manually or on timeout), the result is saved to the
      specified TFTP path and the measurement status transitions to `sampleReady`.

    Attributes:
        logger (logging.Logger): Logger for this service class.
    """

    def __init__(
        self,
        cable_modem: CableModem,
        sample_duration: int = 10,
        tftp_servers: tuple[Inet, Inet] = PnmConfigManager.get_tftp_servers(),
        tftp_path: str = PnmConfigManager.get_tftp_path(),
    ) -> None:
        """
        Initializes the CmDsHistogramService.

        Args:
            cable_modem (CableModem): The cable modem instance to control and retrieve data from.
            sample_duration (int, optional): Sampling duration for the histogram measurement in seconds. Default is 10.
            tftp_servers (Tuple[Inet, Inet], optional): Primary and secondary TFTP server IPs.
            tftp_path (str, optional): Path on the TFTP server where result files should be stored.
        """
        super().__init__(
            DocsPnmCmCtlTest.DS_HISTOGRAM,
            cable_modem,
            tftp_servers,
            tftp_path,
            cable_modem.getWriteCommunity(),
            histogram_sample_duration=sample_duration,
        )
        self.logger = logging.getLogger(self.__class__.__name__)
