# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import pytest

from pypnm.api.routes.common.classes.analysis.analysis import SpecAnCapturePara
from pypnm.api.routes.common.extended.common_measure_service import CommonMeasureService
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.docsis.cm_snmp_operation import DocsPnmCmCtlTest
from pypnm.lib.inet import Inet
from pypnm.pnm.data_type.DocsIf3CmSpectrumAnalysisCtrlCmd import SpectrumRetrievalType


class _FakeCableModem:
    def __init__(self) -> None:
        self._mac = "aa:bb:cc:dd:ee:ff"
        self._inet = "192.168.0.100"
        self.last_cmd = None

    @property
    def get_mac_address(self) -> str:
        return self._mac

    @property
    def get_inet_address(self) -> str:
        return self._inet

    async def setDocsIf3CmSpectrumAnalysisCtrlCmd(self, cmd: object, _retrieval_type: object) -> bool:
        self.last_cmd = cmd
        return True


@pytest.mark.asyncio
async def test_spectrum_analyzer_averages_capped_to_one() -> None:
    cm = _FakeCableModem()
    service = CommonMeasureService(
        pnm_test_type=DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA,
        cable_modem=cm,
        tftp_servers=(Inet("192.168.0.100"), Inet("192.168.0.101")),
    )
    capture = SpecAnCapturePara(
        inactivity_timeout=60,
        first_segment_center_freq=300_000_000,
        last_segment_center_freq=900_000_000,
        segment_freq_span=1_000_000,
        num_bins_per_segment=256,
        noise_bw=150,
        window_function=1,
        num_averages=10,
        spectrum_retrieval_type=SpectrumRetrievalType.SNMP,
    )
    service.setSpectrumCaptureParameters(capture)

    status, _ = await service._generic_spectrum_analyzer_operation()

    assert status == ServiceStatusCode.SUCCESS
    assert cm.last_cmd is not None
    assert getattr(cm.last_cmd, "docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages") == 1
