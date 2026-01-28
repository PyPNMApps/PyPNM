# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pypnm.api.routes.advance.analysis.signal_analysis.multi_ofdm_chan_signal_analysis import (
    ChannelComplexMap,
    ChannelFrequencyMap,
    ChannelOccupiedBwMap,
    MultiOfdmChanSignalAnalysis,
)
from pypnm.api.routes.common.classes.analysis.analysis import Analysis
from pypnm.api.routes.common.classes.analysis.model.schema import (
    DsChannelEstAnalysisModel,
)
from pypnm.lib.types import ChannelId, StringEnum
from pypnm.pnm.parser.CmDsOfdmChanEstimateCoef import CmDsOfdmChanEstimateCoef


# ──────────────────────────────────────────────────────────────
# Enum
# ──────────────────────────────────────────────────────────────
class MultiChanEstAnalysisType(StringEnum):
    """Enumeration Of Supported Multi-ChannelEstimation Analysis Types."""
    MIN_AVG_MAX                 = "min-avg-max"
    GROUP_DELAY                 = "group-delay"
    ECHO_DETECTION_IFFT         = "echo-detection-ifft"
    LTE_DETECTION_PHASE_SLOPE   = "lte-detection-phase-slope"


# ──────────────────────────────────────────────────────────────
# Main Class
# ──────────────────────────────────────────────────────────────
class MultiChanEstimationSignalAnalysis(MultiOfdmChanSignalAnalysis):
    """Performs signal-quality analyses on grouped Multi-ChannelEstimation captures."""

    def _extract_channel_data(self) -> tuple[ChannelComplexMap, ChannelFrequencyMap, ChannelOccupiedBwMap]:
        """Collect Channel Estimation capture data into analysis-ready maps."""
        channel_data: ChannelComplexMap = {}
        freqs: ChannelFrequencyMap = {}
        obw: ChannelOccupiedBwMap = {}

        try:
            for tcm in self._trans_collect.getTransactionCollectionModel():
                model = CmDsOfdmChanEstimateCoef(tcm.data).to_model()
                result: DsChannelEstAnalysisModel = Analysis.basic_analysis_ds_chan_est_from_model(model)

                ch = ChannelId(result.channel_id)
                channel_data.setdefault(ch, []).append(result.carrier_values.complex)
                freqs[ch] = result.carrier_values.frequency
                obw[ch] = result.carrier_values.occupied_channel_bandwidth

        except Exception as e:
            self.logger.error(f"OFDM channel analysis parse failed: {e}")

        return channel_data, freqs, obw
