# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pypnm.api.routes.advance.analysis.signal_analysis.multi_ofdm_chan_signal_analysis import (
    ChannelComplexMap,
    ChannelFrequencyMap,
    ChannelOccupiedBwMap,
    MultiOfdmChanSignalAnalysis,
)
from pypnm.api.routes.advance.common.capture_data_aggregator import (
    CaptureDataAggregator,
)
from pypnm.api.routes.advance.common.transactionsCollection import (
    TransactionCollectionModel,
)
from pypnm.api.routes.common.classes.analysis.analysis import Analysis
from pypnm.api.routes.common.classes.analysis.model.schema import (
    UsOfdmaUsPreEqAnalysisModel,
)
from pypnm.lib.types import (
    ChannelId,
    ComplexArray,
    FrequencyHz,
    FrequencySeriesHz,
    StringEnum,
)
from pypnm.pnm.parser.CmUsOfdmaPreEq import CmUsOfdmaPreEq
from pypnm.pnm.parser.pnm_file_type import PnmFileType


class MultiOfdmaPreEqAnalysisType(StringEnum):
    """Enumeration Of Supported Multi-OFDMA-Pre-EQ Analysis Types."""
    MIN_AVG_MAX         = "min-avg-max"
    GROUP_DELAY         = "group-delay"
    ECHO_DETECTION_IFFT = "echo-detection-ifft"


class MultiOfdmaPreEqSignalAnalysis(MultiOfdmChanSignalAnalysis):
    """Performs signal-quality analyses on grouped OFDMA Pre-EQ captures."""

    def __init__(self, capt_data_agg: CaptureDataAggregator, analysis_type: StringEnum) -> None:
        """
        Initialize Multi-OFDMA Pre-EQ analysis state.

        Parameters
        ----------
        capt_data_agg:
            Aggregator providing access to capture records for analysis.
        analysis_type:
            Requested analysis mode to run across the aggregated captures.
        """
        super().__init__(capt_data_agg, analysis_type)
        self._file_type_by_channel: dict[ChannelId, PnmFileType] = {}

    def _parse_capture(
        self,
        tcm: TransactionCollectionModel,
    ) -> tuple[ChannelId, ComplexArray, FrequencySeriesHz, FrequencyHz, PnmFileType] | None:
        try:
            model = CmUsOfdmaPreEq(tcm.data).to_model()
            result: UsOfdmaUsPreEqAnalysisModel = Analysis.basic_analysis_us_ofdma_pre_equalization_from_model(model)

            try:
                file_type = PnmFileType.fromPnmHeaderModel(model.pnm_header)
            except KeyError as exc:
                self.logger.warning(f"OFDMA pre-eq unknown file type for {tcm.filename}: {exc}")
                file_type = PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS

        except Exception as e:
            self.logger.error(f"OFDMA pre-eq analysis parse failed: {e}")
            return None

        return (
            ChannelId(result.channel_id),
            result.carrier_values.complex,
            result.carrier_values.frequency,
            result.carrier_values.occupied_channel_bandwidth,
            file_type,
        )

    def _extract_channel_data(self) -> tuple[ChannelComplexMap, ChannelFrequencyMap, ChannelOccupiedBwMap]:
        """Collect OFDMA Pre-EQ capture data into analysis-ready maps."""
        channel_data: ChannelComplexMap = {}
        freqs: ChannelFrequencyMap = {}
        obw: ChannelOccupiedBwMap = {}
        self._file_type_by_channel = {}
        models = self._trans_collect.getTransactionCollectionModel()
        self.logger.info(f"OFDMA Pre-EQ captures: count={len(models)}")

        for tcm in models:
            parsed = self._parse_capture(tcm)
            if parsed is None:
                self.logger.info(f"OFDMA Pre-EQ parse skipped: file={tcm.filename} size={len(tcm.data)}")
                continue

            ch, complex_values, frequency, bandwidth, file_type = parsed
            self.logger.info(f"OFDMA Pre-EQ parsed: file={tcm.filename} ch={ch} carriers={len(complex_values)}")
            if complex_values:
                channel_data.setdefault(ch, []).append(complex_values)
            freqs[ch] = frequency
            obw[ch] = bandwidth
            existing = self._file_type_by_channel.get(ch)
            if existing is None:
                self._file_type_by_channel[ch] = file_type
            else:
                if existing != file_type:
                    self.logger.warning(
                        "OFDMA pre-eq file type mismatch: channel=%s existing=%s new=%s",
                        ch,
                        existing.name,
                        file_type.name,
                    )
                    if file_type == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE:
                        self._file_type_by_channel[ch] = file_type

        return channel_data, freqs, obw

    def _plot_title_prefix(self, channel_id: ChannelId) -> str:
        """
        Return the plot title prefix based on the PNM file type for the channel.
        """
        file_type = self._file_type_by_channel.get(channel_id)
        if file_type == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE:
            return "US Last PreEqualization"
        return "US PreEqualization"

    def _plot_extra_tags(self, channel_id: ChannelId) -> list[str]:
        """
        Return filename tags based on the PNM file type for the channel.
        """
        file_type = self._file_type_by_channel.get(channel_id)
        if file_type == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE:
            return ["us-last-pre-eq"]
        return ["us-pre-eq"]
