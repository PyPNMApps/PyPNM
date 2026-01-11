# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
import struct
from typing import Any, Final

from pypnm.lib.types import FloatSeries, FrequencyHz, FrequencySeriesHz
from pypnm.pnm.parser.model.configuration.spect_config_model import (
    SpecAnalysisSnmpConfigModel,
)
from pypnm.pnm.parser.model.parser_rtn_models import CmSpectrumAnalysisSnmpModel


class CmSpectrumAnalysisSnmp:
    """
    DOCSIS SNMP Spectrum Analysis AmplitudeData parser.

    This class decodes the `docsIf3CmSpectrumAnalysisMeasAmplitudeData` byte stream
    returned by SNMP into a validated `CmSpectrumAnalysisSnmpModel`, containing
    frequency and amplitude vectors and a spectrum configuration header, as defined
    by the DOCSIS AmplitudeData textual convention.
    """

    HEADER_FIELD_COUNT: Final[int] = 5
    BYTES_PER_UINT32: Final[int] = 4
    BYTES_PER_AMPLITUDE: Final[int] = 2
    AMPLITUDE_SCALE_DBMV: Final[float] = 100.0

    def __init__(self, byte_stream: bytes) -> None:
        """
        Initialize the parser and immediately decode the SNMP amplitude payload.

        Args:
            byte_stream (bytes): Raw bytes as returned by SNMP for the
                docsIf3CmSpectrumAnalysisMeasAmplitudeData object.
        """
        self.logger = logging.getLogger(f"{self.__class__.__name__}")
        self.data: CmSpectrumAnalysisSnmpModel = self._parse_amplitude_data(byte_stream)

    def _parse_amplitude_data(self, byte_stream: bytes) -> CmSpectrumAnalysisSnmpModel:
        """
        Parse the SNMP AmplitudeData payload into frequency and amplitude arrays.
        """
        offset = 0
        stream_len = len(byte_stream)
        header_len = self.HEADER_FIELD_COUNT * self.BYTES_PER_UINT32

        all_freqs: FrequencySeriesHz = []
        all_amplitudes: FloatSeries = []
        amplitude_chunks: list[bytes] = []

        total_bins_count = 0
        first_group_total_bins: int = 0
        first_group_bin_spacing: FrequencyHz = FrequencyHz(0)
        first_group_res_bw: FrequencyHz = FrequencyHz(0)

        while offset + header_len <= stream_len:
            header = byte_stream[offset : offset + header_len]
            try:
                ch_center_freq, freq_span, num_bins, bin_spacing, res_bw = (
                    struct.unpack(f">{self.HEADER_FIELD_COUNT}I", header)
                )
            except struct.error as exc:
                self.logger.warning(
                    f"Failed to unpack amplitude header at offset {offset}: {exc}"
                )
                break

            if num_bins == 0:
                self.logger.warning(
                    "Encountered spectrum group with zero bins; stopping parse."
                )
                break

            amp_len = num_bins * self.BYTES_PER_AMPLITUDE
            group_end = offset + header_len + amp_len
            if group_end > stream_len:
                self.logger.warning(
                    "Incomplete spectrum group encountered; expected "
                    f"{amp_len} amplitude bytes but payload ended early."
                )
                break

            amp_bytes = byte_stream[offset + header_len : group_end]
            try:
                amplitudes = struct.unpack(f">{num_bins}h", amp_bytes)
            except struct.error as exc:
                self.logger.warning(
                    f"Failed to unpack amplitudes at offset {offset}: {exc}"
                )
                break

            amplitudes_dbmv: list[float] = [
                a / self.AMPLITUDE_SCALE_DBMV for a in amplitudes
            ]
            freq_start_hz = float(ch_center_freq - (freq_span // 2))
            freqs: list[float] = [
                freq_start_hz + float(i * bin_spacing) for i in range(num_bins)
            ]

            all_freqs.extend(freqs)
            all_amplitudes.extend(amplitudes_dbmv)
            amplitude_chunks.append(amp_bytes)

            total_bins_count += num_bins

            if first_group_total_bins == 0:
                first_group_total_bins = num_bins
                first_group_bin_spacing = bin_spacing
                first_group_res_bw = res_bw

            offset = group_end

        amplitude_bytes = b"".join(amplitude_chunks)

        if total_bins_count == 0 or not all_freqs:
            self.logger.warning(
                "No valid spectrum groups parsed from SNMP AmplitudeData payload."
            )
            start_frequency_hz: FrequencyHz = FrequencyHz(0)
            end_frequency_hz: FrequencyHz = FrequencyHz(0)
            frequency_span_hz: FrequencyHz = FrequencyHz(0)
            total_bins_header: int = 0
            bin_spacing_header: FrequencyHz = FrequencyHz(0)
            resolution_bw_header: FrequencyHz = FrequencyHz(0)
        else:
            start_frequency_hz = FrequencyHz(all_freqs[0])
            end_frequency_hz = FrequencyHz(all_freqs[-1])
            frequency_span_hz = FrequencyHz(end_frequency_hz - start_frequency_hz)
            total_bins_header = (
                first_group_total_bins
                if first_group_total_bins > 0
                else total_bins_count
            )
            bin_spacing_header = FrequencyHz(first_group_bin_spacing)
            resolution_bw_header = FrequencyHz(first_group_res_bw)

        spectrum_config = SpecAnalysisSnmpConfigModel(
            start_frequency=start_frequency_hz,
            end_frequency=end_frequency_hz,
            frequency_span=frequency_span_hz,
            total_bins=total_bins_header,
            bin_spacing=bin_spacing_header,
            resolution_bandwidth=resolution_bw_header,
        )

        model = CmSpectrumAnalysisSnmpModel(
            spectrum_config=spectrum_config,
            total_samples=total_bins_count,
            frequency=all_freqs,
            amplitude=all_amplitudes,
            amplitude_bytes=amplitude_bytes,
        )
        return model

    def to_model(self) -> CmSpectrumAnalysisSnmpModel:
        """
        Return the validated `CmSpectrumAnalysisSnmpModel` representation.

        This is the primary entry point for downstream processing, providing
        typed access to the spectrum configuration, flattened frequency and
        amplitude vectors, and the raw amplitude bytes.
        """
        return self.data

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize the SNMP spectrum analysis results to a dictionary.

        Returns:
            dict: Dictionary representation of the `CmSpectrumAnalysisSnmpModel`,
            including the spectrum configuration, frequency and amplitude
            arrays, and raw amplitude bytes (hex-encoded).
        """
        return self.data.model_dump()
