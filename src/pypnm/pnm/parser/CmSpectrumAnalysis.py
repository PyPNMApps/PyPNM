# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
from struct import calcsize, unpack

from pydantic import BaseModel, ConfigDict, Field
from pydantic.functional_serializers import field_serializer

from pypnm.lib.mac_address import MacAddress, MacAddressFormat
from pypnm.lib.types import ChannelId, FloatSeries, FrequencyHz, MacAddressStr
from pypnm.pnm.parser.pnm_file_type import PnmFileType
from pypnm.pnm.parser.pnm_header import PnmHeader, PnmHeaderParameters


class CmSpectrumAnalyzerModel(BaseModel):
    """
    Canonical payload for CM Spectrum Analyzer metadata and results.

    This model captures the key parameters and results of a DOCSIS
    Spectrum Analyzer capture, including frequencies, FFT configuration,
    raw data, and processed amplitude segments.
    """

    model_config = ConfigDict(
        extra="ignore", populate_by_name=True, ser_json_bytes="base64"
    )
    pnm_header: PnmHeaderParameters = Field(..., description="")
    channel_id: ChannelId = Field(
        ..., description="Downstream/upstream channel identifier."
    )
    mac_address: MacAddressStr = Field(..., description="Device MAC address (string).")
    first_segment_center_frequency: FrequencyHz = Field(
        ..., description="Center frequency of the first segment in Hz."
    )
    last_segment_center_frequency: FrequencyHz = Field(
        ..., description="Center frequency of the last segment in Hz."
    )
    segment_frequency_span: FrequencyHz = Field(
        ..., description="Per-segment frequency span in Hz."
    )
    num_bins_per_segment: int = Field(
        ..., ge=1, description="Number of FFT bins per segment."
    )
    equivalent_noise_bandwidth: float = Field(
        ..., gt=0, description="Equivalent noise bandwidth (Hz)."
    )
    window_function: int = Field(
        ...,
        description="Window function identifier used during analysis (e.g., Hann, Hamming).",
    )
    bin_frequency_spacing: int = Field(
        ..., gt=0, description="Frequency spacing between adjacent bins in Hz."
    )
    spectrum_analysis_data_length: int = Field(
        ...,
        ge=0,
        description="Length of the raw spectrum analysis data buffer (bytes).",
    )
    spectrum_analysis_data: bytes = Field(
        ..., description="Raw spectrum analysis payload (bytes)."
    )
    amplitude_bin_segments_float: list[FloatSeries] = Field(
        ...,
        description="Amplitude values per bin (float dB), concatenated across segments.",
    )

    @field_serializer("spectrum_analysis_data")
    def _ser_spectrum_analysis_data(
        self,
        v: bytes,
    ) -> str:
        return v.hex()


class CmSpectrumAnalysis(PnmHeader):
    """
    Parser and decoder for DOCSIS PNM Spectrum Analysis binary data.

    Responsibilities:
      - Validate file type.
      - Parse spectrum analysis header (frequencies, bin setup, bandwidth).
      - Extract raw amplitude bin values from the payload.
      - Build a `CmSpectrumAnalyzerModel` for downstream use.
    """

    AMPLITUDE_BIN_SIZE = 2

    def __init__(self, binary_data: bytes) -> None:
        super().__init__(binary_data)
        self.logger = logging.getLogger(self.__class__.__name__)

        self._channel_id: ChannelId
        self._mac_address: MacAddressStr
        self._first_segment_center_frequency: FrequencyHz
        self._last_segment_center_frequency: FrequencyHz
        self._segment_frequency_span: FrequencyHz
        self._num_bins_per_segment: int
        self._equivalent_noise_bandwidth: int
        self._window_function: int
        self._spectrum_analysis_data_length: int
        self._spectrum_analysis_data: bytes
        self._bin_frequency_spacing: int
        self._amplitude_bin_segments_float: list[FloatSeries] = []
        self._number_of_bin_segments: int
        self._num_of_bin_segments: int = 0

        self._model: CmSpectrumAnalyzerModel

        self.__process()

    def __process(self) -> None:
        """
        Unpack the spectrum analysis header and extract metadata
        and the raw amplitude data stream from the binary payload.
        """
        if self.get_pnm_file_type() != PnmFileType.SPECTRUM_ANALYSIS:
            cann = PnmFileType.SPECTRUM_ANALYSIS.get_pnm_cann()
            actual_type = self.get_pnm_file_type()
            error_cann = actual_type.get_pnm_cann() if actual_type else "Unknown"
            raise ValueError(
                f"PNM File Stream is not RxMER file type: {cann}, Error: {error_cann}"
            )

        spectrum_analysis_format = ">B6sIIIHHHI"
        spectrum_analysis_size = calcsize(spectrum_analysis_format)
        unpacked_data = unpack(
            spectrum_analysis_format, self.pnm_data[:spectrum_analysis_size]
        )

        self._channel_id = unpacked_data[0]
        self._mac_address = MacAddress(unpacked_data[1]).to_mac_format(
            MacAddressFormat.COLON
        )
        self._first_segment_center_frequency = unpacked_data[2]
        self._last_segment_center_frequency = unpacked_data[3]
        self._segment_frequency_span = unpacked_data[4]
        self._num_bins_per_segment = unpacked_data[5]
        self._equivalent_noise_bandwidth = unpacked_data[6]
        self._window_function = unpacked_data[7]
        self._spectrum_analysis_data_length = unpacked_data[8]
        self._spectrum_analysis_data = self.pnm_data[spectrum_analysis_size:]

        if self._num_bins_per_segment:
            self._bin_frequency_spacing = int(
                self._segment_frequency_span / self._num_bins_per_segment
            )

        self._process_amplitude_data()
        self._build_model()

    def _process_amplitude_data(self) -> None:
        """
        Parse the raw amplitude data into segments.

        Each segment contains `num_bins_per_segment` values
        (except possibly the last one). Values are stored as
        16-bit signed integers in hundredths of a dB.
        """
        if not self._spectrum_analysis_data or self._num_bins_per_segment is None:
            self.logger.warning("Amplitude data or bin count not available.")
            return

        try:
            segment_size_bytes = self._num_bins_per_segment * self.AMPLITUDE_BIN_SIZE
            total_data_len = len(self._spectrum_analysis_data)
            self.logger.debug(f"Total Data Length: {total_data_len} bytes")

            for offset in range(0, total_data_len, segment_size_bytes):
                segment_bytes = self._spectrum_analysis_data[
                    offset : offset + segment_size_bytes
                ]
                actual_bins = len(segment_bytes) // self.AMPLITUDE_BIN_SIZE

                if actual_bins == 0:
                    self.logger.warning(
                        f"Empty segment encountered at offset {offset}, skipping."
                    )
                    continue

                if actual_bins < self._num_bins_per_segment:
                    self.logger.warning(
                        f"Incomplete segment encountered at offset {offset} with only {actual_bins} bins."
                    )

                format_string = f">{actual_bins}h"
                self.logger.debug(
                    f"Unpack format: {format_string} for {actual_bins} bins"
                )

                raw_bins = unpack(format_string, segment_bytes)
                amplitude_values = [val / 100.0 for val in raw_bins]
                self._amplitude_bin_segments_float.append(amplitude_values)
                self._num_of_bin_segments += 1

        except Exception as e:
            self.logger.error(f"Failed to unpack spectrum amplitude data: {e}")
            self._amplitude_bin_segments_float = []

    def _build_model(self) -> CmSpectrumAnalyzerModel:
        """
        Build a validated `CmSpectrumAnalyzerModel` from the parsed
        header fields and processed amplitude data.
        """
        self._model = CmSpectrumAnalyzerModel(
            pnm_header=self.getPnmHeaderParameterModel(),
            channel_id=self._channel_id,
            mac_address=self._mac_address,
            first_segment_center_frequency=self._first_segment_center_frequency,
            last_segment_center_frequency=self._last_segment_center_frequency,
            segment_frequency_span=self._segment_frequency_span,
            num_bins_per_segment=self._num_bins_per_segment,
            equivalent_noise_bandwidth=self._equivalent_noise_bandwidth,
            window_function=self._window_function,
            bin_frequency_spacing=self._bin_frequency_spacing,
            spectrum_analysis_data_length=self._spectrum_analysis_data_length,
            spectrum_analysis_data=self._spectrum_analysis_data or b"",
            amplitude_bin_segments_float=self._amplitude_bin_segments_float,
        )
        return self._model

    def to_model(self) -> CmSpectrumAnalyzerModel:
        """
        Return the fully built `CmSpectrumAnalyzerModel`.
        """
        return self._model

    def to_dict(self) -> dict[str, float]:
        """
        Return the spectrum analysis results as a dictionary.

        This is equivalent to calling `.model_dump()` on the underlying model.
        """
        return self._model.model_dump()

    def to_json(self, indent: int = 2) -> str:
        """
        Return the spectrum analysis results as a JSON string.

        Args:
            indent (int): Number of spaces for indentation (default: 2).

        Returns:
            str: JSON representation of the spectrum analysis results.
        """
        return self._model.model_dump_json(indent=indent)
