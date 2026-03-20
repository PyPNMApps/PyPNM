# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from enum import IntEnum
from typing import Any

from pypnm.lib.constants import DEFAULT_SPECTRUM_ANALYZER_NUM_AVERAGES
from pypnm.lib.types import STATUS, ResolutionBw
from pypnm.lib.utils import Generate


class SpectrumRetrievalType(IntEnum):
    """
    Defines the method by which spectrum analysis results are retrieved from a cable modem.

    Attributes:
        FILE (int): Retrieve results from a file (e.g., via TFTP).
        SNMP (int): Retrieve results directly using SNMP queries.
    """
    UNKNOWN = -1
    ERROR   = 0
    FILE    = 1
    SNMP    = 2

class WindowFunction(IntEnum):
    """
    Enum representing windowing functions used during spectrum analysis via
    Discrete Fourier Transform (DFT).

    These functions help reduce spectral leakage by shaping the input signal
    prior to transformation. Not all devices support all functions; attempting
    to configure an unsupported window function may result in an SNMP
    `inconsistentValue` error.

    Reference:
        Harris, Fredric J. (1978). "On the use of Windows for Harmonic Analysis
        with the Discrete Fourier Transform", Proceedings of the IEEE,
        Vol. 66, Issue 1, doi:10.1109/PROC.1978.10837

    Values:
        OTHER (0): Unspecified or device-specific windowing function.
        HANN (1): Hann window — reduces side lobes, suitable for general use.
        BLACKMAN_HARRIS (2): High dynamic range window with low spectral leakage.
        RECTANGULAR (3): No windowing; equivalent to a raw DFT.
        HAMMING (4): Similar to Hann but with slightly different tapering.
        FLAT_TOP (5): Flatter frequency response — good for amplitude accuracy.
        GAUSSIAN (6): Gaussian shape; parameterized by standard deviation.
        CHEBYSHEV (7): Minimizes main lobe width for a given side lobe level.
    """
    OTHER = 0
    HANN = 1
    BLACKMAN_HARRIS = 2
    RECTANGULAR = 3
    HAMMING = 4
    FLAT_TOP = 5
    GAUSSIAN = 6
    CHEBYSHEV = 7

class SpectrumAnalysisDefaults(IntEnum):
    """
    Enum class representing the default configuration values for spectrum analysis.

    These defaults are used to control the parameters for spectrum analysis in DOCSIS-based systems.
    The values are used in the configuration of spectrum analysis commands, like center frequencies,
    frequency span, noise bandwidth, and window function.

    Attributes:
        ENABLE (int): The enable flag for the spectrum analysis.
        FILE_ENABLE (SpectrumRetrievalType): Whether to enable file-based retrieval for spectrum analysis results.
        INACTIVITY_TIMEOUT (int): Timeout in seconds before the spectrum analysis is considered inactive.
        FIRST_SEGMENT_CENTER_FREQ (int): Center frequency (in Hz) for the first spectrum segment.
        LAST_SEGMENT_CENTER_FREQ (int): Center frequency (in Hz) for the last spectrum segment.
        SEGMENT_FREQ_SPAN (int): Frequency span (in Hz) of each spectrum segment.
        NUM_BINS_PER_SEGMENT (int): Number of bins used in each spectrum segment.
        NOISE_BW (int): Equivalent noise bandwidth in MHz.
        WINDOW_FUNCTION (WindowFunction): The window function used in the analysis (e.g., Hann, Hamming).
        NUM_AVERAGES (int): The number of averages used for the analysis.
    """

    ENABLE = 1
    FILE_ENABLE = SpectrumRetrievalType.FILE
    INACTIVITY_TIMEOUT = 100
    FIRST_SEGMENT_CENTER_FREQ = 108_000_000
    LAST_SEGMENT_CENTER_FREQ = 993_000_000
    SEGMENT_FREQ_SPAN = 1_000_000
    NUM_BINS_PER_SEGMENT = 256
    NOISE_BW = 110
    WINDOW_FUNCTION = WindowFunction.HANN
    NUM_AVERAGES = DEFAULT_SPECTRUM_ANALYZER_NUM_AVERAGES

    @classmethod
    def to_dict(cls) -> dict:
        """
        Convert the enum class to a dictionary where each enum name is mapped to its value.

        Returns:
            dict: A dictionary containing the enum names as keys and the corresponding values.
        """
        return {key.name: key.value for key in cls}

    @classmethod
    def to_json(cls) -> str:
        """
        Export the default spectrum analysis configuration values as a JSON string.

        This method serializes the class's default attribute values into a dictionary and converts it
        to a JSON string. This is useful for getting the configuration data in JSON format without
        writing to a file.

        Returns:
            str: The JSON string representation of the class's default configuration.

        Example:
            json_string = SpectrumAnalysisDefaults.to_json()
        """
        return json.dumps(cls.to_dict(), indent=4)

@dataclass
class DocsIf3CmSpectrumAnalysisCtrlCmd:
    """
    Represents the control command configuration for DOCSIS 3.0/3.1+ Cable Modem Spectrum Analysis.

    This class encapsulates all parameters required to initiate a spectrum analysis test using
    SNMP control objects. It includes default values (via `SpectrumAnalysisDefaults`) and provides
    setter methods for each parameter to validate and update values safely before sending SNMP `set` operations.

    Source: https://mibs.cablelabs.com/MIBs/DOCSIS/
    MIB: DOCS-IF3-MIB

    Attributes:
        docsIf3CmSpectrumAnalysisCtrlCmdEnable (int): Enables spectrum analysis (1 = true, 2 = false).
        docsIf3CmSpectrumAnalysisCtrlCmdInactivityTimeout (int): Timeout in seconds for inactivity before abort.
        docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency (int): Starting frequency of analysis (Hz).
        docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency (int): Ending frequency of analysis (Hz).
        docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan (int): Span per segment (Hz).
        docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment (int): Number of FFT bins per segment.
        docsIf3CmSpectrumAnalysisCtrlCmdEquivalentNoiseBandwidth (int): ENBW used in DFT windowing.
        docsIf3CmSpectrumAnalysisCtrlCmdWindowFunction (int): Window function ID to apply (see `WindowFunction` enum).
        docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages (int): Number of FFT averages to smooth noise floor.
        docsIf3CmSpectrumAnalysisCtrlCmdFileEnable (int): Enables storing result to file (1 = true, 2 = false).
        docsIf3CmSpectrumAnalysisCtrlCmdMeasStatus (int): Read-only measurement status (1 = running, 2 = notRunning).
        docsIf3CmSpectrumAnalysisCtrlCmdFileName (str): Optional filename for output binary file.

    Methods:
        set_enable(value): Validates and sets enable flag.
        set_inactivity_timeout(value): Sets inactivity timeout (0-86400).
        set_first_segment_center_frequency(value): Sets first segment center frequency (>0).
        set_last_segment_center_frequency(value): Sets last segment center frequency (>0).
        set_segment_frequency_span(value): Sets span in Hz (1 MHz - 900 MHz).
        set_num_bins_per_segment(value): Sets bin count (2 - 2048).
        set_equivalent_noise_bandwidth(value): Sets ENBW in Hz (50 - 500).
        set_window_function(value): Sets window function from `WindowFunction` enum.
        set_number_of_averages(value): Sets number of FFT averages (1 - 1000).
        set_file_enable(value): Enables/disables file output.
        set_meas_status(value): Sets measurement status (1 = running, 2 = notRunning).
        set_file_name(value): Sets file name for output.
        get_member_list(): Returns full SNMP object list with `.0` instance suffixes.
    """
    docsIf3CmSpectrumAnalysisCtrlCmdEnable: int = SpectrumAnalysisDefaults.ENABLE
    docsIf3CmSpectrumAnalysisCtrlCmdInactivityTimeout: int = SpectrumAnalysisDefaults.INACTIVITY_TIMEOUT
    docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency: int = SpectrumAnalysisDefaults.FIRST_SEGMENT_CENTER_FREQ
    docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency: int = SpectrumAnalysisDefaults.LAST_SEGMENT_CENTER_FREQ
    docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan: int = SpectrumAnalysisDefaults.SEGMENT_FREQ_SPAN
    docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment: int = SpectrumAnalysisDefaults.NUM_BINS_PER_SEGMENT
    docsIf3CmSpectrumAnalysisCtrlCmdEquivalentNoiseBandwidth: int = SpectrumAnalysisDefaults.NOISE_BW
    docsIf3CmSpectrumAnalysisCtrlCmdWindowFunction: int = SpectrumAnalysisDefaults.WINDOW_FUNCTION
    docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages: int = SpectrumAnalysisDefaults.NUM_AVERAGES
    docsIf3CmSpectrumAnalysisCtrlCmdFileEnable: int = SpectrumAnalysisDefaults.FILE_ENABLE
    docsIf3CmSpectrumAnalysisCtrlCmdMeasStatus: int = -1
    docsIf3CmSpectrumAnalysisCtrlCmdFileName: str = f"spectrum_analysis_{Generate.time_stamp()}.bin"

    def __post_init__(self) -> None:
        self.logger = logging.getLogger(__name__)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def autoScaleSpectrumAnalyzerRbw(self, rbw: ResolutionBw, adjust_segment_span: bool) -> tuple[STATUS, bool]:
        """
        This function take priority of the RBW, and calculate the following

        RBW = SegementSpan/FreqSpan

        Rules:
            FreqSpan % SegementSpan == 0
            if adjust_segment_span == true, update SegmentSpan to match RBW and adjust the frequency span inward at a minimum
            if adjust_segment_span == false, keep the frequency span and find SegmentSpan to meet RBW within 5% (prefer exact)

            at teh end, if if it is not achivable, then set STATUS to STATUS_NOK, else STATUS_OK

        """
        min_segment_span_hz = 1_000_000
        max_segment_span_hz = 900_000_000
        min_bins = 2
        max_bins = 2048
        tolerance_ratio = 0.05

        if rbw <= 0:
            self.logger.debug("RBW must be positive.")
            return False, False

        num_bins = int(self.docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment)
        if num_bins < min_bins or num_bins > max_bins:
            self.logger.debug("NumBinsPerSegment out of range: %s", num_bins)
            return False, False

        first_center = int(self.docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency)
        last_center = int(self.docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency)
        total_span = last_center - first_center
        if total_span <= 0:
            self.logger.debug("Invalid frequency span: first=%s last=%s", first_center, last_center)
            return False, False

        current_segment_span = int(self.docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan)
        ideal_segment_span = int(rbw) * num_bins
        if ideal_segment_span <= 0:
            self.logger.debug("Computed segment span is invalid: %s", ideal_segment_span)
            return False, False

        if adjust_segment_span:
            if (ideal_segment_span < min_segment_span_hz or
                ideal_segment_span > max_segment_span_hz or
                ideal_segment_span > total_span):
                self.logger.debug(
                    "Ideal segment span out of range: %s (total span %s)",
                    ideal_segment_span,
                    total_span,
                )
                return False, False

            remainder = total_span % ideal_segment_span
            new_first = first_center
            new_last = last_center
            if remainder != 0:
                lower_adjust = remainder // 2
                upper_adjust = remainder - lower_adjust
                new_first = first_center + lower_adjust
                new_last = last_center - upper_adjust
                if new_last <= new_first:
                    self.logger.debug("Adjusted frequency span is invalid after alignment.")
                    return False, False

            self.docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency = new_first
            self.docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency = new_last
            self.docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan = ideal_segment_span

            changed = (
                new_first != first_center or
                new_last != last_center or
                ideal_segment_span != current_segment_span
            )
            return True, changed

        max_segments = total_span // min_segment_span_hz
        if max_segments < 1:
            self.logger.debug("Total span too small for minimum segment span.")
            return False, False

        best_span = 0
        best_diff = 1.0
        best_distance = 0
        target_rbw = float(rbw)

        for segment_count in range(1, max_segments + 1):
            if total_span % segment_count != 0:
                continue
            segment_span = total_span // segment_count
            if segment_span < min_segment_span_hz or segment_span > max_segment_span_hz:
                continue

            actual_rbw = float(segment_span) / float(num_bins)
            diff_ratio = abs(actual_rbw - target_rbw) / target_rbw
            if diff_ratio > tolerance_ratio:
                continue

            distance = abs(segment_span - ideal_segment_span)
            if diff_ratio < best_diff or (diff_ratio == best_diff and distance < best_distance):
                best_span = segment_span
                best_diff = diff_ratio
                best_distance = distance

        if best_span == 0:
            self.logger.debug("No valid segment span found within RBW tolerance.")
            return False, False

        self.docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan = best_span
        changed = best_span != current_segment_span
        return True, changed

    def precheck_spectrum_analyzer_settings(self) -> bool:
        """
        Validate that the spectrum analyzer's first/last segment center frequencies
        and the per-segment frequency span divide evenly into whole segments.

        If the total frequency range (last_center - first_center) isn't an exact multiple
        of the segment span, this method will **increase** the start segment center frequency
        to the nearest value that yields an integer number of segments.

        Returns:
            bool
                False if settings were already valid (no adjustment needed);
                True if the First segment center frequency was adjusted.

        Raises:
            ValueError
                If the configured last segment center frequency is lower than the first.
        """
        # Read and convert settings
        first_center = float(self.docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency)
        last_center = float(self.docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency)
        seg_freq_span = float(self.docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan)

        # Compute total range and sanity‐check
        total_range = last_center - first_center
        if total_range < 0:
            raise ValueError(
                "docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency "
                "must be >= docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency")

        # Check for exact divisibility
        remainder = total_range % seg_freq_span
        if remainder == 0:
            self.logger.debug(f'No changes to SpectrumAnalysisCtrlCmd due to SegmentCenterFrequency({seg_freq_span}) divisible: ({total_range})')
            return False

        # Adjust the last center downward to the nearest whole‐segment boundary
        adjusted_first = int(first_center + remainder)
        self.logger.debug(f'New Start Center Frequency: {adjusted_first}')
        self.docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency = adjusted_first
        return True

    def set_enable(self, value: int) -> None:
        if value not in (1, 2):
            raise ValueError("Enable must be 1 (true) or 2 (false)")
        self.docsIf3CmSpectrumAnalysisCtrlCmdEnable = value
        self.logger.debug(f"Set enable to {value}")

    def set_inactivity_timeout(self, value: int) -> None:
        if not 0 <= value <= 86400:
            raise ValueError("InactivityTimeout must be between 0 and 86400 seconds")
        self.docsIf3CmSpectrumAnalysisCtrlCmdInactivityTimeout = value
        self.logger.debug(f"Set inactivity timeout to {value}")

    def set_first_segment_center_frequency(self, value: int) -> None:
        if value <= 0:
            raise ValueError("FirstSegmentCenterFrequency must be a positive integer")
        self.docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency = value
        self.logger.debug(f"Set first segment center frequency to {value}")

    def set_last_segment_center_frequency(self, value: int) -> None:
        if value <= 0:
            raise ValueError("LastSegmentCenterFrequency must be a positive integer")
        self.docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency = value
        self.logger.debug(f"Set last segment center frequency to {value}")

    def set_segment_frequency_span(self, value: int) -> None:
        if not 1000000 <= value <= 900000000:
            raise ValueError("SegmentFrequencySpan must be between 1 MHz and 900 MHz")
        self.docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan = value
        self.logger.debug(f"Set segment frequency span to {value}")

    def set_num_bins_per_segment(self, value: int) -> None:
        if not 2 <= value <= 2048:
            raise ValueError("NumBinsPerSegment must be between 2 and 2048")
        self.docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment = value
        self.logger.debug(f"Set number of bins per segment to {value}")

    def set_equivalent_noise_bandwidth(self, value: int) -> None:
        if not 50 <= value <= 500:
            raise ValueError("EquivalentNoiseBandwidth must be between 50 and 500")
        self.docsIf3CmSpectrumAnalysisCtrlCmdEquivalentNoiseBandwidth = value
        self.logger.debug(f"Set equivalent noise bandwidth to {value}")

    def set_window_function(self, value: int) -> None:
        try:
            window = WindowFunction(value)
        except ValueError:
            raise ValueError("Invalid WindowFunction value") from None
        self.docsIf3CmSpectrumAnalysisCtrlCmdWindowFunction = window
        self.logger.debug(f"Set window function to {window.name} ({value})")

    def set_number_of_averages(self, value: int) -> None:
        if not 1 <= value <= 1000:
            raise ValueError("NumberOfAverages must be between 1 and 1000")
        self.docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages = value
        self.logger.debug(f"Set number of averages to {value}")

    def set_file_enable(self, value: int) -> None:
        if value not in (1, 2):
            raise ValueError("FileEnable must be 1 (true) or 2 (false)")
        self.docsIf3CmSpectrumAnalysisCtrlCmdFileEnable = value
        self.logger.debug(f"Set file enable to {value}")

    def set_meas_status(self, value: int) -> None:
        if value not in (1, 2):
            raise ValueError("MeasStatus must be 1 (running) or 2 (notRunning)")
        self.docsIf3CmSpectrumAnalysisCtrlCmdMeasStatus = value
        self.logger.debug(f"Set measurement status to {value}")

    def set_file_name(self, value: str) -> None:
        if not isinstance(value, str):
            raise ValueError("FileName must be a string")
        self.docsIf3CmSpectrumAnalysisCtrlCmdFileName = value
        self.logger.debug(f"Set file name to {value}")

    def to_dict(self) -> dict[str, Any]:
        spectrum_cmd = {
            "docsIf3CmSpectrumAnalysisCtrlCmdEnable":                          self.docsIf3CmSpectrumAnalysisCtrlCmdEnable,
            "docsIf3CmSpectrumAnalysisCtrlCmdInactivityTimeout":               self.docsIf3CmSpectrumAnalysisCtrlCmdInactivityTimeout,
            "docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency":     self.docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency,
            "docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency":      self.docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency,
            "docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan":            self.docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan,
            "docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment":               self.docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment,
            "docsIf3CmSpectrumAnalysisCtrlCmdEquivalentNoiseBandwidth":        self.docsIf3CmSpectrumAnalysisCtrlCmdEquivalentNoiseBandwidth,
            "docsIf3CmSpectrumAnalysisCtrlCmdWindowFunction":                  self.docsIf3CmSpectrumAnalysisCtrlCmdWindowFunction,
            "docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages":                self.docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages,
            "docsIf3CmSpectrumAnalysisCtrlCmdFileEnable":                      self.docsIf3CmSpectrumAnalysisCtrlCmdFileEnable,
            "docsIf3CmSpectrumAnalysisCtrlCmdMeasStatus":                      self.docsIf3CmSpectrumAnalysisCtrlCmdMeasStatus,
            "docsIf3CmSpectrumAnalysisCtrlCmdFileName":                        self.docsIf3CmSpectrumAnalysisCtrlCmdFileName,
        }
        return spectrum_cmd
