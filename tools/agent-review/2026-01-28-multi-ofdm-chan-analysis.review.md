## Agent Review Bundle Summary
- Goal: Refactor multi-channel OFDM analysis into a shared base class for reuse.
- Changes: Added MultiOfdmChanSignalAnalysis base; converted MultiChanEstimationSignalAnalysis to subclass with data extraction hook.
- Files: src/pypnm/api/routes/advance/analysis/signal_analysis/multi_ofdm_chan_signal_analysis.py; src/pypnm/api/routes/advance/analysis/signal_analysis/multi_chan_est_singnal_analysis.py.
- Tests: Not run (not requested).
- Notes: None.

# FILE: src/pypnm/api/routes/advance/analysis/signal_analysis/multi_ofdm_chan_signal_analysis.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import cast

from pydantic import BaseModel, Field

from pypnm.api.routes.advance.analysis.signal_analysis.detection.echo.ifft import (
    IfftEchoDetector,
    IfftMultiEchoDetectionModel,
)
from pypnm.api.routes.advance.analysis.signal_analysis.detection.lte.phase_slope_lte_detection import (
    GroupDelayAnomalyDetector,
)
from pypnm.api.routes.advance.analysis.signal_analysis.group_delay_calculator import (
    GroupDelayCalculator,
)
from pypnm.api.routes.advance.analysis.signal_analysis.multi_rxmer_signal_analysis import (
    MultiAnalysisRpt,
)
from pypnm.api.routes.advance.common.capture_data_aggregator import (
    CaptureDataAggregator,
)
from pypnm.lib.csv.manager import CSVManager
from pypnm.lib.matplot.manager import MatplotManager, PlotConfig
from pypnm.lib.types import (
    ArrayLike,
    ChannelId,
    ComplexArray,
    ComplexSeries,
    FileName,
    FloatSeries,
    FrequencyHz,
    FrequencySeriesHz,
    Sequence,
    StringEnum,
)
from pypnm.pnm.lib.min_avg_max_complex import MinAvgMaxComplex

# ──────────────────────────────────────────────────────────────
# Aliases
# ──────────────────────────────────────────────────────────────
ChannelAmplitudeMap         = dict[ChannelId, list[FloatSeries]]
ChannelFrequencyMap         = dict[ChannelId, FrequencySeriesHz]
ChannelComplexMap           = dict[ChannelId, list[ComplexArray]]
ChannelOccupiedBwMap        = dict[ChannelId, FrequencyHz]
ChannelComplexSeriesMap     = dict[ChannelId, list[ComplexSeries]]
ChannelDataMaps             = tuple[ChannelComplexMap, ChannelFrequencyMap, ChannelOccupiedBwMap]

# ──────────────────────────────────────────────────────────────
# Models
# ──────────────────────────────────────────────────────────────
class MinAvgMaxModel(BaseModel):
    """
    Per-Channel Min/Avg/Max Amplitude Statistics.

    Captures per-subcarrier minimum, average, and maximum amplitude derived
    from one or more ChannelEstimation captures for a single OFDM channel.
    """
    channel_id: ChannelId           = Field(..., description="OFDM downstream channel ID")
    frequency: FrequencySeriesHz    = Field(..., description="Subcarrier frequency bins (Hz)")
    min: FloatSeries                = Field(..., description="Minimum amplitude (dB) per subcarrier")
    avg: FloatSeries                = Field(..., description="Average amplitude (dB) per subcarrier")
    max: FloatSeries                = Field(..., description="Maximum amplitude (dB) per subcarrier")


class GroupDelayAnalysisModel(BaseModel):
    """
    Per-Channel Group Delay Profile.

    Holds the subcarrier frequency bins and corresponding group-delay values
    (in microseconds) computed from averaged complex ChannelEstimation data.
    """
    channel_id: ChannelId           = Field(..., description="OFDM downstream channel ID")
    frequency: FrequencySeriesHz    = Field(..., description="Subcarrier frequency bins (Hz)")
    group_delay_us: FloatSeries     = Field(..., description="Per-subcarrier group delay (µs)")


class LteDetectionModel(BaseModel):
    """
    LTE Anomaly Detection Summary From Group-Delay Ripple.

    Encapsulates anomaly magnitudes or indices, the configured detection
    threshold, and the bin widths used when segmenting group-delay data
    for LTE-style interference detection.
    """
    channel_id: ChannelId           = Field(..., description="OFDM downstream channel ID")
    anomalies: FloatSeries          = Field(..., description="Detected LTE interference magnitudes/indices")
    threshold: float                = Field(..., description="Group-delay ripple threshold")
    bin_widths: FloatSeries         = Field(..., description="Bin widths used for segmentation (Hz)")


class EchoDetectionPhaseSlopeModel(BaseModel):
    """
    Phase-Slope Derived Echo Detection Metrics.

    Stores the phase-slope profile and associated subcarrier frequency bins
    used for phase-slope based echo or anomaly interpretation.
    """
    channel_id: ChannelId           = Field(..., description="OFDM downstream channel ID")
    slope_profile: FloatSeries      = Field(..., description="Phase-slope values (radians/Hz)")
    frequency: FrequencySeriesHz    = Field(..., description="Subcarrier frequency bins (Hz)")


class EchoDetectionIfftModel(BaseModel):
    """
    Single-Channel IFFT-Based Echo Detection Result.

    Represents the impulse-response magnitude versus delay obtained from
    inverse FFT processing of ChannelEstimation data, along with the
    effective sample rate used.
    """
    channel_id: ChannelId           = Field(..., description="OFDM downstream channel ID")
    impulse_response: FloatSeries   = Field(..., description="Impulse-response magnitude vs delay")
    sample_rate: float              = Field(..., description="Sample rate used for IFFT (Hz)")

ChannelEstimationAnalysisRpt =  MinAvgMaxModel              | \
                                GroupDelayAnalysisModel     | \
                                LteDetectionModel           | \
                                EchoDetectionIfftModel      | \
                                IfftMultiEchoDetectionModel | \
                                EchoDetectionPhaseSlopeModel

class MultiChanEstimationResult(BaseModel):
    """
    Aggregate Multi-ChannelEstimation Analysis Result.

    Wraps the executed analysis type, per-channel result models for that
    analysis, and an optional error string when processing fails.
    """
    analysis_type: str                          = Field(..., description="Name of executed analysis type")
    results: list[ChannelEstimationAnalysisRpt] = Field(default_factory=list, description="List of per-channel analysis results")
    error: str | None                           = Field(default=None, description="Error message if analysis failed")

    def to_json(self, indent: int = 2) -> str:
        """
        Serialize The Multi-ChannelEstimation Result To JSON.

        Parameters
        ----------
        indent:
            Number of spaces used when pretty-printing the JSON payload.

        Returns
        -------
        str
            JSON-encoded representation of this result model.
        """
        return self.model_dump_json(indent=indent)


# ──────────────────────────────────────────────────────────────
# Main Class
# ──────────────────────────────────────────────────────────────
class MultiOfdmChanSignalAnalysis(MultiAnalysisRpt, ABC):
    """Performs signal-quality analyses on grouped OFDM channel captures."""

    def __init__(self, capt_data_agg: CaptureDataAggregator, analysis_type: StringEnum) -> None:
        """
        Initialize Multi-OFDM-Channel Signal Analysis.

        Parameters
        ----------
        capt_data_agg:
            Aggregator providing access to one or more capture groups and
            their associated metadata.
        analysis_type:
            Requested analysis mode to run across the aggregated captures
            (for example, min/avg/max, group delay, LTE detection, or
            IFFT-based echo detection).
        """
        super().__init__(capt_data_agg)
        self.logger = logging.getLogger(self.__class__.__name__)
        self._analysis_type = analysis_type
        self._results: MultiChanEstimationResult | None = None
        self._channel_data: ChannelDataMaps | None = None

    @abstractmethod
    def _extract_channel_data(self) -> ChannelDataMaps:
        """
        Extract Channel Data For OFDM-Like Analyses.

        Returns
        -------
        ChannelDataMaps
            Tuple containing channel complex arrays, frequency bins, and
            occupied bandwidth values.
        """
        raise NotImplementedError

    def _get_channel_data(self) -> ChannelDataMaps:
        if self._channel_data is None:
            self._channel_data = self._extract_channel_data()
        return self._channel_data

    def _process(self) -> None:
        """
        Execute The Configured Analysis And Register JSON Archive Models.

        This internal entry point ensures that the analysis is run exactly
        once, caches the resulting ``MultiChanEstimationResult`` instance,
        then builds per-channel JSON-ready models and registers them with
        the JSON archive machinery for downstream export.
        """
        if self._results is None:
            self._results = self.__process()

        models: dict[FileName, BaseModel] = self._build_json_archive_models()

        for fname, model in models.items():
            self.register_models_for_json_archive_files(
                model,
                [str(fname)],
                append_timestamp=False)

    def __process(self) -> MultiChanEstimationResult:
        """
        Core Analysis Dispatcher For Multi-Channel Data.

        Selects and runs the appropriate analysis routine based on
        ``self._analysis_type`` and wraps the per-channel results into a
        ``MultiChanEstimationResult`` model.

        Returns
        -------
        MultiChanEstimationResult
            Aggregated results for the requested analysis type.
        """
        mac = self.getMacAddresses()[0]
        self.logger.info(f"[_process] {self._analysis_type.name} for MAC={mac}")

        data: list[ChannelEstimationAnalysisRpt] = []

        match self._analysis_type.value:
            case "min-avg-max":
                data = cast(list[ChannelEstimationAnalysisRpt], self._analyze_min_avg_max())
            case "group-delay":
                data = cast(list[ChannelEstimationAnalysisRpt], self._analyze_group_delay())
            case "lte-detection-phase-slope":
                data = cast(list[ChannelEstimationAnalysisRpt], self._analyze_lte_detection())
            case "echo-detection-ifft":
                data = cast(list[ChannelEstimationAnalysisRpt], self._analyze_echo_detection_ifft())
            case _:
                raise ValueError(f"Unsupported analysis type: {self._analysis_type}")

        return MultiChanEstimationResult(analysis_type=self._analysis_type.name, results=data)

    def to_model(self) -> MultiChanEstimationResult:
        """
        Return The Cached Multi-Channel Result Model.

        When called for the first time, this method triggers the underlying
        analysis pipeline and populates ``self._results``. On subsequent
        calls, the cached result is returned. If the analysis raises an
        exception, the error is captured in the ``error`` field and an
        otherwise empty result set is returned.

        Returns
        -------
        MultiChanEstimationResult
            Completed analysis result or an error-bearing placeholder
            when processing fails.
        """
        if self._results is None:
            try:
                self._results = self.__process()
            except Exception as e:
                return MultiChanEstimationResult(
                    analysis_type   =   self._analysis_type.name,
                    results         =   [],
                    error           =   str(e),
                )
        return self._results

    def create_csv(self, **kwargs: object) -> list[CSVManager]:
        """
        Materialize Per-Channel Analysis Results As CSV Files.

        For each result in the aggregated analysis model, this method emits
        a CSV file with a schema tailored to the selected analysis type
        (min/avg/max, group delay, LTE detection, or IFFT echo detection).
        Generated files are written using ``CSVManager`` instances, which
        are returned to the caller for further inspection or testing.

        Parameters
        ----------
        **kwargs:
            Reserved for future extensions; currently unused.

        Returns
        -------
        List[CSVManager]
            List of CSV managers, one per successfully exported result.
        """
        csvs: list[CSVManager] = []
        model = self.to_model()

        for r in model.results:
            csv = CSVManager()

            match self._analysis_type.value:
                case "min-avg-max":
                    if not isinstance(r, MinAvgMaxModel):
                        continue
                    csv.set_header(["Frequency (Hz)", "Min (dB)", "Avg (dB)", "Max (dB)"])
                    for f, mn, av, mx in zip(r.frequency, r.min, r.avg, r.max, strict=False):
                        csv.insert_row([f, mn, av, mx])
                    csv.set_path_fname(self.create_csv_fname(tags=[f"ch{r.channel_id}", "minavgmax"]))
                    csv.write()
                    csvs.append(csv)

                case "group-delay":
                    if not isinstance(r, GroupDelayAnalysisModel):
                        continue
                    csv.set_header(["Frequency (Hz)", "Group Delay (µs)"])
                    for f, gd in zip(r.frequency, r.group_delay_us, strict=False):
                        csv.insert_row([f, gd])
                    csv.set_path_fname(self.create_csv_fname(tags=[f"ch{r.channel_id}", "groupdelay"]))
                    csv.write()
                    csvs.append(csv)

                case "lte-detection-phase-slope":
                    if not isinstance(r, LteDetectionModel):
                        continue
                    csv.set_header(["Bin Width (Hz)", "Anomaly Magnitude"])
                    for bw, anom in zip(r.bin_widths, r.anomalies, strict=False):
                        csv.insert_row([bw, anom])
                    csv.insert_row(["Threshold", r.threshold])
                    csv.set_path_fname(self.create_csv_fname(tags=[f"ch{r.channel_id}", "lte-detect"]))
                    csv.write()
                    csvs.append(csv)

                case "echo-detection-ifft":
                    if isinstance(r, EchoDetectionIfftModel):
                        csv.set_header(["Sample Index", "Amplitude"])

                        for i, amp in enumerate(r.impulse_response):
                            csv.insert_row([i, amp])

                        csv.insert_row(["Sample Rate (Hz)", r.sample_rate])
                        csv.set_path_fname(self.create_csv_fname(tags=[f"ch{r.channel_id}", "echo-ifft"]))
                        csv.write()
                        csvs.append(csv)
                        continue

                    if isinstance(r, IfftMultiEchoDetectionModel):
                        csv.set_header(["Type", "Bin", "Time (s)", "Amplitude", "Distance (m)", "Distance (ft)"])

                        dp = r.direct_path
                        csv.insert_row(["direct", dp.bin_index, dp.time_s, dp.amplitude, dp.distance_m, dp.distance_ft])

                        for e in r.echoes:
                            csv.insert_row(["echo", e.bin_index, e.time_s, e.amplitude, e.distance_m, e.distance_ft])

                        csv.insert_row(["sample_rate_hz",   r.sample_rate_hz, "", "", "", ""])
                        csv.insert_row(["cable_type",       r.cable_type, "", "", "", ""])
                        csv.insert_row(["velocity_factor",  r.velocity_factor, "", "", "", ""])
                        csv.insert_row(["threshold_frac",   r.threshold_frac, "", "", "", ""])
                        csv.insert_row(["guard_bins",       r.guard_bins, "", "", "", ""])
                        csv.insert_row(["min_separation_s", r.min_separation_s, "", "", "", ""])

                        if r.max_delay_s is not None:
                            csv.insert_row(["max_delay_s", r.max_delay_s, "", "", "", ""])

                        csv.insert_row(["max_peaks", r.max_peaks, "", "", "", ""])

                        csv.set_path_fname(self.create_csv_fname(tags=[f"ch{r.channel_id}", "echo-ifft-multi"]))
                        csv.write()
                        csvs.append(csv)
        return csvs

    def create_matplot(self, **kwargs: object) -> list[MatplotManager]:
        """
        Generate Matplotlib Plots For Multi-Channel Results.

        Creates one or more ``MatplotManager`` instances per analysis result
        and dispatches to the appropriate plotting helper depending on the
        configured analysis type. Each plot is written to disk with a filename
        derived from the channel identifier and analysis tag.

        Parameters
        ----------
        **kwargs:
            Reserved for future extensions; currently unused.

        Returns
        -------
        List[MatplotManager]
            List of plot managers corresponding to the generated figures.
        """
        plots: list[MatplotManager] = []
        model = self.to_model()

        match self._analysis_type.value:

            case "min-avg-max":
                for r in model.results:
                    if not isinstance(r, MinAvgMaxModel):
                        continue
                    cfg = PlotConfig(
                        title           =   f"Channel Estimation · Channel: {r.channel_id} · Min-Avg-Max",
                        x               =   cast(ArrayLike, r.frequency),
                        y_multi         =   [cast(ArrayLike, r.min), cast(ArrayLike, r.avg), cast(ArrayLike, r.max)],
                        y_multi_label   =   ["Min", "Avg", "Max"],
                        x_tick_mode     =   "unit",
                        x_unit_from     =   "hz",
                        x_unit_out      =   "mhz",
                        x_tick_decimals =   0,
                        xlabel_base     =   "Frequency",
                        ylabel          =   "dB",
                        grid            =   False,
                        legend          =   True,
                        transparent     =   False,
                        line_colors     =   ["#FF5733",  "#3357FF", "#33FF57",],
                        theme           =   "dark",
                    )

                    mp = MatplotManager(default_cfg=cfg)
                    mp.plot_multi_line(self.create_png_fname(tags=[f"ch{r.channel_id}", "minavgmax"]))
                    plots.append(mp)

            case "group-delay":
                for r in model.results:
                    if not isinstance(r, GroupDelayAnalysisModel):
                        continue
                    cfg = PlotConfig(
                        title           = f"Channel Estimation · Channel: {r.channel_id} · GroupDelay",
                        x               = cast(ArrayLike, r.frequency),
                        y               = cast(ArrayLike, r.group_delay_us),
                        xlabel          = None,
                        xlabel_base     = "Frequency",
                        x_tick_mode     = "unit",
                        x_unit_from     = "hz",
                        x_unit_out      = "mhz",
                        x_tick_decimals = 0,
                        ylabel          = "Group Delay (µs)",
                        grid            = False,
                        legend          = False,
                        transparent     = False,
                        theme           = "dark",
                    )

                    mp = MatplotManager(default_cfg=cfg)
                    mp.plot_line(self.create_png_fname(tags=[f"ch{r.channel_id}", "groupdelay"]))
                    plots.append(mp)

            case "echo-detection-ifft":
                for r in model.results:
                    if isinstance(r, EchoDetectionIfftModel):
                        cfg = PlotConfig(
                            title   =   f"Channel Estimation · Channel {r.channel_id} · Echo Detection (IFFT Impulse Response)",
                            x       =   list(range(len(r.impulse_response))),
                            y       =   cast(ArrayLike, r.impulse_response),
                            xlabel  =   "Sample Index",
                            ylabel  =   "Amplitude (Linear Units)",
                            grid    =   True,
                            legend  =   False,
                            theme   =   "dark",
                        )

                        mp = MatplotManager(default_cfg=cfg)
                        mp.plot_line(self.create_png_fname(tags=[f"ch{r.channel_id}", "echo-ifft"]))
                        plots.append(mp)
                        continue

                    # NEW: multi-echo model — plot |h(t)| if present
                    if isinstance(r, IfftMultiEchoDetectionModel) and r.time_response is not None:
                        tr      = r.time_response
                        ir_mag  = [(re * re + im * im) ** 0.5 for (re, im) in tr.time_response]
                        time_us = [t * 1e6 for t in tr.time_axis_s]
                        cfg = PlotConfig(
                            title   =   f"Channel Estimation · Channel {r.channel_id} · Echo Detection (IFFT, {r.cable_type}, VF={r.velocity_factor:.2f})",
                            x       =   cast(ArrayLike, time_us),
                            y       =   ir_mag,
                            xlabel  =   "Time (µs)",
                            ylabel  =   "|h(t)| (linear)",
                            grid    =   True,
                            legend  =   False,
                            theme   =   "dark",
                        )
                        mp = MatplotManager(default_cfg=cfg)
                        mp.plot_line(self.create_png_fname(tags=[f"ch{r.channel_id}", "echo-ifft-multi"]))
                        plots.append(mp)

        return plots

    def _analyze_min_avg_max(self) -> list[MinAvgMaxModel]:
        """
        Compute Per-Channel Min/Avg/Max Amplitude Statistics.

        Aggregates complex carrier values per channel from all available
        captures, computes magnitude statistics using ``MinAvgMaxComplex``,
        and returns a list of ``MinAvgMaxModel`` instances keyed by channel id.
        """
        channel_data, freqs, _ = self._get_channel_data()

        out: list[MinAvgMaxModel] = []

        for ch, cplx in channel_data.items():
            if not any(cplx):
                continue

            stats = MinAvgMaxComplex(cplx, precision=4)

            out.append(
                MinAvgMaxModel(
                    channel_id   =   ch,
                    frequency    =   freqs.get(ch, []),
                    min          =   stats.min_mag,
                    avg          =   stats.avg_mag,
                    max          =   stats.max_mag,
                )
            )

        return out

    def _analyze_group_delay(self) -> list[GroupDelayAnalysisModel]:
        """
        Analyze group delay for each channel.
        Process:
        1. Aggregate complex carrier values per channel from all captures.
        2. For each channel, compute group delay using GroupDelayCalculator.
            2.a Input: List of complex carrier values and frequency bins.
            2.b Calulate the Avg phase response across captures.
            2.c Compute group delay as the negative derivative of phase w.r.t frequency.
        3. Return list of GroupDelayAnalysisModel with results.

        """
        channel_data, chan_freqs_map, _ = self._get_channel_data()

        out: list[GroupDelayAnalysisModel] = []

        for ch, cplx in channel_data.items():

            gd = GroupDelayCalculator(cast(Sequence[Sequence[complex]], cplx),
                                      chan_freqs_map[ch]).to_model().group_delay_full

            out.append(
                GroupDelayAnalysisModel(
                    channel_id      =   ch,
                    frequency       =   gd.freqs,
                    group_delay_us  =   gd.tau_g,
                )
            )

        return out

    def _analyze_echo_detection_ifft(self) -> list[IfftMultiEchoDetectionModel]:
        """Build echo-detection results using IFFT (multi-echo by default)."""
        channel_data, _, obw = self._get_channel_data()

        out: list[IfftMultiEchoDetectionModel] = []
        for ch, cplx in channel_data.items():
            bw = obw.get(ch, 0.0)
            if not bw:
                continue

            # Use the multi-echo detector; include time response for plotting
            det_model = IfftEchoDetector(cast(Sequence[Sequence[complex]], cplx), sample_rate=float(bw)).detect_multiple_reflections(
                cable_type              =   "RG6",
                threshold_frac          =   0.5,
                guard_bins              =   1,
                min_separation_s        =   0.0,
                max_delay_s             =   None,
                max_peaks               =   10,
                n_fft                   =   None,
                include_time_response   =   True,
            )

            # Stamp the channel id so filenames are per-channel
            det_model = det_model.model_copy(update={"channel_id": ch})
            out.append(det_model)

        return out

    def _analyze_lte_detection(self) -> list[LteDetectionModel]:
        """
        Detect LTE-Style Interference Using Group-Delay Anomalies.

        Aggregates complex carrier values per channel, derives group-delay
        behavior via ``GroupDelayAnomalyDetector``, and returns a list of
        ``LteDetectionModel`` instances summarizing anomalies, threshold,
        and bin-width configuration for each channel.
        """
        channel_data, freqs, _ = self._get_channel_data()
        threshold = 1e-9
        bin_widths = [1e6, 5e5, 1e5]

        out: list[LteDetectionModel] = []
        for ch, cplx in channel_data.items():
            res = GroupDelayAnomalyDetector(cplx, list(freqs[ch])).run(bin_widths=bin_widths, threshold=threshold)
            out.append(
                LteDetectionModel(
                    channel_id      =   ch,
                    anomalies       =   res.get("anomalies", []),
                    threshold       =   threshold,
                    bin_widths      =   bin_widths,
                )
            )
        return out

    def _build_json_archive_models(self) -> dict[FileName, BaseModel]:
        """
        Build JSON Archive Models For Each Analysis Result.

        Iterates over the aggregated result set and constructs a mapping
        from a logical filename stem (channel id plus analysis type) to the
        corresponding Pydantic model instance. The caller is responsible for
        handing these models off to the JSON transaction/archive pipeline.

        Returns
        -------
        Dict[FileName, BaseModel]
            Mapping of partial filenames to analysis result models suitable
            for JSON archival.
        """
        models: dict[FileName, BaseModel] = {}
        model = self.to_model()
        for r in model.results:
            match self._analysis_type.value:
                case "min-avg-max":
                    if not isinstance(r, MinAvgMaxModel):
                        continue
                    models[FileName(f"{r.channel_id}_{self._analysis_type.name}")] = r

                case "group-delay":
                    if not isinstance(r, GroupDelayAnalysisModel):
                        continue
                    models[FileName(f"{r.channel_id}_{self._analysis_type.name}")] = r

                case "lte-detection-phase-slope":
                    if not isinstance(r, LteDetectionModel):
                        continue
                    models[FileName(f"{r.channel_id}_{self._analysis_type.name}")] = r

                case "echo-detection-ifft":
                    if isinstance(r, EchoDetectionIfftModel):
                        models[FileName(f"{r.channel_id}_{self._analysis_type.name}")] = r
                        continue

                    if isinstance(r, IfftMultiEchoDetectionModel):
                        models[FileName(f"{r.channel_id}_{self._analysis_type.name}")] = r
        return models

# FILE: src/pypnm/api/routes/advance/analysis/signal_analysis/multi_chan_est_singnal_analysis.py
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

