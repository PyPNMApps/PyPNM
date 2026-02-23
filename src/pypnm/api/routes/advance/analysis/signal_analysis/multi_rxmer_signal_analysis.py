# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
from typing import Any, cast

import numpy as np
from pydantic import BaseModel, Field

from pypnm.api.routes.advance.analysis.report.multi_analysis_rpt import MultiAnalysisRpt
from pypnm.api.routes.advance.common.capture_data_aggregator import (
    CaptureDataAggregator,
)
from pypnm.api.routes.advance.common.transactionsCollection import (
    TransactionCollectionModel,
)
from pypnm.api.routes.common.classes.collection.ds_modulation_profile_aggregator import (
    DsModulationProfileAggregator,
)
from pypnm.api.routes.common.classes.collection.ds_rxmer_aggregator import (
    DsRxMerAggregator,
)
from pypnm.api.routes.common.classes.collection.fec_summary_aggregator import (
    FecSummaryAggregator,
    FecSummaryTotalsModel,
)
from pypnm.docsis.data_type.sysDescr import SystemDescriptorModel
from pypnm.lib.constants import INVALID_CAPTURE_TIME
from pypnm.lib.csv.manager import CSVManager
from pypnm.lib.matplot.manager import MatplotManager, PlotConfig
from pypnm.lib.signal_processing.shan.series import ShannonSeries
from pypnm.lib.types import (
    ArrayLike,
    CaptureTime,
    ChannelId,
    FloatSeries,
    FrequencySeriesHz,
    MacAddressStr,
    MagnitudeSeries,
    StringEnum,
    TimeStamp,
    TimestampSec,
)
from pypnm.pnm.lib.min_avg_max import MinAvgMax
from pypnm.pnm.parser.CmDsOfdmFecSummary import CmDsOfdmFecSummary
from pypnm.pnm.parser.CmDsOfdmModulationProfile import (
    CmDsOfdmModulationProfile,
    ProfileId,
)
from pypnm.pnm.parser.CmDsOfdmRxMer import CmDsOfdmRxMer, CmDsOfdmRxMerModel


class MultiRxMerAnalysisType(StringEnum):
    MIN_AVG_MAX                = "min-avg-max"
    RXMER_HEAT_MAP             = "rxmer-heat-map"
    OFDM_PROFILE_PERFORMANCE_1 = "ofdm-profile-performance-1"

class MultiRxMerAnalysisBaseModel(BaseModel):
    channel_id: ChannelId = Field(..., description="OFDM channel identifier for this result set.")
    frequency: FrequencySeriesHz = Field(..., description="Per-subcarrier frequency bins (Hz).")

class MinAvgMaxAnalysisModel(MultiRxMerAnalysisBaseModel):
    min:       FloatSeries       = Field(..., description="Per-subcarrier minimum values.")
    avg:       FloatSeries       = Field(..., description="Per-subcarrier average values.")
    max:       FloatSeries       = Field(..., description="Per-subcarrier maximum values.")

class ProfileEntryModel(BaseModel):
    capture_time: CaptureTime               = Field(..., description="Epoch capture timestamp.")
    profile_id: ProfileId                   = Field(..., description="Modulation profile index for the capture.")
    profile_min_mer: FloatSeries            = Field(..., description="Per-subcarrier Shannon limits (bits/s/Hz) for the profile.")
    capacity_delta: FloatSeries             = Field(..., description="Average measured MER Subcarrier vs. Min Subcarrier Shannon MER")
    fec_summary: FecSummaryTotalsModel      = Field(..., description="")

class ChannelOfdmProfilePerf01Model(MultiRxMerAnalysisBaseModel):
    avg_mer:            FloatSeries             = Field(..., description="Per-subcarrier average MER (dB).")
    mer_shannon_limits: FloatSeries             = Field(..., description="Per-subcarrier Shannon limits derived from avg MER.")
    profiles:           list[ProfileEntryModel] = Field(..., description="Per-capture per-profile deltas/limits.")

class ChannelHeatMapModel(MultiRxMerAnalysisBaseModel):
    timestamps:  list[TimestampSec]     = Field(..., description="Capture timestamps (epoch) for rows of the heatmap.")
    values:      list[MagnitudeSeries]  = Field(..., description="Matrix: rows=captures, cols=subcarriers; MER values.")

MultiRxMerTemporalObjType   = CmDsOfdmRxMer | CmDsOfdmFecSummary | CmDsOfdmModulationProfile
TemporalMapping             = tuple[CaptureTime, MultiRxMerTemporalObjType]

MinAvgMaxMap                = dict[ChannelId, MinAvgMaxAnalysisModel]
OfdmProfilePerf01Map        = dict[ChannelId, ChannelOfdmProfilePerf01Model]
HeatMapMap                  = dict[ChannelId, ChannelHeatMapModel]
MultiRxMerAnalysisMap       = MinAvgMaxMap | OfdmProfilePerf01Map | HeatMapMap

class MultiRxMerAnalysisResult(BaseModel):
    mac_address:   MacAddressStr            = Field(..., description="Cable modem MAC address associated with this analysis.")
    system_description: SystemDescriptorModel | None = Field(default=None, description="Parsed sysDescr captured with the multi-capture transaction set, if available.")
    analysis_type: MultiRxMerAnalysisType   = Field(..., description="Type of multi-RxMER analysis performed.")
    data:          MultiRxMerAnalysisMap    = Field(..., description="Analysis results mapping (per-channel model).")
    error:         str | None               = Field(default="", description="Optional error message if analysis failed.")


# ---------------------------
# Analyzer (models built during processing; single CM)
# ---------------------------

class MultiRxMerSignalAnalysis(MultiAnalysisRpt):

    def __init__(self, capt_data_agg: CaptureDataAggregator,
                 analysis_type: MultiRxMerAnalysisType) -> None:
        super().__init__(capt_data_agg)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.analysis_type = analysis_type
        self._model: MultiRxMerAnalysisResult | None = None
        self._mac: MacAddressStr | None = None

        self._sorted_temporal_mapping: list[TemporalMapping] = []
        self._analysis_map: MultiRxMerAnalysisMap = {}
        self._is_process:bool = False

    # -----------------------
    # Public API
    # -----------------------

    def to_model(self) -> MultiRxMerAnalysisResult:

        if not self._is_process:
            self._process()

        if self._model is not None:
            return self._model

        mac = self.getMacAddresses()

        if len(mac) > 1:
            self.logger.error(f'Found #({len(mac)}), Not Expection more than 1 MacAddress -> {mac}')

        mac = mac[0].to_mac_format()

        try:
            data = self._dispatch_build()
            self._model = MultiRxMerAnalysisResult(
                mac_address     =   mac,
                system_description = self.get_system_description_model(),
                analysis_type   =   self.analysis_type,
                data            =   data,
            )

        except Exception as e:
            self.logger.error(f'Unable to create MultiRxMerAnalysisResult, reason: {e}')
            self._model = MultiRxMerAnalysisResult(
                mac_address     =   mac,
                system_description = self.get_system_description_model(),
                analysis_type   =   self.analysis_type,
                data            =   None,
                error           =   str(e),
            )

        return self._model

    def to_dict(self) -> dict[str, Any]:
        return self.to_model().model_dump()

    # -----------------------
    # Internals
    # -----------------------

    def _get_temporal_pnm_data(self) -> list[TemporalMapping]:
        self.logger.debug(f'Temporal PNM Data - Record Count: [{len(self._sorted_temporal_mapping)}]')
        return self._sorted_temporal_mapping

    def _get_capture_times(self, channel_id:ChannelId, obj_type:type) -> list[TimestampSec]:

        capture_times: list[TimestampSec] = []

        for capture_time, obj in self._get_temporal_pnm_data():

            chan_id:ChannelId = cast(ChannelId, obj.to_model().channel_id)

            if channel_id == chan_id and isinstance(obj, obj_type):
                capture_times.append(cast(TimestampSec, capture_time))

        return capture_times

    def _dispatch_build(self) -> MultiRxMerAnalysisMap:

        if self.analysis_type == MultiRxMerAnalysisType.MIN_AVG_MAX:
            return self._analyze_min_avg_max_models()

        if self.analysis_type == MultiRxMerAnalysisType.OFDM_PROFILE_PERFORMANCE_1:
            return self._analyze_ofdm_profile_perf_1_models()

        if self.analysis_type == MultiRxMerAnalysisType.RXMER_HEAT_MAP:
            return self._analyze_rxmer_heat_map_models()

        raise ValueError(f"Unsupported analysis type: {self.analysis_type}")

    #--------------------------------------------------------------------------
    #               Analyses (single MAC; return channel->model)
    #--------------------------------------------------------------------------
    def _analyze_min_avg_max_models(self) -> MinAvgMaxMap:
        """
        Aggregate per-subcarrier RxMER across time (by channel) using CmDsOfdmRxMerModel.

        For each CmDsOfdmRxMer object in `self._sorted_temporal_mapping`, this:
        - Converts to CmDsOfdmRxMerModel (`obj.to_model()`),
        - Collects `values` (FloatSeries) per `channel_id`,
        - Applies MinAvgMax across captures to produce per-index min/avg/max arrays.

        Returns
        -------
        MinAvgMaxMap
            Mapping of ChannelId -> MinAvgMaxModel (min/avg/max lists per subcarrier index).
        """
        self.logger.debug('Building MinAvgMax Signal Analysis')

        chan_series: dict[ChannelId, list[MagnitudeSeries]] = {}
        chan_freq: dict[ChannelId, FrequencySeriesHz] = {}
        mamap: MinAvgMaxMap = {}

        for _, obj in self._get_temporal_pnm_data():

            if not isinstance(obj, CmDsOfdmRxMer):
                self.logger.debug('Not a CmDsOfdmRxMer Object, skipping')
                continue

            model: CmDsOfdmRxMerModel = obj.to_model()

            if model.channel_id not in chan_series:
                chan_series[model.channel_id] = []

            chan_series[model.channel_id].append(model.values)
            chan_freq[model.channel_id] = self._build_frequencies(model)

        for cid, series in chan_series.items():

            self.logger.debug(f'Building MinAvgMaxAnalysisModel for Channel: {cid}')
            frequencies = self._build_frequencies(chan_freq.get(cid))

            try:
                mam = MinAvgMax(series, precision=2)
                mam_model = mam.to_model()

                mamap[cid] = MinAvgMaxAnalysisModel(
                    channel_id  =   cid,
                    frequency   =   frequencies,
                    min         =   mam_model.min,
                    avg         =   mam_model.avg,
                    max         =   mam_model.max)

            except ValueError as e:
                self.logger.warning('MinAvgMax failed for channel %s: %s', str(cid), str(e))
                continue

        return mamap

    def _analyze_rxmer_heat_map_models(self) -> HeatMapMap:
        """
        Build RxMER HeatMap Signal Analysis by aggregating per-subcarrier MER values
        across all captures for each channel.

        Returns
        -------
        HeatMapMap
            Mapping of ChannelId -> ChannelHeatMapModel containing timestamps and MER matrix.
        """
        self.logger.info('Building RxMER HeatMap Signal Analysis')

        # Store per-channel temporal data
        channel_data: dict[ChannelId, list[MagnitudeSeries]] = {}
        channel_freqs: dict[ChannelId, FrequencySeriesHz] = {}
        heatmap_map: HeatMapMap = {}

        # Aggregate values for each capture per channel
        for _, obj in self._get_temporal_pnm_data():
            if not isinstance(obj, CmDsOfdmRxMer):
                self.logger.debug('Skipping non-CmDsOfdmRxMer object: %s', type(obj).__name__)
                continue

            model: CmDsOfdmRxMerModel = obj.to_model()
            ch_id = cast(ChannelId, model.channel_id)

            if ch_id not in channel_data:
                channel_data[ch_id] = []

            channel_data[ch_id].append(model.values)
            channel_freqs[ch_id] = self._build_frequencies(model)

        # Build final models
        for ch_id, magnitudes in channel_data.items():
            self.logger.debug('Building ChannelHeatMapModel for Channel: %s', ch_id)

            timestamps: list[TimestampSec] = self._get_capture_times(ch_id, CmDsOfdmRxMer)
            frequencies: FrequencySeriesHz = channel_freqs.get(ch_id, [])

            heatmap_map[ch_id] = ChannelHeatMapModel(
                channel_id  =   ch_id,
                frequency   =   frequencies,
                timestamps  =   timestamps,
                values      =   magnitudes,
            )

        return heatmap_map

    def _analyze_ofdm_profile_perf_1_models(self) -> OfdmProfilePerf01Map:
        """
        Perform OFDM Profile Performance Analysis (Type 1).

        Integrates data from RxMER, Modulation Profile, and FEC Summary aggregators.

        Steps
        -----
        1. Aggregate temporal PNM data by channel.
        2. For each channel:
            - Compute average RxMER and Shannon limits.
            - Retrieve modulation profile analysis results via `mod_pro_agg.basic_analysis()`.
            - Align FEC summary totals.
        3. Build and return structured per-channel performance results.

        Returns
        -------
        OfdmProfilePerf01Map
            Mapping of ChannelId → ChannelOfdmProfilePerf01Model.
        """
        self.logger.info("Running OFDM Profile Performance Analysis (Type 1)")

        rxmer_agg   = DsRxMerAggregator()
        mod_pro_agg = DsModulationProfileAggregator()
        fec_sum_agg = FecSummaryAggregator()
        models: OfdmProfilePerf01Map = {}

        # Step 1: aggregate PNM objects
        for _, obj in self._get_temporal_pnm_data():
            if isinstance(obj, CmDsOfdmRxMer):
                rxmer_agg.add(obj)
            elif isinstance(obj, CmDsOfdmModulationProfile):
                mod_pro_agg.add(obj)
            elif isinstance(obj, CmDsOfdmFecSummary):
                fec_sum_agg.add(obj)

        if self.logger.isEnabledFor(logging.INFO):
            self.logger.info(f'RxMER Aggregator Count: {rxmer_agg.length()}')
            self.logger.info(f'Modulation Profile Aggregator Count: {mod_pro_agg.length()}')
            self.logger.info(f'FEC Summary Aggregator Count: {fec_sum_agg.length()}')

        # Step 2: analyze per channel
        for ch_id in rxmer_agg.get_channel_ids():
            mam = rxmer_agg.get_min_avg_max(ch_id)
            shannon_model = ShannonSeries(mam.avg).to_model()
            frequencies = rxmer_agg.get_frequencies(ch_id)

            # Perform basic modulation profile analysis for this channel
            mod_analysis_map = mod_pro_agg.basic_analysis(ch_id)
            mod_analysis_list = mod_analysis_map.get(ch_id, [])
            if not mod_analysis_list:
                self.logger.warning("No modulation analysis results for channel %s", ch_id)
                continue

            capture_times = sorted(rxmer_agg.get_capture_times(ch_id))
            if not capture_times:
                self.logger.warning("No RxMER captures for channel %s", ch_id)
                continue

            start, stop = TimeStamp(capture_times[0]), TimeStamp(capture_times[-1])
            fec_summary = fec_sum_agg.get_summary_totals(ch_id, start, stop)

            profile_entries: list[ProfileEntryModel] = []

            for mod_analysis in mod_analysis_list:
                # Each DsModulationProfileAnalysisModel corresponds to a snapshot
                capture_time = CaptureTime(getattr(mod_analysis, "capture_time", start))
                for profile_entry in mod_analysis.profiles:
                    pid = profile_entry.profile_id
                    shannon_min = profile_entry.carrier_values.shannon_min_mer
                    capacity_delta = [float(a - b) for a, b in zip(mam.avg, shannon_min, strict=False)]

                    # Match corresponding FEC summary per profile
                    fec_entry = next((p for p in fec_summary.summary if p.profile_id == pid), None)
                    fec_payload = (
                        fec_summary if fec_entry is None
                        else FecSummaryTotalsModel(
                            start      = fec_summary.start,
                            end        = fec_summary.end,
                            channel_id = fec_summary.channel_id,
                            summary    = [fec_entry],))

                    profile_entries.append(
                        ProfileEntryModel(
                            capture_time    = capture_time,
                            profile_id      = pid,
                            profile_min_mer = shannon_min,
                            capacity_delta  = capacity_delta,
                            fec_summary     = fec_payload,
                        )
                    )

            models[ch_id] = ChannelOfdmProfilePerf01Model(
                channel_id          = ch_id,
                frequency           = frequencies,
                avg_mer             = mam.avg,
                mer_shannon_limits  = cast(FloatSeries, shannon_model.snr_db_min),
                profiles            = profile_entries,)

        return models

    """Abstract Required methods"""

    def _process(self) -> None:
        """
        Process transactions into typed PNM objects and build a time-indexed view.

        Steps
        -----
        1) Fetch all TransactionCollectionModel items from the current TransactionCollection.
        2) Attempt to decode each payload (bytes) as one of:
            - CmDsOfdmRxMer
            - CmDsOfdmFecSummary
            - CmDsOfdmModulationProfile
            In that order; on failure, fall through to the next type.
        3) Store each successfully decoded object in a temporal mapping keyed
        by its capture_time (or INVALID_CAPTURE_TIME if missing).
        4) Produce a list `self._sorted_temporal_mapping` of (capture_time, obj) tuples,
        sorted by ascending capture_time, for downstream iteration.
        """
        self._is_process = True
        self.logger.info("Processing Multi-RxMER Analysis Report")

        # Convert Transactions to PNM RxMER Data
        tc = self.getTransactionCollection()
        tcms:list[TransactionCollectionModel] = tc.getTransactionCollectionModel()
        temporal_mapping:dict[CaptureTime, CmDsOfdmRxMer | CmDsOfdmFecSummary | CmDsOfdmModulationProfile] = {}

        self.logger.info(f'TransactionCollectionModel Count: {len(tcms)}')

        # Groom data for general use due to various Analysis that is performed
        for count, tcm in enumerate(tcms):

            try:
                dorm = CmDsOfdmRxMer(tcm.data)
                capture_time: CaptureTime = dorm.getPnmHeaderModel().pnm_header.capture_time or INVALID_CAPTURE_TIME
                temporal_mapping[capture_time] = dorm
                model = dorm.to_model()
                self.register_models_for_json_archive_files(model, [str(model.channel_id) , "CmDsOfdmRxMer" ])
                continue

            except Exception as e:
                self.logger.debug(f'PNM file {count} is not compatible with CmDsOfdmRxMer, skipping: {e}')

            try:
                dofs = CmDsOfdmFecSummary(tcm.data)
                capture_time: CaptureTime = dofs.getPnmHeaderModel().pnm_header.capture_time or INVALID_CAPTURE_TIME
                temporal_mapping[capture_time] = dofs
                model = dofs.to_model()
                self.register_models_for_json_archive_files(model, [str(model.channel_id) , "CmDsOfdmFecSummary"])
                continue

            except Exception as e:
                self.logger.debug(f'PNM file {count} is not compatible with CmDsOfdmFecSummary, skipping: {e}')

            try:
                domp = CmDsOfdmModulationProfile(tcm.data)
                capture_time: CaptureTime = domp.getPnmHeaderModel().pnm_header.capture_time or INVALID_CAPTURE_TIME
                temporal_mapping[capture_time] = domp
                model = domp.to_model()
                self.register_models_for_json_archive_files(model, [str(model.channel_id) , "CmDsOfdmModulationProfile"])
                continue

            except Exception as e:
                self.logger.debug(f'PNM file {count} is not compatible with CmDsOfdmModulationProfile, skipping: {e}')

        # Create a sorted list of tuples based on capture_time (ascending)
        self._sorted_temporal_mapping = sorted(temporal_mapping.items(), key=lambda x: x[0])

        self.logger.debug(
            f"Temporal mapping size={len(temporal_mapping)}, sorted entries={len(self._sorted_temporal_mapping)}")

        self._dispatch_build()

    def create_csv(self, **kwargs: object) -> list[CSVManager]:
        """
        Build CSV outputs for supported analysis types.
        Currently implemented for MIN_AVG_MAX only.
        """
        self.logger.debug("Processing Multi-RxMER Analysis CSV Report")
        out: list[CSVManager] = []
        model = self.to_model()

        if self.analysis_type == MultiRxMerAnalysisType.MIN_AVG_MAX:
            data  = cast(MinAvgMaxMap, model.data)

            for ch_id, ch_model in data.items():
                csv_mgr:CSVManager = self.csv_manager_factory()

                # Convert frequency (Hz) → kHz for readability and to match labeling.
                freq_hz  = ch_model.frequency
                freq_khz = [f / 1_000.0 for f in freq_hz]

                csv_mgr.set_header(["channel_id", "frequency_khz", "min", "avg", "max"])

                for idx, f_khz in enumerate(freq_khz):
                    # Defensive indexing (lists should match by construction)
                    mn = ch_model.min[idx]  if idx < len(ch_model.min)  else None
                    av = ch_model.avg[idx]  if idx < len(ch_model.avg)  else None
                    mx = ch_model.max[idx]  if idx < len(ch_model.max)  else None
                    csv_mgr.insert_row([ch_id, f_khz, mn, av, mx])

                csv_fname = self.create_csv_fname(tags=['rxmer_min_avg_max', f'{ch_id}'])
                csv_mgr.set_path_fname(csv_fname)

                out.append(csv_mgr)

        elif self.analysis_type == MultiRxMerAnalysisType.OFDM_PROFILE_PERFORMANCE_1:
            data = cast(OfdmProfilePerf01Map, model.data)

            for ch_id, ch_model in data.items():
                ch_model = cast(ChannelOfdmProfilePerf01Model, ch_model)

                for profile_model in ch_model.profiles:
                    csv_mgr: CSVManager = self.csv_manager_factory()
                    header = [
                        "ProfileID", "Frequency(Hz)", "AvgMER(dB)",
                        "ProfileMin(dB)", "CapacityDelta(Avg vs. ProfileMin)",
                        "FECTotal", "FECCorrected", "FECUncorrectable"
                    ]
                    csv_mgr.set_header(header)

                    pid   = profile_model.profile_id
                    fec_e = profile_model.fec_summary.summary[0] if profile_model.fec_summary.summary else None
                    total = fec_e.summary.total_codewords if fec_e else 0
                    corr  = fec_e.summary.corrected if fec_e else 0
                    uncor = fec_e.summary.uncorrectable if fec_e else 0

                    for freq, avg_mer, prof_lim, delta in zip(
                        ch_model.frequency,
                        ch_model.avg_mer,
                        profile_model.profile_min_mer,
                        profile_model.capacity_delta, strict=False,
                    ):
                        csv_mgr.insert_row([pid, freq, avg_mer, prof_lim, delta, total, corr, uncor])

                    csv_fname = self.create_csv_fname(tags=["ofdm_profile_perf_1", f"ch{ch_id}", f"pid{pid}"])
                    csv_mgr.set_path_fname(csv_fname)
                    out.append(csv_mgr)

        elif self.analysis_type == MultiRxMerAnalysisType.RXMER_HEAT_MAP:
            data = cast(HeatMapMap, model.data)

            for ch_id, ch_model in data.items():
                ch_model = cast(ChannelHeatMapModel, ch_model)
                csv_mgr: CSVManager = self.csv_manager_factory()

                # Build header: first column is capture time index, then frequency (Hz → kHz)
                freq_khz = [f / 1_000.0 for f in ch_model.frequency]
                header = ["CaptureTime"] + [str(f) for f in freq_khz]
                csv_mgr.set_header(header)

                # Each row contains: capture time + MER values for that time
                for ts, mag_series in zip(ch_model.timestamps, ch_model.values, strict=False):
                    csv_mgr.insert_row([ts] + mag_series)

                # Assign CSV filename
                csv_fname = self.create_csv_fname(tags=["rxmer_ofdm_heat_map", f"{ch_id}"])
                csv_mgr.set_path_fname(csv_fname)

                out.append(csv_mgr)

        return out

    def create_matplot(self, **kwargs: object) -> list[MatplotManager]:
        """
        Build MatPlot PNG outputs for supported analysis types.
        Currently implemented for MIN_AVG_MAX only.
        """
        self.logger.debug("Processing Multi-RxMER Analysis MatPlot Report")
        out: list[MatplotManager] = []
        model = self.to_model()

        if self.analysis_type == MultiRxMerAnalysisType.MIN_AVG_MAX:
            data1  = cast(MinAvgMaxMap, model.data)

            for channel_id, ch_model in data1.items():
                freq_hz  = cast(ArrayLike, ch_model.frequency)
                freq_khz = cast(ArrayLike,freq_hz)

                mn  = cast(ArrayLike, ch_model.min)
                av  = cast(ArrayLike, ch_model.avg)
                mx  = cast(ArrayLike, ch_model.max)

                cfg = PlotConfig(
                    title           =   f"Min-Avg-Max RxMER · Channel: {channel_id}",
                    x               =   cast(ArrayLike, freq_khz),
                    y_multi         =   [mn, av, mx],
                    y_multi_label   =   ["Min", "Avg", "Max"],
                    x_tick_mode     =   "unit",
                    x_unit_from     =   "hz",
                    x_unit_out      =   "mhz",
                    x_tick_decimals =   0,
                    xlabel_base     =   "Frequency",
                    ylabel          =   "dB",
                    grid            =   True,
                    legend          =   True,
                    transparent     =   False,
                    line_colors     =   ["#FF5733",  "#3357FF", "#33FF57",],
                    theme           =   "dark",
                )

                multi = self.create_png_fname(tags=[str(channel_id), "rxmer_min_avg_max"])
                self.logger.debug("Creating MatPlot: %s for channel: %s", multi, channel_id)

                mat_mgr = MatplotManager(default_cfg=cfg)
                mat_mgr.plot_multi_line(filename=multi)

                out.append(mat_mgr)

        elif self.analysis_type == MultiRxMerAnalysisType.RXMER_HEAT_MAP:
            data2  = cast(HeatMapMap, model.data)

            for ch_id, ch_model in data2.items():
                ch_model = cast(ChannelHeatMapModel, ch_model)

                Z = np.asarray(ch_model.values, dtype=float)
                if Z.size == 0:
                    self.logger.warning("RXMER_HEAT_MAP: empty matrix for channel %s; skipping.", ch_id)
                    continue

                x_hz = cast(ArrayLike, ch_model.frequency)
                y_ix = cast(ArrayLike, np.arange(Z.shape[0], dtype=float))

                try:
                    vmin = float(np.nanmin(Z))
                    vmax = float(np.nanmax(Z))
                except Exception:
                    vmin = None
                    vmax = None

                cfg = PlotConfig(
                    title           =   f"HeatMap RxMER · Channel: {ch_id}",
                    x               =   x_hz,
                    x_tick_mode     =   "unit",
                    x_unit_from     =   "hz",
                    x_unit_out      =   "mhz",
                    x_tick_decimals =   0,
                    xlabel_base     =   "Frequency",
                    ylabel          =   "Capture Index",
                    zlabel          =   "MER (dB)",
                    grid            =   False,
                    legend          =   False,
                    transparent     =   False,
                    theme           =   "dark",
                )

                png_name = self.create_png_fname(tags=[str(ch_id), "rxmer_heat_map"])

                mat_mgr = MatplotManager(default_cfg=cfg)
                mat_mgr.heatmap2d(
                    Z.tolist(),
                    png_name,
                    x            = x_hz,
                    y            = y_ix,
                    add_colorbar = True,
                    vmin         = vmin,
                    vmax         = vmax,
                )

                out.append(mat_mgr)

        elif self.analysis_type == MultiRxMerAnalysisType.OFDM_PROFILE_PERFORMANCE_1:
            data3  = cast(OfdmProfilePerf01Map, model.data)

            for ch_id, ch_model in data3.items():
                ch_model = cast(ChannelOfdmProfilePerf01Model, ch_model)

                if not ch_model.profiles:
                    self.logger.warning("OFDM_PROFILE_PERFORMANCE_1: no profiles for channel %s; skipping.", ch_id)
                    continue

                freq_hz  = cast(ArrayLike, ch_model.frequency)
                avg_mer  = cast(ArrayLike, ch_model.avg_mer)

                for profile_model in ch_model.profiles:
                    pid    = profile_model.profile_id
                    pmin   = cast(ArrayLike, profile_model.profile_min_mer)
                    fec_e  = profile_model.fec_summary.summary[0] if profile_model.fec_summary.summary else None
                    total  = getattr(fec_e.summary, "total_codewords", 0) if fec_e else 0
                    corr   = getattr(fec_e.summary, "corrected", 0)       if fec_e else 0
                    uncor  = getattr(fec_e.summary, "uncorrectable", 0)   if fec_e else 0
                    fec_l  = f"FEC(Total={total}, Corr={corr}, Uncorr={uncor})"

                    cfg = PlotConfig(
                        title           =   f"OFDM PROFILE PERFORMANCE 1 · Channel: {ch_id} · Profile: {pid}",
                        x               =   freq_hz,
                        y_multi         =   [avg_mer, pmin],
                        y_multi_label   =   [f"AvgMER (dB) {fec_l}", "ProfileMin (dB)"],
                        x_tick_mode     =   "unit",
                        x_unit_from     =   "hz",
                        x_unit_out      =   "mhz",
                        x_tick_decimals =   0,
                        xlabel_base     =   "Frequency",
                        ylabel          =   "Average MER (dB)",
                        grid            =   True,
                        legend          =   True,
                        transparent     =   False,
                        line_colors     =   ["#3357FF", "#33FF57"],
                        theme           =   "dark",
                    )

                    fname   = self.create_png_fname(tags=[f"{ch_id}", f"profile_{pid}", "ofdm_profile_perf_1"])
                    plotmgr = MatplotManager(default_cfg=cfg)
                    plotmgr.plot_multi_line(filename=fname)
                    out.append(plotmgr)

        return out

    """Helpers"""

    def _parse_rxmer_heatmap_series(self) -> None:
        pass

    def _build_frequencies(self, model: CmDsOfdmRxMerModel | FrequencySeriesHz | None) -> FrequencySeriesHz:
        """
        Build absolute subcarrier center frequencies (Hz) for the RxMER series.
        """
        if isinstance(model, list):
            return model
        if model is None:
            return []

        active_idx  = model.first_active_subcarrier_index
        spacing     = model.subcarrier_spacing
        freq_zero   = model.subcarrier_zero_frequency
        num_idx     = len(model.values)

        start_freq  = freq_zero + (spacing * active_idx)

        freqs: FrequencySeriesHz = cast(FrequencySeriesHz,[start_freq + (i * spacing) for i in range(num_idx)])
        return freqs
