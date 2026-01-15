## Agent Review Bundle Summary
- Goal: Remove JSON ledger references, track JSON exports in DB, and add deprecated config warnings while keeping runtime DB-backed behavior.
- Changes: Linked JSON exports to transactions in multi-RxMER analysis, removed ledger paths from docs and examples, and updated JSON export tests to validate DB tracking.
- Files: src/pypnm/api/routes/advance/analysis/signal_analysis/multi_rxmer_signal_analysis.py; src/pypnm/examples/settings/system.json; docs/api/fast-api/multi/capture-operation.md; docs/api/fast-api/pypnm/db/data-base.md; docs/issues/support-bundle.md; docs/system/system-config.md; tests/test_json_transaction_db.py; tests/test_json_transaction_db_empty_transaction_id.py.
- Tests: python3 -m compileall src; ruff check src; ruff format --check .; pytest -q (596 passed, 9 skipped).
- Notes: Postgres-gated tests skipped (PYPNM_DB_POSTGRES_DSN unset) and PNM_CM_IT integration tests skipped; initial pytest run timed out at 10s and was re-run with a longer timeout.

# FILE: src/pypnm/api/routes/advance/analysis/signal_analysis/multi_rxmer_signal_analysis.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

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
from pypnm.api.routes.common.classes.analysis.model.schema import (
    DsModulationProfileAnalysisModel,
    ProfileAnalysisEntryModel,
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
    MIN_AVG_MAX = "min-avg-max"
    RXMER_HEAT_MAP = "rxmer-heat-map"
    OFDM_PROFILE_PERFORMANCE_1 = "ofdm-profile-performance-1"


class MultiRxMerAnalysisBaseModel(BaseModel):
    channel_id: ChannelId = Field(
        ..., description="OFDM channel identifier for this result set."
    )
    frequency: FrequencySeriesHz = Field(
        ..., description="Per-subcarrier frequency bins (Hz)."
    )


class MinAvgMaxAnalysisModel(MultiRxMerAnalysisBaseModel):
    min: FloatSeries = Field(..., description="Per-subcarrier minimum values.")
    avg: FloatSeries = Field(..., description="Per-subcarrier average values.")
    max: FloatSeries = Field(..., description="Per-subcarrier maximum values.")


class ProfileEntryModel(BaseModel):
    capture_time: CaptureTime = Field(..., description="Epoch capture timestamp.")
    profile_id: ProfileId = Field(
        ..., description="Modulation profile index for the capture."
    )
    profile_min_mer: FloatSeries = Field(
        ..., description="Per-subcarrier Shannon limits (bits/s/Hz) for the profile."
    )
    capacity_delta: FloatSeries = Field(
        ...,
        description="Average measured MER Subcarrier vs. Min Subcarrier Shannon MER",
    )
    fec_summary: FecSummaryTotalsModel = Field(..., description="")


class ChannelOfdmProfilePerf01Model(MultiRxMerAnalysisBaseModel):
    avg_mer: FloatSeries = Field(..., description="Per-subcarrier average MER (dB).")
    mer_shannon_limits: FloatSeries = Field(
        ..., description="Per-subcarrier Shannon limits derived from avg MER."
    )
    profiles: list[ProfileEntryModel] = Field(
        ..., description="Per-capture per-profile deltas/limits."
    )


class ChannelHeatMapModel(MultiRxMerAnalysisBaseModel):
    timestamps: list[TimestampSec] = Field(
        ..., description="Capture timestamps (epoch) for rows of the heatmap."
    )
    values: list[MagnitudeSeries] = Field(
        ..., description="Matrix: rows=captures, cols=subcarriers; MER values."
    )


MultiRxMerTemporalObjType = (
    CmDsOfdmRxMer | CmDsOfdmFecSummary | CmDsOfdmModulationProfile
)
TemporalMapping = tuple[CaptureTime, MultiRxMerTemporalObjType]

MinAvgMaxMap = dict[ChannelId, MinAvgMaxAnalysisModel]
OfdmProfilePerf01Map = dict[ChannelId, ChannelOfdmProfilePerf01Model]
HeatMapMap = dict[ChannelId, ChannelHeatMapModel]
MultiRxMerAnalysisMap = MinAvgMaxMap | OfdmProfilePerf01Map | HeatMapMap


class MultiRxMerAnalysisResult(BaseModel):
    mac_address: MacAddressStr = Field(
        ..., description="Cable modem MAC address associated with this analysis."
    )
    analysis_type: MultiRxMerAnalysisType = Field(
        ..., description="Type of multi-RxMER analysis performed."
    )
    data: MultiRxMerAnalysisMap = Field(
        ..., description="Analysis results mapping (per-channel model)."
    )
    error: str | None = Field(
        default="", description="Optional error message if analysis failed."
    )


# ---------------------------
# Analyzer (models built during processing; single CM)
# ---------------------------


class MultiRxMerSignalAnalysis(MultiAnalysisRpt):
    def __init__(
        self,
        capt_data_agg: CaptureDataAggregator,
        analysis_type: MultiRxMerAnalysisType,
    ) -> None:
        super().__init__(capt_data_agg)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.analysis_type = analysis_type
        self._model: MultiRxMerAnalysisResult | None = None
        self._mac: MacAddressStr | None = None

        self._sorted_temporal_mapping: list[TemporalMapping] = []
        self._analysis_map: MultiRxMerAnalysisMap = {}
        self._is_process: bool = False

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
            self.logger.error(
                f"Found #({len(mac)}), Not Expection more than 1 MacAddress -> {mac}"
            )

        mac = mac[0].to_mac_format()

        try:
            data = self._dispatch_build()
            self._model = MultiRxMerAnalysisResult(
                mac_address=mac,
                analysis_type=self.analysis_type,
                data=data,
            )

        except Exception as e:
            self.logger.error(f"Unable to create MultiRxMerAnalysisResult, reason: {e}")
            self._model = MultiRxMerAnalysisResult(
                mac_address=mac,
                analysis_type=self.analysis_type,
                data={},
                error=str(e),
            )

        return self._model

    def to_dict(self) -> dict[str, Any]:
        return self.to_model().model_dump()

    # -----------------------
    # Internals
    # -----------------------

    def _get_temporal_pnm_data(self) -> list[TemporalMapping]:
        self.logger.debug(
            f"Temporal PNM Data - Record Count: [{len(self._sorted_temporal_mapping)}]"
        )
        return self._sorted_temporal_mapping

    def _get_capture_times(
        self, channel_id: ChannelId, obj_type: type
    ) -> list[TimestampSec]:
        capture_times: list[TimestampSec] = []

        for capture_time, obj in self._get_temporal_pnm_data():
            chan_id: ChannelId = cast(ChannelId, obj.to_model().channel_id)

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

    # --------------------------------------------------------------------------
    #               Analyses (single MAC; return channel->model)
    # --------------------------------------------------------------------------
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
        self.logger.debug("Building MinAvgMax Signal Analysis")

        chan_series: dict[ChannelId, list[MagnitudeSeries]] = {}
        chan_freq: dict[ChannelId, FrequencySeriesHz] = {}
        mamap: MinAvgMaxMap = {}

        for _, obj in self._get_temporal_pnm_data():
            if not isinstance(obj, CmDsOfdmRxMer):
                self.logger.debug("Not a CmDsOfdmRxMer Object, skipping")
                continue

            model: CmDsOfdmRxMerModel = obj.to_model()

            if model.channel_id not in chan_series:
                chan_series[model.channel_id] = []

            chan_series[model.channel_id].append(model.values)
            chan_freq[model.channel_id] = self._build_frequencies(model)

        for cid, series in chan_series.items():
            self.logger.debug(f"Building MinAvgMaxAnalysisModel for Channel: {cid}")
            frequencies = self._build_frequencies(chan_freq.get(cid))

            try:
                mam = MinAvgMax(series, precision=2)
                mam_model = mam.to_model()

                mamap[cid] = MinAvgMaxAnalysisModel(
                    channel_id=cid,
                    frequency=frequencies,
                    min=mam_model.min,
                    avg=mam_model.avg,
                    max=mam_model.max,
                )

            except ValueError as e:
                self.logger.warning(
                    "MinAvgMax failed for channel %s: %s", str(cid), str(e)
                )
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
        self.logger.info("Building RxMER HeatMap Signal Analysis")

        # Store per-channel temporal data
        channel_data: dict[ChannelId, list[MagnitudeSeries]] = {}
        channel_freqs: dict[ChannelId, FrequencySeriesHz] = {}
        heatmap_map: HeatMapMap = {}

        # Aggregate values for each capture per channel
        for _, obj in self._get_temporal_pnm_data():
            if not isinstance(obj, CmDsOfdmRxMer):
                self.logger.debug(
                    "Skipping non-CmDsOfdmRxMer object: %s", type(obj).__name__
                )
                continue

            model: CmDsOfdmRxMerModel = obj.to_model()
            ch_id = cast(ChannelId, model.channel_id)

            if ch_id not in channel_data:
                channel_data[ch_id] = []

            channel_data[ch_id].append(model.values)
            channel_freqs[ch_id] = self._build_frequencies(model)

        # Build final models
        for ch_id, magnitudes in channel_data.items():
            self.logger.debug("Building ChannelHeatMapModel for Channel: %s", ch_id)

            timestamps: list[TimestampSec] = self._get_capture_times(
                ch_id, CmDsOfdmRxMer
            )
            frequencies: FrequencySeriesHz = channel_freqs.get(ch_id, [])

            heatmap_map[ch_id] = ChannelHeatMapModel(
                channel_id=ch_id,
                frequency=frequencies,
                timestamps=timestamps,
                values=magnitudes,
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

        rxmer_agg = DsRxMerAggregator()
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
            self.logger.info(f"RxMER Aggregator Count: {rxmer_agg.length()}")
            self.logger.info(
                f"Modulation Profile Aggregator Count: {mod_pro_agg.length()}"
            )
            self.logger.info(f"FEC Summary Aggregator Count: {fec_sum_agg.length()}")

        # Step 2: analyze per channel
        for ch_id in rxmer_agg.get_channel_ids():
            mam = rxmer_agg.get_min_avg_max(ch_id)
            shannon_model = ShannonSeries(mam.avg).to_model()
            frequencies = rxmer_agg.get_frequencies(ch_id)

            # Perform basic modulation profile analysis for this channel
            mod_analysis_map = mod_pro_agg.basic_analysis(ch_id)
            mod_analysis_list = mod_analysis_map.get(ch_id, [])
            if not mod_analysis_list:
                self.logger.warning(
                    "No modulation analysis results for channel %s", ch_id
                )
                continue

            capture_times = sorted(rxmer_agg.get_capture_times(ch_id))
            if not capture_times:
                self.logger.warning("No RxMER captures for channel %s", ch_id)
                continue

            start, stop = TimeStamp(capture_times[0]), TimeStamp(capture_times[-1])
            fec_summary = fec_sum_agg.get_summary_totals(ch_id, start, stop)

            profile_entries = self._build_profile_entries(
                mod_analysis_list=mod_analysis_list,
                mam=mam,
                start=start,
                fec_summary=fec_summary,
            )

            models[ch_id] = ChannelOfdmProfilePerf01Model(
                channel_id=ch_id,
                frequency=frequencies,
                avg_mer=mam.avg,
                mer_shannon_limits=cast(FloatSeries, shannon_model.snr_db_min),
                profiles=profile_entries,
            )

        return models

    def _build_profile_entries(
        self,
        mod_analysis_list: list[DsModulationProfileAnalysisModel],
        mam: MinAvgMax,
        start: TimeStamp,
        fec_summary: FecSummaryTotalsModel,
    ) -> list[ProfileEntryModel]:
        profile_entries: list[ProfileEntryModel] = []
        for mod_analysis in mod_analysis_list:
            capture_time = CaptureTime(getattr(mod_analysis, "capture_time", start))
            profile_entries.extend(
                self._build_profile_entries_for_analysis(
                    capture_time=capture_time,
                    profiles=mod_analysis.profiles,
                    mam=mam,
                    fec_summary=fec_summary,
                )
            )
        return profile_entries

    def _build_profile_entries_for_analysis(
        self,
        capture_time: CaptureTime,
        profiles: list[ProfileAnalysisEntryModel],
        mam: MinAvgMax,
        fec_summary: FecSummaryTotalsModel,
    ) -> list[ProfileEntryModel]:
        entries: list[ProfileEntryModel] = []
        for profile_entry in profiles:
            pid = profile_entry.profile_id
            shannon_min = profile_entry.carrier_values.shannon_min_mer
            capacity_delta = [
                float(a - b) for a, b in zip(mam.avg, shannon_min, strict=False)
            ]
            fec_entry = next(
                (p for p in fec_summary.summary if p.profile_id == pid), None
            )
            fec_payload = (
                fec_summary
                if fec_entry is None
                else FecSummaryTotalsModel(
                    start=fec_summary.start,
                    end=fec_summary.end,
                    channel_id=fec_summary.channel_id,
                    summary=[fec_entry],
                )
            )

            entries.append(
                ProfileEntryModel(
                    capture_time=capture_time,
                    profile_id=pid,
                    profile_min_mer=shannon_min,
                    capacity_delta=capacity_delta,
                    fec_summary=fec_payload,
                )
            )
        return entries

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
        tcms: list[TransactionCollectionModel] = tc.getTransactionCollectionModel()
        temporal_mapping: dict[
            CaptureTime, CmDsOfdmRxMer | CmDsOfdmFecSummary | CmDsOfdmModulationProfile
        ] = {}

        self.logger.info(f"TransactionCollectionModel Count: {len(tcms)}")

        # Groom data for general use due to various Analysis that is performed
        for count, tcm in enumerate(tcms):
            try:
                dorm = CmDsOfdmRxMer(tcm.data)
                capture_time: CaptureTime = (
                    dorm.getPnmHeaderModel().pnm_header.capture_time
                    or INVALID_CAPTURE_TIME
                )
                temporal_mapping[capture_time] = dorm
                model = dorm.to_model()
                self.register_models_for_json_archive_files(
                    model,
                    [str(model.channel_id), "CmDsOfdmRxMer"],
                    transaction_id=tcm.transaction_id,
                )
                continue

            except Exception as e:
                self.logger.debug(
                    f"PNM file {count} is not compatible with CmDsOfdmRxMer, skipping: {e}"
                )

            try:
                dofs = CmDsOfdmFecSummary(tcm.data)
                capture_time: CaptureTime = (
                    dofs.getPnmHeaderModel().pnm_header.capture_time
                    or INVALID_CAPTURE_TIME
                )
                temporal_mapping[capture_time] = dofs
                model = dofs.to_model()
                self.register_models_for_json_archive_files(
                    model,
                    [str(model.channel_id), "CmDsOfdmFecSummary"],
                    transaction_id=tcm.transaction_id,
                )
                continue

            except Exception as e:
                self.logger.debug(
                    f"PNM file {count} is not compatible with CmDsOfdmFecSummary, skipping: {e}"
                )

            try:
                domp = CmDsOfdmModulationProfile(tcm.data)
                capture_time: CaptureTime = (
                    domp.getPnmHeaderModel().pnm_header.capture_time
                    or INVALID_CAPTURE_TIME
                )
                temporal_mapping[capture_time] = domp
                model = domp.to_model()
                self.register_models_for_json_archive_files(
                    model,
                    [str(model.channel_id), "CmDsOfdmModulationProfile"],
                    transaction_id=tcm.transaction_id,
                )
                continue

            except Exception as e:
                self.logger.debug(
                    f"PNM file {count} is not compatible with CmDsOfdmModulationProfile, skipping: {e}"
                )

        # Create a sorted list of tuples based on capture_time (ascending)
        self._sorted_temporal_mapping = sorted(
            temporal_mapping.items(), key=lambda x: x[0]
        )

        self.logger.debug(
            f"Temporal mapping size={len(temporal_mapping)}, sorted entries={len(self._sorted_temporal_mapping)}"
        )

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
            data = cast(MinAvgMaxMap, model.data)

            for ch_id, ch_model in data.items():
                csv_mgr: CSVManager = self.csv_manager_factory()

                # Convert frequency (Hz) → kHz for readability and to match labeling.
                freq_hz = ch_model.frequency
                freq_khz = [f / 1_000.0 for f in freq_hz]

                csv_mgr.set_header(["channel_id", "frequency_khz", "min", "avg", "max"])

                for idx, f_khz in enumerate(freq_khz):
                    # Defensive indexing (lists should match by construction)
                    mn = ch_model.min[idx] if idx < len(ch_model.min) else None
                    av = ch_model.avg[idx] if idx < len(ch_model.avg) else None
                    mx = ch_model.max[idx] if idx < len(ch_model.max) else None
                    csv_mgr.insert_row([ch_id, f_khz, mn, av, mx])

                csv_fname = self.create_csv_fname(
                    tags=["rxmer_min_avg_max", f"{ch_id}"]
                )
                csv_mgr.set_path_fname(csv_fname)

                out.append(csv_mgr)

        elif self.analysis_type == MultiRxMerAnalysisType.OFDM_PROFILE_PERFORMANCE_1:
            data = cast(OfdmProfilePerf01Map, model.data)

            for ch_id, ch_model in data.items():
                ch_model = cast(ChannelOfdmProfilePerf01Model, ch_model)

                for profile_model in ch_model.profiles:
                    csv_mgr: CSVManager = self.csv_manager_factory()
                    header = [
                        "ProfileID",
                        "Frequency(Hz)",
                        "AvgMER(dB)",
                        "ProfileMin(dB)",
                        "CapacityDelta(Avg vs. ProfileMin)",
                        "FECTotal",
                        "FECCorrected",
                        "FECUncorrectable",
                    ]
                    csv_mgr.set_header(header)

                    pid = profile_model.profile_id
                    fec_e = (
                        profile_model.fec_summary.summary[0]
                        if profile_model.fec_summary.summary
                        else None
                    )
                    total = fec_e.summary.total_codewords if fec_e else 0
                    corr = fec_e.summary.corrected if fec_e else 0
                    uncor = fec_e.summary.uncorrectable if fec_e else 0

                    self._write_profile_perf_rows(
                        csv_mgr=csv_mgr,
                        profile_id=pid,
                        total=total,
                        corr=corr,
                        uncor=uncor,
                        frequencies=ch_model.frequency,
                        avg_mer=ch_model.avg_mer,
                        profile_min_mer=profile_model.profile_min_mer,
                        capacity_delta=profile_model.capacity_delta,
                    )

                    csv_fname = self.create_csv_fname(
                        tags=["ofdm_profile_perf_1", f"ch{ch_id}", f"pid{pid}"]
                    )
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
                for ts, mag_series in zip(
                    ch_model.timestamps, ch_model.values, strict=False
                ):
                    csv_mgr.insert_row([ts] + mag_series)

                # Assign CSV filename
                csv_fname = self.create_csv_fname(
                    tags=["rxmer_ofdm_heat_map", f"{ch_id}"]
                )
                csv_mgr.set_path_fname(csv_fname)

                out.append(csv_mgr)

        return out

    def _write_profile_perf_rows(
        self,
        csv_mgr: CSVManager,
        profile_id: ProfileId,
        total: int,
        corr: int,
        uncor: int,
        frequencies: FrequencySeriesHz,
        avg_mer: FloatSeries,
        profile_min_mer: FloatSeries,
        capacity_delta: FloatSeries,
    ) -> None:
        for freq, avg_value, prof_lim, delta in zip(
            frequencies,
            avg_mer,
            profile_min_mer,
            capacity_delta,
            strict=False,
        ):
            csv_mgr.insert_row(
                [profile_id, freq, avg_value, prof_lim, delta, total, corr, uncor]
            )

    def create_matplot(self, **kwargs: object) -> list[MatplotManager]:
        """
        Build MatPlot PNG outputs for supported analysis types.
        Currently implemented for MIN_AVG_MAX only.
        """
        self.logger.debug("Processing Multi-RxMER Analysis MatPlot Report")
        out: list[MatplotManager] = []
        model = self.to_model()

        if self.analysis_type == MultiRxMerAnalysisType.MIN_AVG_MAX:
            data1 = cast(MinAvgMaxMap, model.data)

            for channel_id, ch_model in data1.items():
                freq_hz = cast(ArrayLike, ch_model.frequency)
                freq_khz = cast(ArrayLike, freq_hz)

                mn = cast(ArrayLike, ch_model.min)
                av = cast(ArrayLike, ch_model.avg)
                mx = cast(ArrayLike, ch_model.max)

                cfg = PlotConfig(
                    title=f"Min-Avg-Max RxMER · Channel: {channel_id}",
                    x=cast(ArrayLike, freq_khz),
                    y_multi=[mn, av, mx],
                    y_multi_label=["Min", "Avg", "Max"],
                    x_tick_mode="unit",
                    x_unit_from="hz",
                    x_unit_out="mhz",
                    x_tick_decimals=0,
                    xlabel_base="Frequency",
                    ylabel="dB",
                    grid=True,
                    legend=True,
                    transparent=False,
                    line_colors=[
                        "#FF5733",
                        "#3357FF",
                        "#33FF57",
                    ],
                    theme="dark",
                )

                multi = self.create_png_fname(
                    tags=[str(channel_id), "rxmer_min_avg_max"]
                )
                self.logger.debug(
                    "Creating MatPlot: %s for channel: %s", multi, channel_id
                )

                mat_mgr = MatplotManager(default_cfg=cfg)
                mat_mgr.plot_multi_line(filename=multi)

                out.append(mat_mgr)

        elif self.analysis_type == MultiRxMerAnalysisType.RXMER_HEAT_MAP:
            data2 = cast(HeatMapMap, model.data)

            for ch_id, ch_model in data2.items():
                ch_model = cast(ChannelHeatMapModel, ch_model)

                Z = np.asarray(ch_model.values, dtype=float)
                if Z.size == 0:
                    self.logger.warning(
                        "RXMER_HEAT_MAP: empty matrix for channel %s; skipping.", ch_id
                    )
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
                    title=f"HeatMap RxMER · Channel: {ch_id}",
                    x=x_hz,
                    x_tick_mode="unit",
                    x_unit_from="hz",
                    x_unit_out="mhz",
                    x_tick_decimals=0,
                    xlabel_base="Frequency",
                    ylabel="Capture Index",
                    zlabel="MER (dB)",
                    grid=False,
                    legend=False,
                    transparent=False,
                    theme="dark",
                )

                png_name = self.create_png_fname(tags=[str(ch_id), "rxmer_heat_map"])

                mat_mgr = MatplotManager(default_cfg=cfg)
                mat_mgr.heatmap2d(
                    Z.tolist(),
                    png_name,
                    x=x_hz,
                    y=y_ix,
                    add_colorbar=True,
                    vmin=vmin,
                    vmax=vmax,
                )

                out.append(mat_mgr)

        elif self.analysis_type == MultiRxMerAnalysisType.OFDM_PROFILE_PERFORMANCE_1:
            data3 = cast(OfdmProfilePerf01Map, model.data)

            for ch_id, ch_model in data3.items():
                ch_model = cast(ChannelOfdmProfilePerf01Model, ch_model)

                if not ch_model.profiles:
                    self.logger.warning(
                        "OFDM_PROFILE_PERFORMANCE_1: no profiles for channel %s; skipping.",
                        ch_id,
                    )
                    continue

                freq_hz = cast(ArrayLike, ch_model.frequency)
                avg_mer = cast(ArrayLike, ch_model.avg_mer)

                for profile_model in ch_model.profiles:
                    pid = profile_model.profile_id
                    pmin = cast(ArrayLike, profile_model.profile_min_mer)
                    fec_e = (
                        profile_model.fec_summary.summary[0]
                        if profile_model.fec_summary.summary
                        else None
                    )
                    total = getattr(fec_e.summary, "total_codewords", 0) if fec_e else 0
                    corr = getattr(fec_e.summary, "corrected", 0) if fec_e else 0
                    uncor = getattr(fec_e.summary, "uncorrectable", 0) if fec_e else 0
                    fec_l = f"FEC(Total={total}, Corr={corr}, Uncorr={uncor})"

                    cfg = PlotConfig(
                        title=f"OFDM PROFILE PERFORMANCE 1 · Channel: {ch_id} · Profile: {pid}",
                        x=freq_hz,
                        y_multi=[avg_mer, pmin],
                        y_multi_label=[f"AvgMER (dB) {fec_l}", "ProfileMin (dB)"],
                        x_tick_mode="unit",
                        x_unit_from="hz",
                        x_unit_out="mhz",
                        x_tick_decimals=0,
                        xlabel_base="Frequency",
                        ylabel="Average MER (dB)",
                        grid=True,
                        legend=True,
                        transparent=False,
                        line_colors=["#3357FF", "#33FF57"],
                        theme="dark",
                    )

                    fname = self.create_png_fname(
                        tags=[f"{ch_id}", f"profile_{pid}", "ofdm_profile_perf_1"]
                    )
                    plotmgr = MatplotManager(default_cfg=cfg)
                    plotmgr.plot_multi_line(filename=fname)
                    out.append(plotmgr)

        return out

    """Helpers"""

    def _parse_rxmer_heatmap_series(self) -> None:
        pass

    def _build_frequencies(
        self, model: CmDsOfdmRxMerModel | FrequencySeriesHz | None
    ) -> FrequencySeriesHz:
        """
        Build absolute subcarrier center frequencies (Hz) for the RxMER series.
        """
        if isinstance(model, list):
            return model
        if model is None:
            return []

        active_idx = model.first_active_subcarrier_index
        spacing = model.subcarrier_spacing
        freq_zero = model.subcarrier_zero_frequency
        num_idx = len(model.values)

        start_freq = freq_zero + (spacing * active_idx)

        freqs: FrequencySeriesHz = cast(
            FrequencySeriesHz, [start_freq + (i * spacing) for i in range(num_idx)]
        )
        return freqs

# FILE: src/pypnm/examples/settings/system.json
{
    "FastApiRequestDefault": {
        "mac_address": "aa:bb:cc:dd:ee:ff",
        "ip_address": "192.168.0.1"
    },
    "SNMP": {
        "timeout": 2,
        "version": {
            "2c": {
                "enable": true,
                "retries": 3,
                "read_community": "public",
                "write_community": "private"
            },
            "3": {
                "enable": false,
                "retries": 3,
                "username": "user",
                "securityLevel": "authPriv",
                "authProtocol": "SHA",
                "authPassword": "pass",
                "privProtocol": "AES",
                "privPassword": "privpass"
            }
        }
    },
    "PnmBulkDataTransfer": {
        "method": "tftp",
        "tftp": {
            "ip_v4": "192.168.0.10",
            "ip_v6": "::1",
            "remote_dir": ""
        },
        "http": {
            "base_url": "http://files.example.com/",
            "port": 80
        },
        "https": {
            "base_url": "https://files.example.com/",
            "port": 443
        }
    },
    "PnmFileRetrieval": {
        "pnm_dir": ".data/pnm",
        "csv_dir": ".data/csv",
        "json_dir": ".data/json",
        "xlsx_dir": ".data/xlsx",
        "png_dir": ".data/png",
        "archive_dir": ".data/archive",
        "msg_rsp_dir": ".data/msg_rsp",
        "capture_group_db": ".data/db/capture_group.json",
        "session_group_db": ".data/db/session_group.json",
        "operation_db": ".data/db/operation_capture.json",
        "retries": 5,
        "retrieval_method": {
            "method": "local",
            "methods": {
                "local": {
                    "src_dir": "/srv/tftp"
                },
                "tftp": {
                    "host": "localhost",
                    "port": 69,
                    "timeout": 5,
                    "remote_dir": ""
                },
                "ftp": {
                    "host": "localhost",
                    "port": 21,
                    "tls": false,
                    "timeout": 5,
                    "user": "test",
                    "password_enc": "",
                    "remote_dir": "/srv/tftp"
                },
                "sftp": {
                    "host": "localhost",
                    "port": 22,
                    "user": "test",
                    "password_enc": "",
                    "remote_dir": "/srv/tftp"
                },
                "http": {
                    "base_url": "http://STUB/",
                    "port": 80
                },
                "https": {
                    "base_url": "https://STUB/",
                    "port": 443
                }
            }
        }
    },
    "Database": {
        "backend": "sqlite",
        "sqlite": {
            "path": ".data/db/pypnm.sqlite3"
        },
        "postgres": {
            "dsn": ""
        }
    },
    "logging": {
        "log_level": "INFO",
        "log_dir": "logs",
        "log_filename": "pypnm.log"
    },
    "TestMode": {
        "global": {
            "mode": {
                "enable": true
            }
        },
        "class_name": {
            "DsScQamChannelSpectrumAnalyzer": {
                "mode": {
                    "enable": true
                }
            }
        }
    }
}

# FILE: docs/api/fast-api/multi/capture-operation.md
# Multi‑Capture Operation Overview

When you initiate a **multi-capture** session (e.g., Multi‑RxMER or Multi‑DS‑Channel‑Estimation), PyPNM maintains a DB-backed tracking system and stages resulting PNM binaries for downstream workflows.

**Directory Layout**:

```text
.data/
├── db/
│   ├── pypnm.sqlite3               # SQLite DB (when backend=sqlite)
├── operations/
│   └── <operation_id>.json         # Status + progress for async operations
├── json/
│   └── <*.json>                    # JSON exports (metadata tracked in DB)
└── pnm/
    └── <.bin files>                # Raw PNM captures retrieved via TFTP
```

Capture metadata is stored in the DB (`transaction_records`, `capture_groups`, `capture_group_transactions`, `operation_captures`). Postgres deployments use the configured external DSN instead of a local SQLite file.

## 1. Operation Status Registry (`operations/<operation_id>.json`)

Each operation has its own status file to support `status`, `result`, and `cancel` endpoints.

**Example**:

```json
{
  "operation_id": "f6afb2d7df2c4a5c",
  "state": "running",
  "created_ts": 1730000000,
  "updated_ts": 1730000010,
  "progress_current": 1,
  "progress_total": 6,
  "message": "Operation running",
  "error": null,
  "artifact_paths": [
    "ds_ofdm_rxmer_per_subcar_aa:bb:cc:dd:ee:ff_160_1730000000.bin"
  ]
}
```

## 2. Operation Mapping (DB: `operation_captures`)

Operation-to-capture-group links are stored in the `operation_captures` table.

Fields:

* **operation_id**: Operation identifier (primary key).
* **capture_group_id**: Associated capture group (foreign key).
* **created_epoch**: Unix timestamp when the operation started.

Legacy JSON key `capture_group` is accepted only during offline migration; runtime resolution uses the DB.

## 3. Capture Group Registry (DB: `capture_groups` + `capture_group_transactions`)

Capture groups live in `capture_groups`, with ordered membership in `capture_group_transactions`.

Fields:

* **capture_group_id**: Capture group identifier (primary key).
* **created_epoch**: Unix timestamp when the group was created.
* **transaction_id**: Linked transaction identifier (foreign key).
* **position**: Ordering index for deterministic listing.

## 4. Transaction Records (DB: `transaction_records` + `transaction_artifacts`)

Transaction metadata is stored in `transaction_records`, while on-disk files are resolved via `transaction_artifacts` and `file_artifacts`.

**Example (logical record shape)**:

```json
{
  "2ee6138bbc1b3c3d": {
      "timestamp": 1748280294,
      "mac_address": "aa:bb:cc:dd:ee:ff",
      "pnm_test_type": "DS_OFDM_RXMER_PER_SUBCAR",
      "filename": "ds_ofdm_rxmer_per_subcar_aa:bb:cc:dd:ee:ff_34_1748280294.bin",
      "device_details": {
          "system_description": {
              "HW_REV": "1.0",
              "VENDOR": "LANCity",
              "BOOTR": "NONE",
              "SW_REV": "1.0.0",
              "MODEL": "LCPET-3"
          }
      }
  }
}
```

* **Key**: `transaction_id` (e.g., `2ee6138bbc1b3c3d`).
* **timestamp**: Unix epoch when the file was staged.
* **mac\_address**: Sanitized MAC of the target modem.
* **pnm\_test\_type**: Identifier of the PNM capture type.
* **filename**: Name of the `.bin` file in `.data/pnm/` (recorded for reference).
* **device\_details.system\_description**: Snapshot of modem metadata at capture time.

Transaction IDs must be non-empty. Blank or whitespace-only IDs are dropped with a warning and are never persisted.
The `mac_address` field is intentionally stored in `transaction_records` (it is not treated as redundant in the SQL-backed schema direction).

## 5. Operation Workflow Endpoints (POST)

Generic workflow endpoints provide a consistent interface for operation status, result, and cancellation.
These endpoints rely on an in-memory OperationRegistry for live stop/status hooks and a filesystem-backed
OperationStore for authoritative state. Cancel requests are best-effort in-process; the OperationStore
status remains authoritative across restarts.

**Request** `POST /advance/operation/start`

```json
{
  "progress_total": 6,
  "message": "Operation created"
}
```

**Response** (start includes legacy + canonical status)

```json
{
  "status": "success",
  "service_status": 0,
  "message": null,
  "operation": {
    "operation_id": "f6afb2d7df2c4a5c",
    "state": "running",
    "created_ts": 1730000000,
    "updated_ts": 1730000000,
    "progress_current": 0,
    "progress_total": 6,
    "message": "Operation created",
    "error": null,
    "artifact_paths": []
  },
  "time_remaining": 0
}
```

**Request** `POST /advance/operation/status`

```json
{
  "operation_id": "f6afb2d7df2c4a5c"
}
```

**Response** (registry status includes legacy + canonical status)

```json
{
  "status": "success",
  "service_status": 0,
  "message": null,
  "operation": {
    "operation_id": "f6afb2d7df2c4a5c",
    "state": "running",
    "created_ts": 1730000000,
    "updated_ts": 1730000010,
    "progress_current": 1,
    "progress_total": 6,
    "message": "Operation running",
    "error": null,
    "artifact_paths": []
  },
  "time_remaining": 0
}
```

**Request** `POST /advance/operation/result`

```json
{
  "operation_id": "f6afb2d7df2c4a5c"
}
```

**Response** (registry result includes legacy + canonical status)

```json
{
  "status": "success",
  "service_status": 0,
  "message": null,
  "operation": {
    "operation_id": "f6afb2d7df2c4a5c",
    "state": "completed",
    "created_ts": 1730000000,
    "updated_ts": 1730000030,
    "progress_current": 6,
    "progress_total": 6,
    "message": "Operation completed",
    "error": null,
    "artifact_paths": []
  }
}
```

**Request** `POST /advance/operation/cancel`

```json
{
  "operation_id": "f6afb2d7df2c4a5c"
}
```

**Response** (registry cancel includes legacy + canonical status)

```json
{
  "status": "success",
  "service_status": 0,
  "message": null,
  "operation": {
    "operation_id": "f6afb2d7df2c4a5c",
    "state": "canceled",
    "created_ts": 1730000000,
    "updated_ts": 1730000020,
    "progress_current": 2,
    "progress_total": 6,
    "message": "Operation canceled",
    "error": null,
    "artifact_paths": []
  }
}
```

## 6. Multi-RxMER Workflow Endpoints (POST)

**Request** `POST /advance/ds/ofdm/rxmer/multi/start`

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "ip_address": "192.168.0.100",
  "duration": 60,
  "interval": 5
}
```

**Request** `POST /advance/ds/ofdm/rxmer/multi/result`

```json
{
  "operation_id": "f6afb2d7df2c4a5c"
}
```

## 7. Multi-ChannelEstimation Workflow Endpoints (POST)

**Request** `POST /advance/multiChannelEstimation/start`

```json
{
  "cable_modem": {
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "ip_address": "192.168.0.100"
  },
  "capture": {
    "parameters": {
      "measurement_duration": 60,
      "sample_interval": 5
    }
  }
}
```

Note: The legacy `measure` payload is currently ignored and will be removed in a future release.

**Request** `POST /advance/multiChannelEstimation/result`

```json
{
  "operation_id": "f6afb2d7df2c4a5c"
}
```

Result behavior:
- Missing transaction records are skipped with warnings.
- If no transaction records resolve, the endpoint returns HTTP 404.

Start response fields:
- capture_group_id is canonical.
- group_id is legacy and will be deprecated.
- status is ServiceStatusCode.SUCCESS when the operation starts; operation_state indicates RUNNING.
Status semantics:
- Top-level status is always a ServiceStatusCode value.
- operation.state carries running/stopped/completed semantics.
- Registry endpoints return legacy status string plus service_status as the canonical ServiceStatusCode.

## Workflow Summary

1. **Start Multi‑Capture**: System generates a new `operation_id` linked to a new `capture_group_id`.
2. **Periodic Triggers**: SNMP instructs the modem to TFTP-upload the PNM blob.
3. **File Staging**: PyPNM copies each `.bin` into `.data/pnm/` and inserts DB metadata (transaction record + artifact linkage).
4. **Database Updates**: `operation_captures`, `capture_groups`, and `capture_group_transactions` reflect the capture state.
5. **Completion**: After the capture ends, the DB tables fully describe what was captured, when, and for which operation/group.

> Downstream tools should query the DB-backed APIs (for example, `searchFiles` or `getMacAddresses`) to discover new PNM files.

# FILE: docs/api/fast-api/pypnm/db/data-base.md
# PyPNM Database

Overview of how PyPNM stores, organizes, and links measurement data for traceability and REST access.

## Table Of Contents

- [Data Repository Layout](#data-repository-layout)
- [Directory Reference](#directory-reference)
- [Operation Capture Linking](#operation-capture-linking)
- [Capture Group Registry](#capture-group-registry)
- [Transaction Records](#transaction-records)
- [JSON Export Artifacts](#json-export-artifacts)
- [Summary Of Relationships](#summary-of-relationships)

## Data Repository Layout

The `.data` tree is the on-disk workspace for all PyPNM captures, intermediate artifacts, plots, and ledgers.

```text
.data
├── archive
│   └── aabbccddeeff_lcpet3_1760940313.zip
├── csv
│   ├── aabbccddeeff_lcpet3_1760940313_ofdm_profile_perf_1_ch33_pid0.csv
│   ├── aabbccddeeff_lcpet3_1760940313_ofdm_profile_perf_1_ch33_pid1.csv
│   ├── aabbccddeeff_lcpet3_1760940313_ofdm_profile_perf_1_ch33_pid3.csv
│   ├── aabbccddeeff_lcpet3_1760940313_ofdm_profile_perf_1_ch34_pid0.csv
│   ├── aabbccddeeff_lcpet3_1760940313_ofdm_profile_perf_1_ch34_pid1.csv
│   └── aabbccddeeff_lcpet3_1760940313_ofdm_profile_perf_1_ch34_pid3.csv
├── db
│   ├── pypnm.sqlite3
├── json
│   ├── aabbccddeeff_example_run_1760940313_33_cmdsofdmrxmer_1760940313000000000.json
│   └── aabbccddeeff_example_run_1760940313_34_cmdsofdmrxmer_1760940313999999999.json
├── msg_rsp
├── png
│   ├── aabbccddeeff_lcpet3_1760940313_33_profile_0_ofdm_profile_perf_1.png
│   ├── aabbccddeeff_lcpet3_1760940313_33_profile_1_ofdm_profile_perf_1.png
│   ├── aabbccddeeff_lcpet3_1760940313_33_profile_3_ofdm_profile_perf_1.png
│   ├── aabbccddeeff_lcpet3_1760940313_34_profile_0_ofdm_profile_perf_1.png
│   ├── aabbccddeeff_lcpet3_1760940313_34_profile_1_ofdm_profile_perf_1.png
│   └── aabbccddeeff_lcpet3_1760940313_34_profile_3_ofdm_profile_perf_1.png
├── pnm
│   ├── ds_ofdm_codeword_error_rate_aabbccddeeff_33_1760940254.bin
│   ├── ds_ofdm_codeword_error_rate_aabbccddeeff_33_1760940285.bin
│   ├── ds_ofdm_codeword_error_rate_aabbccddeeff_34_1760940287.bin
│   ├── ds_ofdm_modulation_profile_aabbccddeeff_33_1760940269.bin
│   ├── ds_ofdm_modulation_profile_aabbccddeeff_34_1760940270.bin
│   ├── ds_ofdm_rxmer_per_subcar_aabbccddeeff_33_1760940252.bin
│   └── ds_ofdm_rxmer_per_subcar_aabbccddeeff_33_1760940260.bin
└── xlsx
```

## Directory Reference

Each subdirectory has a well-defined role. The table below summarizes typical contents and how they are used by PyPNM.

| Directory  | Typical Contents                                                | Example Filenames                                                     | Purpose                                                                                           |
| ---------- | --------------------------------------------------------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `archive/` | ZIP archives combining multi-file outputs (CSV, PNG, summaries) | `aabbccddeeff_lcpet3_1760940313.zip`                                  | One-stop bundle for download/sharing and offline review.                                          |
| `csv/`     | Per-measurement CSV exports                                     | `aabbccddeeff_lcpet3_1760940313_ofdm_profile_perf_1_ch34_pid1.csv`    | Tabular data for analysis, BI tools, and spreadsheets.                                            |
| `db/`      | SQLite DB (or external Postgres via DSN)                        | `pypnm.sqlite3`                                                       | DB-backed metadata: transactions, capture groups, operation mappings, and artifacts.             |
| `json/`    | Raw/processed JSON outputs (when enabled)                       | `aabbccddeeff_example_run_1760940313_33_cmdsofdmrxmer_*.json`         | Structured artifacts for programmatic consumption; metadata is tracked in the DB artifact tables. |
| `msg_rsp/` | Request/response message snapshots (optional)                   | —                                                                     | Diagnostics and audit of REST or SNMP exchanges.                                                  |
| `png/`     | Visualization images per capture/profile/channel                | `aabbccddeeff_lcpet3_1760940313_34_profile_1_ofdm_profile_perf_1.png` | Quick-look plots for reports and UIs.                                                             |
| `pnm/`     | Binary PNM files pulled from devices or uploads                 | `ds_ofdm_rxmer_per_subcar_aabbccddeeff_33_1760940252.bin`             | Source files used by analyses; include the embedded `pnm_header`.                                |
| `xlsx/`    | Excel workbooks                                                 | —                                                                     | Multi-sheet summaries and cross-linked reports.                                                   |

## Operation Capture Linking

Operation-to-capture-group mapping is stored in the `operation_captures` DB table.
An operation represents a higher-level request that may include different PNM test types (RxMER, FEC Summary, Modulation Profile).

### Field Overview

| Field              | Type    | Description                                   |
| ------------------ | ------- | --------------------------------------------- |
| `operation_id`     | string  | Operation identifier (primary key).           |
| `capture_group_id` | string  | Unique ID of the broader capture session.     |
| `created_epoch`    | integer | Operation creation timestamp (epoch seconds). |

Common uses:

- Retrieve a complete session by operation ID via REST.
- Persist session context for deferred or repeat analysis.

## Capture Group Registry

Capture groups are stored in `capture_groups`, with ordered membership in `capture_group_transactions`.
Capture groups can span multiple test types or measurements and underpin multi-file workflows (Excel generation, correlation, etc.).

### Field Overview

| Field              | Type    | Description                                                               |
| ------------------ | ------- | ------------------------------------------------------------------------- |
| `capture_group_id` | string  | Group identifier (primary key).                                           |
| `created_epoch`    | integer | Group creation timestamp (epoch seconds; often the first operation time). |
| `transaction_id`   | string  | Transaction ID linked to the group.                                       |
| `position`         | integer | Ordering index for deterministic listing.                                 |

## Transaction Records

Transactions are stored in the `transaction_records` table, with file resolution via `transaction_artifacts`.
Each entry represents a single file **transaction**, whether:

- Pulled automatically from a cable modem (for example, via TFTP), or
- Manually uploaded by a user via the UI or API.

### Structure

Each transaction is indexed by a unique ID (16-char digest) and stored in the DB:

```json
"1e171e1f8ef5377a": {
  "timestamp": 1751950064,
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "pnm_test_type": "DS_OFDM_RXMER_PER_SUBCAR",
  "filename": "ds_ofdm_rxmer_per_subcar_aabbccddeeff_197_1751950064.bin",
  "device_details": {
    "sys_descr": {
      "HW_REV": "1.0",
      "VENDOR": "LANCity",
      "BOOTR": "NONE",
      "SW_REV": "1.0.0",
      "MODEL": "LCPET-3"
    }
  }
}
```

### Field Overview

| Field            | Type    | Description                                                                 |
| ---------------- | ------- | --------------------------------------------------------------------------- |
| `timestamp`      | integer | Unix epoch seconds when the file was received or uploaded.                  |
| `mac_address`    | string  | Cable modem MAC address.                                                    |
| `pnm_test_type`  | string  | Test type that produced the file (for example, `DS_OFDM_RXMER_PER_SUBCAR`). |
| `filename`       | string  | Saved binary filename in `.data/pnm/`.                                      |
| `device_details` | object  | Parsed device metadata from SNMP when available (`sys_descr` fields shown). |

On-disk file resolution uses `transaction_artifacts` with role preference (`pnm_raw`, then `pnm_uploaded_raw`) and joins through `file_artifacts` and `artifact_stores`.

## JSON Export Artifacts

JSON exports are written under `.data/json/` and tracked in the DB-backed artifact tables (`artifact_stores`, `file_artifacts`, `transaction_artifacts`) when linked to a transaction.
It lets PyPNM track processed JSON outputs separately from raw PNM files.

Each entry is keyed by a transaction ID and points to a JSON file created from a particular capture session.

```json
"df448ebff10d2dd203011b53": {
  "timestamp": 1760940313,
  "filename": "aabbccddeeff_example_run_1760940313_34_cmdsofdmrxmer_1760940313999999999.json",
  "byte_size": 585286,
  "sha256": "98509bf7b8dcbb01638953207e6e6691520daee16212f5ddf96bee41b7511779"
},
"94bab9dc131f173f6bdc4fe5": {
  "timestamp": 1760940313,
  "filename": "aabbccddeeff_example_run_1760940313_33_cmdsofdmrxmer_1760940313000000000.json",
  "byte_size": 586564,
  "sha256": "ed1fdc3f816e6037c1e10f4f66c4489a4ad6bc5421d93c970d7812fa456a7315"
}
```

### Field Overview

| Field       | Type    | Description                                                              |
| ---------- | ------- | ------------------------------------------------------------------------ |
| `timestamp` | integer | Unix epoch seconds when the JSON capture file was written.              |
| `filename`  | string  | JSON filename stored under `.data/json/`.                               |
| `byte_size` | integer | Size of the JSON file in bytes, used for quick sanity checks.           |
| `sha256`    | string  | SHA-256 hash of the JSON file contents for integrity and dedup checks.  |

The filename pattern generally encodes:

- Cable modem MAC address (for example, `aa:bb:cc:dd:ee:ff` as `aabbccddeeff`)
- A run label or hostname (for example, `example_run`)
- A base capture timestamp
- Channel or profile identifier (for example, `33` or `34`)
- The test name (for example, `cmdsofdmrxmer`)
- A high-resolution timestamp or unique suffix

This allows you to map JSON artifacts back to their originating modem, run, and test context.

## Summary Of Relationships

- **Operation Capture → Capture Group → Transaction (PNM binary)**  
  An **operation** references a single **capture group**, which aggregates many **transactions** in `transaction_records`. Each transaction resolves to a PNM file via `transaction_artifacts`.

- **Transactions (PNM) → JSON Captures**  
  JSON exports derived from those PNM files are written to `.data/json/` and tracked in the DB artifact tables with size and checksum metadata.

- **Reporting And REST Access**  
  Use the **operation ID** for API recall, the **capture group** for report generation and correlation across tests, and the **transaction IDs** (PNM and JSON) for raw file or artifact lookup.

# FILE: docs/issues/support-bundle.md
# PyPNM - Support Bundle Builder

Create Sanitized Support Bundles For PNM File And Capture Issues.

## Table Of Contents

- [Overview](#overview)
- [What Gets Collected](#what-gets-collected)
- [Sanitization Rules](#sanitization-rules)
- [Command-Line Usage](#command-line-usage)
- [Examples](#examples)
  - [1. Build Bundle From A Single Transaction ID](#1-build-bundle-from-a-single-transaction-id)
  - [2. Build Bundle From An Operation ID (Multi-Capture)](#2-build-bundle-from-an-operation-id-multi-capture)
  - [3. Build Bundle From A MAC Address](#3-build-bundle-from-a-mac-address)
  - [4. Build Bundle With No Sanitization](#4-build-bundle-with-no-sanitization)
- [Bundle Layout](#bundle-layout)
- [Submitting A Bundle](#submitting-a-bundle)

## Overview

The **Support Bundle Builder** is an offline helper script that creates a
sanitized archive (.zip) containing only the PNM files and metadata required to
debug a specific PyPNM issue.

Instead of sharing your full `.data/` tree, you can run this tool locally and
send a compact bundle that contains:

- Only the captures relevant to your issue (by Transaction ID, Operation ID, or MAC).
- Sanitized MAC addresses (rewritten to `aa:bb:cc:dd:ee:ff` by default).
- Sanitized `system_description` fields using the canonical demo descriptor:

```json
{
  "HW_REV":  "1.0",
  "VENDOR":  "LANCity",
  "BOOTR":   "NONE",
  "SW_REV":  "1.0.0",
  "MODEL":   "LCPET-3"
}
```

The original data stays on your system. The bundle is safe to attach to a
support ticket or email when requesting help.

## What Gets Collected

Given a set of input selectors (Transaction ID, Operation ID, or MAC address),
the tool:

1. Uses the configured DB backend (SQLite or Postgres) to discover the relevant transactions
   via `transaction_records`, `capture_groups`, and `operation_captures`.

2. Resolves each transaction into:

   - The capture file under `.data/pnm`
   - The corresponding transaction record from the transaction DB

3. Builds a temporary **support dataset** under a working directory using the
   same structure as `.data`:

```text
.data/
  pnm/
    <capture files>
  db/
    pypnm.sqlite3
```

4. Sanitizes the dataset (MAC address, filename MAC fragments, and
   `system_description`) so it can be safely shared.

5. Packs the dataset into a ZIP file using the `ArchiveManager.zip_files`
   helper. Unless you pass an absolute `--output-zip` path, the ZIP is created
   under an `issues/` directory in the current working tree.

## Sanitization Rules

By default, the support bundle is sanitized to remove customer-specific identity
details while preserving structure and relative relationships.

### MAC Address

- All MAC addresses in:
  - Transaction JSON records (`mac_address` field)
  - Filenames that include MAC fragments
  - Any capture files passed through `pnm-mac-updater.py`
- Are rewritten to the generic MAC address:

```text
aa:bb:cc:dd:ee:ff
```

This preserves per-modem grouping while removing the original hardware identity.

### System Descriptor

For each transaction record that includes `device_details.system_description`,
the script overwrites the contents with the canonical demo descriptor:

```json
{
  "HW_REV":  "1.0",
  "VENDOR":  "LANCity",
  "BOOTR":   "NONE",
  "SW_REV":  "1.0.0",
  "MODEL":   "LCPET-3"
}
```

This keeps the field present (so parsing and models behave normally) but removes
real vendor and model information.

### Opt-Out

Optional flags allow you to keep real MAC addresses and/or system descriptions
when absolutely necessary for debugging. See the [Examples](#examples) section
for usage notes.

## Command-Line Usage

The support bundle script is intended to live under `tools/`:

```text
tools/build/support_bundle_builder.py
```

Basic invocation:

```bash
./tools/build/support_bundle_builder.py [OPTIONS]
```

Core selectors (you must provide at least one):

- `--transaction-id TRANSACTION_ID`  
  Build a bundle for a single transaction.

- `--operation-id OPERATION_ID`  
  Build a bundle containing all transactions associated with a multi-capture
  operation.

- `--mac-address MAC_ADDRESS`  
  Build a bundle containing all transactions and captures for a cable modem
  MAC address.

Sanitization and behavior flags:

- `--keep-original-mac`  
  Keep the original MAC address in JSON and filenames, and skip binary MAC
  rewriting. By default, all MAC addresses are sanitized to `aa:bb:cc:dd:ee:ff`.

- `--keep-original-sysdescr`  
  Keep the original `device_details.system_description` instead of the demo
  descriptor.

- `--output-zip PATH`  
  Name or path of the output ZIP file. When PATH is relative (the default is
  `pypnm_support_bundle.zip`), the file is written under the `issues/`
  directory (for example, `issues/pypnm_support_bundle.zip`). When PATH is
  absolute, it is used as-is.

- `--support-root PATH`  
  Temporary working directory used to construct the `.data` tree before zipping
  (default: `.support_bundle`). This directory can be safely deleted after the
  bundle is created.

- `--clean-output`  
  Remove any existing `--support-root` directory before building the bundle.

- `--verbose`  
  Enable per-file logging during bundle creation.

The script prints the final ZIP file path at the end, for example:

```text
Support bundle created at: issues/pypnm_support_bundle.zip
```

## Examples

### 1. Build Bundle From A Single Transaction ID

You have a failing analysis for a single capture and want to share that file and
its metadata only.

```bash
./tools/build/support_bundle_builder.py   --transaction-id ea18519a572e2487
```

Results:

- All files and JSON records related to `ea18519a572e2487` are copied into a
  temporary `.data` tree.
- MAC address and system_description are sanitized.
- A ZIP file is created under `issues/` and the full path is printed.

### 2. Build Bundle From An Operation ID (Multi-Capture)

You ran a multi-capture test (for example, multi-RxMER or multi-constellation)
and want to share the entire capture group.

```bash
./tools/build/support_bundle_builder.py   --operation-id ed2fcba02bba42f6
```

The tool:

1. Looks up the capture group for `ed2fcba02bba42f6` via the operation DB.
2. Retrieves all transaction IDs listed for that group.
3. Collects all related capture files and transaction records.
4. Sanitizes and archives them into a single support bundle ZIP under `issues/`.

### 3. Build Bundle From A MAC Address

You suspect a specific modem is mis-behaving and want to share all captures
PyPNM has stored for that MAC address.

```bash
./tools/build/support_bundle_builder.py   --mac-address aa:bb:cc:dd:ee:ff
```

All transactions whose `mac_address` matches the provided value are included in
the bundle, and the sanitized ZIP is written to `issues/pypnm_support_bundle.zip`
by default.

### 4. Build Bundle With No Sanitization

If you are working in a lab environment and want to keep the real MAC and
system_description values, you can disable sanitization:

```bash
./tools/build/support_bundle_builder.py   --transaction-id ea18519a572e2487   \
                                    --keep-original-mac                 \
                                    --keep-original-sysdescr
```

Use this only when you are comfortable with sharing identifying details.

## Bundle Layout

Inside the ZIP file, the support bundle uses a **minimal** `.data` layout that
mirrors the PyPNM runtime structure but contains only the files needed to
reproduce the issue:

```text
.data/
  pnm/
    ds_ofdm_rxmer_per_subcar_aa_bb_cc_dd_ee_ff_194_1764820674.bin
    ds_ofdm_constellation_aa_bb_cc_dd_ee_ff_194_1764820678.bin
    ...
  db/
    pypnm.sqlite3
```

Key points:

- Only PNM files and JSON metadata for the selected transactions are included.
- Paths are relative to `.data/` so the bundle can be dropped into another
  PyPNM instance for reproduction.
- If sanitization is enabled, the contents are safe to share outside your
  environment.

## Submitting A Bundle

When you open a support request for PyPNM, include:

1. The generated ZIP file (for example:  
   `issues/pypnm_support_bundle.zip`)

2. A short description of the problem:
   - Which endpoint or CLI command you used.
   - What you expected to happen.
   - The actual error message or behavior.

3. Any relevant screenshots or logs (for example, `logs/pypnm.log`).

With a sanitized support bundle attached, PyPNM maintainers can reproduce and
investigate issues without requiring full access to your production data.

# FILE: docs/system/system-config.md
# System Configuration Reference

Canonical Structure And Field Semantics For `system.json`.

* **Config file**: [`src/pypnm/settings/system.json`](https://github.com/PyPNMApps/PyPNM/blob/main/src/pypnm/settings/system.json)
* **ConfigManager class**: [`src/pypnm/config/config_manager.py`](https://github.com/PyPNMApps/PyPNM/blob/main/src/pypnm/config/config_manager.py)
* **PnmConfigManager class**: [`src/pypnm/config/pnm_config_manager.py`](https://github.com/PyPNMApps/PyPNM/blob/main/src/pypnm/config/pnm_config_manager.py)

## Table Of Contents

* [1. FastApiRequestDefault](#1-fastapirequestdefault)
* [2. SNMP](#2-snmp)
* [3. PnmBulkDataTransfer](#3-pnmbulkdatatransfer)
* [4. PnmFileRetrieval](#4-pnmfileretrieval)
* [5. Database](#5-database)
* [6. Logging](#6-logging)
* [7. TestMode](#7-testmode)
* [Loading Configuration](#loading-configuration)

## 1. FastApiRequestDefault

Default Parameters For REST Requests To The FastAPI Service.

```json
"FastApiRequestDefault": {
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "ip_address": "192.168.0.100"
}
```

| Field       | Type   | Description                       |
| ----------- | ------ | --------------------------------- |
| mac_address | string | Default device MAC address.       |
| ip_address  | string | Default device IP (IPv4 or IPv6). |

## 2. SNMP

Global SNMP Settings, Including Version-Specific Options.

```json
"SNMP": {
  "timeout": 2,
  "version": {
    "2c": {
      "enable": true,
      "retries": 3,
      "read_community": "public",
      "write_community": "private"
    },
    "3": {
      "enable": false,
      "retries": 3,
      "username": "user",
      "securityLevel": "authPriv",
      "authProtocol": "SHA",
      "authPassword": "pass",
      "privProtocol": "AES",
      "privPassword": "privpass"
    }
  }
}
```

**Top-Level**

| Field   | Type   | Description                                  |
| ------- | ------ | -------------------------------------------- |
| timeout | number | Per-request timeout (seconds).               |
| version | object | Container for v2c/v3 configuration versions. |

**SNMP v2c**

| Field           | Type    | Description                     |
| --------------- | ------- | ------------------------------- |
| enable          | boolean | Enable v2c operations.          |
| retries         | number  | Retry count on timeout/failure. |
| read_community  | string  | Community for GET/WALK.         |
| write_community | string  | Community for SET.              |

**SNMP v3**

| Field         | Type    | Description                                  |
| ------------- | ------- | -------------------------------------------- |
| enable        | boolean | Enable v3 operations.                        |
| retries       | number  | Retry count on timeout/failure.              |
| username      | string  | Security name.                               |
| securityLevel | string  | `noAuthNoPriv`, `authNoPriv`, or `authPriv`. |
| authProtocol  | string  | For example `MD5`, `SHA`.                    |
| authPassword  | string  | Required when `auth*` is used.               |
| privProtocol  | string  | For example `DES`, `AES`.                    |
| privPassword  | string  | Required when `*Priv` is used.               |

## 3. PnmBulkDataTransfer

Transport Parameters For CM-Generated Files (for example, RxMER, FEC Summary) Sent To A Server.

```json
"PnmBulkDataTransfer": {
  "method": "tftp",
  "tftp": {
    "ip_v4": "192.168.0.10",
    "ip_v6": "::1",
    "remote_dir": ""
  },
  "http": {
    "base_url": "http://files.example.com/",
    "port": 80
  },
  "https": {
    "base_url": "https://files.example.com/",
    "port": 443
  }
}
```

| Field   | Type   | Description                                                |
| ------- | ------ | ---------------------------------------------------------- |
| method  | string | Preferred bulk method: `tftp`, `http`, or `https`.         |
| tftp.*  | object | TFTP targets for IPv4/IPv6 plus optional remote directory. |
| http.*  | object | HTTP base URL and port for file delivery.                  |
| https.* | object | HTTPS base URL and port for file delivery.                 |

## 4. PnmFileRetrieval

Local Storage Layout And Remote Retrieval Methods.

Related Guide: [File Transfer Methods](pnm-file-retrieval/index.md)

Runtime DB location policy: SQLite DB files live under `.data/db/` (demo uses `demo/.data/db/`), while Postgres is external and does not create a local DB file.

```json
"PnmFileRetrieval": {
  "pnm_dir": ".data/pnm",
  "csv_dir": ".data/csv",
  "json_dir": ".data/json",
  "xlsx_dir": ".data/xlsx",
  "png_dir": ".data/png",
  "archive_dir": ".data/archive",
  "msg_rsp_dir": ".data/msg_rsp",
  "capture_group_db": ".data/db/capture_group.json",
  "session_group_db": ".data/db/session_group.json",
  "operation_db": ".data/db/operation_capture.json",
  "retries": 5,
  "retrieval_method": {
    "method": "local",
    "methods": {
      "local": {
        "src_dir": "/srv/tftp"
      },
      "tftp": {
        "host": "localhost",
        "port": 69,
        "timeout": 5,
        "remote_dir": ""
      },
      "ftp": {
        "host": "localhost",
        "port": 21,
        "tls": false,
        "timeout": 5,
        "user": "user",
        "password_enc": "",
        "remote_dir": "/srv/tftp"
      },
      "sftp": {
        "host": "localhost",
        "port": 22,
        "user": "user",
        "password_enc": "",
        "private_key_path": "",
        "remote_dir": "/srv/tftp"
      },
      "http": {
        "base_url": "http://STUB/",
        "port": 80
      },
      "https": {
        "base_url": "https://STUB/",
        "port": 443
      }
    }
  }
}
```

`password_enc` is the preferred password field for file retrieval methods. Plaintext `password` is supported only as a legacy fallback and is deprecated.
Deprecated JSON ledger keys are ignored at runtime; metadata persistence is DB-backed.

**Directories And Databases**

| Field               | Type   | Description                                  |
| ------------------- | ------ | -------------------------------------------- |
| pnm_dir             | string | Local storage for raw PNM binaries.          |
| csv_dir             | string | Local storage for derived CSVs.              |
| json_dir            | string | Local storage for derived JSON.              |
| xlsx_dir            | string | Local storage for Excel reports.             |
| png_dir             | string | Local storage for generated PNGs.            |
| archive_dir         | string | Local storage for analysis ZIP archives.     |
| msg_rsp_dir         | string | Local storage for message/response metadata. |
| transaction_db      | string | Deprecated and ignored at runtime; remove from config.      |
| capture_group_db    | string | Legacy JSON map of grouped transactions (migration only).  |
| session_group_db    | string | Legacy JSON map of session groups (migration only).        |
| operation_db        | string | Legacy JSON map of operation to capture group (migration only). |
| json_transaction_db | string | Deprecated and ignored at runtime; remove from config.      |

**Retrieval Settings**

| Field                                  | Type   | Description                                                           |
| -------------------------------------- | ------ | --------------------------------------------------------------------- |
| retrieval_method.method                 | string | Active retrieval method: `local`, `tftp`, `ftp`, `sftp`, `http`, `https`. |
| retrieval_method.methods.local.src_dir  | string | Source directory to watch/copy from when using `local`.               |
| retrieval_method.methods.tftp.*         | object | TFTP host/port/timeout and remote directory.                          |
| retrieval_method.methods.ftp.*          | object | FTP connection, credentials, and remote directory.                    |
| retrieval_method.methods.sftp.*         | object | SFTP connection and remote directory.                                 |
| retrieval_method.methods.http.*         | object | HTTP base URL and port.                                               |
| retrieval_method.methods.https.*        | object | HTTPS base URL and port.                                              |
| retries                                | number | Max attempts per retrieval operation.                                 |

> The legacy key name `retrival_method` is accepted for backward compatibility.

## 5. Database

Database Backend Selection And Connection Settings.

```json
"Database": {
  "backend": "sqlite",
  "sqlite": {
    "path": ".data/db/pypnm.sqlite3"
  },
  "postgres": {
    "dsn": ""
  }
}
```

Backend selection is set at install time (SQLite default; Postgres recommended for multi-worker deployments). Set `PYPNM_DB_BACKEND` to override the backend selection (`sqlite` or `postgres`). SQLite stores its DB file under `.data/db/` (demo uses `demo/.data/db/`), while Postgres is external and does not create a local DB file. For Postgres, supply the DSN via `PYPNM_DB_POSTGRES_DSN` to avoid storing plaintext credentials in tracked JSON files. Blank strings for required values are invalid when the backend is active.

On startup, PyPNM applies the schema for the selected backend and seeds the canonical `UNKNOWN` sysDescr row and the default artifact store entry.

DB backend migration is in progress; legacy ledger keys remain until Phase M6.

## 6. Logging

Application Logging Options.

```json
"logging": {
  "log_level": "INFO",
  "log_dir": "logs",
  "log_filename": "pypnm.log"
}
```

| Field        | Type   | Description                                 |
| ------------ | ------ | ------------------------------------------- |
| log_level    | string | `DEBUG`, `INFO`, `WARN`, or `ERROR`.        |
| log_dir      | string | Directory for log files.                    |
| log_filename | string | Log filename (created under `log_dir`).     |

## 7. TestMode

Global And Class-Specific Test-Mode Controls.

```json
"TestMode": {
  "global": {
    "mode": {
      "enable": true
    }
  },
  "class_name": {
    "DsScQamChannelSpectrumAnalyzer": {
      "mode": {
        "enable": true
      }
    }
  }
}
```

| Field                          | Type    | Description                                            |
| ------------------------------ | ------- | ------------------------------------------------------ |
| global.mode.enable             | boolean | Enable or disable global test mode.                    |
| class_name.<Class>.mode.enable | boolean | Per-class override for test mode, keyed by class name. |

## Loading Configuration

Typical Access Pattern Using The Manager Abstractions.

```python
from pypnm.config.config_manager import ConfigManager
from pypnm.config.pnm_config_manager import PnmConfigManager

cfg = ConfigManager()

mac = cfg.get("FastApiRequestDefault", "mac_address")
ip  = cfg.get("FastApiRequestDefault", "ip_address")

pnm_cfg = PnmConfigManager()
tftp_v4 = pnm_cfg.get("PnmBulkDataTransfer", "tftp")["ip_v4"]
```

# FILE: tests/test_json_transaction_db.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from pathlib import Path

import pytest

from pypnm.config.pnm_config_manager import SystemConfigSettings
from pypnm.lib.db.artifact_repository import ROLE_JSON_EXPORT
from pypnm.lib.db.db_schema_manager import (
    DatabaseSchemaManager,
    JSON_ARTIFACT_STORE_NAME,
)
from pypnm.lib.db.json_transaction import JsonTransactionDb
from pypnm.lib.db.transaction_repository import (
    DeviceDetailsRepository,
    SystemDescriptionRepository,
    TransactionRepository,
)
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    FileName,
    HashStr,
    TimestampSec,
    TransactionId,
)

SYS_DESCR: dict[str, str] = {
    "HW_REV": "1.0",
    "VENDOR": "LANCity",
    "BOOTR": "NONE",
    "SW_REV": "1.0.0",
    "MODEL": "LCPET-3",
}
DEVICE_DETAILS: dict[str, object] = {"system_description": SYS_DESCR}
DEFAULT_MAC = MacAddress("aa:bb:cc:dd:ee:ff")
DEFAULT_TEST_TYPE = "DS_RXMER"


def _configure_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    db_path = tmp_path / "pypnm.sqlite3"
    json_dir = tmp_path / "json"
    json_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(
        SystemConfigSettings,
        "pnm_dir",
        classmethod(lambda cls: str(tmp_path / "pnm")),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "json_dir",
        classmethod(lambda cls: str(json_dir)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_backend",
        classmethod(lambda cls: DatabaseBackend.SQLITE),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_sqlite_path",
        classmethod(lambda cls: DatabasePath(str(db_path))),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_postgres_dsn",
        classmethod(lambda cls: DatabaseDsn("")),
    )

    DatabaseSchemaManager.from_system_config().initialize_schema()
    return db_path, json_dir


def _seed_transaction(db_path: Path, transaction_id: TransactionId) -> None:
    sqlite_path = DatabasePath(str(db_path))
    postgres_dsn = DatabaseDsn("")
    sys_repo = SystemDescriptionRepository.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )
    device_repo = DeviceDetailsRepository.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )
    txn_repo = TransactionRepository.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )
    sysdescr_id = sys_repo.get_or_create_sysdescr_id(SYS_DESCR)
    device_detail_id = device_repo.get_or_create_device_detail_id(
        DEVICE_DETAILS, sysdescr_id
    )
    txn_repo.insert_transaction(
        transaction_id=transaction_id,
        timestamp_epoch=TimestampSec(1234),
        mac_address=DEFAULT_MAC,
        pnm_test_type=DEFAULT_TEST_TYPE,
        filename=FileName("rxmer.bin"),
        device_detail_id=device_detail_id,
    )


def test_write_json_registers_json_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path, json_dir = _configure_db(tmp_path, monkeypatch)
    payload: Mapping[str, object] = {"foo": "bar", "value": 42}

    db = JsonTransactionDb()
    path = db.write_json(payload, fname="payload", extension="json")

    assert path.exists()
    assert path.parent == json_dir

    with sqlite3.connect(db_path) as conn:
        cursor = conn.execute(
            "SELECT store_id FROM artifact_stores WHERE store_name = ?;",
            (JSON_ARTIFACT_STORE_NAME,),
        )
        row = cursor.fetchone()
        assert row is not None
        store_id = int(row[0])

        cursor = conn.execute(
            "SELECT filename, relative_path, sha256 FROM file_artifacts WHERE store_id = ?;",
            (store_id,),
        )
        artifact_row = cursor.fetchone()
        assert artifact_row is not None
        filename, relative_path, sha256 = artifact_row
        assert filename == path.name
        assert relative_path.endswith(path.name)
        assert isinstance(sha256, str)
        assert len(sha256) == len(HashStr("a" * 64))


def test_write_json_links_transaction_artifact_when_provided(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path, _ = _configure_db(tmp_path, monkeypatch)
    transaction_id = TransactionId("txn-json-export")
    _seed_transaction(db_path, transaction_id)

    db = JsonTransactionDb()
    db.write_json(
        {"alpha": 1},
        fname="payload",
        extension="json",
        transaction_id=transaction_id,
    )

    with sqlite3.connect(db_path) as conn:
        cursor = conn.execute(
            "SELECT role FROM transaction_artifacts WHERE transaction_id = ?;",
            (str(transaction_id),),
        )
        row = cursor.fetchone()
        assert row is not None
        assert row[0] == ROLE_JSON_EXPORT


def test_write_json_raises_on_non_serializable_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_db(tmp_path, monkeypatch)
    db = JsonTransactionDb()

    class _NonSerializable: ...

    bad_payload: Mapping[str, object] = {"obj": _NonSerializable()}

    with pytest.raises(ValueError):
        db.write_json(bad_payload, fname="bad", extension="json")

# FILE: tests/test_json_transaction_db_empty_transaction_id.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from pypnm.config.pnm_config_manager import SystemConfigSettings
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.db.json_transaction import JsonTransactionDb
from pypnm.lib.types import DatabaseBackend, DatabaseDsn, DatabasePath


def _configure_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    db_path = tmp_path / "pypnm.sqlite3"
    json_dir = tmp_path / "json"
    json_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(
        SystemConfigSettings,
        "pnm_dir",
        classmethod(lambda cls: str(tmp_path / "pnm")),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "json_dir",
        classmethod(lambda cls: str(json_dir)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_backend",
        classmethod(lambda cls: DatabaseBackend.SQLITE),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_sqlite_path",
        classmethod(lambda cls: DatabasePath(str(db_path))),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_postgres_dsn",
        classmethod(lambda cls: DatabaseDsn("")),
    )

    DatabaseSchemaManager.from_system_config().initialize_schema()
    return db_path


def test_write_json_without_transaction_id_does_not_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_db(tmp_path, monkeypatch)
    db = JsonTransactionDb()

    db.write_json({"alpha": 1}, fname="payload", extension="json")

    with sqlite3.connect(db_path) as conn:
        cursor = conn.execute("SELECT COUNT(*) FROM transaction_artifacts;")
        row = cursor.fetchone()
        assert row is not None
        assert int(row[0]) == 0
