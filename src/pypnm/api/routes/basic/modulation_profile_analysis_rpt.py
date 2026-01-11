# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any, TypeVar, cast

from pydantic import BaseModel, ConfigDict, Field

from pypnm.api.routes.basic.abstract.analysis_report import (
    AnalysisReport,
    AnalysisRptMatplotConfig,
)
from pypnm.api.routes.basic.abstract.base_models.common_analysis import CommonAnalysis
from pypnm.api.routes.common.classes.analysis.analysis import Analysis
from pypnm.lib.constants import INVALID_CHANNEL_ID, INVALID_PROFILE_ID
from pypnm.lib.csv.manager import CSVManager
from pypnm.lib.matplot.manager import MatplotManager, PlotConfig
from pypnm.lib.types import (
    ArrayLike,
    ChannelId,
    FloatSeries,
    FrequencyHz,
    FrequencySeriesHz,
    ProfileId,
    StringArray,
)


class ModulationProfileRptModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    profile_id: int = Field(..., description="Profile identifier")
    modulation: list[str] = Field(
        default_factory=list,
        description="Per-carrier modulation label (e.g., 'QAM256')",
    )
    bits_per_symbol: list[int] = Field(
        default_factory=list,
        description="Per-carrier bits per symbol (derived or provided)",
    )
    shannon_min_mer: list[float] = Field(
        default_factory=list, description="Per-carrier minimum MER per Shannon (dB)"
    )


class ModulationProfileParametersAnalysisRpt(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    profiles: list[ModulationProfileRptModel] = Field(
        default_factory=list, description="All profiles for a channel"
    )


class ModulationProfileAnalysisRptModel(CommonAnalysis):
    parameters: ModulationProfileParametersAnalysisRpt = Field(
        ..., description="Modulation profile parameters"
    )


class ModulationProfileReport(AnalysisReport):
    FNAME_TAG: str = "modulationprofile"

    def __init__(
        self,
        analysis: Analysis,
        analysis_matplot_config: AnalysisRptMatplotConfig | None = None,
        **kwargs: object,
    ) -> None:
        if analysis_matplot_config is None:
            analysis_matplot_config = AnalysisRptMatplotConfig()
        super().__init__(analysis, analysis_matplot_config)
        self.logger = logging.getLogger("ModulationProfileReport")
        self._results: dict[int, ModulationProfileAnalysisRptModel] = {}

    def create_csv(self, **kwargs: object) -> list[CSVManager]:
        """
        Stream validated models into CSVs. Assumes `_process()` already enforced.
        Emits one CSV per channel/profile pair.
        """
        csv_mgr_list: list[CSVManager] = []
        any_models = False

        for common_model in self.get_common_analysis_model():
            any_models = True
            model = cast(ModulationProfileAnalysisRptModel, common_model)
            channel_id: int = int(model.channel_id)
            freq: FrequencySeriesHz = cast(FrequencySeriesHz, model.raw_x)

            if not freq:
                self.logger.warning(
                    f"Channel {channel_id} has empty frequency array; skipping CSV."
                )
                continue

            try:
                header: list[str] = [
                    "ChannelID",
                    "ProfileID",
                    "Frequency_Hz",
                    "Modulation",
                    "BitsPerSymbol",
                    "ShannonMinMER_dB",
                ]

                for profile in model.parameters.profiles:
                    csv_mgr: CSVManager = self.csv_manager_factory()
                    csv_mgr.set_header(header)

                    csv_fname = self.create_csv_fname(
                        tags=[str(channel_id), str(profile.profile_id), self.FNAME_TAG]
                    )
                    csv_mgr.set_path_fname(csv_fname)

                    n = len(freq)
                    mod = self._align_len(profile.modulation, n, fill="UNKNOWN")
                    bps = self._align_len(profile.bits_per_symbol, n, fill=0)
                    mer = self._align_len(profile.shannon_min_mer, n, fill=float("nan"))

                    rows_written = 0
                    for i in range(n):
                        csv_mgr.insert_row(
                            [
                                channel_id,
                                profile.profile_id,
                                freq[i],
                                mod[i],
                                int(bps[i]),
                                float(mer[i]),
                            ]
                        )
                        rows_written += 1

                    self.logger.info(
                        f"CSV rows for channel {channel_id} profile {profile.profile_id}: {rows_written}"
                    )
                    self.logger.info(
                        f"CSV created for channel {channel_id}: {csv_fname} (rows={csv_mgr.get_row_count()})"
                    )

                    csv_mgr_list.append(csv_mgr)

            except Exception as exc:
                self.logger.exception(
                    f"Failed to create CSV for channel {channel_id}: {exc}",
                    exc_info=True,
                )

        if not any_models:
            self.logger.info("No analysis data available; no CSVs created.")

        return csv_mgr_list

    def create_matplot(self) -> list[MatplotManager]:
        """
        Generate per-channel plots, one set per profile:
        1) Bits-per-symbol vs. Frequency
        2) Shannon Min MER vs. Frequency
        3) Modulation vs. Frequency with a preloaded M-QAM scale (linear spacing via log₂(M) positions,
            tick labels shown as M values: 4, 8, 16, 32, …, 4096)

        Notes
        -----
        - Frequency axis is formatted by Matplot using unit scaling (Hz → MHz) and zero decimals.
        - Theme is taken from AnalysisRptMatplotConfig (e.g., "dark" or "light").
        - The M-QAM axis uses evenly spaced positions at log₂(M) to avoid visually "log-like" spacing,
        while the visible tick labels are the true QAM orders (M).
        """
        out: list[MatplotManager] = []

        for common_model in self.get_common_analysis_model():
            model = cast(ModulationProfileAnalysisRptModel, common_model)
            channel_id: ChannelId = ChannelId(model.channel_id)
            freq: FrequencySeriesHz = cast(FrequencySeriesHz, model.raw_x)

            if not freq:
                self.logger.warning(
                    f"Channel {channel_id} has empty frequency array; skipping plots."
                )
                continue

            for profile in model.parameters.profiles:
                profile_id: ProfileId = ProfileId(profile.profile_id)

                # Align inputs to frequency length
                try:
                    n = len(freq)
                    bpsym: FloatSeries = self._align_len(
                        profile.bits_per_symbol, n, fill=0
                    )
                    min_mer: FloatSeries = self._align_len(
                        profile.shannon_min_mer, n, fill=float("nan")
                    )
                    mod_lbls: StringArray = self._align_len(
                        profile.modulation, n, fill="UNKNOWN"
                    )
                    mod_order: list[int] = [
                        self._derive_qam_order(lbl) for lbl in mod_lbls
                    ]
                except Exception as exc:
                    self.logger.exception(
                        f"Failed to align arrays for channel {channel_id} profile {profile_id}: {exc}",
                        exc_info=True,
                    )
                    continue

                # 1) Bits-per-symbol vs Frequency
                try:
                    bps_cfg = PlotConfig(
                        title=f"Bits-Per-Symbol vs Frequency — OFDM Ch {channel_id} · Profile {profile_id}",
                        x=cast(ArrayLike, freq),
                        y=cast(ArrayLike, bpsym),
                        ylabel="Bits per Symbol",
                        x_tick_mode="unit",
                        x_unit_from="hz",
                        x_unit_out="mhz",
                        x_tick_decimals=0,
                        xlabel_base="Frequency",
                        grid=True,
                        legend=False,
                        transparent=False,
                        theme=self.getAnalysisRptMatplotConfig().theme,
                    )

                    png_fname = self.create_png_fname(
                        tags=[str(channel_id), str(profile_id), "bps", self.FNAME_TAG]
                    )
                    self.logger.info(
                        f"Creating Bits-Per-Symbol plot: {png_fname} for channel: {channel_id}"
                    )
                    mplot_mgr = MatplotManager(default_cfg=bps_cfg)
                    mplot_mgr.plot_line(filename=png_fname)
                    out.append(mplot_mgr)
                except Exception as exc:
                    self.logger.exception(
                        f"Failed to create Bits-Per-Symbol plot for channel {channel_id} profile {profile_id}: {exc}",
                        exc_info=True,
                    )

                # 2) Shannon Min MER vs Frequency
                try:
                    mer_cfg = PlotConfig(
                        title=f"Shannon Min MER vs Frequency — OFDM Ch {channel_id} · Profile {profile_id}",
                        x=cast(ArrayLike, freq),
                        y=cast(ArrayLike, min_mer),
                        ylabel="Shannon Min MER (dB)",
                        x_tick_mode="unit",
                        x_unit_from="hz",
                        x_unit_out="mhz",
                        x_tick_decimals=0,
                        xlabel_base="Frequency",
                        grid=True,
                        legend=False,
                        transparent=False,
                        theme=self.getAnalysisRptMatplotConfig().theme,
                    )

                    png_fname = self.create_png_fname(
                        tags=[
                            str(channel_id),
                            str(profile_id),
                            "shannon",
                            self.FNAME_TAG,
                        ]
                    )
                    self.logger.info(
                        f"Creating Shannon Min MER plot: {png_fname} for channel: {channel_id}"
                    )
                    mplot_mgr = MatplotManager(default_cfg=mer_cfg)
                    mplot_mgr.plot_line(filename=png_fname)
                    out.append(mplot_mgr)
                except Exception as exc:
                    self.logger.exception(
                        f"Failed to create Shannon Min MER plot for channel {channel_id} profile {profile_id}: {exc}",
                        exc_info=True,
                    )

                # 3) Modulation vs Frequency with preloaded M-QAM scale (linear spacing via log₂(M), labels show M)
                try:
                    from math import isfinite, log2

                    # Convert M to positions (bits per symbol) for linear spacing
                    mod_bits: list[int] = []
                    for m in mod_order:
                        if m and m > 0:
                            try:
                                v = log2(m)
                                mod_bits.append(int(v) if isfinite(v) else 0)
                            except Exception:
                                mod_bits.append(0)
                        else:
                            mod_bits.append(0)

                    # Predefine a comprehensive M-QAM ladder and its bit positions
                    ladder_M = [4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096]
                    ladder_bits = [int(log2(m)) for m in ladder_M]

                    max_bits_seen = max(mod_bits) if mod_bits else 8
                    max_bits_cap = max(2, min(max_bits_seen, ladder_bits[-1]))

                    y_ticks_bits = [b for b in ladder_bits if b <= max_bits_cap]
                    y_labels_M = [
                        str(2**b) for b in y_ticks_bits
                    ]  # labels: "4","8","16","32",...

                    mod_cfg = PlotConfig(
                        title=f"Modulation vs Frequency · OFDM · Channel ({channel_id}) · Profile ({profile_id})",
                        x=cast(ArrayLike, freq),
                        y=cast(ArrayLike, mod_bits),
                        ylabel="Modulation Order (M-QAM)",
                        x_tick_mode="unit",
                        x_unit_from="hz",
                        x_unit_out="mhz",
                        x_tick_decimals=0,
                        xlabel_base="Frequency",
                        y_ticks=y_ticks_bits,
                        y_tick_labels=y_labels_M,
                        ylim=(0.0, float(max_bits_cap)),
                        grid=True,
                        legend=False,
                        transparent=False,
                        theme=self.getAnalysisRptMatplotConfig().theme,
                    )

                    png_fname = self.create_png_fname(
                        tags=[
                            str(channel_id),
                            str(profile_id),
                            "modulation",
                            self.FNAME_TAG,
                        ]
                    )
                    self.logger.info(
                        f"Creating Modulation plot: {png_fname} for channel: {channel_id}"
                    )
                    mplot_mgr = MatplotManager(default_cfg=mod_cfg)
                    mplot_mgr.plot_line(filename=png_fname)
                    out.append(mplot_mgr)
                except Exception as exc:
                    self.logger.exception(
                        f"Failed to create Modulation plot for channel {channel_id} profile {profile_id}: {exc}",
                        exc_info=True,
                    )

        if not out:
            self.logger.info("No analysis data available; no plots created.")

        return out

    def _process(self) -> None:
        """
        Expected per-item shape (keys are case-sensitive):

        {
          "device_details": {...},
          "pnm_header": {...},
          "mac_address": "...",
          "channel_id": int,
          "frequency_unit": "Hz",
          "shannon_limit_unit": "dB",
          "profiles": [
            {
              "profile_id": int,
              "carrier_values": {
                "frequency": [...],           # List[float] (Hz)
                "modulation": [...],          # List[str]  (e.g., 'QAM256')
                "bits_per_symbol": [...],     # Optional[List[int]]
                "shannon_min_mer": [...]      # List[float] (dB)
              }
            },
            ...
          ]
        }
        """
        data_list: list[dict[str, Any]] = self.get_analysis_data() or []

        try:
            for _idx, data in enumerate(data_list):
                channel_id = ChannelId(data.get("channel_id", INVALID_CHANNEL_ID))
                profiles_in: list[dict[str, Any]] = data.get("profiles", [])

                freq_array: FrequencySeriesHz = []
                profile_models: list[ModulationProfileRptModel] = []

                for profile_entry in profiles_in:
                    cv: dict[str, Any] = profile_entry.get("carrier_values", {})
                    profile_id: int = int(
                        profile_entry.get("profile_id", INVALID_PROFILE_ID)
                    )

                    freqs: FrequencySeriesHz = list(
                        map(FrequencyHz, cv.get("frequency", []) or [])
                    )
                    mod: list[str] = list(map(str, cv.get("modulation", []) or []))
                    bps: list[int] = list(map(int, cv.get("bits_per_symbol", []) or []))
                    mer: list[float] = list(
                        map(float, cv.get("shannon_min_mer", []) or [])
                    )

                    if not bps and mod:
                        bps = [self._derive_bits_per_symbol(m) for m in mod]

                    if not freq_array and freqs:
                        freq_array = freqs

                    n = len(freq_array) if freq_array else len(freqs)
                    if n:
                        mod = self._align_len(mod, n, fill="UNKNOWN")
                        bps = self._align_len(bps, n, fill=0)
                        mer = self._align_len(mer, n, fill=float("nan"))

                    profile_models.append(
                        ModulationProfileRptModel(
                            profile_id=profile_id,
                            modulation=mod,
                            bits_per_symbol=bps,
                            shannon_min_mer=mer,
                        )
                    )

                params = ModulationProfileParametersAnalysisRpt(profiles=profile_models)

                model = ModulationProfileAnalysisRptModel(
                    channel_id=channel_id,
                    raw_x=freq_array,
                    raw_y=[0.0],
                    parameters=params,
                )

                self.register_common_analysis_model(channel_id, model)

        except Exception as exc:
            self.logger.exception(
                f"Failed to process Modulation Profile data: {exc}", exc_info=True
            )

    T = TypeVar("T")

    @staticmethod
    def _align_len(seq: Iterable[T] | list[T], n: int, *, fill: T) -> list[T]:
        """
        Force a sequence to length n using truncation or padding with `fill`.
        """
        lst = list(seq) if not isinstance(seq, list) else seq
        if n <= 0:
            return []
        if len(lst) >= n:
            return lst[:n]
        return lst + [fill] * (n - len(lst))

    @staticmethod
    def _derive_bits_per_symbol(mod_label: str) -> int:
        """
        Best-effort mapping from modulation label to bits/symbol. Accepts forms like 'QAM256', 'QAM-256', '256QAM', 'qam1024', etc.
        """
        if not mod_label:
            return 0
        s = mod_label.strip().upper().replace("-", "").replace("_", "")
        digits = "".join(ch for ch in s if ch.isdigit())
        if not digits:
            return 0
        try:
            order = int(digits)
            from math import isfinite, log2

            val = log2(order)
            return int(val) if isfinite(val) else 0
        except Exception:
            return 0

    @staticmethod
    def _derive_qam_order(mod_label: str) -> int:
        """
        Parse modulation label to return QAM order M (e.g., 'QAM256' -> 256). If the label is missing digits, returns 0.
        """
        if not mod_label:
            return 0
        s = mod_label.strip().upper().replace("-", "").replace("_", "")
        digits = "".join(ch for ch in s if ch.isdigit())
        if not digits:
            return 0
        try:
            return int(digits)
        except Exception:
            return 0
