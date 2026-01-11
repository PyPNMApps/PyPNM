# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import contextlib
import logging
import math
import re
from collections.abc import Mapping
from typing import cast

from pydantic import BaseModel, ConfigDict, Field

from pypnm.api.routes.basic.abstract.analysis_report import (
    AnalysisReport,
    AnalysisRptMatplotConfig,
)
from pypnm.api.routes.basic.abstract.base_models.common_analysis import CommonAnalysis
from pypnm.api.routes.basic.common.signal_capture_agg import SignalCaptureAggregator
from pypnm.api.routes.common.classes.analysis.analysis import Analysis
from pypnm.api.routes.common.classes.analysis.model.schema import DsRxMerAnalysisModel
from pypnm.lib.csv.manager import CSVManager
from pypnm.lib.format_string import Format
from pypnm.lib.matplot.manager import MatplotManager, PlotConfig
from pypnm.lib.signal_processing.shan.series import Shannon
from pypnm.lib.types import ArrayLike, FloatSeries, FrequencySeriesHz, IntSeries


class RxMerParametersAnalysisRpt(BaseModel):
    """
    Parameters that augment RxMER analysis output.

    - shannon_limit_db: Per-subcarrier Shannon/SNR limit (dB), len == len(raw_x)
    - regression_line : Per-subcarrier fitted values (ŷ) from linear regression over index domain
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    shannon_limit_db: FloatSeries = Field(
        ..., description="Shannon/SNR limit per subcarrier (dB)"
    )
    regression_line: FloatSeries = Field(
        ..., description="Regression fitted values per subcarrier"
    )
    modulation_count: dict[str, int] = Field(
        ..., description="Number of supported modulation schemes"
    )


class RxMerAnalysisRptModel(CommonAnalysis):
    """
    Analysis view over RxMER data (extends CommonAnalysis).
    """

    parameters: RxMerParametersAnalysisRpt = Field(
        ..., description="RxMER analysis parameters and limits."
    )


class RxMerAnalysisReport(AnalysisReport):
    """Concrete report builder for RxMER measurements."""

    def __init__(
        self,
        analysis: Analysis,
        analysis_matplot_config: AnalysisRptMatplotConfig | None = None,
    ) -> None:
        if analysis_matplot_config is None:
            analysis_matplot_config = AnalysisRptMatplotConfig()
        super().__init__(analysis, analysis_matplot_config)
        self.logger = logging.getLogger("RxMerAnalysisReport")
        self._results: dict[int, RxMerAnalysisRptModel] = {}
        self._sig_cap_agg: SignalCaptureAggregator = SignalCaptureAggregator()

    def create_csv(self) -> list[CSVManager]:
        """
        Stream validated models into CSVs. Assumes `_process()` already enforced
        """
        csv_mgr_list: list[CSVManager] = []
        any_models = False

        for common_model in self.get_common_analysis_model():
            any_models = True
            model = cast(RxMerAnalysisRptModel, common_model)
            chan = model.channel_id

            x: FrequencySeriesHz = cast(FrequencySeriesHz, model.raw_x)
            y: FloatSeries = model.raw_y
            sh: FloatSeries = model.parameters.shannon_limit_db
            rl: FloatSeries = model.parameters.regression_line

            """
            Single Channel Capture
            """
            try:
                csv_mgr: CSVManager = self.csv_manager_factory()
                csv_fname = self.create_csv_fname(tags=[str(chan)])
                csv_mgr.set_path_fname(csv_fname)

                csv_mgr.set_header(
                    [
                        "ChannelID",
                        "Frequency(Hz)",
                        "Magnitude(dB)",
                        "Shannon Limit(dB)",
                        "Regression Line(dB)",
                    ]
                )
                for rx, ry, s, r in zip(x, y, sh, rl, strict=False):
                    csv_mgr.insert_row([chan, rx, ry, s, r])

                self.logger.debug(
                    "CSV created for channel %s: %s (rows=%d)", chan, csv_fname, len(x)
                )
                csv_mgr_list.append(csv_mgr)

            except Exception as exc:
                self.logger.exception(
                    "Failed to create CSV for channel %s: %s", chan, exc
                )

            """
            Signal Capture Aggregation - All OFDM DS Channels
            """
            try:
                csv_mgr: CSVManager = self.csv_manager_factory()
                csv_fname = self.create_csv_fname(tags=["signal_aggregate"])
                csv_mgr.set_path_fname(csv_fname)

                csv_mgr.set_header(["Frequency(Hz)", "Magnitude(dB)"])

                x_agg, y_agg = self._sig_cap_agg.get_series()
                for rx, ry in zip(x_agg, y_agg, strict=False):
                    csv_mgr.insert_row([rx, ry])

                self.logger.debug(f"CSV created: {csv_fname} (rows={len(x_agg)})")
                csv_mgr_list.append(csv_mgr)

            except Exception as exc:
                self.logger.exception(f"Failed to create CSV, Reason: {exc}")

        if not any_models:
            self.logger.debug("No analysis data available; no CSVs created.")

        return csv_mgr_list

    def create_matplot(self) -> list[MatplotManager]:
        """
        Generate per-channel line and multi-line plots from validated models.
        """
        out: list[MatplotManager] = []
        any_models = False
        chan_id_list: list[int] = []

        for common_model in self.get_common_analysis_model():
            any_models = True
            model = cast(RxMerAnalysisRptModel, common_model)
            channel_id = model.channel_id
            freq = cast(ArrayLike, model.raw_x)
            db = cast(ArrayLike, model.raw_y)
            rl = cast(ArrayLike, model.parameters.regression_line)
            mc = model.parameters.modulation_count

            chan_id_list.append(channel_id)

            title_prefix = f"RxMER OFDM Channel: ({channel_id})"

            """
            RxMER with Regression Line - All OFDM DS Channels
            """
            try:
                cfg = PlotConfig(
                    title=f"{title_prefix}",
                    x=cast(ArrayLike, freq),
                    y_multi=[db, rl],
                    y_multi_label=["RxMER", "Regression Line"],
                    x_tick_mode="unit",
                    x_unit_from="hz",
                    x_unit_out="mhz",
                    x_tick_decimals=0,
                    xlabel_base="Frequency",
                    ylabel="dB",
                    grid=True,
                    legend=True,
                    transparent=False,
                    theme=self.getAnalysisRptMatplotConfig().theme,
                )

                multi = self.create_png_fname(tags=[str(channel_id), "rxmer"])
                self.logger.debug(
                    "Creating MatPlot: %s for channel: %s", multi, channel_id
                )

                mgr = MatplotManager(default_cfg=cfg)
                mgr.plot_multi_line(filename=multi)

                out.append(mgr)

            except Exception as exc:
                self.logger.exception(
                    "Failed to create plot for channel %s: %s", channel_id, exc
                )

            """
            Modulation Order Count - All OFDM DS Channels
            """
            try:
                bpsym, order_count = self.__modulation_order_count_to_series(mc)

                cfg = PlotConfig(
                    title=f"{title_prefix} - Modulation Order Count",
                    x=cast(ArrayLike, bpsym),
                    xlabel="Bits Per Symbol (bps)",
                    y=cast(ArrayLike, order_count),
                    ylabel="Order Count",
                    grid=True,
                    legend=False,
                    transparent=False,
                    theme=self.getAnalysisRptMatplotConfig().theme,
                )

                mod_count_fname = self.create_png_fname(
                    tags=[str(channel_id), "modulation_count"]
                )
                self.logger.debug(
                    "Creating MatPlot: %s for channel: %s", mod_count_fname, channel_id
                )

                mgr = MatplotManager(default_cfg=cfg)
                mgr.plot_line(filename=mod_count_fname)

                out.append(mgr)

            except Exception as exc:
                self.logger.exception(
                    "Failed to create plot for channel %s: %s", channel_id, exc
                )

            """
            Signal Capture Aggregation - All OFDM DS Channels
            """
            try:
                freq, db = self._sig_cap_agg.get_series()

                cfg = PlotConfig(
                    title=f"RxMER · OFDM Channel(s): {Format.join_paren(chan_id_list)}",
                    x=cast(ArrayLike, freq),
                    y=cast(ArrayLike, db),
                    xlabel=None,
                    xlabel_base="Frequency",
                    x_tick_mode="unit",
                    x_unit_from="hz",
                    x_unit_out="mhz",
                    x_tick_decimals=0,
                    ylabel="dB",
                    grid=True,
                    legend=True,
                    transparent=False,
                    theme=self.getAnalysisRptMatplotConfig().theme,
                )

                signal_aggregate_fname = self.create_png_fname(
                    tags=["signal_aggregate"]
                )
                self.logger.debug(
                    f"Creating MatPlot: {signal_aggregate_fname} for aggregated RxMER capture"
                )

                mgr = MatplotManager(default_cfg=cfg)
                mgr.plot_line(filename=signal_aggregate_fname, label="Aggregated RxMER")

                out.append(mgr)

            except Exception as exc:
                self.logger.exception(
                    f"Failed to create aggregated RxMER capture plot, reason: {exc}"
                )

        if not any_models:
            self.logger.warning("No analysis data available; no plots created.")

        return out

    def _process(self) -> None:
        analysis_models: list[DsRxMerAnalysisModel] = cast(
            list[DsRxMerAnalysisModel], self.get_analysis_model()
        )

        def coerce_finite(seq: ArrayLike, name: str) -> list[float]:
            """coerce -> float (and finiteness)"""
            out: list[float] = []
            for v in seq:
                fv = float(v)
                if not math.isfinite(fv):
                    raise ValueError(f"non-finite {name} value: {v!r}")
                out.append(fv)
            return out

        def process_single_model(
            idx: int, data: DsRxMerAnalysisModel
        ) -> tuple[bool, str]:
            """Process a single analysis model, returning success status and error message."""
            try:
                channel_id = data.channel_id
                x_raw = data.carrier_values.frequency
                y_raw = data.carrier_values.magnitude
                snr_db_limit = data.modulation_statistics.snr_db_min
                mod_count: dict[str, int] = (
                    data.modulation_statistics.supported_modulation_counts
                )

                x = coerce_finite(x_raw, "raw_x")
                y = coerce_finite(y_raw, "raw_y")
                sh = coerce_finite(snr_db_limit, "shannon_limit_db")

                # length checks (strict)
                n = len(x)
                if not (n and len(y) == n and len(sh) == n):
                    raise ValueError(
                        f"length mismatch x/y/shannon: {len(x)}/{len(y)}/{len(sh)} (n must be equal & > 0)"
                    )

                model = RxMerAnalysisRptModel(
                    channel_id=data.channel_id,
                    raw_x=x,
                    raw_y=y,
                    parameters=RxMerParametersAnalysisRpt(
                        shannon_limit_db=sh,
                        regression_line=data.regression.slope,
                        modulation_count=mod_count,
                    ),
                )

                # MUST register Model
                self.register_common_analysis_model(channel_id, model)

                # Add to Signal Capture Aggregator
                self.logger.debug(
                    f"Adding OFDM RxMER Channel: {channel_id} for aggregated signal capture"
                )
                self._sig_cap_agg.add_series(
                    cast(ArrayLike, x_raw), cast(ArrayLike, y_raw)
                )

                return True, ""
            except Exception as exc:
                return False, str(exc)

        for idx, data in enumerate(analysis_models):
            success, error_msg = process_single_model(idx, data)
            if not success:
                self.logger.exception(
                    "Failed to process RxMER item %d: %s", idx, error_msg
                )

        # Finalize signal capture aggregation
        self._sig_cap_agg.reconstruct()

    def __modulation_order_count_to_series(
        self, mod_count: Mapping[str, int]
    ) -> tuple[IntSeries, IntSeries]:
        """
        Convert {"qam_<M>": count} → (bits_per_symbol_series, count_series),
        sorted by ascending QAM order M. Skips malformed entries with warnings.

        Returns
        -------
        (order_bits, order_counts) : Tuple[IntSeries, IntSeries]
            - order_bits[i]   = bits per symbol for QAM-M_i (e.g., log2(M_i))
            - order_counts[i] = count for that modulation
        """
        if not mod_count:
            return [], []

        items = []  # (M, bits_per_symbol, count)

        for key, cnt in mod_count.items():
            # extract numeric order M from key (e.g., "qam_4096", "QAM-64", "qam4096")
            m = None
            if isinstance(key, str):
                m_match = re.search(r"(\d+)", key)
                if m_match:
                    with contextlib.suppress(Exception):
                        m = int(m_match.group(1))
            if m is None:
                self.logger.warning("Skipping unsupported modulation key: %r", key)
                continue

            try:
                c_int = int(cnt)
            except Exception:
                self.logger.warning("Non-integer count for %s: %r", key, cnt)
                continue
            if c_int < 0:
                self.logger.warning(
                    "Negative count for %s (%d); clamping to 0", key, c_int
                )
                c_int = 0

            # compute bits/symbol via your Shannon helper
            try:
                bps = int(
                    Shannon.bits_from_symbol_count(m)
                )  # ensure int for powers-of-two M
            except Exception as e:
                self.logger.warning("Unable to compute bits/symbol for %s: %s", key, e)
                continue

            items.append((m, bps, c_int))

        if not items:
            return [], []

        items.sort(key=lambda t: t[0])  # sort by QAM order M

        order_bits: IntSeries = [bps for _, bps, _ in items]
        order_counts: IntSeries = [c for _, _, c in items]

        self.logger.debug(f"Modulation order series: {order_bits}")
        self.logger.debug(f"Modulation order series: {order_counts}")

        return order_bits, order_counts
