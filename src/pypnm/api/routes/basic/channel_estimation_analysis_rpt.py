# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
import math
from typing import cast

import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from pypnm.api.routes.basic.abstract.analysis_report import (
    AnalysisReport,
    AnalysisRptMatplotConfig,
)
from pypnm.api.routes.basic.abstract.base_models.common_analysis import CommonAnalysis
from pypnm.api.routes.basic.common.signal_capture_agg import SignalCaptureAggregator
from pypnm.api.routes.common.classes.analysis.analysis import Analysis
from pypnm.api.routes.common.classes.analysis.model.schema import (
    ChanEstCarrierModel,
    DsChannelEstAnalysisModel,
)
from pypnm.lib.csv.manager import CSVManager
from pypnm.lib.matplot.manager import MatplotManager, PlotConfig
from pypnm.lib.signal_processing.db_linear_converter import DbLinearConverter
from pypnm.lib.signal_processing.linear_regression import LinearRegression1D
from pypnm.lib.signal_processing.magnitude_metrics import compute_magnitude_summary
from pypnm.lib.types import (
    ArrayLike,
    ChannelId,
    ComplexArray,
    FloatSeries,
    FrequencyHz,
    PathLike,
)


class ChanEstimationParametersRptModel(BaseModel):
    """
    Parameters that augment channel estimation analysis output.
    - regression_line : Per-subcarrier fitted values (ŷ) from linear regression over index domain
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    regression_line: FloatSeries = Field(
        ..., description="Regression fitted values per subcarrier"
    )
    group_delay: FloatSeries = Field(..., description="Group Delay")


class ChanEstimationAnalysisRptModel(CommonAnalysis):
    """
    Analysis view over channel estimation data (extends CommonAnalysis).
    """

    parameters: ChanEstimationParametersRptModel = Field(
        ..., description="Channel estimation analysis parameters and limits."
    )


class ChanEstimationReport(AnalysisReport):
    """Concrete report builder for channel estimation measurements."""

    FNAME_TAG = "chanest"

    def __init__(
        self,
        analysis: Analysis,
        analysis_matplot_config: AnalysisRptMatplotConfig | None = None,
    ) -> None:
        if analysis_matplot_config is None:
            analysis_matplot_config = AnalysisRptMatplotConfig()
        super().__init__(analysis, analysis_matplot_config)
        self.logger = logging.getLogger("ChanEstimationReport")
        self._results: dict[int, ChanEstimationAnalysisRptModel] = {}
        self._sig_cap_agg: SignalCaptureAggregator = SignalCaptureAggregator()

    def create_csv(self, **kwargs: object) -> list[CSVManager]:
        """
        Stream validated models into CSVs. Assumes `_process()` already enforced.
        """
        csv_mgr_list: list[CSVManager] = []
        any_models: bool = False

        for common_model in self.get_common_analysis_model():
            any_models = True
            model = cast(ChanEstimationAnalysisRptModel, common_model)
            chan = int(model.channel_id)

            freq: FrequencyHz = cast(FrequencyHz, model.raw_x)
            magnitude: FloatSeries = cast(FloatSeries, model.raw_y)
            ca: ComplexArray = model.raw_complex
            rl: FloatSeries = model.parameters.regression_line
            db: FloatSeries = DbLinearConverter.complex_to_db(ca)
            gd: FloatSeries = model.parameters.group_delay

            # Single Channel Capture
            try:
                csv_mgr: CSVManager = self.csv_manager_factory()
                csv_fname: PathLike = self.create_csv_fname(
                    tags=[str(chan), self.FNAME_TAG]
                )
                csv_mgr.set_path_fname(csv_fname)

                csv_mgr.set_header(
                    [
                        "ChannelID",
                        "Frequency(Hz)",
                        "Magnitude(Linear)",
                        "Magnitude(dB)",
                        "Regression(Linear)",
                        "Group Delay",
                        "Real",
                        "Imaginary",
                    ]
                )

                for rx, ry, reg, cdb, _rl_v, gd_v, cmp in zip(
                    freq, magnitude, rl, db, rl, gd, ca, strict=False
                ):
                    real, img = cmp
                    csv_mgr.insert_row([chan, rx, ry, cdb, reg, gd_v, real, img])

                self.logger.info(
                    "CSV created for channel %s: %s (rows=%d)",
                    chan,
                    csv_fname,
                    len(freq),
                )
                csv_mgr_list.append(csv_mgr)

            except Exception as exc:
                self.logger.exception(
                    "Failed to create CSV for channel %s: %s", chan, exc
                )

        if not any_models:
            self.logger.info("No analysis data available; no CSVs created.")

        return csv_mgr_list

    def create_matplot(self, **kwargs: object) -> list[MatplotManager]:
        """
        Generate per-channel line and multi-line plots from validated models.
        """
        # Lazy import to avoid changing module-level imports
        from pypnm.api.routes.advance.analysis.signal_analysis.detection.echo.echo_detector import (
            EchoDetector,
        )

        matplot_mgr: list[MatplotManager] = []
        any_models: bool = False
        chan_id_list: list[ChannelId] = []

        for common_model in self.get_common_analysis_model():
            any_models = True
            model = cast(ChanEstimationAnalysisRptModel, common_model)
            channel_id = model.channel_id
            chan_id_list.append(channel_id)

            freq = cast(ArrayLike, model.raw_x)
            linear = cast(ArrayLike, model.raw_y)
            cplex: ComplexArray = model.raw_complex
            rl = cast(ArrayLike, model.parameters.regression_line)
            gd_us = cast(ArrayLike, model.parameters.group_delay)

            # Absolute dB view; no normalization
            db = cast(ArrayLike, DbLinearConverter.complex_to_db(cplex))

            title_prefix = f"Channel Estimation · Channel: {channel_id}"

            # IQ scatter
            try:
                if not cplex:
                    self.logger.warning(
                        "No complex samples; skipping IQ scatter for channel %s",
                        channel_id,
                    )
                else:
                    i, q = zip(*cplex, strict=False)
                    max_abs = max(
                        max(abs(v) for v in i) if i else 0.0,
                        max(abs(v) for v in q) if q else 0.0,
                    )
                    pad = 0.05 * max_abs if max_abs > 0 else 1.0
                    xlim = (-max_abs - pad, max_abs + pad)
                    ylim = (-max_abs - pad, max_abs + pad)

                    cfg = PlotConfig(
                        title=f"{title_prefix} · IQ Scatter Plot",
                        x=list(i),
                        y=list(q),
                        x_tick_decimals=0,
                        xlabel="In-Phase",
                        ylabel="Quadrature",
                        xlim=xlim,
                        ylim=ylim,
                        grid=True,
                        legend=False,
                        transparent=False,
                        scatter_size=1.0,
                        theme=self.getAnalysisRptMatplotConfig().theme,
                    )

                    fn_iq = self.create_png_fname(
                        tags=[str(channel_id), self.FNAME_TAG, "iq_scatter"]
                    )
                    self.logger.info(
                        "Creating MatPlot IQ scatter: %s for channel: %s",
                        fn_iq,
                        channel_id,
                    )

                    mgr = MatplotManager(default_cfg=cfg)
                    mgr.plot_scatter(filename=fn_iq)
                    matplot_mgr.append(mgr)

            except Exception as exc:
                self.logger.exception(
                    "Failed to create IQ scatter for channel %s: %s", channel_id, exc
                )

            # Linear + regression
            try:
                cfg = PlotConfig(
                    title=f"{title_prefix} · Linear with Regression Line",
                    x=freq,
                    x_tick_mode="unit",
                    x_unit_from="hz",
                    x_unit_out="mhz",
                    x_tick_decimals=0,
                    xlabel_base="Frequency",
                    y_multi=[linear, rl],
                    y_multi_label=["Channel Estimation", "Regression Line"],
                    ylabel="Linear",
                    grid=True,
                    legend=True,
                    transparent=False,
                    theme=self.getAnalysisRptMatplotConfig().theme,
                )

                multi = self.create_png_fname(
                    tags=[str(channel_id), self.FNAME_TAG, "linear"]
                )
                self.logger.info(
                    "Creating MatPlot: %s for channel: %s", multi, channel_id
                )

                mgr = MatplotManager(default_cfg=cfg)
                mgr.plot_multi_line(filename=multi)
                matplot_mgr.append(mgr)

            except Exception as exc:
                self.logger.exception(
                    "Failed to create plot for channel %s: %s", channel_id, exc
                )

            # dB view
            try:
                cfg = PlotConfig(
                    title=f"{title_prefix} · Standard (dB)",
                    x=freq,
                    x_tick_mode="unit",
                    x_unit_from="hz",
                    x_unit_out="mhz",
                    x_tick_decimals=0,
                    xlabel_base="Frequency",
                    y_multi=[db],
                    y_multi_label=["Channel Estimation"],
                    ylabel="dB",
                    grid=True,
                    legend=True,
                    transparent=False,
                    theme=self.getAnalysisRptMatplotConfig().theme,
                )

                multi = self.create_png_fname(
                    tags=[str(channel_id), self.FNAME_TAG, "db"]
                )
                self.logger.info(
                    "Creating MatPlot: %s for channel: %s", multi, channel_id
                )

                mgr = MatplotManager(default_cfg=cfg)
                mgr.plot_multi_line(filename=multi)
                matplot_mgr.append(mgr)

            except Exception as exc:
                self.logger.exception(
                    "Failed to create plot for channel %s: %s", channel_id, exc
                )

            # Best-Fit (dB) and Residuals
            try:
                metrics = compute_magnitude_summary(
                    cast(FrequencyHz, model.raw_x), cplex
                )
                yhat_db = cast(ArrayLike, metrics.fitted_line_db)

                cfg = PlotConfig(
                    title=f"Channel Estimation (dB) with Best-Fit - Ch {channel_id}  "
                    f"(m={metrics.slope_db_per_mhz:.4f} dB/MHz, "
                    f"Rrms={metrics.rms_ripple_db:.3f} dB, "
                    f"Rpp={metrics.p2p_ripple_db:.3f} dB)",
                    x=freq,
                    x_tick_mode="unit",
                    x_unit_from="hz",
                    x_unit_out="mhz",
                    x_tick_decimals=0,
                    xlabel_base="Frequency",
                    y_multi=[db, yhat_db],
                    y_multi_label=["Measured (dB)", "Best-Fit (dB)"],
                    ylabel="dB",
                    grid=True,
                    legend=True,
                    transparent=False,
                    theme=self.getAnalysisRptMatplotConfig().theme,
                )

                multi = self.create_png_fname(
                    tags=[str(channel_id), self.FNAME_TAG, "dbfit"]
                )
                self.logger.info(
                    "Creating MatPlot (dB fit): %s for channel: %s", multi, channel_id
                )

                mgr = MatplotManager(default_cfg=cfg)
                mgr.plot_multi_line(filename=multi)
                matplot_mgr.append(mgr)

                # Residuals (dB)
                residuals = cast(
                    ArrayLike,
                    [
                        d - h
                        for d, h in zip(cast(list[float], db), yhat_db, strict=False)
                    ],
                )

                cfg = PlotConfig(
                    title=f"Residual Ripple (dB) - OFDM Channel: {channel_id}  "
                    f"(Rrms={metrics.rms_ripple_db:.3f} dB, "
                    f"Rpp={metrics.p2p_ripple_db:.3f} dB)",
                    x=freq,
                    x_tick_mode="unit",
                    x_unit_from="hz",
                    x_unit_out="mhz",
                    x_tick_decimals=0,
                    xlabel_base="Frequency",
                    y=residuals,
                    ylabel="dB",
                    grid=True,
                    legend=False,
                    transparent=False,
                    theme=self.getAnalysisRptMatplotConfig().theme,
                )

                fname = self.create_png_fname(
                    tags=[str(channel_id), self.FNAME_TAG, "dbresid"]
                )
                self.logger.info(
                    "Creating Residual Ripple MatPlot: %s for channel: %s",
                    fname,
                    channel_id,
                )

                mgr = MatplotManager(default_cfg=cfg)
                mgr.plot_line(filename=fname)
                matplot_mgr.append(mgr)

            except Exception as exc:
                self.logger.exception(
                    "Failed to create best-fit/residual plots for channel %s: %s",
                    channel_id,
                    exc,
                )

            # Group Delay
            try:
                cfg = PlotConfig(
                    title=f"{title_prefix} · Group Delay",
                    x=freq,
                    x_tick_mode="unit",
                    x_unit_from="hz",
                    x_unit_out="mhz",
                    xlabel_base="Frequency",
                    y=gd_us,
                    ylabel="uS",
                    grid=True,
                    legend=False,
                    transparent=False,
                    theme=self.getAnalysisRptMatplotConfig().theme,
                )

                multi = self.create_png_fname(
                    tags=[str(channel_id), self.FNAME_TAG, "groupdelay"]
                )
                self.logger.info(
                    "Creating Group Delay MatPlot: %s for channel: %s",
                    multi,
                    channel_id,
                )

                mgr = MatplotManager(default_cfg=cfg)
                mgr.plot_line(filename=multi)
                matplot_mgr.append(mgr)

            except Exception as exc:
                self.logger.exception(
                    "Failed to create plot for channel %s: %s", channel_id, exc
                )

            # IFFT Time Response via EchoDetector (no local IFFT math here)
            try:
                if not cplex or len(cplex) < 2 or len(freq) < 2:
                    self.logger.info(
                        "Insufficient samples for IFFT plot; channel=%s", channel_id
                    )
                else:
                    # Infer Δf from frequency axis (median step, Hz)
                    diffs = [
                        abs(float(freq[i + 1]) - float(freq[i]))
                        for i in range(min(len(freq) - 1, len(cplex) - 1))
                    ]
                    if not diffs:
                        raise ValueError(
                            "Unable to infer Δf from frequency axis for IFFT plot."
                        )
                    df_hz = float(np.median(diffs))

                    det = EchoDetector(
                        freq_data=cplex,  # (N,2) real/imag pairs are supported
                        subcarrier_spacing_hz=df_hz,
                        n_fft=None,  # use default (next pow2 ≥ N, min 1024)
                        cable_type="RG6",
                        channel_id=channel_id,
                    )

                    tr = det.time_response(
                        window="hann", direct_at_zero=True, normalize_power=True
                    )
                    time_axis_us: list[float] = [t * 1e6 for t in tr.time_axis_s]
                    mag_list: list[float] = tr.time_response

                    cfg = PlotConfig(
                        title=f"{title_prefix} · IFFT Time Response |h(t)|"
                        f"(fs={det.fs / 1e6:.3f} MHz, n_fft={det.nfft})",
                        x=time_axis_us,
                        xlabel="Time (µs)",
                        y=mag_list,
                        ylabel="Magnitude (linear)",
                        grid=True,
                        legend=False,
                        transparent=False,
                        theme=self.getAnalysisRptMatplotConfig().theme,
                    )

                    fname = self.create_png_fname(
                        tags=[str(channel_id), self.FNAME_TAG, "ifft"]
                    )
                    self.logger.info(
                        "Creating IFFT Time Response MatPlot: %s for channel: %s",
                        fname,
                        channel_id,
                    )

                    mgr = MatplotManager(default_cfg=cfg)
                    mgr.plot_line(filename=fname)
                    matplot_mgr.append(mgr)

            except Exception as exc:
                self.logger.exception(
                    "Failed to create IFFT time-response plot for channel %s: %s",
                    channel_id,
                    exc,
                )

        if not any_models:
            self.logger.info("No analysis data available; no plots created.")

        return matplot_mgr

    def _process(self) -> None:
        """
        Normalize validated `DsChannelEstAnalysisModel` items into `ChanEstimationAnalysis`
        and register them for reporting/plotting.
        """
        data_list: list[DsChannelEstAnalysisModel] = cast(
            list[DsChannelEstAnalysisModel], self.get_analysis_model()
        )

        # Coerce -> float and ensure finiteness
        def coerce_finite(seq: ArrayLike, name: str) -> list[float]:
            out: list[float] = []
            for v in seq:
                fv = float(v)
                if not math.isfinite(fv):
                    raise ValueError(f"non-finite {name} value: {v!r}")
                out.append(fv)
            return out

        for idx, data in enumerate(data_list):
            # Pull strongly-typed fields directly from BaseModel
            channel_id: ChannelId = data.channel_id

            # Carrier values block
            cv: ChanEstCarrierModel = cast(ChanEstCarrierModel, data.carrier_values)
            x_raw: FloatSeries = list(cv.frequency)
            y_raw: FloatSeries = list(cv.magnitudes)
            cplex: ComplexArray = list(cv.complex)
            group_delay: FloatSeries = list(cv.group_delay.magnitude)

            try:
                x: FloatSeries = coerce_finite(x_raw, "raw_x")
                y: FloatSeries = coerce_finite(y_raw, "raw_y")
            except (ValueError, TypeError) as exc:
                self.logger.exception(
                    "Failed to process Channel Estimation item %d: Reason: %s", idx, exc
                )
                continue

            try:
                y_hat: FloatSeries = cast(
                    FloatSeries, LinearRegression1D(cast(ArrayLike, y)).fitted_values()
                )
            except Exception as exc:
                self.logger.exception(
                    "Failed to compute regression for item %d: Reason: %s", idx, exc
                )
                continue

            params = ChanEstimationParametersRptModel(
                regression_line=y_hat,
                group_delay=group_delay,
            )

            model = ChanEstimationAnalysisRptModel(
                channel_id=channel_id,
                raw_x=x,
                raw_y=y,
                raw_complex=cplex,
                parameters=params,
            )

            # Register model for downstream CSV/plot generation
            self.register_common_analysis_model(channel_id, model)

            # Add to Signal Capture Aggregator
            self.logger.debug(
                "Adding Channel Estimation, ChannelID: %s for aggregated signal capture",
                channel_id,
            )
            self._sig_cap_agg.add_series(cast(ArrayLike, x), cast(ArrayLike, y))

        # Finalize signal capture aggregation
        self._sig_cap_agg.reconstruct()
