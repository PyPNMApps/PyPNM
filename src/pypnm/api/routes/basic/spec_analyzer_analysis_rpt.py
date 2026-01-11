# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
from typing import cast

from pydantic import BaseModel, ConfigDict, Field

from pypnm.api.routes.basic.abstract.analysis_report import (
    AnalysisReport,
    AnalysisRptMatplotConfig,
)
from pypnm.api.routes.basic.abstract.base_models.common_analysis import CommonAnalysis
from pypnm.api.routes.common.classes.analysis.analysis import Analysis
from pypnm.api.routes.common.classes.analysis.model.spectrum_analyzer_schema import (
    SpectrumAnalyzerAnalysisModel,
)
from pypnm.lib.csv.manager import CSVManager
from pypnm.lib.matplot.manager import MatplotManager, PlotConfig
from pypnm.lib.types import ArrayLike, FloatSeries, FrequencySeriesHz


class SpecAnaWindowAvgRptModel(BaseModel):
    """Window-average metadata and values."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    window_size: int = Field(..., description="Number of points in the moving average.")
    windows_average: FloatSeries = Field(
        ..., description="Smoothed magnitudes (same length as frequency)."
    )
    length: int = Field(..., description="Number of samples.")


class SpectrumAnalyzerSignalProcessRptModel(BaseModel):
    """Per-point frequency, amplitude (dBmV), linear anti-log, and windowed average."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    frequencies: FrequencySeriesHz = Field(
        ..., description="Frequencies in Hz for each bin (all segments)."
    )
    amplitude: FloatSeries = Field(..., description="Magnitude per bin (dBmV).")
    anti_log: FloatSeries = Field(..., description="Linear ratio: 10^(dBmV/20).")
    window: SpecAnaWindowAvgRptModel = Field(
        ..., description="Moving-average for visualization."
    )


class SpectrumAnalyzerAnalysisRptModel(CommonAnalysis):
    """Spectrum Analyzer report model bound to a channel."""

    signal: SpectrumAnalyzerSignalProcessRptModel = Field(
        ..., description="Signal data and smoothing."
    )


class SpectrumAnalyzerReport(AnalysisReport):
    """Builds CSV and plots from Spectrum Analyzer analysis results."""

    FNAME_TAG: str = "spec_analysis"

    def __init__(
        self,
        analysis: Analysis,
        analysis_matplot_config: AnalysisRptMatplotConfig | None = None,
        **kwargs: object,
    ) -> None:
        if analysis_matplot_config is None:
            analysis_matplot_config = AnalysisRptMatplotConfig()
        super().__init__(analysis, analysis_matplot_config)
        self.logger = logging.getLogger("SpectrumAnalyzerReport")
        self._results: dict[int, SpectrumAnalyzerAnalysisRptModel] = {}

    def create_csv(self, **kwargs: object) -> list[CSVManager]:
        """Emit CSV with columns: Frequency, Magnitude(dBmV), MovingAverage."""
        csv_mgr_list: list[CSVManager] = []

        for common_model in self.get_common_analysis_model():
            model = cast(SpectrumAnalyzerAnalysisRptModel, common_model)
            sig = model.signal

            try:
                csv_mgr: CSVManager = self.csv_manager_factory()
                csv_mgr.set_header(["Frequency", "Magnitude(dBmV)", "MovingAverage"])

                # Rows aligned by index
                for f_hz, mag_dbmv, ma in zip(
                    sig.frequencies,
                    sig.amplitude,
                    sig.window.windows_average,
                    strict=False,
                ):
                    csv_mgr.insert_row([f_hz, mag_dbmv, ma])

                csv_fname = self.create_csv_fname(tags=[self.FNAME_TAG])
                csv_mgr.set_path_fname(csv_fname)

                self.logger.debug(
                    "CSV created: %s (rows=%s)", csv_fname, csv_mgr.get_row_count()
                )
                csv_mgr_list.append(csv_mgr)

            except Exception as exc:
                self.logger.exception("Failed to create CSV: %s", exc, exc_info=True)

        return csv_mgr_list

    def create_matplot(self, **kwargs: object) -> list[MatplotManager]:
        """Create two figures per channel: raw spectrum and moving average."""
        out: list[MatplotManager] = []

        for common_model in self.get_common_analysis_model():
            m = cast(SpectrumAnalyzerAnalysisRptModel, common_model)
            sig = m.signal

            try:
                fname = self.create_png_fname(tags=[self.FNAME_TAG, "standard"])
                self.logger.debug("Creating Standard Spectrum Plot: %s", fname)

                cfg = PlotConfig(
                    title="Spectrum Analysis · Standard",
                    x=cast(ArrayLike, sig.frequencies),
                    y=cast(ArrayLike, sig.amplitude),
                    xlabel=None,
                    xlabel_base="Frequency",
                    x_tick_mode="unit",
                    x_unit_from="hz",
                    x_unit_out="mhz",
                    x_tick_decimals=0,
                    ylabel="dB",
                    grid=False,
                    legend=False,
                    transparent=False,
                    theme=self.getAnalysisRptMatplotConfig().theme,
                )

                mgr = MatplotManager(default_cfg=cfg)
                mgr.plot_line(filename=fname)
                out.append(mgr)

            except Exception as exc:
                self.logger.exception(
                    "Failed to create plot for (standard): %s", exc, exc_info=True
                )

            try:
                fname = self.create_png_fname(tags=[self.FNAME_TAG, "moving_average"])
                self.logger.debug("Creating Window Average Spectrum Plot: %s", fname)

                cfg = PlotConfig(
                    title=f"Spectrum Analysis · Moving Average n={sig.window.window_size}",
                    x=cast(ArrayLike, sig.frequencies),
                    y=cast(ArrayLike, sig.window.windows_average),
                    xlabel=None,
                    xlabel_base="Frequency",
                    x_tick_mode="unit",
                    x_unit_from="hz",
                    x_unit_out="mhz",
                    x_tick_decimals=0,
                    ylabel="dB",
                    grid=False,
                    legend=False,
                    transparent=False,
                    theme=self.getAnalysisRptMatplotConfig().theme,
                )

                mgr = MatplotManager(default_cfg=cfg)
                mgr.plot_line(filename=fname)
                out.append(mgr)

            except Exception as exc:
                self.logger.exception(
                    "Failed to create plot for (moving avg): %s", exc, exc_info=True
                )

        return out

    def _process(self) -> None:
        """Convert SpectrumAnalyzerAnalysisModel → SpectrumAnalyzerAnalysisRptModel per channel."""
        models: list[SpectrumAnalyzerAnalysisModel] = cast(
            list[SpectrumAnalyzerAnalysisModel], self.get_analysis_model()
        )

        for _idx, _model in enumerate(models):
            sig_analysis = _model.signal_analysis
            freq_hz: FrequencySeriesHz = [int(f) for f in sig_analysis.frequencies]
            mag_dbmv: FloatSeries = list(sig_analysis.magnitudes)
            ma_vals: FloatSeries = list(sig_analysis.window_average.magnitudes)

            # Anti-log in linear ratio (suitable for amplitude-like values)
            anti_log: FloatSeries = [10.0 ** (v / 20.0) for v in mag_dbmv]

            window = SpecAnaWindowAvgRptModel(
                window_size=sig_analysis.window_average.points,
                windows_average=ma_vals,
                length=len(ma_vals),
            )

            signal = SpectrumAnalyzerSignalProcessRptModel(
                frequencies=freq_hz,
                amplitude=mag_dbmv,
                anti_log=anti_log,
                window=window,
            )

            rpt = SpectrumAnalyzerAnalysisRptModel(
                channel_id=_model.channel_id,
                signal=signal,
            )

            self.register_common_analysis_model(_model.channel_id, rpt)
