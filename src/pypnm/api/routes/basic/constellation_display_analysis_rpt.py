# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
from typing import Any, cast

from pydantic import BaseModel, ConfigDict, Field

from pypnm.api.routes.basic.abstract.analysis_report import (
    AnalysisReport,
    AnalysisRptMatplotConfig,
)
from pypnm.api.routes.basic.abstract.base_models.common_analysis import CommonAnalysis
from pypnm.api.routes.basic.common.signal_capture_agg import SignalCaptureAggregator
from pypnm.api.routes.common.classes.analysis.analysis import Analysis
from pypnm.lib.constants import INVALID_CHANNEL_ID
from pypnm.lib.csv.manager import CSVManager
from pypnm.lib.matplot.manager import MatplotManager, PlotConfig
from pypnm.lib.qam.types import QamModulation
from pypnm.lib.types import ChannelId, ComplexArray


class ConstDisplayAnalysisRptMatplotConfig(AnalysisRptMatplotConfig):
    display_crosshair: bool = Field(
        default=True,
        description="Enable or disable crosshair on the constellation plot",
    )


class ConstellationDisplayParameters(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    modulation: QamModulation = Field(..., description="")
    hard: ComplexArray = Field(..., description="")
    soft: ComplexArray = Field(..., description="")
    sample_count: int = Field(..., description="")


class ConstellationDisplayAnalysisRptModel(CommonAnalysis):
    parameters: ConstellationDisplayParameters = Field(
        ..., description="Channel estimation analysis parameters and limits."
    )


class ConstellationDisplayReport(AnalysisReport):
    FNAME_TAG: str = "constdisplay"

    def __init__(
        self,
        analysis: Analysis,
        analysis_matplot_config: ConstDisplayAnalysisRptMatplotConfig | None = None,
        **kwargs: object,
    ) -> None:
        if analysis_matplot_config is None:
            analysis_matplot_config = ConstDisplayAnalysisRptMatplotConfig()
        super().__init__(analysis, analysis_matplot_config)
        self.logger = logging.getLogger("ConstellationDisplayReport")
        self._results: dict[int, ConstellationDisplayAnalysisRptModel] = {}
        self._sig_cap_agg: SignalCaptureAggregator = SignalCaptureAggregator()
        self._matplot_config: ConstDisplayAnalysisRptMatplotConfig = (
            analysis_matplot_config
        )

    def create_csv(self, **kwargs: object) -> list[CSVManager]:
        """
        Stream validated models into CSVs. Assumes `_process()` already enforced
        """
        csv_mgr_list: list[CSVManager] = []
        any_models = False

        for common_model in self.get_common_analysis_model():
            any_models = True
            model = cast(ConstellationDisplayAnalysisRptModel, common_model)
            channel_id = int(model.channel_id)
            modulation: QamModulation = model.parameters.modulation
            hard: ComplexArray = model.parameters.hard
            soft: ComplexArray = model.parameters.soft

            """
            Single Channel Capture
            """
            try:
                csv_mgr: CSVManager = self.csv_manager_factory()
                csv_fname = self.create_csv_fname(
                    tags=[str(channel_id), self.FNAME_TAG]
                )
                csv_mgr.set_path_fname(csv_fname)

                csv_mgr.set_header(
                    [
                        "ChannelID",
                        "Modulation",
                        "Hard(I)",
                        "Hard(Q)",
                        "Soft(I)",
                        "Soft(Q)",
                    ]
                )

                for h, s in zip(hard, soft, strict=False):
                    hard_real, hard_img = h
                    soft_real, soft_img = s
                    csv_mgr.insert_row(
                        [
                            channel_id,
                            modulation,
                            hard_real,
                            hard_img,
                            soft_real,
                            soft_img,
                        ]
                    )

                self.logger.debug(
                    f"CSV created for channel {channel_id}: {csv_fname} (rows={csv_mgr.get_row_count()})"
                )

                csv_mgr_list.append(csv_mgr)

            except Exception as exc:
                self.logger.exception(
                    f"Failed to create CSV for channel {channel_id}: {exc}"
                )

        if not any_models:
            self.logger.debug("No analysis data available; no CSVs created.")

        return csv_mgr_list

    def create_matplot(self, **kwargs: object) -> list[MatplotManager]:
        """
        Generate per-channel line and multi-line plots from validated models.
        """
        matplot_mgr: list[MatplotManager] = []
        any_models: bool = False

        for common_model in self.get_common_analysis_model():
            any_models = True
            model = cast(ConstellationDisplayAnalysisRptModel, common_model)
            channel_id = int(model.channel_id)
            modulation: QamModulation = model.parameters.modulation
            hard: ComplexArray = model.parameters.hard
            soft: ComplexArray = model.parameters.soft
            sample_count: int = model.parameters.sample_count

            """
            Constellation Display - All OFDM DS Channels
            """
            try:
                title = f"Constellation Display · OFDM Channel: {channel_id} · Modulation: {modulation.name} · SampleSize: {sample_count}"
                cfg = PlotConfig(
                    title=title,
                    x=[0],  # TODO: need to fix this, don't need to put in a dummy value
                    xlabel="In-phase (I)",
                    ylabel="Quadrature (Q)",
                    qam=modulation,
                    hard=hard,
                    soft=soft,
                    grid=False,
                    legend=True,
                    transparent=False,
                    show_crosshair=self._matplot_config.display_crosshair,
                    theme=self._matplot_config.theme,
                )

                const_disp = self.create_png_fname(
                    tags=[str(channel_id), self.FNAME_TAG]
                )
                self.logger.debug(
                    "Creating MatPlot: %s for channel: %s", const_disp, channel_id
                )

                mgr = MatplotManager(default_cfg=cfg)
                mgr.plot_constellation(filename=const_disp)

                matplot_mgr.append(mgr)

            except Exception as exc:
                self.logger.exception(
                    "Failed to create plot for channel %s: %s", channel_id, exc
                )

        if not any_models:
            self.logger.warning("No analysis data available; no plots created.")

        return matplot_mgr

    def _process(self) -> None:
        """
        Required input shape per item:
        {
            pnm_header          = measurement.get("pnm_header", {}),
            mac_address         = measurement.get("mac_address"),
            channel_id          = measurement.get("channel_id"),
            num_sample_symbols  = num_sample_symbols,
            modulation_order    = qm, # QamModulation
            hard                = hard,
            soft                = samples
        }

        """
        data_list: list[dict[str, Any]] = self.get_analysis_data() or []

        try:
            for _idx, data in enumerate(data_list):
                channel_id = int(data.get("channel_id", INVALID_CHANNEL_ID))
                modulation_order = data.get("modulation_order", QamModulation.UNKNOWN)
                hard = data.get("hard", [])
                soft = data.get("soft", [])
                sample_count = data.get("num_sample_symbols", 0)

                params = ConstellationDisplayParameters(
                    modulation=modulation_order,
                    hard=hard,
                    soft=soft,
                    sample_count=sample_count,
                )

                model = ConstellationDisplayAnalysisRptModel(
                    channel_id=ChannelId(channel_id),
                    raw_x=[0],
                    raw_y=[0],
                    parameters=params,
                )

                # Must register Model
                self.register_common_analysis_model(channel_id, model)

        except Exception as exc:
            self.logger.exception(
                f"Failed to process Channel Estimation data: Reason: {exc}"
            )
