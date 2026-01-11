# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from typing import cast

from pydantic import BaseModel, ConfigDict, Field

from pypnm.api.routes.basic.abstract.analysis_report import (
    AnalysisReport,
    AnalysisRptMatplotConfig,
)
from pypnm.api.routes.basic.abstract.base_models.common_analysis import CommonAnalysis
from pypnm.api.routes.common.classes.analysis.analysis import (
    Analysis,
    DsHistogramAnalysisModel,
)
from pypnm.lib.constants import INVALID_CHANNEL_ID, T
from pypnm.lib.csv.manager import CSVManager
from pypnm.lib.matplot.manager import MatplotManager, PlotConfig
from pypnm.lib.types import ArrayLike, ChannelId, FloatSeries, IntSeries


class DsHistrogramParameters(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    symmetry: int = Field(
        ..., description="Histogram symmetry flag (implementation-defined)"
    )
    dwell_counts: IntSeries = Field(
        ..., description="Total capture dwell count in samples"
    )
    hit_counts: IntSeries = Field(
        default_factory=list, description="Histogram bin hit counts (one value per bin)"
    )


class DsHistrogramAnalysisRpt(CommonAnalysis):
    parameters: DsHistrogramParameters = Field(
        ..., description="Downstream Histogram parameters and bin counts"
    )


class DsHistrogramReport(AnalysisReport):
    """
    Build CSV and Matplotlib artifacts for Downstream Histogram analysis.

    This report consumes `DsHistogramAnalysisModel` items from `Analysis`, normalizes them
    into `DsHistrogramAnalysisRpt` per-channel models, and emits:
      - One CSV per channel with per-bin hit counts and metadata.
      - One PNG histogram per channel (options via kwargs to `create_matplot`).
    """

    FNAME_TAG: str = "DsHistrogram"

    def __init__(
        self,
        analysis: Analysis,
        analysis_matplot_config: AnalysisRptMatplotConfig | None = None,
        **kwargs: object,
    ) -> None:
        """
        Initialize the report builder.

        Parameters
        ----------
        analysis : Analysis
            Source analysis instance providing `DsHistogramAnalysisModel` items.
        analysis_matplot_config : AnalysisRptMatplotConfig
            Theme and rendering options used by downstream plots.
        """
        if analysis_matplot_config is None:
            analysis_matplot_config = AnalysisRptMatplotConfig()
        super().__init__(analysis, analysis_matplot_config)
        self.logger = logging.getLogger(f"{self.__class__.__name__}")
        self._results: dict[int, DsHistrogramAnalysisRpt] = {}

    def create_csv(self, **kwargs: object) -> list[CSVManager]:
        """
        Emit one CSV per channel; rows are (ChannelID, BinIndex, HitCount, Symmetry, DwellCount).

        Returns
        -------
        List[CSVManager]
            Managers with headers, rows, and target filenames set. The caller can persist them.
        """
        csv_mgr_list: list[CSVManager] = []

        for common_model in self.get_common_analysis_model():
            model = cast(DsHistrogramAnalysisRpt, common_model)
            channel_id: int = int(model.channel_id)
            symmetry: int = int(model.parameters.symmetry)
            dwell_counts: IntSeries = list(model.parameters.dwell_counts)
            hit_counts: IntSeries = list(model.parameters.hit_counts)

            try:
                csv_mgr: CSVManager = self.csv_manager_factory()
                csv_mgr.set_header(
                    ["ChannelID", "BinIndex", "HitCount", "Symmetry", "DwellCount"]
                )
                csv_fname = self.create_csv_fname(
                    tags=[str(channel_id), self.FNAME_TAG]
                )
                csv_mgr.set_path_fname(csv_fname)

                for idx, hit in enumerate(hit_counts):
                    csv_mgr.insert_row(
                        [channel_id, idx, int(hit), symmetry, dwell_counts]
                    )

                csv_mgr_list.append(csv_mgr)

            except Exception as exc:
                self.logger.exception(
                    f"Failed to create CSV for channel {channel_id}: {exc}",
                    exc_info=True,
                )

        return csv_mgr_list

    def create_matplot(
        self,
        *,
        normalized: bool = False,
        cumulative: bool = False,
        orientation: str = "vertical",
        histtype: str = "bar",
        align: str = "mid",
        label: str | None = None,
        bins: int | Sequence[float] | None = None,
        **kwargs: object,
    ) -> list[MatplotManager]:
        """
        Render a per-channel histogram using `MatplotManager.plot_histogram` and pre-binned counts.

        Keyword Args
        ------------
        normalized : bool
            If True, render probability density (fractions). Default False.
        cumulative : bool
            If True, render cumulative histogram. Default False.
        orientation : str
            "vertical" (default) or "horizontal".
        histtype : str
            One of {"bar", "step", "stepfilled", "barstacked"}. Default "bar".
        align : str
            "mid" | "left" | "right". Default "mid".
        bins : int | Sequence[number]
            Optional override for bin edges/count. By default uses unit-width bins per hit_counts entry.
        label : str | None
            Optional legend label.

        Returns
        -------
        List[MatplotManager]
            Plot managers with PNGs saved to disk and file paths tracked.
        """
        out: list[MatplotManager] = []

        # Normalize and validate incoming parameters
        orientation = str(orientation).lower()
        histtype = str(histtype)
        align = str(align)
        normalized = bool(normalized)
        cumulative = bool(cumulative)
        bins_override = bins

        for common_model in self.get_common_analysis_model():
            model = cast(DsHistrogramAnalysisRpt, common_model)
            channel_id: ChannelId = ChannelId(model.channel_id)
            hit_counts: FloatSeries = [
                float(v) for v in (model.parameters.hit_counts or [])
            ]

            if not hit_counts:
                continue

            bin_indices: FloatSeries = [float(i) for i in range(len(hit_counts))]
            default_edges: FloatSeries = [float(i) for i in range(len(hit_counts) + 1)]
            bins_arg = bins_override if bins_override is not None else default_edges

            title = "Downstream Histogram"
            xlabel = "Bin Index"
            ylabel = "Hit Count"
            if normalized and not cumulative:
                ylabel = "Fraction"
            elif not normalized and cumulative:
                ylabel = "Cumulative Count"
            elif normalized and cumulative:
                ylabel = "Cumulative Fraction"

            png_tags = [str(channel_id), self.FNAME_TAG]
            if normalized:
                png_tags.append("norm")
            if cumulative:
                png_tags.append("cum")
            if orientation == "horizontal":
                png_tags.append("h")

            png = self.create_png_fname(tags=png_tags)

            cfg = PlotConfig(
                title=title,
                x=cast(ArrayLike, bin_indices),
                xlabel=xlabel,
                y=cast(ArrayLike, hit_counts),
                ylabel=ylabel,
                grid=True,
                legend=False,
                transparent=False,
                theme=self.getAnalysisRptMatplotConfig().theme,
            )

            mgr = MatplotManager(default_cfg=cfg)
            mgr.plot_histogram(
                data=cast(ArrayLike, bin_indices),
                filename=png,
                bins=bins_arg,
                density=normalized,
                weights=cast(ArrayLike, hit_counts),
                orientation=orientation,
                cumulative=cumulative,
                histtype=histtype,
                align=align,
                label=label,
                cfg=cfg,
            )
            out.append(mgr)

        return out

    def _process(self) -> None:
        """
        Normalize `DsHistogramAnalysisModel` items into `DsHistrogramAnalysisRpt` records.

        Expected input shape (illustrative):
        {
            "channel_id": int,
            "symmetry": int,
            "dwell_count": int,
            "hit_counts": List[int]
        }
        """
        models: list[DsHistogramAnalysisModel] = cast(
            list[DsHistogramAnalysisModel], self.get_analysis_model()
        )

        try:
            for _idx, src in enumerate(models):
                channel_id: ChannelId = ChannelId(
                    getattr(src, "channel_id", INVALID_CHANNEL_ID)
                )
                symmetry: int = int(src.symmetry)
                dwell_counts: IntSeries = list(src.dwell_counts)
                hit_counts: IntSeries = list(src.hit_counts)

                raw_x: IntSeries = list(range(len(hit_counts)))
                raw_y: IntSeries = hit_counts

                model = DsHistrogramAnalysisRpt(
                    channel_id=channel_id,
                    raw_x=raw_x,
                    raw_y=raw_y,
                    parameters=DsHistrogramParameters(
                        symmetry=symmetry,
                        dwell_counts=dwell_counts,
                        hit_counts=hit_counts,
                    ),
                )
                self.register_common_analysis_model(channel_id, model)

        except Exception as exc:
            self.logger.exception(
                f"Failed to process DS Histogram items: {exc}", exc_info=True
            )

    @staticmethod
    def _align_len(seq: Iterable[T] | list[T], n: int, *, fill: T) -> list[T]:
        """
        Ensure `seq` has length `n` by truncation or padding with `fill`.

        Parameters
        ----------
        seq : Iterable[T] | List[T]
            Source sequence.
        n : int
            Desired length.
        fill : T
            Pad value when `seq` is shorter than `n`.

        Returns
        -------
        List[T]
            Sequence of exactly length `n`.
        """
        lst = list(seq) if not isinstance(seq, list) else seq
        if n <= 0:
            return []
        if len(lst) >= n:
            return lst[:n]
        return lst + [fill] * (n - len(lst))
