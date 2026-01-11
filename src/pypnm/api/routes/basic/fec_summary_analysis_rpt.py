# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from typing import cast

from pydantic import Field

from pypnm.api.routes.basic.abstract.analysis_report import (
    AnalysisReport,
    AnalysisRptMatplotConfig,
)
from pypnm.api.routes.basic.abstract.base_models.common_analysis import CommonAnalysis
from pypnm.api.routes.common.classes.analysis.analysis import Analysis
from pypnm.api.routes.common.classes.analysis.model.schema import (
    OfdmFecSummaryAnalysisModel,
)
from pypnm.lib.csv.manager import CSVManager
from pypnm.lib.matplot.manager import MatplotManager, PlotConfig
from pypnm.lib.types import ArrayLike, ChannelId, IntSeries, ScalarValue


class FecSummaryAnalysisRptModel(CommonAnalysis):
    """
    CommonAnalysis wrapper for OFDM FEC Summary outputs.

    Attributes
    ----------
    parameters : OfdmFecSummaryAnalysisModel
        Structured FEC summary model produced by the analysis layer.
    """

    parameters: OfdmFecSummaryAnalysisModel = Field(
        ...,
        description="Structured OFDM FEC summary model (per-channel, per-profile codeword time series).",
    )


class FecSummaryAnalysisReport(AnalysisReport):
    """
    Report generator for OFDM FEC Summary analysis.

    Responsibilities
    ----------------
    - Emit one CSV per channel/profile with time-series codeword counters.
    - Emit one PNG per channel/profile with Total/Corrected/Uncorrected curves.
    """

    FNAME_TAG: str = "FecSummary"

    def __init__(
        self,
        analysis: Analysis,
        analysis_matplot_config: AnalysisRptMatplotConfig | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize report generator and internal result registry."""
        if analysis_matplot_config is None:
            analysis_matplot_config = AnalysisRptMatplotConfig()
        super().__init__(analysis, analysis_matplot_config)
        self.logger = logging.getLogger(f"{self.__class__.__name__}")
        self._results: dict[int, FecSummaryAnalysisRptModel] = {}

    @staticmethod
    def _as_seq(x: ScalarValue | Sequence[ScalarValue] | None) -> list[ScalarValue]:
        """
        Convert scalar or sequence of scalars into a list of ScalarValue.

        Notes
        -----
        - None         → []
        - list/tuple   → list(x)
        - other scalar → [x]
        """
        if x is None:
            return []
        if isinstance(x, (list, tuple)):
            return list(x)
        try:
            return list(x)
        except Exception:
            return [x]

    @staticmethod
    def _get(obj: object, *names: str) -> object | None:
        """
        Retrieve the first matching attribute or mapping key from a set of candidates.

        Parameters
        ----------
        obj : Any
            Source object or mapping.
        *names : str
            Candidate attribute or key names to probe in order.

        Returns
        -------
        Any
            Value of the first attribute/key found, otherwise None.
        """
        for n in names:
            if hasattr(obj, n):
                return getattr(obj, n)
            if isinstance(obj, Mapping) and n in obj:
                return obj[n]
        return None

    def _resolve_profile(self, profile_entry: object) -> str:
        """
        Resolve a human-readable profile identifier string.

        Parameters
        ----------
        profile_entry : Any
            Profile entry object or mapping with one of: profile, profile_id, id.

        Returns
        -------
        str
            Profile identifier coerced to string (integer string when possible).
        """
        p = self._get(profile_entry, "profile", "profile_id", "id")
        try:
            return str(int(p))
        except Exception:
            return str(p) if p is not None else "unknown"

    def _resolve_codewords(
        self,
        profile_entry: object,
    ) -> tuple[list[ScalarValue], IntSeries, IntSeries, IntSeries, dict[str, int]]:
        """
        Resolve timestamp and codeword counter series from schema variants.

        Parameters
        ----------
        profile_entry : Any
            Profile entry containing codeword time-series data in one of several
            supported field layouts.

        Returns
        -------
        Tuple[List[ScalarValue], IntSeries, IntSeries, IntSeries, Dict[str, int]]
            - List[ScalarValue] : Timestamps (epoch seconds or formatted labels).
            - IntSeries         : Total codewords per timestamp.
            - IntSeries         : Corrected codewords per timestamp.
            - IntSeries         : Uncorrected codewords per timestamp.
            - Dict[str, int]    : Shape summary for logging (keys: ts, tc, cc, uc).
        """
        cw = self._get(
            profile_entry, "codewords", "codeword_entries", "entries", "codeword"
        )
        shape: dict[str, int] = {}
        candidates = [cw, self._get(cw, "values"), self._get(cw, "data")]

        ts: list[ScalarValue] = []
        tc: IntSeries = []
        cc: IntSeries = []
        uc: IntSeries = []
        for node in candidates:
            if node is None:
                continue
            ts = self._as_seq(self._get(node, "timestamps", "timestamp"))
            tc = [
                int(v)
                for v in self._as_seq(
                    self._get(node, "total_codewords", "total", "totals")
                )
            ]
            cc = [int(v) for v in self._as_seq(self._get(node, "corrected"))]
            uc = [int(v) for v in self._as_seq(self._get(node, "uncorrected"))]
            if any((ts, tc, cc, uc)):
                break

        shape["ts"] = len(ts)
        shape["tc"] = len(tc)
        shape["cc"] = len(cc)
        shape["uc"] = len(uc)
        return ts, tc, cc, uc, shape

    def _log_preview(
        self,
        ch: ChannelId,
        profile: str,
        ts: Sequence[ScalarValue],
        tc: Sequence[int],
        cc: Sequence[int],
        uc: Sequence[int],
    ) -> None:
        """
        Log a short preview of the first few samples for a channel/profile series.

        Parameters
        ----------
        ch : ChannelId
            Channel identifier.
        profile : str
            Profile identifier.
        ts : Sequence[ScalarValue]
            Timestamp sequence.
        tc : Sequence[int]
            Total codeword counts.
        cc : Sequence[int]
            Corrected codeword counts.
        uc : Sequence[int]
            Uncorrected codeword counts.
        """

        def head(
            seq: Sequence[ScalarValue | int], k: int = 5
        ) -> list[ScalarValue | int]:
            return list(seq[:k])

        self.logger.debug(
            "Preview ch=%s prof=%s ts[:5]=%s total[:5]=%s corr[:5]=%s unc[:5]=%s",
            int(ch),
            profile,
            head(ts),
            head(tc),
            head(cc),
            head(uc),
        )

    def create_csv(self, **kwargs: object) -> list[CSVManager]:
        """
        Produce CSV files with per-timestamp codeword counters for each channel/profile.

        Returns
        -------
        list[CSVManager]
            Managers pointing at the generated CSV files.
        """
        mgr_out: list[CSVManager] = []
        for common_model in self.get_common_analysis_model():
            c_model = cast(FecSummaryAnalysisRptModel, common_model)
            channel_id: int = int(c_model.channel_id)
            analysis_model = c_model.parameters
            profiles = getattr(analysis_model, "profiles", []) or []

            for profile_entry in profiles:
                profile = self._resolve_profile(profile_entry)
                ts, tc, cc, uc, shape = self._resolve_codewords(profile_entry)
                n = min(len(ts), len(tc), len(cc), len(uc))
                self.logger.debug(
                    "CSV series lengths ch=%s prof=%s shape=%s n=%d",
                    channel_id,
                    profile,
                    shape,
                    n,
                )
                if n == 0:
                    self.logger.warning(
                        "No data for Channel %s, Profile %s (timestamps/counters empty).",
                        channel_id,
                        profile,
                    )
                    continue

                try:
                    csv_mgr: CSVManager = self.csv_manager_factory()
                    csv_mgr.set_header(
                        [
                            "ChannelID",
                            "Profile",
                            "Timestamp",
                            "TotalCodewords",
                            "Corrected",
                            "Uncorrected",
                        ]
                    )
                    csv_fname = self.create_csv_fname(
                        tags=[str(channel_id), profile, self.FNAME_TAG]
                    )
                    csv_mgr.set_path_fname(csv_fname)
                    self._append_csv_rows(
                        csv_mgr=csv_mgr,
                        channel_id=channel_id,
                        profile=profile,
                        ts=ts,
                        tc=tc,
                        cc=cc,
                        uc=uc,
                        count=n,
                    )
                    self._log_preview(channel_id, profile, ts, tc, cc, uc)
                    self.logger.debug(
                        "CSV created ch=%s prof=%s -> %s (rows=%d)",
                        channel_id,
                        profile,
                        csv_fname,
                        csv_mgr.get_row_count(),
                    )
                    mgr_out.append(csv_mgr)
                except Exception as exc:
                    self.logger.exception(
                        "Failed to create CSV for channel %s (profile %s): %s",
                        channel_id,
                        profile,
                        exc,
                    )
        return mgr_out

    def _append_csv_rows(
        self,
        csv_mgr: CSVManager,
        channel_id: int,
        profile: str,
        ts: Sequence[ScalarValue],
        tc: Sequence[int],
        cc: Sequence[int],
        uc: Sequence[int],
        count: int,
    ) -> None:
        for idx in range(count):
            csv_mgr.insert_row(
                [channel_id, profile, ts[idx], tc[idx], cc[idx], uc[idx]]
            )

    def create_matplot(self, **kwargs: object) -> list[MatplotManager]:
        """
        Produce PNG plots (Total/Corrected/Uncorrected) for each channel/profile.

        Notes
        -----
        - X axis ticks are hidden.
        - A single human-readable time range ("start → end") is used as the xlabel.

        Returns
        -------
        list[MatplotManager]
            Managers used to generate and reference plot outputs.
        """
        mgr_out: list[MatplotManager] = []
        for common_model in self.get_common_analysis_model():
            c_model = cast(FecSummaryAnalysisRptModel, common_model)
            ch_id: ChannelId = ChannelId(c_model.channel_id)
            analysis_model = c_model.parameters
            profiles = getattr(analysis_model, "profiles", []) or []

            for profile_entry in profiles:
                profile = self._resolve_profile(profile_entry)
                ts, tc, cc, uc, shape = self._resolve_codewords(profile_entry)
                n = min(len(ts), len(tc), len(cc), len(uc))
                self.logger.debug(
                    "Plot series lengths ch=%s prof=%s shape=%s n=%d",
                    int(ch_id),
                    profile,
                    shape,
                    n,
                )
                if n == 0:
                    self.logger.warning(
                        "No data for Channel %s, Profile %s (timestamps/counters empty).",
                        int(ch_id),
                        profile,
                    )
                    continue

                try:
                    cfg = PlotConfig(
                        title=f"FEC Summary · OFDM · Channel {int(ch_id)} · Profile ({profile})",
                        x=cast(ArrayLike, ts[:n]),
                        ylabel="Codeword Count",
                        y_multi=[
                            cast(ArrayLike, tc[:n]),
                            cast(ArrayLike, cc[:n]),
                            cast(ArrayLike, uc[:n]),
                        ],
                        y_multi_label=["Total", "Corrected", "Uncorrected"],
                        grid=True,
                        legend=True,
                        transparent=False,
                        theme=self.getAnalysisRptMatplotConfig().theme,
                        line_colors=["tab:blue", "tab:green", "tab:red"],
                        # ── X-axis time range label & tick suppression ──
                        x_ticks_visible=False,  # hide all x ticks/labels
                        x_time_labels="from_to",  # render "start → end" as xlabel
                        x_time_input_unit="s",  # timestamps are epoch seconds
                        x_time_format="%Y-%m-%d %H:%M",  # adjust as needed
                        xlabel_prefix="Time Range: ",  # optional prefix before start→end
                    )

                    mgr = MatplotManager(default_cfg=cfg)
                    png_path = self.create_png_fname(
                        tags=[str(int(ch_id)), profile, self.FNAME_TAG]
                    )
                    self._log_preview(ch_id, profile, ts, tc, cc, uc)
                    self.logger.debug(
                        "Creating MatPlot: %s ch=%s prof=%s",
                        png_path,
                        int(ch_id),
                        profile,
                    )
                    mgr.plot_multi_line(filename=png_path)
                    mgr_out.append(mgr)
                except Exception as exc:
                    self.logger.exception(
                        "Failed to create plot for channel %s (profile %s): %s",
                        int(ch_id),
                        profile,
                        exc,
                    )
        return mgr_out

    def _process(self) -> None:
        """
        Register CommonAnalysis wrappers for each OfdmFecSummaryAnalysisModel.

        Expected
        --------
        The analysis model list is `list[OfdmFecSummaryAnalysisModel]`.
        """
        models: list[OfdmFecSummaryAnalysisModel] = cast(
            list[OfdmFecSummaryAnalysisModel], self.get_analysis_model()
        )
        for model in models:
            channel_id: int = int(model.channel_id)
            a_model = FecSummaryAnalysisRptModel(
                channel_id=channel_id, parameters=model
            )
            self.register_common_analysis_model(channel_id, a_model)
