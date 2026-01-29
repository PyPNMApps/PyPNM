## Agent Review Bundle Summary
- Goal: Emit plots for both Pre-Equalization and Last Pre-Equalization in multi OFDMA analysis runs.
- Changes: Added file-type filtering with dual plot generation, extended tests to cover dual outputs, and documented the fix in the FAQ.
- Files: src/pypnm/api/routes/advance/analysis/signal_analysis/multi_ofdma_pre_eq_signal_analysis.py; tests/test_multi_ofdma_pre_eq_analysis_data.py; docs/issues/index.md
- Tests: python3 -m compileall src; ruff check src; pytest -q
- Notes: pytest skipped hardware integration tests (PNM_CM_IT not set).

# FILE: /home/dev01/Projects/PyPNM/src/pypnm/api/routes/advance/analysis/signal_analysis/multi_ofdma_pre_eq_signal_analysis.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pypnm.api.routes.advance.analysis.signal_analysis.multi_ofdm_chan_signal_analysis import (
    ChannelComplexMap,
    ChannelFrequencyMap,
    ChannelOccupiedBwMap,
    MultiOfdmChanSignalAnalysis,
)
from pypnm.api.routes.advance.common.capture_data_aggregator import (
    CaptureDataAggregator,
)
from pypnm.api.routes.advance.common.transactionsCollection import (
    TransactionCollectionModel,
)
from pypnm.api.routes.common.classes.analysis.analysis import Analysis
from pypnm.api.routes.common.classes.analysis.model.schema import (
    UsOfdmaUsPreEqAnalysisModel,
)
from pypnm.lib.matplot.manager import MatplotManager
from pypnm.lib.types import (
    ChannelId,
    ComplexArray,
    FrequencyHz,
    FrequencySeriesHz,
    StringEnum,
)
from pypnm.pnm.parser.CmUsOfdmaPreEq import CmUsOfdmaPreEq
from pypnm.pnm.parser.pnm_file_type import PnmFileType


class MultiOfdmaPreEqAnalysisType(StringEnum):
    """Enumeration Of Supported Multi-OFDMA-Pre-EQ Analysis Types."""
    MIN_AVG_MAX         = "min-avg-max"
    GROUP_DELAY         = "group-delay"
    ECHO_DETECTION_IFFT = "echo-detection-ifft"


class MultiOfdmaPreEqSignalAnalysis(MultiOfdmChanSignalAnalysis):
    """Performs signal-quality analyses on grouped OFDMA Pre-EQ captures."""

    def __init__(self, capt_data_agg: CaptureDataAggregator, analysis_type: StringEnum) -> None:
        """
        Initialize Multi-OFDMA Pre-EQ analysis state.

        Parameters
        ----------
        capt_data_agg:
            Aggregator providing access to capture records for analysis.
        analysis_type:
            Requested analysis mode to run across the aggregated captures.
        """
        super().__init__(capt_data_agg, analysis_type)
        self._file_type_by_channel: dict[ChannelId, PnmFileType] = {}
        self._available_file_types: set[PnmFileType] = set()
        self._filter_file_type: PnmFileType | None = None

    def _parse_capture(
        self,
        tcm: TransactionCollectionModel,
    ) -> tuple[ChannelId, ComplexArray, FrequencySeriesHz, FrequencyHz, PnmFileType] | None:
        try:
            model = CmUsOfdmaPreEq(tcm.data).to_model()
            result: UsOfdmaUsPreEqAnalysisModel = Analysis.basic_analysis_us_ofdma_pre_equalization_from_model(model)

            try:
                file_type = PnmFileType.fromPnmHeaderModel(model.pnm_header)
            except KeyError as exc:
                self.logger.warning(f"OFDMA pre-eq unknown file type for {tcm.filename}: {exc}")
                file_type = PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS

            self._available_file_types.add(file_type)
            if self._filter_file_type is not None and file_type != self._filter_file_type:
                return None

        except Exception as e:
            self.logger.error(f"OFDMA pre-eq analysis parse failed: {e}")
            return None

        return (
            ChannelId(result.channel_id),
            result.carrier_values.complex,
            result.carrier_values.frequency,
            result.carrier_values.occupied_channel_bandwidth,
            file_type,
        )

    def _extract_channel_data(self) -> tuple[ChannelComplexMap, ChannelFrequencyMap, ChannelOccupiedBwMap]:
        """Collect OFDMA Pre-EQ capture data into analysis-ready maps."""
        channel_data: ChannelComplexMap = {}
        freqs: ChannelFrequencyMap = {}
        obw: ChannelOccupiedBwMap = {}
        self._file_type_by_channel = {}
        self._available_file_types = set()
        models = self._trans_collect.getTransactionCollectionModel()
        self.logger.info(f"OFDMA Pre-EQ captures: count={len(models)}")

        for tcm in models:
            parsed = self._parse_capture(tcm)
            if parsed is None:
                self.logger.info(f"OFDMA Pre-EQ parse skipped: file={tcm.filename} size={len(tcm.data)}")
                continue

            ch, complex_values, frequency, bandwidth, file_type = parsed
            self.logger.info(f"OFDMA Pre-EQ parsed: file={tcm.filename} ch={ch} carriers={len(complex_values)}")
            if complex_values:
                channel_data.setdefault(ch, []).append(complex_values)
            freqs[ch] = frequency
            obw[ch] = bandwidth
            existing = self._file_type_by_channel.get(ch)
            if existing is None:
                self._file_type_by_channel[ch] = file_type
            else:
                if existing != file_type:
                    self.logger.warning(
                        "OFDMA pre-eq file type mismatch: channel=%s existing=%s new=%s",
                        ch,
                        existing.name,
                        file_type.name,
                    )
                    if file_type == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE:
                        self._file_type_by_channel[ch] = file_type

        return channel_data, freqs, obw

    def _ordered_file_types(self) -> list[PnmFileType]:
        return [
            PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS,
            PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE,
        ]

    def _collect_available_file_types(self) -> list[PnmFileType]:
        if not self._available_file_types:
            self._extract_channel_data()
        return [ft for ft in self._ordered_file_types() if ft in self._available_file_types]

    def _set_file_type_filter(self, file_type: PnmFileType | None) -> None:
        self._filter_file_type = file_type
        self._results = None
        self._channel_data = None
        self._file_type_by_channel = {}
        self._available_file_types = set()

    def _plot_title_prefix(self, channel_id: ChannelId) -> str:
        """
        Return the plot title prefix based on the PNM file type for the channel.
        """
        file_type = self._file_type_by_channel.get(channel_id)
        if file_type == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE:
            return "US Last PreEqualization"
        return "US PreEqualization"

    def _plot_extra_tags(self, channel_id: ChannelId) -> list[str]:
        """
        Return filename tags based on the PNM file type for the channel.
        """
        file_type = self._file_type_by_channel.get(channel_id)
        if file_type == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE:
            return ["us-last-pre-eq"]
        return ["us-pre-eq"]

    def create_matplot(self, **kwargs: object) -> list[MatplotManager]:
        """
        Generate Matplotlib plots for both Pre-EQ and Last Pre-EQ captures when present.
        """
        file_types = self._collect_available_file_types()
        if not file_types:
            return super().create_matplot(**kwargs)

        plots: list[MatplotManager] = []
        original_filter = self._filter_file_type
        original_results = self._results
        original_channel_data = self._channel_data
        original_file_type_map = dict(self._file_type_by_channel)
        original_available = set(self._available_file_types)

        try:
            for file_type in file_types:
                self._set_file_type_filter(file_type)
                plots.extend(super().create_matplot(**kwargs))
        finally:
            self._filter_file_type = original_filter
            self._results = original_results
            self._channel_data = original_channel_data
            self._file_type_by_channel = original_file_type_map
            self._available_file_types = original_available

        return plots

# FILE: /home/dev01/Projects/PyPNM/tests/test_multi_ofdma_pre_eq_analysis_data.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

from pypnm.api.routes.advance.analysis.signal_analysis.multi_chan_est_singnal_analysis import (
    MultiChanEstAnalysisType,
)
from pypnm.api.routes.advance.analysis.signal_analysis.multi_ofdma_pre_eq_signal_analysis import (
    MultiOfdmaPreEqSignalAnalysis,
)
from pypnm.api.routes.advance.common.capture_data_aggregator import (
    CaptureDataAggregator,
)
from pypnm.api.routes.advance.common.transactionsCollection import (
    TransactionCollection,
)
from pypnm.api.routes.common.classes.file_capture.types import (
    DeviceDetailsModel,
    TransactionRecordModel,
)
from pypnm.docsis.cm_snmp_operation import SystemDescriptor
from pypnm.lib.types import FileName, MacAddressStr, TimestampSec, TransactionId

DATA_DIR: Path = Path(__file__).parent / "files"
US_PREEQ_PATH: Path = DATA_DIR / "us_pre_equalizer_coef.bin"
US_PREEQ_LAST_PATH: Path = DATA_DIR / "us_pre_equalizer_coef_last.bin"


class FakeCaptureDataAggregator(CaptureDataAggregator):
    def __init__(self, collection: TransactionCollection) -> None:
        self._collection = collection

    def collect(self) -> TransactionCollection:
        return self._collection


def _build_collection(data_path: Path, filename: str) -> TransactionCollection:
    collection = TransactionCollection()
    record = TransactionRecordModel(
        transaction_id  =   TransactionId("txn-1"),
        timestamp       =   TimestampSec(0),
        mac_address     =   MacAddressStr("aa:bb:cc:dd:ee:ff"),
        pnm_test_type   =   "us_pre_eq",
        filename        =   FileName(filename),
        device_details  =   DeviceDetailsModel(system_description=SystemDescriptor.empty().to_model()),
    )
    collection.add(record, data_path.read_bytes())
    return collection


def _build_dual_collection() -> TransactionCollection:
    collection = TransactionCollection()
    record = TransactionRecordModel(
        transaction_id  =   TransactionId("txn-1"),
        timestamp       =   TimestampSec(0),
        mac_address     =   MacAddressStr("aa:bb:cc:dd:ee:ff"),
        pnm_test_type   =   "us_pre_eq",
        filename        =   FileName("us_pre_equalizer_coef.bin"),
        device_details  =   DeviceDetailsModel(system_description=SystemDescriptor.empty().to_model()),
    )
    collection.add(record, US_PREEQ_PATH.read_bytes())
    record_last = TransactionRecordModel(
        transaction_id  =   TransactionId("txn-2"),
        timestamp       =   TimestampSec(1),
        mac_address     =   MacAddressStr("aa:bb:cc:dd:ee:ff"),
        pnm_test_type   =   "us_pre_eq_last",
        filename        =   FileName("us_pre_equalizer_coef_last.bin"),
        device_details  =   DeviceDetailsModel(system_description=SystemDescriptor.empty().to_model()),
    )
    collection.add(record_last, US_PREEQ_LAST_PATH.read_bytes())
    return collection


def test_multi_ofdma_pre_eq_extract_channel_data() -> None:
    collection = _build_collection(US_PREEQ_PATH, "us_pre_equalizer_coef.bin")
    analyzer = MultiOfdmaPreEqSignalAnalysis(
        FakeCaptureDataAggregator(collection),
        MultiChanEstAnalysisType.MIN_AVG_MAX,
    )

    channel_data, freqs, obw = analyzer._extract_channel_data()

    assert channel_data

    channel_id = next(iter(channel_data.keys()))
    assert channel_id in freqs
    assert channel_id in obw
    assert len(channel_data[channel_id]) >= 1
    assert freqs[channel_id]
    assert obw[channel_id] > 0


def test_multi_ofdma_pre_eq_matplot_title_pre_eq() -> None:
    collection = _build_collection(US_PREEQ_PATH, "us_pre_equalizer_coef.bin")
    analyzer = MultiOfdmaPreEqSignalAnalysis(
        FakeCaptureDataAggregator(collection),
        MultiChanEstAnalysisType.MIN_AVG_MAX,
    )

    plots = analyzer.create_matplot()

    assert plots
    title = plots[0].default_cfg.title
    assert title is not None
    assert title.startswith("US PreEqualization · Channel:")
    png_files = plots[0].get_png_files()
    assert png_files
    assert "us-pre-eq" in str(png_files[0])


def test_multi_ofdma_pre_eq_matplot_title_last_pre_eq() -> None:
    collection = _build_collection(US_PREEQ_LAST_PATH, "us_pre_equalizer_coef_last.bin")
    analyzer = MultiOfdmaPreEqSignalAnalysis(
        FakeCaptureDataAggregator(collection),
        MultiChanEstAnalysisType.MIN_AVG_MAX,
    )

    plots = analyzer.create_matplot()

    assert plots
    title = plots[0].default_cfg.title
    assert title is not None
    assert title.startswith("US Last PreEqualization · Channel:")
    png_files = plots[0].get_png_files()
    assert png_files
    assert "us-last-pre-eq" in str(png_files[0])


def test_multi_ofdma_pre_eq_matplot_includes_last_pre_eq() -> None:
    collection = _build_dual_collection()
    analyzer = MultiOfdmaPreEqSignalAnalysis(
        FakeCaptureDataAggregator(collection),
        MultiChanEstAnalysisType.MIN_AVG_MAX,
    )

    plots = analyzer.create_matplot()

    assert plots
    png_files = [str(png) for plot in plots for png in plot.get_png_files()]
    assert any("us-pre-eq" in name for name in png_files)
    assert any("us-last-pre-eq" in name for name in png_files)

# FILE: /home/dev01/Projects/PyPNM/docs/issues/index.md
# Reporting Issues

If you encounter a bug or unexpected behavior while using PyPNM, please report it
so we can investigate and resolve the issue. This document outlines the steps to
create a support bundle that captures the necessary data for debugging.

[REPORTING ISSUES](reporting-issues.md)

## Support Bundle Script

PyPNM includes a support bundle script that collects relevant logs, database
entries, and configuration files related to your issue. This script helps
sanitize sensitive information before sharing it with the PyPNM support team.

[Support Bundle Builder](support-bundle.md)

## FAQ

Q: Why is extension data missing after processing a PNM transaction record?  
A: Ensure the transaction record includes an `extension` mapping and that the update helper merges the extension into the PNM data before returning the result.

Q: Why does US PreEq SNMP retrieval log validation errors about missing fields?  
A: Some modems return sparse or empty entries for certain indices. Ensure the device supports the table and that the entry is populated; missing required fields will cause the entry to be skipped.

Q: Why do multi US OFDMA Pre-Equalization plots show a Channel Estimation title?  
A: Update to a build that includes the plot title fix; the title now reflects the PNM file type as US PreEqualization (PNN6) or US Last PreEqualization (PNN7).

Q: Why do US OFDMA Pre-Equalization analysis examples reject uppercase analysis types?  
A: The multi-capture analysis endpoints accept the string enum values (`min-avg-max`, `group-delay`, `echo-detection-ifft`) along with the standard analysis output structure.

Q: Why do multi US OFDMA Pre-Equalization plots only show Pre-Equalization data?  
A: Ensure both Pre-Equalization (PNN6) and Last Pre-Equalization (PNN7) files are present; the multi-capture plots now emit both sets when available.

## TODO

- Add or update a FAQ entry whenever an error is fixed so the resolution is documented.
- Add FAQ entries when SNMP validation errors are addressed to capture the resolution.
- Track FAQ updates for the US OFDMA Pre-Equalization plot title fix.
- Track FAQ updates for the US OFDMA Pre-Equalization analysis request format.
- Track FAQ updates for the US OFDMA Pre-Equalization dual plot output.
