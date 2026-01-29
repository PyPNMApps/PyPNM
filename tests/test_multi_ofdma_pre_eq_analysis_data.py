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
