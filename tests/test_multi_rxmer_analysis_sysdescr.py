# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pypnm.api.routes.advance.analysis.report.multi_analysis_rpt import MultiAnalysisRpt
from pypnm.api.routes.advance.analysis.signal_analysis.multi_rxmer_signal_analysis import (
    MultiRxMerAnalysisType,
    MultiRxMerSignalAnalysis,
)
from pypnm.api.routes.advance.common.transactionsCollection import TransactionCollection
from pypnm.api.routes.advance.multi_ds_chan_est.schemas import (
    AnalysisDataModel as DsAnalysisDataModel,
)
from pypnm.api.routes.advance.multi_ds_chan_est.schemas import (
    MultiChanEstimationAnalysisResponse,
)
from pypnm.api.routes.advance.multi_rxmer.schemas import MultiRxMerAnalysisResponse
from pypnm.api.routes.advance.multi_us_ofdma_pre_eq.schemas import (
    AnalysisDataModel as UsAnalysisDataModel,
)
from pypnm.api.routes.advance.multi_us_ofdma_pre_eq.schemas import (
    MultiUsOfdmaPreEqAnalysisResponse,
)
from pypnm.api.routes.common.classes.file_capture.types import TransactionRecordModel
from pypnm.docsis.data_type.sysDescr import SystemDescriptor
from pypnm.lib.types import TransactionId


class _FakeCaptureDataAggregator:
    def __init__(self, trans: TransactionCollection) -> None:
        self._trans = trans

    def collect(self) -> TransactionCollection:
        return self._trans


class _DummyMultiAnalysisRpt(MultiAnalysisRpt):
    def _process(self) -> None:
        return None

    def create_csv(self, **kwargs: object) -> list[object]:
        return []

    def create_matplot(self, **kwargs: object) -> list[object]:
        return []


def _record(txn_id: str, filename: str, sys_descr: SystemDescriptor) -> TransactionRecordModel:
    return TransactionRecordModel(
        transaction_id=TransactionId(txn_id),
        timestamp=1,
        mac_address="aa:bb:cc:dd:ee:ff",
        pnm_test_type="DS_OFDM_RXMER_PER_SUBCAR",
        filename=filename,
        device_details={"system_description": sys_descr.to_model().model_dump()},
    )


def test_multi_analysis_rpt_plucks_first_non_empty_sysdescr() -> None:
    trans = TransactionCollection()
    trans.add(_record("tx0", "empty.bin", SystemDescriptor.empty()), b"0")
    wanted = SystemDescriptor.parse(
        "<<HW_REV: 1.0; VENDOR: LANCity; BOOTR: NONE; SW_REV: 1.0.0; MODEL: LCPET-3>>"
    )
    trans.add(_record("tx1", "good.bin", wanted), b"1")

    rpt = _DummyMultiAnalysisRpt(_FakeCaptureDataAggregator(trans))

    sdm = rpt.get_system_description_model()
    assert sdm is not None
    assert sdm.MODEL == "LCPET-3"


def test_multi_analysis_rpt_returns_null_sysdescr_when_no_transactions() -> None:
    rpt = _DummyMultiAnalysisRpt(_FakeCaptureDataAggregator(TransactionCollection()))

    assert rpt.get_system_description_model() is None
    assert rpt.get_system_description().is_empty() is True


def test_multi_rxmer_signal_analysis_empty_collection_returns_error_model() -> None:
    engine = MultiRxMerSignalAnalysis(
        _FakeCaptureDataAggregator(TransactionCollection()),
        MultiRxMerAnalysisType.MIN_AVG_MAX,
    )

    model = engine.to_model()

    assert model.mac_address == "00:00:00:00:00:00"
    assert model.data == {}
    assert model.error


def test_multi_rxmer_analysis_response_allows_optional_system_description() -> None:
    resp = MultiRxMerAnalysisResponse(
        mac_address="aa:bb:cc:dd:ee:ff",
        status="success",
        message="ok",
        system_description=SystemDescriptor.parse(
            "<<HW_REV: 1.0; VENDOR: LANCity; BOOTR: NONE; SW_REV: 1.0.0; MODEL: LCPET-3>>"
        ).to_model(),
        data={},
    )

    assert resp.system_description is not None
    assert resp.system_description.MODEL == "LCPET-3"

    resp_none = MultiRxMerAnalysisResponse(
        mac_address="aa:bb:cc:dd:ee:ff",
        status="success",
        message="ok",
        system_description=None,
        data={},
    )
    assert resp_none.system_description is None


def test_system_descriptor_load_from_dict_marks_non_empty() -> None:
    sdm = SystemDescriptor.load_from_dict(
        {
            "HW_REV": "0B",
            "VENDOR": "Hitron Technologies",
            "BOOTR": "2022.01-MXL-v-4.0.369",
            "SW_REV": "8.5.0.0.1b4",
            "MODEL": "CGNDP4",
        }
    ).to_model()

    assert sdm.is_empty is False


def test_multi_ds_chan_est_analysis_response_allows_optional_system_description() -> None:
    resp = MultiChanEstimationAnalysisResponse(
        mac_address="aa:bb:cc:dd:ee:ff",
        status="success",
        message="ok",
        system_description=SystemDescriptor.parse(
            "<<HW_REV: 1.0; VENDOR: LANCity; BOOTR: NONE; SW_REV: 1.0.0; MODEL: LCPET-3>>"
        ).to_model(),
        data=DsAnalysisDataModel(analysis_type="MIN_AVG_MAX", results=[]),
    )
    assert resp.system_description is not None
    assert resp.system_description.MODEL == "LCPET-3"

    resp_none = MultiChanEstimationAnalysisResponse(
        mac_address="aa:bb:cc:dd:ee:ff",
        status="success",
        message="ok",
        data=DsAnalysisDataModel(analysis_type="MIN_AVG_MAX", results=[]),
    )
    assert resp_none.system_description is None


def test_multi_us_ofdma_preeq_analysis_response_allows_optional_system_description() -> None:
    resp = MultiUsOfdmaPreEqAnalysisResponse(
        mac_address="aa:bb:cc:dd:ee:ff",
        status="success",
        message="ok",
        system_description=SystemDescriptor.parse(
            "<<HW_REV: 1.0; VENDOR: LANCity; BOOTR: NONE; SW_REV: 1.0.0; MODEL: LCPET-3>>"
        ).to_model(),
        data=UsAnalysisDataModel(analysis_type="MIN_AVG_MAX", results=[]),
    )
    assert resp.system_description is not None
    assert resp.system_description.MODEL == "LCPET-3"

    resp_none = MultiUsOfdmaPreEqAnalysisResponse(
        mac_address="aa:bb:cc:dd:ee:ff",
        status="success",
        message="ok",
        data=UsAnalysisDataModel(analysis_type="MIN_AVG_MAX", results=[]),
    )
    assert resp_none.system_description is None
