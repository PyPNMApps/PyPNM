# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from types import SimpleNamespace

from pypnm.api.routes.advance.multi_ds_chan_est.router import MultiDsChanEstRouter
from pypnm.api.routes.advance.multi_ds_chan_est.schemas import (
    MultiChanEstAnalysisRequest,
)
from pypnm.api.routes.advance.multi_us_ofdma_pre_eq.router import (
    MultiUsOfdmaPreEqRouter,
)
from pypnm.api.routes.advance.multi_us_ofdma_pre_eq.schemas import (
    MultiUsOfdmaPreEqAnalysisRequest,
)


def _analysis_endpoint(router_obj: object) -> object:
    for route in router_obj.router.routes:
        if route.path.endswith("/analysis"):
            return route.endpoint
    raise AssertionError("analysis endpoint not found")


def test_multi_ds_chan_est_archive_skips_json_model_build(monkeypatch) -> None:
    router = MultiDsChanEstRouter()
    endpoint = _analysis_endpoint(router)
    release_calls: list[str] = []

    class FakeEngine:
        to_model_calls = 0
        build_report_calls = 0
        release_calls = 0

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def to_model(self) -> object:
            type(self).to_model_calls += 1
            raise AssertionError("archive path should not call to_model()")

        def build_report(self) -> SimpleNamespace:
            type(self).build_report_calls += 1
            return SimpleNamespace(name="chan-est.zip")

        def release_analysis_memory(self) -> None:
            type(self).release_calls += 1

    class FakePnmFileService:
        def get_file(self, *_args: object) -> str:
            return "archive:chan-est.zip"

    monkeypatch.setattr(
        "pypnm.api.routes.advance.multi_ds_chan_est.router.MultiChanEstimationSignalAnalysis",
        FakeEngine,
    )
    monkeypatch.setattr(
        "pypnm.api.routes.advance.multi_ds_chan_est.router.CaptureDataAggregator",
        lambda _capture_group_id: object(),
    )
    monkeypatch.setattr(
        "pypnm.api.routes.advance.multi_ds_chan_est.router.PnmFileService",
        FakePnmFileService,
    )
    monkeypatch.setattr(router, "_get_capture_group_or_none", lambda _operation_id: "cg-1")
    monkeypatch.setattr(
        router,
        "_repair_capture_group_from_service_samples",
        lambda _operation_id, _capture_group_id: None,
    )
    monkeypatch.setattr(
        router,
        "_release_operation_memory",
        lambda operation_id: release_calls.append(operation_id),
    )

    request = MultiChanEstAnalysisRequest.model_validate(
        {
            "operation_id": "op-1",
            "analysis": {
                "type": "min-avg-max",
                "output": {"type": "archive"},
                "plot": {"ui": {"theme": "dark"}},
            },
        },
    )

    response = endpoint(request)

    assert response == "archive:chan-est.zip"
    assert FakeEngine.to_model_calls == 0
    assert FakeEngine.build_report_calls == 1
    assert FakeEngine.release_calls == 1
    assert release_calls == ["op-1"]


def test_multi_us_pre_eq_archive_skips_json_model_build(monkeypatch) -> None:
    router = MultiUsOfdmaPreEqRouter()
    endpoint = _analysis_endpoint(router)
    release_calls: list[str] = []

    class FakeEngine:
        to_model_calls = 0
        build_report_calls = 0
        release_calls = 0

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def to_model(self) -> object:
            type(self).to_model_calls += 1
            raise AssertionError("archive path should not call to_model()")

        def build_report(self) -> SimpleNamespace:
            type(self).build_report_calls += 1
            return SimpleNamespace(name="us-pre-eq.zip")

        def release_analysis_memory(self) -> None:
            type(self).release_calls += 1

    class FakePnmFileService:
        def get_file(self, *_args: object) -> str:
            return "archive:us-pre-eq.zip"

    monkeypatch.setattr(
        "pypnm.api.routes.advance.multi_us_ofdma_pre_eq.router.MultiOfdmaPreEqSignalAnalysis",
        FakeEngine,
    )
    monkeypatch.setattr(
        "pypnm.api.routes.advance.multi_us_ofdma_pre_eq.router.CaptureDataAggregator",
        lambda _capture_group_id: object(),
    )
    monkeypatch.setattr(
        "pypnm.api.routes.advance.multi_us_ofdma_pre_eq.router.PnmFileService",
        FakePnmFileService,
    )
    monkeypatch.setattr(router, "_get_capture_group_or_none", lambda _operation_id: "cg-1")
    monkeypatch.setattr(
        router,
        "_repair_capture_group_from_service_samples",
        lambda _operation_id, _capture_group_id: None,
    )
    monkeypatch.setattr(
        router,
        "_release_operation_memory",
        lambda operation_id: release_calls.append(operation_id),
    )

    request = MultiUsOfdmaPreEqAnalysisRequest.model_validate(
        {
            "operation_id": "op-2",
            "analysis": {
                "type": "min-avg-max",
                "output": {"type": "archive"},
                "plot": {"ui": {"theme": "dark"}},
            },
        },
    )

    response = endpoint(request)

    assert response == "archive:us-pre-eq.zip"
    assert FakeEngine.to_model_calls == 0
    assert FakeEngine.build_report_calls == 1
    assert FakeEngine.release_calls == 1
    assert release_calls == ["op-2"]
