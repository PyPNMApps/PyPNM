# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import pypnm.api.routes.advance.multi_rxmer.router as rxmer_router
from pypnm.api.routes.advance.common.operation_registry import OperationRegistry
from pypnm.api.routes.advance.multi_rxmer.router import router
from pypnm.lib.types import OperationId

_TEST_TIME_REMAINING: int = 123


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


def test_registry_status_endpoint_uses_service_time_remaining(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _StubService:
        def status(self, operation_id: OperationId) -> dict[str, int]:
            return {"time_remaining": _TEST_TIME_REMAINING}

    def _fake_status(operation_id: OperationId) -> object:
        return {
            "operation_id": str(operation_id),
            "state": "running",
            "created_ts": 1,
            "updated_ts": 1,
            "progress_current": 0,
            "progress_total": 1,
            "message": "Operation running",
            "error": None,
            "artifact_paths": None,
        }

    monkeypatch.setattr(
        rxmer_router.OperationWorkflowService,
        "get_status",
        staticmethod(_fake_status),
    )
    monkeypatch.setattr(
        OperationRegistry,
        "get",
        staticmethod(lambda operation_id: _StubService()),
    )

    client = TestClient(_build_app())
    response = client.post(
        "/advance/multiRxMer/status",
        json={"operation_id": "op-800"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["time_remaining"] == _TEST_TIME_REMAINING


def test_registry_status_endpoint_uses_default_time_remaining_when_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _fake_status(operation_id: OperationId) -> object:
        return {
            "operation_id": str(operation_id),
            "state": "running",
            "created_ts": 1,
            "updated_ts": 1,
            "progress_current": 0,
            "progress_total": 1,
            "message": "Operation running",
            "error": None,
            "artifact_paths": None,
        }

    monkeypatch.setattr(
        rxmer_router.OperationWorkflowService,
        "get_status",
        staticmethod(_fake_status),
    )
    monkeypatch.setattr(
        OperationRegistry,
        "get",
        staticmethod(lambda operation_id: None),
    )

    client = TestClient(_build_app())
    response = client.post(
        "/advance/multiRxMer/status",
        json={"operation_id": "op-801"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert (
        payload["time_remaining"]
        == rxmer_router.MultiRxMerRouter._DEFAULT_TIME_REMAINING
    )
