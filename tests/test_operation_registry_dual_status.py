# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from collections.abc import Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import pypnm.api.routes.advance.common.operation_workflow_router as workflow_router
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.lib.types import OperationId


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(workflow_router.router)
    return app


def _fake_status(operation_id: OperationId) -> dict[str, object]:
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


def _fake_cancel(
    operation_id: OperationId, service: object | None = None
) -> dict[str, object]:
    return {
        "operation_id": str(operation_id),
        "state": "canceled",
        "created_ts": 1,
        "updated_ts": 2,
        "progress_current": 1,
        "progress_total": 1,
        "message": "Operation canceled",
        "error": None,
        "artifact_paths": None,
    }


def _fake_result(operation_id: OperationId) -> dict[str, object]:
    return {
        "operation_id": str(operation_id),
        "state": "completed",
        "created_ts": 1,
        "updated_ts": 2,
        "progress_current": 1,
        "progress_total": 1,
        "message": "Operation completed",
        "error": None,
        "artifact_paths": None,
    }


def _fake_start(progress_total: int, message: str | None) -> dict[str, object]:
    return {
        "operation_id": "op-start-1",
        "state": "running",
        "created_ts": 1,
        "updated_ts": 1,
        "progress_current": 0,
        "progress_total": progress_total,
        "message": message,
        "error": None,
        "artifact_paths": None,
    }


def _patch_service(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    func: Callable[..., dict[str, object]],
) -> None:
    monkeypatch.setattr(
        workflow_router.OperationWorkflowService,
        name,
        staticmethod(func),
    )
    monkeypatch.setattr(
        workflow_router.OperationRegistry,
        "get",
        staticmethod(lambda operation_id: None),
    )


def test_operation_status_returns_dual_status_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_service(monkeypatch, "get_status", _fake_status)
    client = TestClient(_build_app())
    response = client.post(
        "/advance/operation/status",
        json={"operation_id": "op-700"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "success"
    assert payload["service_status"] == ServiceStatusCode.SUCCESS


def test_operation_start_returns_dual_status_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_service(monkeypatch, "start", _fake_start)
    client = TestClient(_build_app())
    response = client.post(
        "/advance/operation/start",
        json={"progress_total": 1, "message": "Operation created"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "success"
    assert payload["service_status"] == ServiceStatusCode.SUCCESS
    assert "operation" in payload
    assert "time_remaining" in payload


def test_operation_cancel_returns_dual_status_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_service(monkeypatch, "cancel", _fake_cancel)
    client = TestClient(_build_app())
    response = client.post(
        "/advance/operation/cancel",
        json={"operation_id": "op-701"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "success"
    assert payload["service_status"] == ServiceStatusCode.SUCCESS


def test_operation_result_returns_dual_status_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_service(monkeypatch, "get_result", _fake_result)
    client = TestClient(_build_app())
    response = client.post(
        "/advance/operation/result",
        json={"operation_id": "op-702"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "success"
    assert payload["service_status"] == ServiceStatusCode.SUCCESS
