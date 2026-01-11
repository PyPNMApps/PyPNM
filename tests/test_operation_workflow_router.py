# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from pypnm.api.routes.advance.common.operation_registry import OperationRegistry
from pypnm.api.routes.advance.common.operation_workflow_router import router
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.constants import OperationExecutionState
from pypnm.lib.operations.operation_store import OperationStore
from pypnm.lib.types import OperationId


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


def _configure_operation_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pnm_dir = tmp_path / ".data" / "pnm"
    pnm_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(
        SystemConfigSettings,
        "pnm_dir",
        classmethod(lambda cls: str(pnm_dir)),
    )


def test_operation_status_and_result_flow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())

    start_resp = client.post("/advance/operation/start", json={"progress_total": 1})
    assert start_resp.status_code == 200
    operation_id = start_resp.json()["operation"]["operation_id"]
    assert start_resp.json()["operation"]["state"] == OperationExecutionState.RUNNING

    status_resp = client.post(
        "/advance/operation/status", json={"operation_id": operation_id}
    )
    assert status_resp.status_code == 200
    assert status_resp.json()["operation"]["operation_id"] == operation_id

    result_resp = client.post(
        "/advance/operation/result", json={"operation_id": operation_id}
    )
    assert result_resp.status_code == 400

    store = OperationStore()
    store.update_operation(
        operation_id=OperationId(operation_id),
        state=OperationExecutionState.COMPLETED,
        progress_current=1,
        progress_total=1,
        message="Operation completed",
        error=None,
        artifact_paths=None,
    )

    result_ok = client.post(
        "/advance/operation/result", json={"operation_id": operation_id}
    )
    assert result_ok.status_code == 200
    assert result_ok.json()["operation"]["state"] == OperationExecutionState.COMPLETED


def test_operation_cancel_invokes_registry_stop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())

    start_resp = client.post("/advance/operation/start", json={"progress_total": 1})
    assert start_resp.status_code == 200
    operation_id = start_resp.json()["operation"]["operation_id"]

    class _FakeService:
        def __init__(self) -> None:
            self.stopped = False

        def stop(self, _operation_id: OperationId) -> None:
            self.stopped = True

    service = _FakeService()
    OperationRegistry.register(OperationId(operation_id), service)

    cancel_resp = client.post(
        "/advance/operation/cancel", json={"operation_id": operation_id}
    )
    assert cancel_resp.status_code == 200
    assert cancel_resp.json()["operation"]["state"] == OperationExecutionState.CANCELED
    assert service.stopped is True
    OperationRegistry.unregister(OperationId(operation_id))
