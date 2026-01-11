# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import pypnm.api.routes.advance.multi_ds_chan_est.router as ds_router
from pypnm.api.routes.advance.common.operation_registry import OperationRegistry
from pypnm.api.routes.advance.multi_ds_chan_est.router import router
from pypnm.api.routes.advance.multi_ds_chan_est.service import (
    MultiChannelEstimationService,
)
from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.types import OperationId

_TEST_TIME_REMAINING: int = 123


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


def _configure_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base_dir = tmp_path / ".data"
    pnm_dir = base_dir / "pnm"
    db_dir = base_dir / "db"
    pnm_dir.mkdir(parents=True, exist_ok=True)
    db_dir.mkdir(parents=True, exist_ok=True)

    capture_group_db = db_dir / "capture_group.json"
    operation_db = db_dir / "operation_capture.json"
    transaction_db = db_dir / "transactions.json"

    monkeypatch.setattr(
        SystemConfigSettings,
        "pnm_dir",
        classmethod(lambda cls: str(pnm_dir)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "capture_group_db",
        classmethod(lambda cls: str(capture_group_db)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "operation_db",
        classmethod(lambda cls: str(operation_db)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "transaction_db",
        classmethod(lambda cls: str(transaction_db)),
    )


def _start_request_payload() -> dict[str, object]:
    return {
        "cable_modem": {
            "mac_address": "aa:bb:cc:dd:ee:ff",
            "ip_address": "192.168.0.100",
            "pnm_parameters": {
                "tftp": {
                    "ipv4": None,
                    "ipv6": None,
                },
                "capture": {
                    "channel_ids": None,
                },
            },
            "snmp": {
                "snmp_v2c": {
                    "community": "public",
                }
            },
        },
        "capture": {
            "parameters": {
                "measurement_duration": 1,
                "sample_interval": 1,
            }
        },
    }


@pytest.mark.asyncio
async def test_start_returns_success_status_and_group_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)

    async def _fake_precheck(
        self: CableModemServicePreCheck,
    ) -> tuple[ServiceStatusCode, str]:
        return ServiceStatusCode.SUCCESS, "ok"

    async def _fake_capture(self: MultiChannelEstimationService) -> MessageResponse:
        return MessageResponse(ServiceStatusCode.SUCCESS, payload=[])

    monkeypatch.setattr(CableModemServicePreCheck, "run_precheck", _fake_precheck)
    monkeypatch.setattr(
        MultiChannelEstimationService, "_capture_message_response", _fake_capture
    )

    client = TestClient(_build_app())
    response = client.post(
        "/advance/multiChannelEstimation/start",
        json=_start_request_payload(),
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == ServiceStatusCode.SUCCESS
    assert payload["operation_id"]
    assert payload["capture_group_id"]
    assert payload["group_id"] == payload["capture_group_id"]
    assert payload["operation_state"] == "running"
    OperationRegistry.unregister(OperationId(payload["operation_id"]))


def test_analysis_returns_capture_group_not_found_when_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)
    db_path = Path(SystemConfigSettings.operation_db())
    db_path.write_text(json.dumps({}), encoding="utf-8")

    client = TestClient(_build_app())
    response = client.post(
        "/advance/multiChannelEstimation/analysis",
        json={"operation_id": "op-missing"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == ServiceStatusCode.CAPTURE_GROUP_NOT_FOUND
    assert "No capture group found for operation" in payload["message"]


class _StubMac:
    mac_address = "aa:bb:cc:dd:ee:ff"


class _StubCm:
    get_mac_address = _StubMac()


class _StubService:
    def __init__(self) -> None:
        self.cm = _StubCm()
        self._state = "running"

    def status(self, operation_id: OperationId) -> dict[str, object]:
        return {
            "state": self._state,
            "collected": 0,
            "time_remaining": 0,
        }

    def stop(self, operation_id: OperationId) -> None:
        self._state = "stopped"


def test_status_endpoint_uses_service_status_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)
    stub = _StubService()
    monkeypatch.setattr(
        ds_router.MultiDsChanEstRouter,
        "getService",
        lambda self, operation_id: stub,
    )

    client = TestClient(_build_app())
    response = client.get("/advance/multiChannelEstimation/status/op-500")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == ServiceStatusCode.SUCCESS
    assert payload["operation"]["operation_id"] == "op-500"


def test_stop_endpoint_uses_service_status_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)
    stub = _StubService()
    monkeypatch.setattr(
        ds_router.MultiDsChanEstRouter,
        "getService",
        lambda self, operation_id: stub,
    )

    client = TestClient(_build_app())
    response = client.delete("/advance/multiChannelEstimation/stop/op-501")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == ServiceStatusCode.SUCCESS
    assert payload["operation"]["state"] == "stopped"


def test_registry_status_endpoint_returns_dual_status_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)

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
        ds_router.OperationWorkflowService,
        "get_status",
        staticmethod(_fake_status),
    )

    client = TestClient(_build_app())
    response = client.post(
        "/advance/multiChannelEstimation/status",
        json={"operation_id": "op-600"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "success"
    assert payload["service_status"] == ServiceStatusCode.SUCCESS


def test_registry_status_endpoint_uses_service_time_remaining(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)

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
        ds_router.OperationWorkflowService,
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
        "/advance/multiChannelEstimation/status",
        json={"operation_id": "op-602"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["time_remaining"] == _TEST_TIME_REMAINING


def test_registry_status_endpoint_uses_default_time_remaining_when_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)

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
        ds_router.OperationWorkflowService,
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
        "/advance/multiChannelEstimation/status",
        json={"operation_id": "op-603"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert (
        payload["time_remaining"]
        == ds_router.MultiDsChanEstRouter._DEFAULT_TIME_REMAINING
    )


def test_registry_cancel_endpoint_returns_dual_status_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)

    def _fake_cancel(
        operation_id: OperationId, service: object | None = None
    ) -> object:
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

    monkeypatch.setattr(
        ds_router.OperationWorkflowService,
        "cancel",
        staticmethod(_fake_cancel),
    )

    client = TestClient(_build_app())
    response = client.post(
        "/advance/multiChannelEstimation/cancel",
        json={"operation_id": "op-601"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "success"
    assert payload["service_status"] == ServiceStatusCode.SUCCESS
