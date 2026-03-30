# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import pytest

from pypnm.api.routes.advance.common.operation_kind import MultiCaptureOperation
from pypnm.api.routes.advance.common.operation_state import OperationState
from pypnm.api.routes.advance.common.schema.common_capture_schema import (
    MultiCapturePersistedRecordModel,
)
from pypnm.api.routes.advance.multi_ds_chan_est.router import MultiDsChanEstRouter
from pypnm.api.routes.advance.multi_rxmer.router import MultiRxMerRouter
from pypnm.api.routes.advance.multi_us_ofdma_pre_eq.router import (
    MultiUsOfdmaPreEqRouter,
)


def test_multi_operation_id_routes_are_registered() -> None:
    rxmer_paths = {route.path for route in MultiRxMerRouter().router.routes}
    chan_est_paths = {route.path for route in MultiDsChanEstRouter().router.routes}
    us_pre_eq_paths = {route.path for route in MultiUsOfdmaPreEqRouter().router.routes}

    assert "/advance/multi/ds/rxMer/operationId" in rxmer_paths
    assert "/advance/multi/ds/channelEstimation/operationId" in chan_est_paths
    assert "/advance/multi/us/ofdmaPreEqualization/operationId" in us_pre_eq_paths


def test_multi_rxmer_operation_id_helper_returns_filtered_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = {
        "op-1": MultiCapturePersistedRecordModel(
            capture_group_id="group-1",
            created=123,
            operation={"name": "multi_rxmer", "measure_mode": "continuous"},
            metadata={"mac_address": "00:00:00:dd:ee:ff"},
        ),
    }

    monkeypatch.setattr(
        "pypnm.api.routes.advance.common.operation_manager.OperationManager.list_operation_records_by_name",
        lambda operation_name: expected if operation_name == "multi_rxmer" else {},
    )

    response = MultiRxMerRouter()._build_operation_id_response(MultiCaptureOperation.MULTI_RXMER)

    assert response.status == "success"
    assert response.operations == expected


def test_multi_rxmer_status_helper_uses_persisted_terminal_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    persisted = {
        "capture_group_id": "group-1",
        "created": 123,
        "operation": {
            "name": "multi_rxmer",
            "measure_mode": "continuous",
        },
        "metadata": {
            "mac_address": "aa:bb:cc:dd:ee:ff",
            "system_description": {
                "HW_REV": "1.0",
                "VENDOR": "LANCity",
                "BOOTR": "NONE",
                "SW_REV": "1.0.0",
                "MODEL": "LCPET-3",
            },
        },
        "operation_status": {
            "state": "completed",
            "collected": 9,
            "time_remaining": 0,
            "updated": 125,
        },
    }

    monkeypatch.setattr(
        "pypnm.api.routes.advance.common.operation_manager.OperationManager.get_operation_record",
        lambda operation_id: persisted if operation_id == "op-1" else None,
    )

    status = MultiRxMerRouter()._get_operation_status_or_404("op-1")

    assert status.operation_id == "op-1"
    assert status.state == OperationState.COMPLETED
    assert status.collected == 9
    assert status.device.mac_address == "aa:bb:cc:dd:ee:ff"
    assert status.device.system_description.MODEL == "LCPET-3"
