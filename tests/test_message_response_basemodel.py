# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode


def test_message_response_payload_coercion() -> None:
    payload = [
        {
            "status": ServiceStatusCode.SUCCESS.name,
            "message_type": "PNM_FILE_TRANSACTION",
            "message": {
                "transaction_id": "abc123",
                "filename": "capture.bin",
            },
            "extra_field": "extra",
        },
    ]

    msg_rsp = MessageResponse(ServiceStatusCode.SUCCESS, payload=payload)

    assert msg_rsp.status == ServiceStatusCode.SUCCESS
    assert msg_rsp.payload is not None
    assert msg_rsp.payload[0].status == ServiceStatusCode.SUCCESS.name

    payload_dict = msg_rsp.payload_to_dict()
    assert payload_dict["data"][0]["message_type"] == "PNM_FILE_TRANSACTION"
    assert payload_dict["data"][0]["extra_field"] == "extra"

    msg_dict = msg_rsp.get()
    assert msg_dict["status"] == ServiceStatusCode.SUCCESS.name
