# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging

from fastapi import HTTPException

from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_connect_request import (
    SNMPConfig,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_snmp import (
    SNMPv2c,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schemas import PnmResponse
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.dev.schemas import EventLogEntry
from pypnm.docsis.cable_modem import CableModem
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import InetAddressStr, MacAddressStr

logger = logging.getLogger(__name__)


class CmDocsDevService:
    def __init__(
        self,
        mac_address: MacAddressStr,
        ip_address: InetAddressStr,
        snmp_config: SNMPConfig | None = None,
    ) -> None:
        if snmp_config is None:
            snmp_config = SNMPConfig(snmp_v2c=SNMPv2c(community=None))
        self._mac = MacAddress(mac_address)
        self._ip = Inet(ip_address)
        self._cm = CableModem(
            mac_address=self._mac,
            inet=self._ip,
            write_community=snmp_config.snmp_v2c.community,
        )

    def get_mac_address(self) -> MacAddressStr:
        return self._mac.mac_address

    async def fetch_event_log(self) -> list[EventLogEntry]:
        """
        Fetch DOCSIS event log entries and return a list of structured models.
        """
        raw_entries: list[dict] = await self._cm.getDocsDevEventEntry(to_dict=True)

        log_entries = []
        for raw in raw_entries:
            if not isinstance(raw, dict) or not raw:
                continue

            try:
                _, event_data = next(iter(raw.items()))
                log_entries.append(
                    EventLogEntry(
                        docsDevEvFirstTime=event_data.get("docsDevEvFirstTime", ""),
                        docsDevEvLastTime=event_data.get("docsDevEvLastTime", ""),
                        docsDevEvCounts=event_data.get("docsDevEvCounts", 0),
                        docsDevEvLevel=event_data.get("docsDevEvLevel", 0),
                        docsDevEvId=event_data.get("docsDevEvId", 0),
                        docsDevEvText=event_data.get("docsDevEvText", ""),
                    )
                )
            except Exception:
                continue

        return log_entries

    async def reset_cable_modem(self) -> PnmResponse:
        try:
            if not await self._cm.setDocsDevResetNow():
                return PnmResponse(
                    mac_address=self._mac.mac_address,
                    status=ServiceStatusCode.RESET_NOW_FAILED,
                    message=f"Reset command to cable modem at {self._ip} failed.",
                )

            return PnmResponse(
                mac_address=self._mac.mac_address,
                status=ServiceStatusCode.SUCCESS,
                message=f"Reset command sent to cable modem at {self._ip} successfully.",
            )

        except Exception as e:
            logger.exception("Failed to reset cable modem")
            raise HTTPException(status_code=500, detail=str(e)) from e

    async def ping_cable_modem(self) -> PnmResponse:
        try:
            if not self._cm.is_ping_reachable():
                return PnmResponse(
                    mac_address=self._mac.mac_address,
                    status=ServiceStatusCode.PING_FAILED,
                    message=f"Ping to {self._ip} failed.",
                )

            return PnmResponse(
                mac_address=self._mac.mac_address,
                status=ServiceStatusCode.SUCCESS,
                message=f"Ping to cable modem at {self._ip} succeeded.",
            )

        except Exception as e:
            logger.exception("Failed to send ping to cable modem")
            raise HTTPException(status_code=500, detail=str(e)) from e
