#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import asyncio
import logging
from typing import Sequence

from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.cm_snmp_operation import DocsPnmCmCtlStatus
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import InetAddressStr, MacAddressStr, SnmpCommunity

DEFAULT_PNM_POLL_INTERVAL_SECONDS: float = 1.0

logger = logging.getLogger(__name__)


async def build_cable_modem(
    mac_address: MacAddressStr,
    ip_address: InetAddressStr,
    write_community: SnmpCommunity,
) -> CableModem:
    """
    Build And Verify A CableModem Instance For PNM Operations.

    Construct a ``CableModem`` using the supplied MAC address, IP address,
    and SNMP write community. Basic reachability is verified using ICMP ping,
    and the device ``sysDescr`` is logged for visibility.

    A ``RuntimeError`` is raised if the modem is not reachable so callers
    can treat this as an all-or-nothing setup step for subsequent PNM calls.
    """
    cm = CableModem(
        mac_address     = MacAddress(mac_address),
        inet            = Inet(ip_address),
        write_community = write_community,
    )

    if not cm.is_ping_reachable():
        logger.error("%s not reachable", cm.get_inet_address)
        raise RuntimeError(f"{cm.get_inet_address} not reachable")

    logger.info("Connected to: %s", await cm.getSysDescr())
    return cm


async def discover_ofdm_indices(cm: CableModem) -> Sequence[int]:
    """
    Discover Downstream OFDM Channel Indices For The Cable Modem.

    Wrap the DOCSIS SNMP query that returns downstream OFDM channel
    indices. The discovered list is logged. A ``RuntimeError`` is raised
    if no indices are found, which typically indicates that the modem is
    not configured for OFDM or not provisioned as expected.
    """
    ofdm_idx_list: Sequence[int] = await cm.getDocsIf31CmDsOfdmChannelIdIndex()

    if not ofdm_idx_list:
        logger.error("No downstream OFDM channel indices discovered")
        raise RuntimeError("No downstream OFDM channel indices discovered")

    logger.info("Discovered OFDM channel indices: %s", list(ofdm_idx_list))
    return ofdm_idx_list


async def configure_pnm_bulk_tftp(
    cm: CableModem,
    tftp_ipv4: InetAddressStr,
    tftp_dest_dir: str,
) -> None:
    """
    Configure PNM Bulk Transfer TFTP Server And Destination Directory.

    Program the DOCSIS PNM bulk data transfer settings on the cable modem
    for the provided IPv4 TFTP server and destination directory. A
    ``RuntimeError`` is raised if configuration fails so callers can stop
    the workflow early.
    """
    if await cm.setDocsPnmBulk(
        tftp_server = str(tftp_ipv4),
        tftp_path   = tftp_dest_dir,
    ):
        logger.info("PNM bulk TFTP configured: server=%s path=%s", tftp_ipv4, tftp_dest_dir)
        return

    logger.error("Unable to set TFTP server %s and/or TFTP path %s", tftp_ipv4, tftp_dest_dir)
    raise RuntimeError(f"Unable to configure PNM bulk TFTP: server={tftp_ipv4} path={tftp_dest_dir}")


async def poll_pnm_test_until_complete(
    cm: CableModem,
    poll_interval_seconds: float = DEFAULT_PNM_POLL_INTERVAL_SECONDS,
) -> DocsPnmCmCtlStatus:
    """
    Poll The PNM Control Status Until The Test Completes.

    Repeatedly read ``DocsPnmCmCtlStatus`` and block until the status
    transitions away from ``TEST_IN_PROGRESS``. The final status value is
    returned so callers can validate success or failure.

    A configurable poll interval balances test responsiveness with
    network and CPU usage.
    """
    while True:
        status: DocsPnmCmCtlStatus = await cm.getDocsPnmCmCtlStatus()

        if status == DocsPnmCmCtlStatus.TEST_IN_PROGRESS:
            logger.warning("PNM test in progress...")
            await asyncio.sleep(poll_interval_seconds)
        else:
            logger.info("PNM test completed with status: %s", status.name)
            return status
