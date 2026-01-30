#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations


import argparse
import asyncio
import json
import logging
from typing import Any, Sequence

from pypnm.api.routes.common.classes.operation.cable_modem_precheck import CableModemServicePreCheck
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.extended.common_process_service import CommonProcessService
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.ds.ofdm.rxmer.service import CmDsOfdmRxMerService
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.cm_snmp_operation import DocsPnmCmDsOfdmRxMerEntry
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import InetAddressStr, MacAddressStr, SnmpCommunity
from pypnm.lib.utils import Generate, TimeUnit

LOG_FORMAT: str   = "%(asctime)s - %(levelname)s - %(message)s"
EXIT_FAILURE: int = 1

logger = logging.getLogger("PyPnmDsOfdmRxMerCli")


def _build_parser() -> argparse.ArgumentParser:
    """
    Build The Command-Line Argument Parser For The RxMER Set-And-Go CLI.

    Arguments are aligned with the FastAPI single-capture request for
    ``/docs/pnm/ds/ofdm/rxMer/getCapture`` so that configuration is
    consistent between REST and CLI usage.
    """
    parser = argparse.ArgumentParser(description="Downstream OFDM RxMER Set-And-Go CLI")

    parser.add_argument(
        "--mac", "-m",
        required=True,
        help="MAC address of the cable modem (for example: aa:bb:cc:dd:ee:ff)",
    )
    parser.add_argument(
        "--inet", "-i",
        required=True,
        help="IP address of the cable modem (for example: 192.168.0.100)",
    )
    parser.add_argument(
        "--tftp-ipv4", "-t4",
        required=True,
        help="IPv4 address of the TFTP server used for PNM bulk transfers",
    )
    parser.add_argument(
        "--tftp-ipv6", "-t6",
        required=False,
        help="IPv6 address of the TFTP server used for PNM bulk transfers "
             "(optional; defaults to --tftp-ipv4 when omitted)",
    )
    parser.add_argument(
        "--community-write", "-cw",
        default="private",
        help="SNMP write community string (default: private)",
    )

    return parser


async def _build_cable_modem(
    mac_address: MacAddressStr,
    ip_address: InetAddressStr,
    write_community: SnmpCommunity,
) -> CableModem:
    """
    Build A CableModem Instance For PNM Operations.

    Construct a ``CableModem`` using the supplied MAC address, IP address,
    and SNMP write community. Connectivity and OFDM presence are validated
    separately by ``CableModemServicePreCheck`` before any RxMER workflow
    is executed.
    """
    cm = CableModem(
        mac_address     = MacAddress(mac_address),
        inet            = Inet(ip_address),
        write_community = write_community,
    )
    return cm


def _parse_pnm_payload(msg_rsp: MessageResponse) -> list[Any]:
    """
    Parse PNM Payload Objects From The MessageResponse.

    The processed ``MessageResponse`` from ``CommonProcessService`` may
    contain payload entries as JSON strings or already-decoded Python
    structures. This helper normalizes all entries into Python objects so
    that they can be emitted as a single JSON document on stdout.
    """
    parsed: list[Any] = []

    for payload in msg_rsp.payload:  # type: ignore[attr-defined]
        if isinstance(payload, str):
            try:
                parsed.append(json.loads(payload))
            except json.JSONDecodeError:
                parsed.append(payload)
        else:
            parsed.append(payload)

    return parsed


async def _run_rxmer_set_and_go(
    mac: MacAddressStr,
    ip: InetAddressStr,
    tftp_ipv4: InetAddressStr,
    tftp_ipv6: InetAddressStr | None,
    write_community: SnmpCommunity,
) -> None:
    """
    Run The Downstream OFDM RxMER Set-And-Go Workflow And Emit Merged JSON.

    Workflow:

    1. Build a ``CableModem`` instance.
    2. Run ``CableModemServicePreCheck`` with ``validate_ofdm_exist=True`` to:
       - Verify basic connectivity.
       - Confirm at least one downstream OFDM channel exists.
    3. Build the TFTP server tuple ``tftp_servers`` from the IPv4 and IPv6
       CLI arguments (IPv6 falls back to IPv4 when omitted).
    4. Invoke ``CmDsOfdmRxMerService.set_and_go()`` to:
       - Configure PNM bulk transfer as needed.
       - Trigger RxMER capture on the modem.
       - Retrieve the resulting PNM file into a ``MessageResponse``.
    5. Pass the ``MessageResponse`` through ``CommonProcessService`` to
       parse the PNM file into structured payload objects.
    6. Query the SNMP RxMER statistics via
       ``CmDsOfdmRxMerService.getPnmMeasurementStatistics()`` to obtain
       ``DocsPnmCmDsOfdmRxMerEntry`` rows.
    7. Build a single merged JSON document containing:
       - Basic metadata (MAC, IP, status, timestamp)
       - Parsed PNM payload objects
       - RxMER measurement statistics
    8. Print the resulting JSON to stdout for downstream tooling.
    """
    cm: CableModem = await _build_cable_modem(
        mac_address     = mac,
        ip_address      = ip,
        write_community = write_community,
    )

    status, msg = await CableModemServicePreCheck(
        cable_modem        = cm,
        validate_ofdm_exist = True,
    ).run_precheck()

    if status != ServiceStatusCode.SUCCESS:
        logger.error("Cable modem pre-check failed: %s", msg)
        raise RuntimeError(f"Pre-check failed: {msg}")

    logger.info("Cable modem pre-check passed: %s", msg)

    tftp_server_ipv4 = Inet(tftp_ipv4)
    tftp_server_ipv6 = Inet(tftp_ipv6) if tftp_ipv6 is not None else Inet(tftp_ipv4)
    tftp_servers     = (tftp_server_ipv4, tftp_server_ipv6)

    service: CmDsOfdmRxMerService = CmDsOfdmRxMerService(cm, tftp_servers)
    msg_rsp: MessageResponse      = await service.set_and_go()

    if msg_rsp.status != ServiceStatusCode.SUCCESS:
        logger.error("RxMER set-and-go failed with status: %s", msg_rsp.status.name)
        raise RuntimeError(f"RxMER set-and-go failed: {msg_rsp.status.name}")

    msg_rsp.get_payload_msg()

    pnm_payloads: list[Any] = _parse_pnm_payload(msg_rsp)

    merged: dict[str, Any] = {
        "mac_address":       str(mac),
        "ip_address":        str(ip),
        "status":            msg_rsp.status.name,
        "timestamp_ms":      int(Generate.time_stamp(TimeUnit.MILLISECONDS)),
        "pnm_payloads":      pnm_payloads,
        "measurement_stats": [entry.model_dump() for entry in measurement_stats],
    }

    print(json.dumps(merged, indent=2))


async def main() -> None:
    """
    CLI Entry Point For The RxMER Set-And-Go Example.

    Parse command-line arguments, normalize them into typed parameters,
    and invoke the RxMER set-and-go workflow. The resulting merged PNM
    JSON document (parsed PNM payload plus RxMER SNMP entries) is printed
    to stdout.
    """
    parser = _build_parser()
    args = parser.parse_args()

    mac: MacAddressStr        = MacAddressStr(args.mac)
    ip: InetAddressStr        = InetAddressStr(args.inet)
    tftp_ipv4: InetAddressStr = InetAddressStr(args.tftp_ipv4)
    tftp_ipv6: InetAddressStr | None = (
        InetAddressStr(args.tftp_ipv6) if args.tftp_ipv6 is not None else None
    )
    write_community: SnmpCommunity      = SnmpCommunity(args.community_write)

    try:
        await _run_rxmer_set_and_go(
            mac             = mac,
            ip              = ip,
            tftp_ipv4       = tftp_ipv4,
            tftp_ipv6       = tftp_ipv6,
            write_community = write_community,
        )
    except RuntimeError as exc:
        logger.error("RxMER set-and-go capture failed: %s", exc)
        raise SystemExit(EXIT_FAILURE) from exc


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
    asyncio.run(main())
