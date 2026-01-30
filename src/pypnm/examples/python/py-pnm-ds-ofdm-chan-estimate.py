#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import argparse
import asyncio
import json
import logging
from typing import Sequence

from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.cm_snmp_operation import DocsPnmCmCtlStatus
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import InetAddressStr, MacAddressStr, SnmpCommunity
from pypnm.lib.utils import Generate

LOG_FORMAT: str                    = "%(asctime)s - %(levelname)s - %(message)s"
EXIT_FAILURE: int                  = 1
DEFAULT_PNM_POLL_INTERVAL_SECONDS: float = 1.0

logger = logging.getLogger("PyPnmDsOfdmChanEstCli")


async def _build_cable_modem(
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


async def _discover_ofdm_indices(cm: CableModem) -> Sequence[int]:
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


async def _configure_pnm_bulk_tftp(
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


async def _poll_pnm_test_until_complete(
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
            logger.info("Channel estimation measurement in progress...")
            await asyncio.sleep(poll_interval_seconds)
        else:
            logger.info("Channel estimation test completed with status: %s", status.name)
            return status


def _build_parser() -> argparse.ArgumentParser:
    """
    Build The Command-Line Argument Parser For The Channel Estimation CLI.

    Arguments mirror the FastAPI single-capture request for the OFDM
    downstream channel estimation endpoint so that configuration and
    invocation are consistent between REST and CLI usage.
    """
    parser = argparse.ArgumentParser(description="OFDM Downstream Channel Estimation CLI")

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
        "--tftp-dest-dir", "-td",
        default="",
        help="TFTP server destination directory (for example: /tftpboot/pnm)",
    )
    parser.add_argument(
        "--community-write", "-cw",
        default="private",
        help="SNMP write community string (default: private)",
    )

    return parser


async def _run_chan_estimation_capture(
    mac: MacAddressStr,
    ip: InetAddressStr,
    tftp_ipv4: InetAddressStr,
    tftp_dest_dir: str,
    write_community: SnmpCommunity,
) -> None:
    """
    Run A Downstream OFDM Channel Estimation Capture And Print Results As JSON.

    Workflow:

    1. Build and verify a ``CableModem`` instance.
    2. Discover downstream OFDM channel indices.
    3. Configure PNM bulk TFTP settings.
    4. For each OFDM index:
       - Request a new channel estimation capture file.
       - Poll the PNM control status until the test finishes.
    5. Fetch all channel estimation entries and print them as
       pretty-printed JSON on stdout for downstream tooling.
    """
    cm: CableModem = await _build_cable_modem(
        mac_address     = mac,
        ip_address      = ip,
        write_community = write_community,
    )

    ofdm_idx_list: Sequence[int] = await _discover_ofdm_indices(cm)
    await _configure_pnm_bulk_tftp(
        cm,
        tftp_ipv4     = tftp_ipv4,
        tftp_dest_dir = tftp_dest_dir,
    )

    for idx in ofdm_idx_list:
        chan_est_filename: str = f"ds-chan-est_{idx}_{Generate.time_stamp()}.bin"
        logger.info(
            "Requesting channel estimation capture for OFDM index %d with filename %s",
            idx,
            chan_est_filename,
        )

        await cm.setDocsPnmCmOfdmChEstCoef(
            ofdm_idx          = idx,
            chan_est_file_name = chan_est_filename,
        )
        await _poll_pnm_test_until_complete(cm)

    entries = await cm.getDocsPnmCmOfdmChanEstCoefEntry()
    results = [entry.model_dump() for entry in entries]

    json_data: str = json.dumps(results, indent=2)
    print(json_data)


async def main() -> None:
    """
    CLI Entry Point For The OFDM Downstream Channel Estimation Example.

    Parse command-line arguments, normalize them into typed parameters,
    and invoke the channel estimation capture workflow. This mirrors the
    behavior of the corresponding FastAPI endpoint while demonstrating
    direct Python API usage and printing JSON results directly to stdout.
    """
    parser = _build_parser()
    args = parser.parse_args()

    mac: MacAddressStr        = MacAddressStr(args.mac)
    ip: InetAddressStr        = InetAddressStr(args.inet)
    tftp_ipv4: InetAddressStr = InetAddressStr(args.tftp_ipv4)
    tftp_dest_dir: str        = str(args.tftp_dest_dir)
    write_community: SnmpCommunity      = SnmpCommunity(args.community_write)

    try:
        await _run_chan_estimation_capture(
            mac             = mac,
            ip              = ip,
            tftp_ipv4       = tftp_ipv4,
            tftp_dest_dir   = tftp_dest_dir,
            write_community = write_community,
        )
    except RuntimeError as exc:
        logger.error("Channel estimation capture failed: %s", exc)
        raise SystemExit(EXIT_FAILURE) from exc


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
    asyncio.run(main())
