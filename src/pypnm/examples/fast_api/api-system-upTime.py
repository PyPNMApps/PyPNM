#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import argparse
import sys

from pypnm.examples.common.common_cli import (
    DEFAULT_BASE_URL,
    DEFAULT_SNMP_COMMUNITY,
    EXIT_SUCCESS,
    send_cable_modem_request,
)
from pypnm.lib.types import SnmpCommunity


ENDPOINT_PATH: str = "/system/upTime"


def _build_arg_parser() -> argparse.ArgumentParser:
    """
    Build The Command Line Argument Parser For The /system/upTime Example.

    This CLI helper issues a POST request to the PyPNM /system/upTime endpoint
    using the common cable_modem payload structure. The MAC address, IP address,
    SNMP community, and base URL can be provided on the command line.
    """
    parser = argparse.ArgumentParser(
        description="PyPNM FastAPI example client for /system/upTime",
    )

    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"Base URL for the PyPNM FastAPI server (default: {DEFAULT_BASE_URL})",
    )

    parser.add_argument(
        "--community",
        default=DEFAULT_SNMP_COMMUNITY,
        help=f"SNMP v2c community string (default: {DEFAULT_SNMP_COMMUNITY})",
    )

    parser.add_argument(
        "--mac",
        dest="mac_address",
        required=True,
        help="Cable modem MAC address (e.g. aa:bb:cc:dd:ee:ff)",
    )

    parser.add_argument(
        "--inet",
        dest="ip_address",
        required=True,
        help="Cable modem management IP address (e.g. 172.19.32.171)",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """
    Entry Point For The /system/upTime Example Client.

    This function parses command line arguments and sends a POST request to
    the /system/upTime endpoint using send_cable_modem_request. The JSON
    response is printed to stdout. The return value is an exit status where
    zero indicates success.
    """
    if argv is None:
        argv = sys.argv[1:]

    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    community = SnmpCommunity(args.community)
    status: int = send_cable_modem_request(
        endpoint_path=ENDPOINT_PATH,
        base_url=args.base_url,
        mac=args.mac_address,
        ip=args.ip_address,
        community=community,
    )

    if status == EXIT_SUCCESS:
        return EXIT_SUCCESS
    return status


if __name__ == "__main__":
    raise SystemExit(main())
