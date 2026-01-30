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
    EXIT_REQUEST_ERROR,
    send_cable_modem_request,
)
from pypnm.lib.types import SnmpCommunity

ENDPOINT_PATH: str = "/system/sysDescr"


def parse_args() -> argparse.Namespace:
    """
    Parse Command-Line Arguments For The /system/sysDescr Example.
    """
    parser = argparse.ArgumentParser(
        description="Call /system/sysDescr on a PyPNM FastAPI server.",
    )
    parser.add_argument(
        "--mac",
        required=True,
        help="Cable modem MAC address (for example: aa:bb:cc:dd:ee:ff).",
    )
    parser.add_argument(
        "--inet",
        dest="ip",
        required=True,
        help="Cable modem IP address (for example: 192.168.0.100).",
    )
    parser.add_argument(
        "--community",
        default=DEFAULT_SNMP_COMMUNITY,
        help=f"SNMP v2c community (default: {DEFAULT_SNMP_COMMUNITY}).",
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"Base URL of the PyPNM FastAPI service (default: {DEFAULT_BASE_URL}).",
    )
    return parser.parse_args()


def main() -> int:
    """
    Entry Point For The /system/sysDescr CLI Example.

    Builds The cable_modem Payload And Sends A POST Request To The
    /system/sysDescr Endpoint Using The Shared Common CLI Helpers.
    """
    args = parse_args()

    community = SnmpCommunity(args.community)
    return send_cable_modem_request(
        endpoint_path=ENDPOINT_PATH,
        base_url=args.base_url,
        mac=args.mac,
        ip=args.ip,
        community=community,
    )


if __name__ == "__main__":
    sys.exit(main())
