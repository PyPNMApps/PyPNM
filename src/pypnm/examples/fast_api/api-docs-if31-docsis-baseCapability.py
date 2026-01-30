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

ENDPOINT_PATH: str = "/docs/if31/docsis/baseCapability"


def parse_args() -> argparse.Namespace:
    """
    Parse Command-Line Arguments For The Base Capability Example CLI.
    """
    parser = argparse.ArgumentParser(
        description="Call the /docs/if31/docsis/baseCapability endpoint with a cable_modem payload.",
    )

    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"PyPNM FastAPI server base URL (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--community",
        default=DEFAULT_SNMP_COMMUNITY,
        help=f"SNMP v2c community string (default: {DEFAULT_SNMP_COMMUNITY})",
    )
    parser.add_argument(
        "--mac",
        required=True,
        help="Cable modem MAC address (for example: aa:bb:cc:dd:ee:ff)",
    )
    parser.add_argument(
        "--inet",
        required=True,
        help="Cable modem IP address (for example: 172.19.32.171)",
    )

    return parser.parse_args()


def main() -> int:
    """
    Execute The /docs/if31/docsis/baseCapability Example Request.
    """
    args = parse_args()

    community = SnmpCommunity(args.community)
    return send_cable_modem_request(
        endpoint_path=ENDPOINT_PATH,
        base_url=args.base_url,
        mac=args.mac,
        ip=args.inet,
        community=community,
    )


if __name__ == "__main__":
    sys.exit(main())
