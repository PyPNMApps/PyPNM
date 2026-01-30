#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import argparse
import sys

from pypnm.examples.common.common_cli import (
    DEFAULT_BASE_URL,
    DEFAULT_SNMP_COMMUNITY,
    send_cable_modem_request,
)
from pypnm.lib.types import SnmpCommunity


ENDPOINT_PATH: str = "/docs/if31/ds/ofdm/chan/stats"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Example client for /docs/if31/ds/ofdm/chan/stats",
    )

    parser.add_argument(
        "--mac",
        required=True,
        help="Cable modem MAC address (e.g. aa:bb:cc:dd:ee:ff)",
    )
    parser.add_argument(
        "--inet",
        dest="ip_address",
        required=True,
        help="Cable modem IP address (e.g. 172.19.32.171)",
    )
    parser.add_argument(
        "--community",
        default=DEFAULT_SNMP_COMMUNITY,
        help=f"SNMPv2c community string (default: {DEFAULT_SNMP_COMMUNITY})",
    )
    parser.add_argument(
        "--url",
        default=DEFAULT_BASE_URL,
        help=f"Base FastAPI server URL (default: {DEFAULT_BASE_URL})",
    )

    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    community = SnmpCommunity(args.community)
    exit_code: int = send_cable_modem_request(
        endpoint_path=ENDPOINT_PATH,
        base_url=args.url,
        mac=args.mac,
        ip=args.ip_address,
        community=community,
    )

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
