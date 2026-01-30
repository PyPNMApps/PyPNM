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


ATDMA_US_PRE_EQ_ENDPOINT: str = "/docs/if30/us/atdma/chan/preEqualization"


def main() -> int:
    """
    Test The /docs/if30/us/atdma/chan/preEqualization Endpoint Using A CLI Example.

    This entry point parses the MAC address, IP address, optional base URL,
    and SNMP v2c community string from the command line. It then uses the
    shared send_cable_modem_request helper to POST a cable_modem payload to
    the /docs/if30/us/atdma/chan/preEqualization endpoint. The resulting exit
    status is propagated as the process exit code so that automated scripts
    can detect failures.
    """
    parser = argparse.ArgumentParser(
        description="CLI example for the /docs/if30/us/atdma/chan/preEqualization endpoint.",
    )
    parser.add_argument(
        "--mac",
        "-m",
        required=True,
        help="MAC address of the cable modem (example: aa:bb:cc:dd:ee:ff)",
    )
    parser.add_argument(
        "--inet",
        "-i",
        required=True,
        help="IP address of the cable modem (example: 192.168.0.100)",
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"Base URL for the PyPNM API (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--snmp-community",
        default=DEFAULT_SNMP_COMMUNITY,
        help=f"SNMP v2c community string (default: {DEFAULT_SNMP_COMMUNITY})",
    )

    args = parser.parse_args()

    community = SnmpCommunity(args.snmp_community)
    return send_cable_modem_request(
        endpoint_path=ATDMA_US_PRE_EQ_ENDPOINT,
        base_url=args.base_url,
        mac=args.mac,
        ip=args.inet,
        community=community,
    )


if __name__ == "__main__":
    sys.exit(main())
