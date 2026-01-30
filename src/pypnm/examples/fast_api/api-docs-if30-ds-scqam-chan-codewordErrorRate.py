#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import argparse
import sys

from pypnm.examples.common.common_cli import (
    DEFAULT_BASE_URL,
    DEFAULT_SNMP_COMMUNITY,
    DEFAULT_SAMPLE_TIME_ELAPSED_SEC,
    send_cable_modem_capture_request,
)
from pypnm.lib.types import SnmpCommunity


SCQAM_DS_CER_ENDPOINT: str = "/docs/if30/ds/scqam/chan/codewordErrorRate"


def main() -> int:
    """
    Test The /docs/if30/ds/scqam/chan/codewordErrorRate Endpoint Using A CLI Example.

    This entry point parses the MAC address, IP address, optional base URL,
    SNMP v2c community string, and capture duration from the command line. It
    then uses the shared send_cable_modem_capture_request helper to POST a
    payload containing cable_modem and capture_parameters to the
    /docs/if30/ds/scqam/chan/codewordErrorRate endpoint. The resulting exit
    status is propagated as the process exit code so that automated scripts
    can detect failures.
    """
    parser = argparse.ArgumentParser(
        description="CLI example for the /docs/if30/ds/scqam/chan/codewordErrorRate endpoint.",
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
    parser.add_argument(
        "--sample-time-elapsed",
        "--sample_time_elapsed",
        "-t",
        type=int,
        default=DEFAULT_SAMPLE_TIME_ELAPSED_SEC,
        help=(
            "capture_parameters.sample_time_elapsed value in seconds "
            f"(default: {DEFAULT_SAMPLE_TIME_ELAPSED_SEC})"
        ),
    )

    args = parser.parse_args()

    community = SnmpCommunity(args.snmp_community)
    return send_cable_modem_capture_request(
        endpoint_path=SCQAM_DS_CER_ENDPOINT,
        base_url=args.base_url,
        mac=args.mac,
        ip=args.inet,
        community=community,
        sample_time_elapsed=args.sample_time_elapsed,
    )


if __name__ == "__main__":
    sys.exit(main())
