#!/usr/bin/env python3

from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

import argparse
import sys

from pypnm.examples.common.common_cli import (
    DEFAULT_BASE_URL,
    DEFAULT_SNMP_COMMUNITY,
    send_cable_modem_pnm_and_analysis_request,
)
from pypnm.lib.types import SnmpCommunity

ENDPOINT_PATH: str = "/docs/pnm/ds/ofdm/channelEstCoeff/getCapture"


def main() -> int:
    """
    PyPNM FastAPI - Downstream OFDM Channel Estimate Coefficients - getCapture.

    This example issues a POST to the PyPNM FastAPI endpoint
    `/docs/pnm/ds/ofdm/channelEstCoeff/getCapture` using a `cable_modem`
    + `pnm_parameters` + `analysis` request payload. The TFTP server is
    passed on the command line and used for PNM file retrieval.
    """
    parser = argparse.ArgumentParser(
        description="PyPNM FastAPI - Downstream OFDM Channel Estimate Coefficients - getCapture"
    )
    parser.add_argument(
        "--base-url",
        "-b",
        default=DEFAULT_BASE_URL,
        help=f"PyPNM FastAPI base URL (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--mac",
        "-m",
        required=True,
        help="Cable modem MAC address",
    )
    parser.add_argument(
        "--inet",
        "-i",
        required=True,
        help="Cable modem IP address",
    )
    parser.add_argument(
        "--community",
        "-c",
        default=DEFAULT_SNMP_COMMUNITY,
        help=f"SNMP v2c community string (default: {DEFAULT_SNMP_COMMUNITY})",
    )
    parser.add_argument(
        "--tftp-ipv4",
        "-t4",
        required=True,
        help="TFTP server IPv4 address used for PNM file retrieval",
    )
    parser.add_argument(
        "--tftp-ipv6",
        "-t6",
        default="::1",
        help="TFTP server IPv6 address (default: ::1)",
    )

    args = parser.parse_args()

    community = SnmpCommunity(args.community)
    return send_cable_modem_pnm_and_analysis_request(
        endpoint_path=ENDPOINT_PATH,
        base_url=args.base_url,
        mac=args.mac,
        ip=args.inet,
        community=community,
        tftp_ipv4=args.tftp_ipv4,
        tftp_ipv6=args.tftp_ipv6,
    )


if __name__ == "__main__":
    raise SystemExit(main())
