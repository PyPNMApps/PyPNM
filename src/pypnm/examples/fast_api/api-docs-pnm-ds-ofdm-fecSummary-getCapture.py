#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict

try:
    import requests
except ImportError:
    print("The 'requests' library is not installed. Please install it before running this example.")
    sys.exit(2)

from pypnm.examples.common.common_cli import (
    DEFAULT_BASE_URL,
    DEFAULT_SNMP_COMMUNITY,
    DEFAULT_HTTP_TIMEOUT_SEC,
    CableModemRequestPayload,
    build_cable_modem_payload,
)
from pypnm.lib.types import SnmpCommunity

ENDPOINT_PATH: str = "/docs/pnm/ds/ofdm/fecSummary/getCapture"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="FastAPI Example: /docs/pnm/ds/ofdm/fecSummary/getCapture"
    )
    parser.add_argument("--mac", "-m", required=True, help="MAC address of the cable modem")
    parser.add_argument("--inet", "-i", required=True, help="IP address of the cable modem")
    parser.add_argument("--tftp-ipv4", "-t4", required=True, help="IPv4 address of the TFTP server")
    parser.add_argument(
        "--tftp-ipv6",
        "-t6",
        default="::1",
        help="IPv6 address of the TFTP server (default: ::1)",
    )
    parser.add_argument(
        "--fec-summary-type",
        "-f",
        type=int,
        choices=(2, 3),
        default=2,
        help="FEC summary type: 2 = 10 minutes, 3 = 24 hours (default: 2)",
    )
    parser.add_argument(
        "--community",
        "-c",
        default=DEFAULT_SNMP_COMMUNITY,
        help=f"SNMP v2c community string (default: {DEFAULT_SNMP_COMMUNITY})",
    )
    parser.add_argument(
        "--base-url",
        "-b",
        default=DEFAULT_BASE_URL,
        help=f"Base URL of the FastAPI service (default: {DEFAULT_BASE_URL})",
    )

    args = parser.parse_args()

    url: str = _join_url(args.base_url, ENDPOINT_PATH)

    community = SnmpCommunity(args.community)
    base_payload: CableModemRequestPayload = build_cable_modem_payload(
        mac=args.mac,
        ip=args.inet,
        community=community,
    )

    request_body: Dict[str, Any] = {
        "cable_modem": {
            **base_payload["cable_modem"],
            "pnm_parameters": {
                "tftp": {
                    "ipv4": args.tftp_ipv4,
                    "ipv6": args.tftp_ipv6,
                },
            },
        },
        "analysis": {
            "type": "basic",
            "output": {
                "type": "json",
            },
            "plot": {
                "ui": {
                    "theme": "dark",
                },
            },
        },
        "capture_settings": {
            "fec_summary_type": args.fec_summary_type,
        },
    }

    print()
    print(f"Sending POST to {url} with payload:")
    print(json.dumps(request_body, indent=2))

    try:
        response = requests.post(url, json=request_body, timeout=DEFAULT_HTTP_TIMEOUT_SEC)
        response.raise_for_status()
    except requests.RequestException as exc:
        print()
        print("Request failed:")
        print(str(exc))
        return 3

    print()
    print("Response:")
    try:
        print(json.dumps(response.json(), indent=2))
    except ValueError:
        print(response.text)

    return 0


def _join_url(base_url: str, endpoint_path: str) -> str:
    base: str = base_url.rstrip("/")
    path: str = endpoint_path.lstrip("/")
    return f"{base}/{path}"


if __name__ == "__main__":
    raise SystemExit(main())
