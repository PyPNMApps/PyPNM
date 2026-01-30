#!/usr/bin/env python3

from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

import argparse
import json
import sys
from typing import Any, Dict

import requests

from pypnm.examples.common.common_cli import (
    DEFAULT_BASE_URL,
    DEFAULT_HTTP_TIMEOUT_SEC,
    DEFAULT_SNMP_COMMUNITY,
)
from pypnm.lib.types import SnmpCommunity

EXIT_SUCCESS: int = 0
EXIT_REQUEST_ERROR: int = 3


def build_ds_histogram_payload(
    mac: str,
    ip: str,
    community: SnmpCommunity,
    tftp_ipv4: str,
    tftp_ipv6: str,
    sample_duration: int,
) -> Dict[str, Any]:
    """
    Build The Request Payload For /docs/pnm/ds/histogram/getCapture.

    This payload extends the common cable_modem block with:
    - pnm_parameters.tftp: TFTP server IPv4/IPv6 for PNM file upload
    - analysis: basic JSON analysis with dark themed plotting hints
    - capture_settings.sample_duration: histogram dwell time in seconds
    """
    return {
        "cable_modem": {
            "mac_address": mac,
            "ip_address": ip,
            "pnm_parameters": {
                "tftp": {
                    "ipv4": tftp_ipv4,
                    "ipv6": tftp_ipv6,
                }
            },
            "snmp": {
                "snmpV2C": {
                    "community": community,
                }
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
                }
            },
        },
        "capture_settings": {
            "sample_duration": sample_duration,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="PyPNM - Downstream Histogram Capture Via FastAPI"
    )
    parser.add_argument(
        "--mac",
        "-m",
        required=True,
        help="MAC address of cable modem (e.g. aa:bb:cc:dd:ee:ff)",
    )
    parser.add_argument(
        "--inet",
        "-i",
        required=True,
        help="IP address of cable modem (e.g. 192.168.0.100)",
    )
    parser.add_argument(
        "--tftp-ipv4",
        "-t4",
        required=True,
        help="IPv4 address of TFTP server used for PNM file upload",
    )
    parser.add_argument(
        "--tftp-ipv6",
        "-t6",
        default="::1",
        help="IPv6 address of TFTP server (default: ::1)",
    )
    parser.add_argument(
        "--sample-duration",
        "-s",
        type=int,
        default=10,
        help="Histogram capture duration in seconds (default: 10)",
    )
    parser.add_argument(
        "--community",
        "-c",
        default=DEFAULT_SNMP_COMMUNITY,
        help=f"SNMP v2c community string (default: {DEFAULT_SNMP_COMMUNITY})",
    )
    parser.add_argument(
        "--base-url",
        "-u",
        default=DEFAULT_BASE_URL,
        help=f"Base URL for PyPNM FastAPI service (default: {DEFAULT_BASE_URL})",
    )
    args = parser.parse_args()

    endpoint_path: str = "/docs/pnm/ds/histogram/getCapture"
    base_url: str = args.base_url.rstrip("/")
    url: str = f"{base_url}{endpoint_path}"

    community = SnmpCommunity(args.community)
    payload: Dict[str, Any] = build_ds_histogram_payload(
        mac=args.mac,
        ip=args.inet,
        community=community,
        tftp_ipv4=args.tftp_ipv4,
        tftp_ipv6=args.tftp_ipv6,
        sample_duration=args.sample_duration,
    )

    print()
    print(f"Sending POST to {url} with payload:")
    print(json.dumps(payload, indent=2))

    try:
        response = requests.post(url, json=payload, timeout=DEFAULT_HTTP_TIMEOUT_SEC)
        response.raise_for_status()
    except requests.RequestException as exc:
        print()
        print("Request failed:")
        print(str(exc))
        return EXIT_REQUEST_ERROR

    print()
    print("Response:")
    try:
        print(json.dumps(response.json(), indent=2))
    except ValueError:
        # Non-JSON payload
        print(response.text)

    return EXIT_SUCCESS


if __name__ == "__main__":
    sys.exit(main())
