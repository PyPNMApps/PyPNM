#!/usr/bin/env python3

from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

import argparse
import json
from typing import Any

import requests

from pypnm.examples.common.common_cli import (
    CableModemRequestPayload,
    DEFAULT_BASE_URL,
    DEFAULT_HTTP_TIMEOUT_SEC,
    DEFAULT_SNMP_COMMUNITY,
    EXIT_REQUEST_ERROR,
    EXIT_SUCCESS,
    _join_url,
    build_cable_modem_payload,
)
from pypnm.lib.types import SnmpCommunity


def main() -> int:
    """
    Downstream OFDM RxMER - Trigger Capture Via FastAPI.

    This example sends a POST request to the PyPNM FastAPI endpoint
    /docs/pnm/ds/ofdm/rxMer/getCapture using the common cable_modem
    payload plus PNM TFTP parameters and a basic analysis block.
    """
    parser = argparse.ArgumentParser(description="PyPNM FastAPI - DS OFDM RxMER Get Capture")
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
        help="IP address of cable modem (e.g. 172.19.32.171)",
    )
    parser.add_argument(
        "--tftp-ipv4",
        "-t4",
        required=True,
        help="IPv4 address of TFTP server (e.g. 172.19.8.28)",
    )
    parser.add_argument(
        "--tftp-ipv6",
        "-t6",
        default="::1",
        help="IPv6 address of TFTP server (default: ::1)",
    )
    parser.add_argument(
        "--community-write",
        "-cw",
        default=DEFAULT_SNMP_COMMUNITY,
        help=f"SNMP write community string (default: {DEFAULT_SNMP_COMMUNITY})",
    )
    parser.add_argument(
        "--base-url",
        "-b",
        default=DEFAULT_BASE_URL,
        help=f"Base URL for FastAPI service (default: {DEFAULT_BASE_URL})",
    )

    args = parser.parse_args()

    # Strongly-typed base payload (TypedDict)
    community = SnmpCommunity(args.community_write)
    cm_payload: CableModemRequestPayload = build_cable_modem_payload(
        mac=args.mac,
        ip=args.inet,
        community=community,
    )

    # Top-level JSON payload for FastAPI - use a plain dict so we can
    # safely add extra fields (pnm_parameters, analysis, etc.)
    payload: dict[str, Any] = {
        "cable_modem": {
            **cm_payload["cable_modem"],
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
    }

    url: str = _join_url(args.base_url, "/docs/pnm/ds/ofdm/rxMer/getCapture")

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
        print(response.text)

    return EXIT_SUCCESS


if __name__ == "__main__":
    raise SystemExit(main())
