#!/usr/bin/env python3
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

import argparse
import json
from typing import Any, Dict

import requests

from pypnm.lib.types import SnmpCommunity


DEFAULT_BASE_URL: str = "http://127.0.0.1:8000"
DEFAULT_SNMP_COMMUNITY: SnmpCommunity = SnmpCommunity("private")
DEFAULT_TIMEOUT_SEC: float = 30.0


def build_payload(mac: str, ip: str, community: SnmpCommunity) -> Dict[str, Any]:
    """
    Build The Request Payload For /docs/if31/ds/ofdm/profile/stats.
    """
    return {
        "cable_modem": {
            "mac_address": mac,
            "ip_address": ip,
            "snmp": {
                "snmpV2C": {
                    "community": community,
                }
            },
        }
    }


def parse_args() -> argparse.Namespace:
    """
    Parse Command Line Arguments.
    """
    parser = argparse.ArgumentParser(
        description="Example client for /docs/if31/ds/ofdm/profile/stats"
    )

    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"FastAPI base URL (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--mac",
        required=True,
        help="Cable modem MAC address (e.g. aa:bb:cc:dd:ee:ff)",
    )
    parser.add_argument(
        "--inet",
        required=True,
        help="Cable modem IP address (e.g. 172.19.32.171)",
    )
    parser.add_argument(
        "--community",
        default=DEFAULT_SNMP_COMMUNITY,
        help=f"SNMPv2c community string (default: {DEFAULT_SNMP_COMMUNITY})",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SEC,
        help=f"HTTP timeout in seconds (default: {DEFAULT_TIMEOUT_SEC})",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    url = f"{args.base_url.rstrip('/')}/docs/if31/ds/ofdm/profile/stats"
    community = SnmpCommunity(args.community)
    payload = build_payload(args.mac, args.inet, community)

    print(f"Sending POST to {url} with payload:")
    print(json.dumps(payload, indent=2))
    print()

    try:
        resp = requests.post(url, json=payload, timeout=args.timeout)
        resp.raise_for_status()
    except requests.RequestException as exc:
        print("Request failed:")
        print(str(exc))
        return

    print("Response:")
    try:
        data = resp.json()
        print(json.dumps(data, indent=2))
    except ValueError:
        print(resp.text)


if __name__ == "__main__":
    main()
