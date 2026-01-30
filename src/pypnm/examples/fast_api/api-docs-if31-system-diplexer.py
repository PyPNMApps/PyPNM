#!/usr/bin/env python3
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

import argparse
import json
import sys
from typing import Any, Dict

import requests

from pypnm.lib.types import SnmpCommunity


DEFAULT_BASE_URL: str = "http://127.0.0.1:8000"
DEFAULT_SNMP_COMMUNITY: SnmpCommunity = SnmpCommunity("private")
DEFAULT_MAC_ADDRESS: str = "aa:bb:cc:dd:ee:ff"
DEFAULT_IP_ADDRESS: str = "192.168.0.100"
DEFAULT_TIMEOUT_SEC: float = 30.0


def build_payload(mac_address: str, ip_address: str, community: SnmpCommunity) -> Dict[str, Any]:
    """
    Build The Common Request Payload For Diplexer System Info.

    This matches the standard CommonRequest → cable_modem block used
    across the PyPNM FastAPI docs endpoints.
    """
    return {
        "cable_modem": {
            "mac_address": mac_address,
            "ip_address": ip_address,
            "snmp": {
                "snmpV2C": {
                    "community": community,
                }
            },
        }
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Example client for POST /docs/if31/system/diplexer"
    )

    parser.add_argument(
        "--mac",
        dest="mac_address",
        default=DEFAULT_MAC_ADDRESS,
        help=f"Cable modem MAC address (default: {DEFAULT_MAC_ADDRESS})",
    )
    parser.add_argument(
        "--inet",
        dest="ip_address",
        default=DEFAULT_IP_ADDRESS,
        help=f"Cable modem IP address (default: {DEFAULT_IP_ADDRESS})",
    )
    parser.add_argument(
        "--community",
        dest="community",
        default=DEFAULT_SNMP_COMMUNITY,
        help=f"SNMP v2c community (default: {DEFAULT_SNMP_COMMUNITY})",
    )
    parser.add_argument(
        "--base-url",
        dest="base_url",
        default=DEFAULT_BASE_URL,
        help=f"Base URL for FastAPI service (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--timeout",
        dest="timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SEC,
        help=f"HTTP timeout in seconds (default: {DEFAULT_TIMEOUT_SEC})",
    )

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    url = args.base_url.rstrip("/") + "/docs/if31/system/diplexer"
    community = SnmpCommunity(args.community)
    payload = build_payload(args.mac_address, args.ip_address, community)

    print(f"Sending POST to {url} with payload:")
    print(json.dumps(payload, indent=2))

    try:
        response = requests.post(url, json=payload, timeout=args.timeout)
        response.raise_for_status()
    except requests.RequestException as exc:
        print("\nRequest failed:")
        print(str(exc))
        return 1

    print("\nResponse:")
    try:
        data = response.json()
        print(json.dumps(data, indent=2))
    except ValueError:
        # Not JSON, just dump raw text
        print(response.text)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
