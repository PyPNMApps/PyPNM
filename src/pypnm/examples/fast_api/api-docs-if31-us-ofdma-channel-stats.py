#!/usr/bin/env python3
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

# Example CLI client for:
# POST /docs/if31/us/ofdma/channel/stats

import argparse
import json
from typing import Any

import requests

from pypnm.lib.types import SnmpCommunity


DEFAULT_FAST_API_HOST: str = "127.0.0.1"
DEFAULT_FAST_API_PORT: int = 8000
DEFAULT_SNMP_COMMUNITY: SnmpCommunity = SnmpCommunity("private")
DEFAULT_TIMEOUT_SEC: float = 30.0


def build_payload(mac_address: str, ip_address: str, community: SnmpCommunity) -> dict[str, Any]:
    """
    Build The Request Payload For The OFDMA Upstream Channel Stats Endpoint.
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


def parse_args() -> argparse.Namespace:
    """
    Parse Command-Line Arguments For The Example Client.
    """
    parser = argparse.ArgumentParser(
        description="Example client for /docs/if31/us/ofdma/channel/stats"
    )
    parser.add_argument(
        "--mac",
        dest="mac_address",
        required=True,
        help="Cable modem MAC address (e.g. aa:bb:cc:dd:ee:ff)",
    )
    parser.add_argument(
        "--inet",
        dest="ip_address",
        required=True,
        help="Cable modem IP address (e.g. 192.168.0.100)",
    )
    parser.add_argument(
        "--community",
        dest="community",
        default=DEFAULT_SNMP_COMMUNITY,
        help=f"SNMPv2c community (default: {DEFAULT_SNMP_COMMUNITY})",
    )
    parser.add_argument(
        "--host",
        dest="host",
        default=DEFAULT_FAST_API_HOST,
        help=f"FastAPI host (default: {DEFAULT_FAST_API_HOST})",
    )
    parser.add_argument(
        "--port",
        dest="port",
        type=int,
        default=DEFAULT_FAST_API_PORT,
        help=f"FastAPI port (default: {DEFAULT_FAST_API_PORT})",
    )
    parser.add_argument(
        "--timeout",
        dest="timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SEC,
        help=f"HTTP timeout in seconds (default: {DEFAULT_TIMEOUT_SEC})",
    )
    parser.add_argument(
        "--no-pretty",
        dest="pretty",
        action="store_false",
        help="Disable pretty-printed JSON output",
    )
    parser.set_defaults(pretty=True)

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    url: str = f"http://{args.host}:{args.port}/docs/if31/us/ofdma/channel/stats"
    community = SnmpCommunity(args.community)
    payload: dict[str, Any] = build_payload(
        mac_address=args.mac_address,
        ip_address=args.ip_address,
        community=community,
    )

    print(f"Sending POST to {url} with payload:")
    print(json.dumps(payload, indent=2))

    try:
        response = requests.post(url, json=payload, timeout=args.timeout)
        response.raise_for_status()
    except requests.RequestException as exc:
        print("\nRequest failed:")
        print(str(exc))
        return

    print("\nResponse:")
    if args.pretty:
        try:
            obj = response.json()
            print(json.dumps(obj, indent=2))
        except ValueError:
            # Not JSON, just print text
            print(response.text)
    else:
        print(response.text)


if __name__ == "__main__":
    main()
