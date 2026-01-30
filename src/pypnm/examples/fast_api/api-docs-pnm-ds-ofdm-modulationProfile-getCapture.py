#!/usr/bin/env python3

from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

import argparse
import json
from typing import Any

import requests

from pypnm.examples.common.common_cli import (
    DEFAULT_BASE_URL,
    DEFAULT_HTTP_TIMEOUT_SEC,
    DEFAULT_SNMP_COMMUNITY,
    EXIT_REQUEST_ERROR,
    EXIT_SUCCESS,
)
from pypnm.lib.types import SnmpCommunity

ENDPOINT_PATH: str = "/docs/pnm/ds/ofdm/modulationProfile/getCapture"
DEFAULT_TFTP_IPV6: str = "::1"


def _join_url(base_url: str, endpoint_path: str) -> str:
    """
    Join Base URL And Endpoint Path Into A Single URL String.
    """
    base: str = base_url.rstrip("/")
    path: str = endpoint_path.lstrip("/")
    return f"{base}/{path}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="PyPNM FastAPI - Downstream OFDM Modulation Profile getCapture",
    )
    parser.add_argument(
        "--mac",
        "-m",
        required=True,
        help="MAC address of the cable modem",
    )
    parser.add_argument(
        "--inet",
        "-i",
        required=True,
        help="IPv4 address of the cable modem",
    )
    parser.add_argument(
        "--tftp-ipv4",
        "-t4",
        required=True,
        help="IPv4 address of the TFTP server used for PNM file transfers",
    )
    parser.add_argument(
        "--tftp-ipv6",
        "-t6",
        default=DEFAULT_TFTP_IPV6,
        help=f"IPv6 address of the TFTP server (default: {DEFAULT_TFTP_IPV6})",
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
        help=f"FastAPI base URL (default: {DEFAULT_BASE_URL})",
    )
    return parser.parse_args()


def build_payload(
    mac: str,
    ip: str,
    community: SnmpCommunity,
    tftp_ipv4: str,
    tftp_ipv6: str,
) -> dict[str, Any]:
    """
    Build Request Payload For /docs/pnm/ds/ofdm/modulationProfile/getCapture.
    """
    cable_modem: dict[str, Any] = {
        "mac_address": mac,
        "ip_address": ip,
        "pnm_parameters": {
            "tftp": {
                "ipv4": tftp_ipv4,
                "ipv6": tftp_ipv6,
            },
        },
        "snmp": {
            "snmpV2C": {
                "community": community,
            },
        },
    }

    analysis: dict[str, Any] = {
        "type": "basic",
        "output": {
            "type": "json",
        },
        "plot": {
            "ui": {
                "theme": "dark",
            },
        },
    }

    return {
        "cable_modem": cable_modem,
        "analysis": analysis,
    }


def main() -> int:
    args = parse_args()

    url: str = _join_url(args.base_url, ENDPOINT_PATH)
    community = SnmpCommunity(args.community)
    payload: dict[str, Any] = build_payload(
        mac=args.mac,
        ip=args.inet,
        community=community,
        tftp_ipv4=args.tftp_ipv4,
        tftp_ipv6=args.tftp_ipv6,
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
        print(response.text)

    return EXIT_SUCCESS


if __name__ == "__main__":
    raise SystemExit(main())
