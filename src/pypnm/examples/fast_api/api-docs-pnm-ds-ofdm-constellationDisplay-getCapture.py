#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import argparse
import json
from typing import Any, Dict

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


ENDPOINT_PATH: str = "/docs/pnm/ds/ofdm/constellationDisplay/getCapture"


def build_constellation_display_payload(
    mac: str,
    ip: str,
    community: SnmpCommunity,
    tftp_ipv4: str,
    tftp_ipv6: str,
) -> Dict[str, Any]:
    """
    Build The Request Payload For Downstream OFDM Constellation Display getCapture.

    This helper wraps the common cable_modem payload and extends it with PNM
    parameters (TFTP server), analysis configuration, and capture settings.
    """
    cable_modem_payload: CableModemRequestPayload = build_cable_modem_payload(
        mac=mac,
        ip=ip,
        community=community,
    )

    request_payload: Dict[str, Any] = {
        "cable_modem": {
            **cable_modem_payload["cable_modem"],
            "pnm_parameters": {
                "tftp": {
                    "ipv4": tftp_ipv4,
                    "ipv6": tftp_ipv6,
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
                "options": {
                    "display_cross_hair": True,
                },
            },
        },
        "capture_settings": {
            "modulation_order_offset": 0,
            "number_sample_symbol": 8192,
        },
    }
    return request_payload


def main() -> int:
    """
    Issue A Constellation Display getCapture Request Against The PyPNM FastAPI Service.

    This script sends a POST request to the /docs/pnm/ds/ofdm/constellationDisplay/getCapture
    endpoint using the provided cable modem MAC address, IP address, SNMP v2c community,
    and TFTP server configuration. The response JSON is printed to stdout.
    """
    parser = argparse.ArgumentParser(
        description="PyPNM - PNM Downstream OFDM Constellation Display getCapture (FastAPI example)",
    )
    parser.add_argument(
        "--mac",
        "-m",
        required=True,
        help="MAC address of cable modem (aa:bb:cc:dd:ee:ff)",
    )
    parser.add_argument(
        "--inet",
        "-i",
        required=True,
        help="IP address of cable modem (192.168.0.1)",
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
        help="IPv4 address of TFTP server (e.g., 192.168.0.10)",
    )
    parser.add_argument(
        "--tftp-ipv6",
        "-t6",
        default="::1",
        help="IPv6 address of TFTP server (default: ::1)",
    )
    parser.add_argument(
        "--base-url",
        "-b",
        default=DEFAULT_BASE_URL,
        help=f"Base URL of FastAPI service (default: {DEFAULT_BASE_URL})",
    )

    args = parser.parse_args()

    url: str = _join_url(args.base_url, ENDPOINT_PATH)
    community = SnmpCommunity(args.community)
    payload: Dict[str, Any] = build_constellation_display_payload(
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
