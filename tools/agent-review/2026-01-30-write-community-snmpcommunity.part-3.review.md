## Agent Review Bundle Summary
- Goal: Update community type hints to SnmpCommunity and fix default handling
- Changes: Swap community annotations, add SnmpCommunity casts, and refresh SPDX years
- Files: src/pypnm/api/routes/common/classes/common_endpoint_classes/schema/base_snmp.py, src/pypnm/api/routes/common/extended/common_measure_service.py, src/pypnm/api/routes/docs/pnm/ds/ofdm/mer_margin/router.py, src/pypnm/api/routes/docs/pnm/interface/router.py, src/pypnm/api/routes/docs/pnm/interface/service.py, src/pypnm/docsis/cable_modem.py, src/pypnm/docsis/cm_snmp_operation.py, src/pypnm/examples/common/cm_pnm_helpers.py, src/pypnm/examples/common/common_cli.py, src/pypnm/examples/fast_api/api-docs-dev-eventlog.py, src/pypnm/examples/fast_api/api-docs-if30-ds-scqam-chan-codewordErrorRate.py, src/pypnm/examples/fast_api/api-docs-if30-ds-scqam-chan-stats.py, src/pypnm/examples/fast_api/api-docs-if30-us-atdma-chan-preEqualization.py, src/pypnm/examples/fast_api/api-docs-if30-us-atdma-chan-stats.py, src/pypnm/examples/fast_api/api-docs-if31-docsis-baseCapability.py, src/pypnm/examples/fast_api/api-docs-if31-ds-ofdm-chan-stats.py, src/pypnm/examples/fast_api/api-docs-if31-ds-ofdm-profile-stats.py, src/pypnm/examples/fast_api/api-docs-if31-system-diplexer.py, src/pypnm/examples/fast_api/api-docs-if31-us-ofdma-channel-stats.py, src/pypnm/examples/fast_api/api-docs-pnm-ds-histogram-getCapture.py, src/pypnm/examples/fast_api/api-docs-pnm-ds-ofdm-channelEstCoeff-getCapture.py, src/pypnm/examples/fast_api/api-docs-pnm-ds-ofdm-constellationDisplay-getCapture.py, src/pypnm/examples/fast_api/api-docs-pnm-ds-ofdm-fecSummary-getCapture.py, src/pypnm/examples/fast_api/api-docs-pnm-ds-ofdm-modulationProfile-getCapture.py, src/pypnm/examples/fast_api/api-docs-pnm-ds-ofdm-rxMer-getCapture.py, src/pypnm/examples/fast_api/api-docs-pnm-interface-stats.py, src/pypnm/examples/fast_api/api-system-sysDescr.py, src/pypnm/examples/fast_api/api-system-upTime.py, src/pypnm/examples/python/py-pnm-ds-ofdm-chan-estimate.py, src/pypnm/examples/python/py-pnm-ds-ofdm-rxmer.py, src/pypnm/snmp/snmp_v2c.py
- Tests: python3 -m compileall src; ruff check src; ruff format --check . (fails pre-existing formatting); pytest -q
- Notes: Ruff format check fails due to pre-existing repo formatting drift

# FILE: src/pypnm/examples/fast_api/api-docs-if30-ds-scqam-chan-codewordErrorRate.py
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
# FILE: src/pypnm/examples/fast_api/api-docs-if30-ds-scqam-chan-stats.py
#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import argparse
import sys

from pypnm.examples.common.common_cli import (
    DEFAULT_BASE_URL,
    DEFAULT_SNMP_COMMUNITY,
    send_cable_modem_request,
)
from pypnm.lib.types import SnmpCommunity


SCQAM_DS_STATS_ENDPOINT: str = "/docs/if30/ds/scqam/chan/stats"


def main() -> int:
    """
    Test The /docs/if30/ds/scqam/chan/stats Endpoint Using A CLI Example.

    This entry point parses the MAC address, IP address, optional base URL,
    and SNMP v2c community string from the command line. It then uses the
    shared send_cable_modem_request helper to POST a cable_modem payload to
    the /docs/if30/ds/scqam/chan/stats endpoint. The resulting exit status is
    propagated as the process exit code so that automated scripts can detect
    failures.
    """
    parser = argparse.ArgumentParser(
        description="CLI example for the /docs/if30/ds/scqam/chan/stats endpoint.",
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

    args = parser.parse_args()

    community = SnmpCommunity(args.snmp_community)
    return send_cable_modem_request(
        endpoint_path=SCQAM_DS_STATS_ENDPOINT,
        base_url=args.base_url,
        mac=args.mac,
        ip=args.inet,
        community=community,
    )


if __name__ == "__main__":
    sys.exit(main())
# FILE: src/pypnm/examples/fast_api/api-docs-if30-us-atdma-chan-preEqualization.py
#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import argparse
import sys

from pypnm.examples.common.common_cli import (
    DEFAULT_BASE_URL,
    DEFAULT_SNMP_COMMUNITY,
    send_cable_modem_request,
)
from pypnm.lib.types import SnmpCommunity


ATDMA_US_PRE_EQ_ENDPOINT: str = "/docs/if30/us/atdma/chan/preEqualization"


def main() -> int:
    """
    Test The /docs/if30/us/atdma/chan/preEqualization Endpoint Using A CLI Example.

    This entry point parses the MAC address, IP address, optional base URL,
    and SNMP v2c community string from the command line. It then uses the
    shared send_cable_modem_request helper to POST a cable_modem payload to
    the /docs/if30/us/atdma/chan/preEqualization endpoint. The resulting exit
    status is propagated as the process exit code so that automated scripts
    can detect failures.
    """
    parser = argparse.ArgumentParser(
        description="CLI example for the /docs/if30/us/atdma/chan/preEqualization endpoint.",
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

    args = parser.parse_args()

    community = SnmpCommunity(args.snmp_community)
    return send_cable_modem_request(
        endpoint_path=ATDMA_US_PRE_EQ_ENDPOINT,
        base_url=args.base_url,
        mac=args.mac,
        ip=args.inet,
        community=community,
    )


if __name__ == "__main__":
    sys.exit(main())
# FILE: src/pypnm/examples/fast_api/api-docs-if30-us-atdma-chan-stats.py
#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import argparse
import sys

from pypnm.examples.common.common_cli import (
    DEFAULT_BASE_URL,
    DEFAULT_SNMP_COMMUNITY,
    send_cable_modem_request,
)
from pypnm.lib.types import SnmpCommunity


ATDMA_US_STATS_ENDPOINT: str = "/docs/if30/us/atdma/chan/stats"


def main() -> int:
    """
    Test The /docs/if30/us/atdma/chan/stats Endpoint Using A CLI Example.

    This entry point parses the MAC address, IP address, optional base URL,
    and SNMP v2c community string from the command line. It then uses the
    shared send_cable_modem_request helper to POST a cable_modem payload to
    the /docs/if30/us/atdma/chan/stats endpoint. The resulting exit status is
    propagated as the process exit code so that automated scripts can detect
    failures.
    """
    parser = argparse.ArgumentParser(
        description="CLI example for the /docs/if30/us/atdma/chan/stats endpoint.",
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

    args = parser.parse_args()

    community = SnmpCommunity(args.snmp_community)
    return send_cable_modem_request(
        endpoint_path=ATDMA_US_STATS_ENDPOINT,
        base_url=args.base_url,
        mac=args.mac,
        ip=args.inet,
        community=community,
    )


if __name__ == "__main__":
    sys.exit(main())
# FILE: src/pypnm/examples/fast_api/api-docs-if31-docsis-baseCapability.py
#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import argparse
import sys

from pypnm.examples.common.common_cli import (
    DEFAULT_BASE_URL,
    DEFAULT_SNMP_COMMUNITY,
    EXIT_SUCCESS,
    send_cable_modem_request,
)
from pypnm.lib.types import SnmpCommunity

ENDPOINT_PATH: str = "/docs/if31/docsis/baseCapability"


def parse_args() -> argparse.Namespace:
    """
    Parse Command-Line Arguments For The Base Capability Example CLI.
    """
    parser = argparse.ArgumentParser(
        description="Call the /docs/if31/docsis/baseCapability endpoint with a cable_modem payload.",
    )

    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"PyPNM FastAPI server base URL (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--community",
        default=DEFAULT_SNMP_COMMUNITY,
        help=f"SNMP v2c community string (default: {DEFAULT_SNMP_COMMUNITY})",
    )
    parser.add_argument(
        "--mac",
        required=True,
        help="Cable modem MAC address (for example: aa:bb:cc:dd:ee:ff)",
    )
    parser.add_argument(
        "--inet",
        required=True,
        help="Cable modem IP address (for example: 172.19.32.171)",
    )

    return parser.parse_args()


def main() -> int:
    """
    Execute The /docs/if31/docsis/baseCapability Example Request.
    """
    args = parse_args()

    community = SnmpCommunity(args.community)
    return send_cable_modem_request(
        endpoint_path=ENDPOINT_PATH,
        base_url=args.base_url,
        mac=args.mac,
        ip=args.inet,
        community=community,
    )


if __name__ == "__main__":
    sys.exit(main())
# FILE: src/pypnm/examples/fast_api/api-docs-if31-ds-ofdm-chan-stats.py
#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import argparse
import sys

from pypnm.examples.common.common_cli import (
    DEFAULT_BASE_URL,
    DEFAULT_SNMP_COMMUNITY,
    send_cable_modem_request,
)
from pypnm.lib.types import SnmpCommunity


ENDPOINT_PATH: str = "/docs/if31/ds/ofdm/chan/stats"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Example client for /docs/if31/ds/ofdm/chan/stats",
    )

    parser.add_argument(
        "--mac",
        required=True,
        help="Cable modem MAC address (e.g. aa:bb:cc:dd:ee:ff)",
    )
    parser.add_argument(
        "--inet",
        dest="ip_address",
        required=True,
        help="Cable modem IP address (e.g. 172.19.32.171)",
    )
    parser.add_argument(
        "--community",
        default=DEFAULT_SNMP_COMMUNITY,
        help=f"SNMPv2c community string (default: {DEFAULT_SNMP_COMMUNITY})",
    )
    parser.add_argument(
        "--url",
        default=DEFAULT_BASE_URL,
        help=f"Base FastAPI server URL (default: {DEFAULT_BASE_URL})",
    )

    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    community = SnmpCommunity(args.community)
    exit_code: int = send_cable_modem_request(
        endpoint_path=ENDPOINT_PATH,
        base_url=args.url,
        mac=args.mac,
        ip=args.ip_address,
        community=community,
    )

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
# FILE: src/pypnm/examples/fast_api/api-docs-if31-ds-ofdm-profile-stats.py
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
# FILE: src/pypnm/examples/fast_api/api-docs-if31-system-diplexer.py
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
# FILE: src/pypnm/examples/fast_api/api-docs-if31-us-ofdma-channel-stats.py
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
# FILE: src/pypnm/examples/fast_api/api-docs-pnm-ds-histogram-getCapture.py
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
# FILE: src/pypnm/examples/fast_api/api-docs-pnm-ds-ofdm-channelEstCoeff-getCapture.py
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
# FILE: src/pypnm/examples/fast_api/api-docs-pnm-ds-ofdm-constellationDisplay-getCapture.py
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
# FILE: src/pypnm/examples/fast_api/api-docs-pnm-ds-ofdm-fecSummary-getCapture.py
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
# FILE: src/pypnm/examples/fast_api/api-docs-pnm-ds-ofdm-modulationProfile-getCapture.py
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
# FILE: src/pypnm/examples/fast_api/api-docs-pnm-ds-ofdm-rxMer-getCapture.py
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
# FILE: src/pypnm/examples/fast_api/api-docs-pnm-interface-stats.py
#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import argparse
import sys

from pypnm.examples.common.common_cli import (
    DEFAULT_BASE_URL,
    DEFAULT_SNMP_COMMUNITY,
    send_cable_modem_request,
)
from pypnm.lib.types import SnmpCommunity


PNM_INTERFACE_STATS_ENDPOINT: str = "/docs/pnm/interface/stats"


def main() -> int:
    """
    Test The /docs/pnm/interface/stats Endpoint Using A CLI Example.

    This entry point parses the MAC address, IP address, optional base URL, and
    SNMP v2c community string from the command line. It then uses the shared
    send_cable_modem_request helper to POST a payload containing the cable_modem
    configuration to the /docs/pnm/interface/stats endpoint. The resulting exit
    status is propagated as the process exit code so that automated scripts can
    detect failures.
    """
    parser = argparse.ArgumentParser(
        description="CLI example for the /docs/pnm/interface/stats endpoint.",
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

    args = parser.parse_args()

    community = SnmpCommunity(args.snmp_community)
    return send_cable_modem_request(
        endpoint_path=PNM_INTERFACE_STATS_ENDPOINT,
        base_url=args.base_url,
        mac=args.mac,
        ip=args.inet,
        community=community,
    )


if __name__ == "__main__":
    sys.exit(main())
# FILE: src/pypnm/examples/fast_api/api-system-sysDescr.py
#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import argparse
import sys

from pypnm.examples.common.common_cli import (
    DEFAULT_BASE_URL,
    DEFAULT_SNMP_COMMUNITY,
    EXIT_SUCCESS,
    EXIT_REQUEST_ERROR,
    send_cable_modem_request,
)
from pypnm.lib.types import SnmpCommunity

ENDPOINT_PATH: str = "/system/sysDescr"


def parse_args() -> argparse.Namespace:
    """
    Parse Command-Line Arguments For The /system/sysDescr Example.
    """
    parser = argparse.ArgumentParser(
        description="Call /system/sysDescr on a PyPNM FastAPI server.",
    )
    parser.add_argument(
        "--mac",
        required=True,
        help="Cable modem MAC address (for example: aa:bb:cc:dd:ee:ff).",
    )
    parser.add_argument(
        "--inet",
        dest="ip",
        required=True,
        help="Cable modem IP address (for example: 192.168.0.100).",
    )
    parser.add_argument(
        "--community",
        default=DEFAULT_SNMP_COMMUNITY,
        help=f"SNMP v2c community (default: {DEFAULT_SNMP_COMMUNITY}).",
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"Base URL of the PyPNM FastAPI service (default: {DEFAULT_BASE_URL}).",
    )
    return parser.parse_args()


def main() -> int:
    """
    Entry Point For The /system/sysDescr CLI Example.

    Builds The cable_modem Payload And Sends A POST Request To The
    /system/sysDescr Endpoint Using The Shared Common CLI Helpers.
    """
    args = parse_args()

    community = SnmpCommunity(args.community)
    return send_cable_modem_request(
        endpoint_path=ENDPOINT_PATH,
        base_url=args.base_url,
        mac=args.mac,
        ip=args.ip,
        community=community,
    )


if __name__ == "__main__":
    sys.exit(main())
# FILE: src/pypnm/examples/fast_api/api-system-upTime.py
#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import argparse
import sys

from pypnm.examples.common.common_cli import (
    DEFAULT_BASE_URL,
    DEFAULT_SNMP_COMMUNITY,
    EXIT_SUCCESS,
    send_cable_modem_request,
)
from pypnm.lib.types import SnmpCommunity


ENDPOINT_PATH: str = "/system/upTime"


def _build_arg_parser() -> argparse.ArgumentParser:
    """
    Build The Command Line Argument Parser For The /system/upTime Example.

    This CLI helper issues a POST request to the PyPNM /system/upTime endpoint
    using the common cable_modem payload structure. The MAC address, IP address,
    SNMP community, and base URL can be provided on the command line.
    """
    parser = argparse.ArgumentParser(
        description="PyPNM FastAPI example client for /system/upTime",
    )

    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"Base URL for the PyPNM FastAPI server (default: {DEFAULT_BASE_URL})",
    )

    parser.add_argument(
        "--community",
        default=DEFAULT_SNMP_COMMUNITY,
        help=f"SNMP v2c community string (default: {DEFAULT_SNMP_COMMUNITY})",
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
        help="Cable modem management IP address (e.g. 172.19.32.171)",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """
    Entry Point For The /system/upTime Example Client.

    This function parses command line arguments and sends a POST request to
    the /system/upTime endpoint using send_cable_modem_request. The JSON
    response is printed to stdout. The return value is an exit status where
    zero indicates success.
    """
    if argv is None:
        argv = sys.argv[1:]

    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    community = SnmpCommunity(args.community)
    status: int = send_cable_modem_request(
        endpoint_path=ENDPOINT_PATH,
        base_url=args.base_url,
        mac=args.mac_address,
        ip=args.ip_address,
        community=community,
    )

    if status == EXIT_SUCCESS:
        return EXIT_SUCCESS
    return status


if __name__ == "__main__":
    raise SystemExit(main())
# FILE: src/pypnm/examples/python/py-pnm-ds-ofdm-chan-estimate.py
#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import argparse
import asyncio
import json
import logging
from typing import Sequence

from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.cm_snmp_operation import DocsPnmCmCtlStatus
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import InetAddressStr, MacAddressStr, SnmpCommunity
from pypnm.lib.utils import Generate

LOG_FORMAT: str                    = "%(asctime)s - %(levelname)s - %(message)s"
EXIT_FAILURE: int                  = 1
DEFAULT_PNM_POLL_INTERVAL_SECONDS: float = 1.0

logger = logging.getLogger("PyPnmDsOfdmChanEstCli")


async def _build_cable_modem(
    mac_address: MacAddressStr,
    ip_address: InetAddressStr,
    write_community: SnmpCommunity,
) -> CableModem:
    """
    Build And Verify A CableModem Instance For PNM Operations.

    Construct a ``CableModem`` using the supplied MAC address, IP address,
    and SNMP write community. Basic reachability is verified using ICMP ping,
    and the device ``sysDescr`` is logged for visibility.

    A ``RuntimeError`` is raised if the modem is not reachable so callers
    can treat this as an all-or-nothing setup step for subsequent PNM calls.
    """
    cm = CableModem(
        mac_address     = MacAddress(mac_address),
        inet            = Inet(ip_address),
        write_community = write_community,
    )

    if not cm.is_ping_reachable():
        logger.error("%s not reachable", cm.get_inet_address)
        raise RuntimeError(f"{cm.get_inet_address} not reachable")

    logger.info("Connected to: %s", await cm.getSysDescr())
    return cm


async def _discover_ofdm_indices(cm: CableModem) -> Sequence[int]:
    """
    Discover Downstream OFDM Channel Indices For The Cable Modem.

    Wrap the DOCSIS SNMP query that returns downstream OFDM channel
    indices. The discovered list is logged. A ``RuntimeError`` is raised
    if no indices are found, which typically indicates that the modem is
    not configured for OFDM or not provisioned as expected.
    """
    ofdm_idx_list: Sequence[int] = await cm.getDocsIf31CmDsOfdmChannelIdIndex()

    if not ofdm_idx_list:
        logger.error("No downstream OFDM channel indices discovered")
        raise RuntimeError("No downstream OFDM channel indices discovered")

    logger.info("Discovered OFDM channel indices: %s", list(ofdm_idx_list))
    return ofdm_idx_list


async def _configure_pnm_bulk_tftp(
    cm: CableModem,
    tftp_ipv4: InetAddressStr,
    tftp_dest_dir: str,
) -> None:
    """
    Configure PNM Bulk Transfer TFTP Server And Destination Directory.

    Program the DOCSIS PNM bulk data transfer settings on the cable modem
    for the provided IPv4 TFTP server and destination directory. A
    ``RuntimeError`` is raised if configuration fails so callers can stop
    the workflow early.
    """
    if await cm.setDocsPnmBulk(
        tftp_server = str(tftp_ipv4),
        tftp_path   = tftp_dest_dir,
    ):
        logger.info("PNM bulk TFTP configured: server=%s path=%s", tftp_ipv4, tftp_dest_dir)
        return

    logger.error("Unable to set TFTP server %s and/or TFTP path %s", tftp_ipv4, tftp_dest_dir)
    raise RuntimeError(f"Unable to configure PNM bulk TFTP: server={tftp_ipv4} path={tftp_dest_dir}")


async def _poll_pnm_test_until_complete(
    cm: CableModem,
    poll_interval_seconds: float = DEFAULT_PNM_POLL_INTERVAL_SECONDS,
) -> DocsPnmCmCtlStatus:
    """
    Poll The PNM Control Status Until The Test Completes.

    Repeatedly read ``DocsPnmCmCtlStatus`` and block until the status
    transitions away from ``TEST_IN_PROGRESS``. The final status value is
    returned so callers can validate success or failure.

    A configurable poll interval balances test responsiveness with
    network and CPU usage.
    """
    while True:
        status: DocsPnmCmCtlStatus = await cm.getDocsPnmCmCtlStatus()

        if status == DocsPnmCmCtlStatus.TEST_IN_PROGRESS:
            logger.info("Channel estimation measurement in progress...")
            await asyncio.sleep(poll_interval_seconds)
        else:
            logger.info("Channel estimation test completed with status: %s", status.name)
            return status


def _build_parser() -> argparse.ArgumentParser:
    """
    Build The Command-Line Argument Parser For The Channel Estimation CLI.

    Arguments mirror the FastAPI single-capture request for the OFDM
    downstream channel estimation endpoint so that configuration and
    invocation are consistent between REST and CLI usage.
    """
    parser = argparse.ArgumentParser(description="OFDM Downstream Channel Estimation CLI")

    parser.add_argument(
        "--mac", "-m",
        required=True,
        help="MAC address of the cable modem (for example: aa:bb:cc:dd:ee:ff)",
    )
    parser.add_argument(
        "--inet", "-i",
        required=True,
        help="IP address of the cable modem (for example: 192.168.0.100)",
    )
    parser.add_argument(
        "--tftp-ipv4", "-t4",
        required=True,
        help="IPv4 address of the TFTP server used for PNM bulk transfers",
    )
    parser.add_argument(
        "--tftp-dest-dir", "-td",
        default="",
        help="TFTP server destination directory (for example: /tftpboot/pnm)",
    )
    parser.add_argument(
        "--community-write", "-cw",
        default="private",
        help="SNMP write community string (default: private)",
    )

    return parser


async def _run_chan_estimation_capture(
    mac: MacAddressStr,
    ip: InetAddressStr,
    tftp_ipv4: InetAddressStr,
    tftp_dest_dir: str,
    write_community: SnmpCommunity,
) -> None:
    """
    Run A Downstream OFDM Channel Estimation Capture And Print Results As JSON.

    Workflow:

    1. Build and verify a ``CableModem`` instance.
    2. Discover downstream OFDM channel indices.
    3. Configure PNM bulk TFTP settings.
    4. For each OFDM index:
       - Request a new channel estimation capture file.
       - Poll the PNM control status until the test finishes.
    5. Fetch all channel estimation entries and print them as
       pretty-printed JSON on stdout for downstream tooling.
    """
    cm: CableModem = await _build_cable_modem(
        mac_address     = mac,
        ip_address      = ip,
        write_community = write_community,
    )

    ofdm_idx_list: Sequence[int] = await _discover_ofdm_indices(cm)
    await _configure_pnm_bulk_tftp(
        cm,
        tftp_ipv4     = tftp_ipv4,
        tftp_dest_dir = tftp_dest_dir,
    )

    for idx in ofdm_idx_list:
        chan_est_filename: str = f"ds-chan-est_{idx}_{Generate.time_stamp()}.bin"
        logger.info(
            "Requesting channel estimation capture for OFDM index %d with filename %s",
            idx,
            chan_est_filename,
        )

        await cm.setDocsPnmCmOfdmChEstCoef(
            ofdm_idx          = idx,
            chan_est_file_name = chan_est_filename,
        )
        await _poll_pnm_test_until_complete(cm)

    entries = await cm.getDocsPnmCmOfdmChanEstCoefEntry()
    results = [entry.model_dump() for entry in entries]

    json_data: str = json.dumps(results, indent=2)
    print(json_data)


async def main() -> None:
    """
    CLI Entry Point For The OFDM Downstream Channel Estimation Example.

    Parse command-line arguments, normalize them into typed parameters,
    and invoke the channel estimation capture workflow. This mirrors the
    behavior of the corresponding FastAPI endpoint while demonstrating
    direct Python API usage and printing JSON results directly to stdout.
    """
    parser = _build_parser()
    args = parser.parse_args()

    mac: MacAddressStr        = MacAddressStr(args.mac)
    ip: InetAddressStr        = InetAddressStr(args.inet)
    tftp_ipv4: InetAddressStr = InetAddressStr(args.tftp_ipv4)
    tftp_dest_dir: str        = str(args.tftp_dest_dir)
    write_community: SnmpCommunity      = SnmpCommunity(args.community_write)

    try:
        await _run_chan_estimation_capture(
            mac             = mac,
            ip              = ip,
            tftp_ipv4       = tftp_ipv4,
            tftp_dest_dir   = tftp_dest_dir,
            write_community = write_community,
        )
    except RuntimeError as exc:
        logger.error("Channel estimation capture failed: %s", exc)
        raise SystemExit(EXIT_FAILURE) from exc


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
    asyncio.run(main())
# FILE: src/pypnm/examples/python/py-pnm-ds-ofdm-rxmer.py
#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations


import argparse
import asyncio
import json
import logging
from typing import Any, Sequence

from pypnm.api.routes.common.classes.operation.cable_modem_precheck import CableModemServicePreCheck
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.extended.common_process_service import CommonProcessService
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.ds.ofdm.rxmer.service import CmDsOfdmRxMerService
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.cm_snmp_operation import DocsPnmCmDsOfdmRxMerEntry
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import InetAddressStr, MacAddressStr, SnmpCommunity
from pypnm.lib.utils import Generate, TimeUnit

LOG_FORMAT: str   = "%(asctime)s - %(levelname)s - %(message)s"
EXIT_FAILURE: int = 1

logger = logging.getLogger("PyPnmDsOfdmRxMerCli")


def _build_parser() -> argparse.ArgumentParser:
    """
    Build The Command-Line Argument Parser For The RxMER Set-And-Go CLI.

    Arguments are aligned with the FastAPI single-capture request for
    ``/docs/pnm/ds/ofdm/rxMer/getCapture`` so that configuration is
    consistent between REST and CLI usage.
    """
    parser = argparse.ArgumentParser(description="Downstream OFDM RxMER Set-And-Go CLI")

    parser.add_argument(
        "--mac", "-m",
        required=True,
        help="MAC address of the cable modem (for example: aa:bb:cc:dd:ee:ff)",
    )
    parser.add_argument(
        "--inet", "-i",
        required=True,
        help="IP address of the cable modem (for example: 192.168.0.100)",
    )
    parser.add_argument(
        "--tftp-ipv4", "-t4",
        required=True,
        help="IPv4 address of the TFTP server used for PNM bulk transfers",
    )
    parser.add_argument(
        "--tftp-ipv6", "-t6",
        required=False,
        help="IPv6 address of the TFTP server used for PNM bulk transfers "
             "(optional; defaults to --tftp-ipv4 when omitted)",
    )
    parser.add_argument(
        "--community-write", "-cw",
        default="private",
        help="SNMP write community string (default: private)",
    )

    return parser


async def _build_cable_modem(
    mac_address: MacAddressStr,
    ip_address: InetAddressStr,
    write_community: SnmpCommunity,
) -> CableModem:
    """
    Build A CableModem Instance For PNM Operations.

    Construct a ``CableModem`` using the supplied MAC address, IP address,
    and SNMP write community. Connectivity and OFDM presence are validated
    separately by ``CableModemServicePreCheck`` before any RxMER workflow
    is executed.
    """
    cm = CableModem(
        mac_address     = MacAddress(mac_address),
        inet            = Inet(ip_address),
        write_community = write_community,
    )
    return cm


def _parse_pnm_payload(msg_rsp: MessageResponse) -> list[Any]:
    """
    Parse PNM Payload Objects From The MessageResponse.

    The processed ``MessageResponse`` from ``CommonProcessService`` may
    contain payload entries as JSON strings or already-decoded Python
    structures. This helper normalizes all entries into Python objects so
    that they can be emitted as a single JSON document on stdout.
    """
    parsed: list[Any] = []

    for payload in msg_rsp.payload:  # type: ignore[attr-defined]
        if isinstance(payload, str):
            try:
                parsed.append(json.loads(payload))
            except json.JSONDecodeError:
                parsed.append(payload)
        else:
            parsed.append(payload)

    return parsed


async def _run_rxmer_set_and_go(
    mac: MacAddressStr,
    ip: InetAddressStr,
    tftp_ipv4: InetAddressStr,
    tftp_ipv6: InetAddressStr | None,
    write_community: SnmpCommunity,
) -> None:
    """
    Run The Downstream OFDM RxMER Set-And-Go Workflow And Emit Merged JSON.

    Workflow:

    1. Build a ``CableModem`` instance.
    2. Run ``CableModemServicePreCheck`` with ``validate_ofdm_exist=True`` to:
       - Verify basic connectivity.
       - Confirm at least one downstream OFDM channel exists.
    3. Build the TFTP server tuple ``tftp_servers`` from the IPv4 and IPv6
       CLI arguments (IPv6 falls back to IPv4 when omitted).
    4. Invoke ``CmDsOfdmRxMerService.set_and_go()`` to:
       - Configure PNM bulk transfer as needed.
       - Trigger RxMER capture on the modem.
       - Retrieve the resulting PNM file into a ``MessageResponse``.
    5. Pass the ``MessageResponse`` through ``CommonProcessService`` to
       parse the PNM file into structured payload objects.
    6. Query the SNMP RxMER statistics via
       ``CmDsOfdmRxMerService.getPnmMeasurementStatistics()`` to obtain
       ``DocsPnmCmDsOfdmRxMerEntry`` rows.
    7. Build a single merged JSON document containing:
       - Basic metadata (MAC, IP, status, timestamp)
       - Parsed PNM payload objects
       - RxMER measurement statistics
    8. Print the resulting JSON to stdout for downstream tooling.
    """
    cm: CableModem = await _build_cable_modem(
        mac_address     = mac,
        ip_address      = ip,
        write_community = write_community,
    )

    status, msg = await CableModemServicePreCheck(
        cable_modem        = cm,
        validate_ofdm_exist = True,
    ).run_precheck()

    if status != ServiceStatusCode.SUCCESS:
        logger.error("Cable modem pre-check failed: %s", msg)
        raise RuntimeError(f"Pre-check failed: {msg}")

    logger.info("Cable modem pre-check passed: %s", msg)

    tftp_server_ipv4 = Inet(tftp_ipv4)
    tftp_server_ipv6 = Inet(tftp_ipv6) if tftp_ipv6 is not None else Inet(tftp_ipv4)
    tftp_servers     = (tftp_server_ipv4, tftp_server_ipv6)

    service: CmDsOfdmRxMerService = CmDsOfdmRxMerService(cm, tftp_servers)
    msg_rsp: MessageResponse      = await service.set_and_go()

    if msg_rsp.status != ServiceStatusCode.SUCCESS:
        logger.error("RxMER set-and-go failed with status: %s", msg_rsp.status.name)
        raise RuntimeError(f"RxMER set-and-go failed: {msg_rsp.status.name}")

    msg_rsp.get_payload_msg()

    pnm_payloads: list[Any] = _parse_pnm_payload(msg_rsp)

    merged: dict[str, Any] = {
        "mac_address":       str(mac),
        "ip_address":        str(ip),
        "status":            msg_rsp.status.name,
        "timestamp_ms":      int(Generate.time_stamp(TimeUnit.MILLISECONDS)),
        "pnm_payloads":      pnm_payloads,
        "measurement_stats": [entry.model_dump() for entry in measurement_stats],
    }

    print(json.dumps(merged, indent=2))


async def main() -> None:
    """
    CLI Entry Point For The RxMER Set-And-Go Example.

    Parse command-line arguments, normalize them into typed parameters,
    and invoke the RxMER set-and-go workflow. The resulting merged PNM
    JSON document (parsed PNM payload plus RxMER SNMP entries) is printed
    to stdout.
    """
    parser = _build_parser()
    args = parser.parse_args()

    mac: MacAddressStr        = MacAddressStr(args.mac)
    ip: InetAddressStr        = InetAddressStr(args.inet)
    tftp_ipv4: InetAddressStr = InetAddressStr(args.tftp_ipv4)
    tftp_ipv6: InetAddressStr | None = (
        InetAddressStr(args.tftp_ipv6) if args.tftp_ipv6 is not None else None
    )
    write_community: SnmpCommunity      = SnmpCommunity(args.community_write)

    try:
        await _run_rxmer_set_and_go(
            mac             = mac,
            ip              = ip,
            tftp_ipv4       = tftp_ipv4,
            tftp_ipv6       = tftp_ipv6,
            write_community = write_community,
        )
    except RuntimeError as exc:
        logger.error("RxMER set-and-go capture failed: %s", exc)
        raise SystemExit(EXIT_FAILURE) from exc


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
    asyncio.run(main())
