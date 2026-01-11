#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import argparse
import os

import uvicorn

try:
    from pypnm import __version__ as PYPNM_VERSION
except Exception:
    PYPNM_VERSION = "unknown"


def main() -> None:
    HOST_DEFAULT = "127.0.0.1"
    PORT_DEFAULT = 8000

    parser = argparse.ArgumentParser(
        description="Launch the PyPNM FastAPI service with optional HTTPS support."
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"{PYPNM_VERSION}",
        help="Show PyPNM version and exit.",
    )

    parser.add_argument(
        "--host", default=HOST_DEFAULT, help=f"Host to bind (default: {HOST_DEFAULT})"
    )
    parser.add_argument(
        "--port",
        default=PORT_DEFAULT,
        type=int,
        help=f"Port to bind (default: {PORT_DEFAULT})",
    )
    parser.add_argument(
        "--ssl", action="store_true", help="Enable HTTPS (requires cert and key)"
    )
    parser.add_argument(
        "--cert", default="./certs/cert.pem", help="Path to SSL certificate"
    )
    parser.add_argument(
        "--key", default="./certs/key.pem", help="Path to SSL private key"
    )

    parser.add_argument(
        "--log-level",
        default="info",
        choices=["critical", "error", "warning", "info", "debug", "trace"],
        help="Uvicorn log level (default: info).",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of worker processes (default: 1).",
    )

    parser.add_argument(
        "--no-access-log",
        action="store_true",
        help="Disable Uvicorn access log.",
    )

    # Hot-reload controls
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload on file changes (dev only).",
    )

    parser.add_argument(
        "--reload-dir",
        dest="reload_dirs",
        action="append",
        default=[],
        help="Directory to watch for changes. Can be passed multiple times. Default: src (when --reload)",
    )

    parser.add_argument(
        "--reload-include",
        dest="reload_includes",
        action="append",
        default=["*.py"],
        help="Glob pattern(s) to include for reload. Can be passed multiple times. Default: *.py",
    )

    parser.add_argument(
        "--reload-exclude",
        dest="reload_excludes",
        action="append",
        default=["*.pyc", "*__pycache__*", "*.tmp", "*.log"],
        help="Glob pattern(s) to exclude from reload. Can be passed multiple times.",
    )

    args = parser.parse_args()

    if args.ssl:
        print(f"🔒 Launching FastAPI with HTTPS on https://{args.host}:{args.port}")
    else:
        print(f"🌐 Launching FastAPI with HTTP on http://{args.host}:{args.port}")

    # Ensure local package import works when running as a script
    os.environ["PYTHONPATH"] = os.getcwd() + "/src:" + os.environ.get("PYTHONPATH", "")

    uvicorn_args = {
        "app": "pypnm.api.main:app",
        "host": args.host,
        "port": args.port,
        "timeout_keep_alive": 120,
        "log_level": args.log_level,
        "workers": args.workers,
        "access_log": not args.no_access_log,
    }

    # Only enable reload settings if requested
    if args.reload:
        # In dev reload mode, multiple workers are not supported by Uvicorn.
        if args.workers != 1:
            print(
                "[WARN] --workers is ignored when --reload is enabled; using workers=1 for dev reload."
            )
            uvicorn_args["workers"] = 1

        # default to watching 'src' if user didn't pass any reload dirs
        reload_dirs = args.reload_dirs or ["src"]
        uvicorn_args.update(
            {
                "reload": True,
                "reload_dirs": reload_dirs,
                "reload_includes": args.reload_includes,
                "reload_excludes": args.reload_excludes,
            }
        )
        print(f"🔁 Auto-reload enabled. Watching: {', '.join(reload_dirs)}")

    if args.ssl:
        uvicorn_args.update(
            {
                "ssl_certfile": args.cert,
                "ssl_keyfile": args.key,
            }
        )

    uvicorn.run(**uvicorn_args)
