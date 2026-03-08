#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import uvicorn

from pypnm.config.runtime_flags import ENV_MUTE_TAGS, ENV_MUTE_TAGS_HARD
from pypnm.tools.system_config.menu import SystemConfigMenu

try:
    from pypnm import __version__ as PYPNM_VERSION
except Exception:
    PYPNM_VERSION = "unknown"

SUCCESS_EXIT_CODE = 0
EXIT_CODE_USAGE = 2
EXIT_CODE_SIGINT = 130
HOST_DEFAULT = "127.0.0.1"
PORT_DEFAULT = 8000
LOG_LEVEL_DEFAULT = "info"
DEFAULT_WORKERS = 1
TIMEOUT_KEEP_ALIVE_SECONDS = 120


def _sanitize_pythonpath_for_serve() -> None:
    """Restrict serve-time PYTHONPATH to this repo's src directory."""
    src_path = str(Path.cwd() / "src")
    existing_pythonpath = os.environ.get("PYTHONPATH", "")
    existing_entries = [entry for entry in existing_pythonpath.split(os.pathsep) if entry.strip() != ""]

    filtered_sys_path: list[str] = []
    for entry in sys.path:
        if entry in existing_entries and entry != src_path:
            continue
        filtered_sys_path.append(entry)
    sys.path = filtered_sys_path

    if src_path not in sys.path:
        sys.path.insert(0, src_path)
    os.environ["PYTHONPATH"] = src_path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="PyPNM CLI for service startup and system configuration.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  pypnm serve --host 0.0.0.0 --port 8080\n"
            "  pypnm serve --reload\n"
            "  pypnm serve --mute-tags \"PNM Operations - Multi-Downstream OFDM RxMER\"\n"
            "  pypnm serve --mute-tags \"Orchestrator,Operational\" --mute-tags-hard\n"
            "  pypnm config-menu\n"
        ),
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"{PYPNM_VERSION}",
        help="Show PyPNM version and exit.",
    )

    subparsers = parser.add_subparsers(dest="command")

    serve_parser = subparsers.add_parser("serve", help="Start the FastAPI service (Uvicorn).")
    serve_parser.add_argument("--host", default=HOST_DEFAULT, help=f"Host to bind (default: {HOST_DEFAULT})")
    serve_parser.add_argument("--port", default=PORT_DEFAULT, type=int, help=f"Port to bind (default: {PORT_DEFAULT})")
    serve_parser.add_argument("--ssl", action="store_true", help="Enable HTTPS (requires cert and key).")
    serve_parser.add_argument("--cert", default="./certs/cert.pem", help="Path to SSL certificate (PEM).")
    serve_parser.add_argument("--key", default="./certs/key.pem", help="Path to SSL private key (PEM).")
    serve_parser.add_argument(
        "--mute-tags",
        default="",
        help="Comma-separated route tags to mute at startup (example: Orchestrator,Operational).",
    )
    serve_parser.add_argument(
        "--mute-tags-hard",
        action="store_true",
        help="When used with --mute-tags, enforce 403 for matching tagged routes.",
    )
    serve_parser.add_argument(
        "--log-level",
        default=LOG_LEVEL_DEFAULT,
        choices=["critical", "error", "warning", "info", "debug", "trace"],
        help="Uvicorn log level (default: info).",
    )
    serve_parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help="Number of worker processes (default: 1).",
    )
    serve_parser.add_argument(
        "--no-access-log",
        action="store_true",
        help="Disable Uvicorn access log.",
    )
    serve_parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload on file changes (dev only).",
    )
    serve_parser.add_argument(
        "--reload-dir",
        dest="reload_dirs",
        action="append",
        default=[],
        help="Directory to watch for changes (repeatable). Default: src (when --reload).",
    )
    serve_parser.add_argument(
        "--reload-include",
        dest="reload_includes",
        action="append",
        default=["*.py"],
        help="Glob pattern(s) to include for reload (repeatable). Default: *.py.",
    )
    serve_parser.add_argument(
        "--reload-exclude",
        dest="reload_excludes",
        action="append",
        default=["*.pyc", "*__pycache__*", "*.tmp", "*.log"],
        help="Glob pattern(s) to exclude from reload (repeatable).",
    )

    subparsers.add_parser("config-menu", help="Launch the interactive system.json configuration menu.")

    parser._serve_parser = serve_parser
    return parser


def _run_serve(args: argparse.Namespace) -> int:
    if args.ssl:
        print(f"🔒 Launching FastAPI with HTTPS on https://{args.host}:{args.port}")
    else:
        print(f"🌐 Launching FastAPI with HTTP on http://{args.host}:{args.port}")

    _sanitize_pythonpath_for_serve()

    if str(args.mute_tags).strip() != "":
        os.environ[ENV_MUTE_TAGS] = str(args.mute_tags).strip()
    if bool(args.mute_tags_hard):
        os.environ[ENV_MUTE_TAGS_HARD] = "1"

    uvicorn_args = {
        "app": "pypnm.api.main:app",
        "host": args.host,
        "port": args.port,
        "timeout_keep_alive": TIMEOUT_KEEP_ALIVE_SECONDS,
        "log_level": args.log_level,
        "workers": args.workers,
        "access_log": not args.no_access_log,
    }

    if args.reload:
        if args.workers != DEFAULT_WORKERS:
            print("[WARN] --workers is ignored when --reload is enabled; using workers=1 for dev reload.")
            uvicorn_args["workers"] = DEFAULT_WORKERS

        reload_dirs = args.reload_dirs or ["src"]
        uvicorn_args.update(
            {
                "reload": True,
                "reload_dirs": reload_dirs,
                "reload_includes": args.reload_includes,
                "reload_excludes": args.reload_excludes,
            },
        )
        print(f"🔁 Auto-reload enabled. Watching: {', '.join(reload_dirs)}")

    if args.ssl:
        uvicorn_args.update(
            {
                "ssl_certfile": args.cert,
                "ssl_keyfile": args.key,
            },
        )

    try:
        uvicorn.run(**uvicorn_args)
    except KeyboardInterrupt:
        return EXIT_CODE_SIGINT

    return SUCCESS_EXIT_CODE


def _run_cli() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "serve":
        return _run_serve(args)

    if args.command == "config-menu":
        return SystemConfigMenu().run()

    parser.print_help()
    return EXIT_CODE_USAGE


def main() -> int:
    return _run_cli()


if __name__ == "__main__":
    raise SystemExit(main())
