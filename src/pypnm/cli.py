#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from time import time

import uvicorn

from pypnm.config.runtime_flags import ENV_MUTE_TAGS, ENV_MUTE_TAGS_HARD
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.support.serve_background import (
    BACKGROUND_CHILD_ENV,
    BACKGROUND_PIDFILE_ENV,
    launch_background_serve,
)
from pypnm.support.worker_profile import (
    WorkerProfile,
    default_profile_env_path,
    detect_worker_profile,
    load_seeded_profile,
)
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
DEFAULT_LIMIT_MAX_REQUESTS = 0
ALL_INTERFACES_HOST = "0.0.0.0"


def _runtime_profile_selection_message(workers: int, limit_max_requests: int) -> str:
    source = os.environ.get("PYPNM_ACTIVE_RUNTIME_SOURCE", "explicit_cli")
    profile_env_path = os.environ.get("PYPNM_SERVE_ENV_FILE", str(default_profile_env_path()))

    if source == "seeded_profile":
        return (
            "Auto-selected FastAPI runtime profile: "
            f"workers={workers} limit_max_requests={limit_max_requests} "
            f"profile={profile_env_path}"
        )

    return (
        "FastAPI runtime profile: "
        f"workers={workers} limit_max_requests={limit_max_requests} "
        f"source={source} profile={profile_env_path}"
    )


def _log_runtime_profile_selection(workers: int, limit_max_requests: int) -> None:
    print(f"[INFO] {_runtime_profile_selection_message(workers, limit_max_requests)}")


def _record_background_parent_pid() -> None:
    if os.environ.get(BACKGROUND_CHILD_ENV) != "1":
        return
    pidfile = os.environ.get(BACKGROUND_PIDFILE_ENV, "").strip()
    if pidfile == "":
        return
    Path(pidfile).write_text(f"{os.getpid()}\n", encoding="utf-8")


def _resolve_runtime_worker_profile(args: argparse.Namespace) -> tuple[int, int]:
    profile_env_path = Path(os.environ.get("PYPNM_SERVE_ENV_FILE", str(default_profile_env_path())))

    if args.workers is not None and args.limit_max_requests is not None:
        os.environ["PYPNM_ACTIVE_RUNTIME_SOURCE"] = "explicit_cli"
        return args.workers, args.limit_max_requests

    profile: WorkerProfile | None = load_seeded_profile(profile_env_path)
    if profile is not None:
        os.environ["PYPNM_ACTIVE_RUNTIME_SOURCE"] = "seeded_profile"
    else:
        profile = detect_worker_profile()
        os.environ["PYPNM_ACTIVE_RUNTIME_SOURCE"] = "hardware_auto"

    workers = args.workers if args.workers is not None else profile.workers
    limit_max_requests = (
        args.limit_max_requests
        if args.limit_max_requests is not None
        else profile.limit_max_requests
    )
    return workers, limit_max_requests


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


def _resolve_bind_host(args: argparse.Namespace) -> str:
    return ALL_INTERFACES_HOST if bool(getattr(args, "host_all", False)) else str(args.host)


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
    host_group = serve_parser.add_mutually_exclusive_group()
    host_group.add_argument("--host", default=HOST_DEFAULT, help=f"Host to bind (default: {HOST_DEFAULT})")
    host_group.add_argument(
        "--host-all",
        action="store_true",
        help=f"Bind on all IPv4 interfaces ({ALL_INTERFACES_HOST}).",
    )
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
        default=None,
        help="Number of worker processes (default: auto-select from hardware profile).",
    )
    serve_parser.add_argument(
        "--limit-max-requests",
        type=int,
        default=None,
        help=(
            "Restart a worker after serving this many requests. "
            "Default: auto-select from hardware profile."
        ),
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
    serve_parser.add_argument(
        "--run-background",
        action="store_true",
        help="Detach the FastAPI service into the background and return the child PID.",
    )
    serve_parser.add_argument(
        "--background-log-file",
        default="",
        help="Optional log file path for --run-background.",
    )
    serve_parser.add_argument(
        "--background-pidfile",
        default="",
        help="Optional pidfile path for --run-background.",
    )

    subparsers.add_parser("config-menu", help="Launch the interactive system.json configuration menu.")

    parser._serve_parser = serve_parser
    return parser


def _run_serve(args: argparse.Namespace) -> int:
    bind_host = _resolve_bind_host(args)
    run_background = bool(getattr(args, "run_background", False))
    background_log_file = str(getattr(args, "background_log_file", "")).strip()
    background_pidfile = str(getattr(args, "background_pidfile", "")).strip()

    if run_background and bool(args.reload):
        print("[ERROR] --run-background cannot be used with --reload")
        return EXIT_CODE_USAGE

    if args.ssl:
        print(f"🔒 Launching FastAPI with HTTPS on https://{bind_host}:{args.port}")
    else:
        print(f"🌐 Launching FastAPI with HTTP on http://{bind_host}:{args.port}")

    _sanitize_pythonpath_for_serve()

    if run_background:
        return launch_background_serve(
            module_name="pypnm.cli",
            app_slug="pypnm",
            runtime_dir=SystemConfigSettings.runtime_dir(),
            argv=sys.argv[1:],
            log_file=background_log_file,
            pidfile=background_pidfile,
        )

    if str(args.mute_tags).strip() != "":
        os.environ[ENV_MUTE_TAGS] = str(args.mute_tags).strip()
    if bool(args.mute_tags_hard):
        os.environ[ENV_MUTE_TAGS_HARD] = "1"

    if args.limit_max_requests is not None and args.limit_max_requests < 0:
        print("[ERROR] --limit-max-requests must be >= 0")
        return EXIT_CODE_USAGE

    os.environ.setdefault("PYPNM_SERVE_ENV_FILE", str(default_profile_env_path()))
    resolved_workers, resolved_limit_max_requests = _resolve_runtime_worker_profile(args)

    uvicorn_args = {
        "app": "pypnm.api.main:app",
        "host": bind_host,
        "port": args.port,
        "timeout_keep_alive": TIMEOUT_KEEP_ALIVE_SECONDS,
        "log_level": args.log_level,
        "workers": resolved_workers,
        "access_log": not args.no_access_log,
    }
    if resolved_limit_max_requests > 0:
        uvicorn_args["limit_max_requests"] = resolved_limit_max_requests

    if args.reload:
        if resolved_workers != DEFAULT_WORKERS:
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

    effective_workers = int(uvicorn_args["workers"])
    effective_limit_max_requests = int(uvicorn_args.get("limit_max_requests", 0))
    os.environ.setdefault("PYPNM_SERVE_SESSION_ID", f"{os.getpid()}-{int(time())}")
    os.environ["PYPNM_ACTIVE_WORKERS"] = str(effective_workers)
    os.environ["PYPNM_ACTIVE_LIMIT_MAX_REQUESTS"] = str(effective_limit_max_requests)
    _log_runtime_profile_selection(
        workers=effective_workers,
        limit_max_requests=effective_limit_max_requests,
    )
    _record_background_parent_pid()

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
