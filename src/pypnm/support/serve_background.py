#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

BACKGROUND_CHILD_ENV = "PYPNM_BACKGROUND_CHILD"
RUN_BACKGROUND_FLAG = "--run-background"
BACKGROUND_LOG_FILE_FLAG = "--background-log-file"
BACKGROUND_PID_FILE_FLAG = "--background-pidfile"


def background_log_path(runtime_dir: str, app_slug: str) -> Path:
    """Return the default detached-serve log file path."""
    return Path(runtime_dir) / f"{app_slug}.serve.log"


def background_pidfile_path(runtime_dir: str, app_slug: str) -> Path:
    """Return the default detached-serve pidfile path."""
    return Path(runtime_dir) / f"{app_slug}.serve.pid"


def launch_background_serve(
    *,
    module_name: str,
    app_slug: str,
    runtime_dir: str,
    argv: list[str],
    log_file: str | None,
    pidfile: str | None,
) -> int:
    """Detach a serve command into the background and return success."""
    runtime_path = Path(runtime_dir)
    runtime_path.mkdir(parents=True, exist_ok=True)

    resolved_log_file = Path(log_file) if log_file is not None and log_file.strip() != "" else background_log_path(runtime_dir, app_slug)
    resolved_pidfile = Path(pidfile) if pidfile is not None and pidfile.strip() != "" else background_pidfile_path(runtime_dir, app_slug)
    resolved_log_file.parent.mkdir(parents=True, exist_ok=True)
    resolved_pidfile.parent.mkdir(parents=True, exist_ok=True)

    child_argv = _strip_background_flags(argv)
    command = [sys.executable, "-m", module_name, *child_argv]
    child_env = os.environ.copy()
    child_env[BACKGROUND_CHILD_ENV] = "1"

    with resolved_log_file.open("ab") as log_handle:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            close_fds=True,
            env=child_env,
        )

    resolved_pidfile.write_text(f"{int(process.pid)}\n", encoding="utf-8")
    print(f"[INFO] Background serve started: pid={int(process.pid)}")
    print(f"[INFO] Background serve log: {resolved_log_file}")
    print(f"[INFO] Background serve pidfile: {resolved_pidfile}")
    return 0


def _strip_background_flags(argv: list[str]) -> list[str]:
    """Return argv without background-launch flags and their values."""
    stripped: list[str] = []
    skip_next = False
    for token in argv:
        if skip_next:
            skip_next = False
            continue
        if token == RUN_BACKGROUND_FLAG:
            continue
        if token in (BACKGROUND_LOG_FILE_FLAG, BACKGROUND_PID_FILE_FLAG):
            skip_next = True
            continue
        if token.startswith(f"{BACKGROUND_LOG_FILE_FLAG}=") or token.startswith(f"{BACKGROUND_PID_FILE_FLAG}="):
            continue
        stripped.append(token)
    return stripped


__all__ = [
    "BACKGROUND_CHILD_ENV",
    "RUN_BACKGROUND_FLAG",
    "BACKGROUND_LOG_FILE_FLAG",
    "BACKGROUND_PID_FILE_FLAG",
    "background_log_path",
    "background_pidfile_path",
    "launch_background_serve",
]
