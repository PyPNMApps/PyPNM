#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import argparse
import os
import shlex
import signal
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.support.serve_background import background_pidfile_path


@dataclass(frozen=True)
class ProcessRow:
    line_no: int
    pid: int
    ppid: int
    etime: str
    source: str
    command: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="List and terminate active pypnm processes by table line number.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Kill all active pypnm processes.",
    )
    parser.add_argument(
        "--line",
        dest="line_numbers",
        nargs="+",
        type=int,
        default=[],
        help="One or more table line numbers to kill (example: --line 1 3).",
    )
    parser.add_argument(
        "--signal",
        dest="signal_name",
        default="TERM",
        help="Signal to send (default: TERM). Examples: TERM, KILL, INT.",
    )
    return parser.parse_args()


def resolve_signal(signal_name: str) -> int:
    normalized = signal_name.strip().upper()
    if normalized.startswith("SIG"):
        normalized = normalized[3:]
    signal_attr = f"SIG{normalized}"
    if not hasattr(signal, signal_attr):
        raise ValueError(f"Unsupported signal: {signal_name}")
    return int(getattr(signal, signal_attr))


def collect_processes() -> list[ProcessRow]:
    try:
        completed = subprocess.run(
            ["ps", "-eo", "pid=,ppid=,etime=,args="],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"Failed to query process list: {exc}") from exc

    rows: list[ProcessRow] = []
    current_pid = os.getpid()
    seen_pids: set[int] = set()
    line_no = 0
    for raw_line in completed.stdout.splitlines():
        line = raw_line.strip()
        if line == "":
            continue
        parts = line.split(maxsplit=3)
        if len(parts) < 4:
            continue
        pid_text, ppid_text, etime, command = parts
        if not _is_pypnm_command(command):
            continue
        try:
            pid = int(pid_text)
            ppid = int(ppid_text)
        except ValueError:
            continue
        if pid == current_pid:
            continue
        seen_pids.add(pid)
        line_no += 1
        rows.append(
            ProcessRow(
                line_no=line_no,
                pid=pid,
                ppid=ppid,
                etime=etime,
                source="process_scan",
                command=command,
            )
        )
    background_row = _background_serve_row(current_pid)
    if background_row is not None and background_row.pid not in seen_pids:
        line_no += 1
        rows.append(
            ProcessRow(
                line_no=line_no,
                pid=background_row.pid,
                ppid=background_row.ppid,
                etime=background_row.etime,
                source=background_row.source,
                command=background_row.command,
            )
        )
    return rows


def _is_pypnm_command(command: str) -> bool:
    try:
        tokens = shlex.split(command)
    except ValueError:
        return False
    return any(os.path.basename(token) == "pypnm" for token in tokens)


def print_table(rows: list[ProcessRow]) -> None:
    if not rows:
        print("No active pypnm processes found.")
        return

    try:
        from tabulate import tabulate
    except ModuleNotFoundError:
        _print_table_plain(rows)
        return

    table_rows = [
        [row.line_no, row.pid, row.ppid, row.etime, row.source, row.command]
        for row in rows
    ]
    print(
        tabulate(
            table_rows,
            headers=["LINE", "PID", "PPID", "ELAPSED", "SOURCE", "COMMAND"],
            tablefmt="github",
            numalign="left",
            stralign="left",
            colalign=("left", "left", "left", "left", "left", "left"),
        )
    )


def _print_table_plain(rows: list[ProcessRow]) -> None:
    line_width = max(4, max(len(str(row.line_no)) for row in rows))
    pid_width = max(7, max(len(str(row.pid)) for row in rows))
    ppid_width = max(7, max(len(str(row.ppid)) for row in rows))
    etime_width = max(7, max(len(row.etime) for row in rows))
    source_width = max(6, max(len(row.source) for row in rows))

    header = (
        f"{'LINE':<{line_width}}  "
        f"{'PID':<{pid_width}}  "
        f"{'PPID':<{ppid_width}}  "
        f"{'ELAPSED':<{etime_width}}  "
        f"{'SOURCE':<{source_width}}  "
        "COMMAND"
    )
    print(header)
    print("-" * len(header))
    for row in rows:
        line = (
            f"{row.line_no:<{line_width}}  "
            f"{row.pid:<{pid_width}}  "
            f"{row.ppid:<{ppid_width}}  "
            f"{row.etime:<{etime_width}}  "
            f"{row.source:<{source_width}}  "
            f"{row.command}"
        )
        print(line)


def _background_serve_row(current_pid: int) -> ProcessRow | None:
    pidfile_path = _background_pidfile()
    if not pidfile_path.exists():
        return None
    try:
        pid = int(pidfile_path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None
    if pid <= 0 or pid == current_pid:
        return None
    ps_stat = _ps_stat(pid)
    if ps_stat is None:
        return None
    ppid, etime, command = ps_stat
    return ProcessRow(
        line_no=0,
        pid=pid,
        ppid=ppid,
        etime=etime,
        source="background_pidfile",
        command=f"{command} [pidfile={pidfile_path}]",
    )


def _background_pidfile() -> Path:
    return background_pidfile_path(SystemConfigSettings.runtime_dir(), "pypnm")


def _ps_stat(pid: int) -> tuple[int, str, str] | None:
    try:
        completed = subprocess.run(
            ["ps", "-p", str(pid), "-o", "ppid=,etime=,args="],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError:
        return None
    line = completed.stdout.strip()
    if line == "":
        return None
    parts = line.split(maxsplit=2)
    if len(parts) < 3:
        return None
    try:
        ppid = int(parts[0])
    except ValueError:
        return None
    return (ppid, parts[1], parts[2])


def select_rows(rows: list[ProcessRow], line_numbers: list[int]) -> tuple[list[ProcessRow], list[int]]:
    by_line = {row.line_no: row for row in rows}
    selected: list[ProcessRow] = []
    missing: list[int] = []
    for line_no in line_numbers:
        row = by_line.get(int(line_no))
        if row is None:
            missing.append(int(line_no))
            continue
        selected.append(row)
    return (selected, missing)


def kill_rows(rows: list[ProcessRow], signal_number: int) -> int:
    killed = 0
    signal_name = signal.Signals(signal_number).name
    for row in rows:
        if _kill_row(row, signal_number, signal_name):
            killed += 1
    return killed


def _kill_row(row: ProcessRow, signal_number: int, signal_name: str) -> bool:
    try:
        os.kill(row.pid, signal_number)
    except ProcessLookupError:
        print(f"PID {row.pid} no longer exists; skipping.")
        return False
    except PermissionError as exc:
        print(f"Failed to send {signal_name} to PID {row.pid}: {exc}", file=sys.stderr)
        return False
    print(f"Sent {signal_name} to PID {row.pid} (line {row.line_no}).")
    return True


def main() -> int:
    args = parse_args()
    rows = collect_processes()

    if not args.all and len(args.line_numbers) == 0:
        print_table(rows)
        return 0

    try:
        signal_number = resolve_signal(args.signal_name)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if args.all:
        if not rows:
            print("No active pypnm processes found.")
            return 0
        killed = kill_rows(rows, signal_number)
        print(f"Killed {killed} process(es).")
        return 0

    selected, missing = select_rows(rows, args.line_numbers)
    if missing:
        print(f"Unknown line number(s): {', '.join(str(item) for item in missing)}", file=sys.stderr)
        print_table(rows)
        return 2
    if not selected:
        print("No matching pypnm processes selected.")
        return 0
    killed = kill_rows(selected, signal_number)
    print(f"Killed {killed} process(es).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
