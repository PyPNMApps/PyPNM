#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

RUNTIME_SCAN_ROOTS = [
    Path("src"),
    Path("scripts"),
]
ALLOWLIST = {
    Path("src/pypnm/config/system_config_settings.py"),
    Path("src/pypnm/support/worker_profile.py"),
}
SKIP_PREFIXES = (
    Path("src/pypnm/examples"),
    Path("src/pypnm/settings"),
)
PATH_LITERAL_PATTERN = re.compile(r"""["'](?:\.data(?:/[^"']*)?)["']""")


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan runtime code for hardcoded .data path literals.",
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Repository root to scan (default: current directory).",
    )
    parser.add_argument(
        "--fail-on-found",
        action="store_true",
        help="Exit non-zero when hardcoded .data path literals are found.",
    )
    return parser.parse_args(argv)


def _iter_candidate_files(repo_root: Path) -> list[Path]:
    candidates: list[Path] = []
    for scan_root in RUNTIME_SCAN_ROOTS:
        root = repo_root / scan_root
        if not root.exists():
            continue
        candidates.extend(path for path in root.rglob("*") if path.is_file())
    return candidates


def _is_allowed(repo_root: Path, path: Path) -> bool:
    relative_path = path.relative_to(repo_root)
    if relative_path in ALLOWLIST:
        return True
    return any(relative_path.is_relative_to(prefix) for prefix in SKIP_PREFIXES)


def _scan_file(repo_root: Path, path: Path) -> list[str]:
    findings: list[str] = []
    if _is_allowed(repo_root, path):
        return findings

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return findings

    relative_path = path.relative_to(repo_root)
    for line_number, line in enumerate(lines, start=1):
        if PATH_LITERAL_PATTERN.search(line) is None:
            continue
        findings.append(f"{relative_path}:{line_number}: hardcoded .data path literal")
    return findings


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    args = _parse_args(argv)

    repo_root = Path(args.root).resolve()
    findings: list[str] = []
    for path in _iter_candidate_files(repo_root):
        findings.extend(_scan_file(repo_root, path))

    if findings:
        print("Hardcoded .data path literals found in runtime code:")
        for finding in findings:
            print(f"  {finding}")
        return 2 if args.fail_on_found else 0

    print("No hardcoded .data path literals found in runtime code.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
