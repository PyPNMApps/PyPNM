#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Final


ENC_PATTERN: Final[re.Pattern[str]] = re.compile(
    r'password_enc\s*[:=]\s*["\']ENC\[v1\]:[^"\']+["\']',
    re.IGNORECASE,
)

SCAN_EXTENSIONS: Final[set[str]] = {
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".env",
    ".template",
}

SKIP_DIRS: Final[set[str]] = {
    ".git",
    ".env",
    ".venv",
    "build",
    "dist",
    "release-reports",
    "site",
    "logs",
    "backup",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".pyright",
    "htmlcov",
}


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan repo files for encrypted password patterns (ENC[v1])."
    )
    parser.add_argument(
        "--path",
        default=".",
        help="Root directory to scan (default: current working directory).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output.",
    )
    parser.add_argument(
        "--no-fail",
        action="store_true",
        help="Return exit code 0 even when findings are detected.",
    )
    return parser.parse_args()


def _should_scan(path: Path) -> bool:
    if path.suffix.lower() in SCAN_EXTENSIONS:
        return True
    return path.name.endswith(".json.template")


def _iter_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_dir():
            continue
        if path.suffix == "" and not path.name.endswith(".env"):
            continue
        if _should_scan(path):
            files.append(path)
    return files


def _scan_file(path: Path) -> list[dict[str, str]]:
    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []

    matches: list[dict[str, str]] = []
    for match in ENC_PATTERN.finditer(content):
        line_no = content.count("\n", 0, match.start()) + 1
        snippet = match.group(0)
        matches.append(
            {
                "path": str(path),
                "line": str(line_no),
                "match": snippet,
            }
        )
    return matches


def _render_text(findings: list[dict[str, str]]) -> None:
    if not findings:
        print("No encrypted password patterns found.")
        return
    print("Encrypted password patterns detected:")
    for finding in findings:
        print(
            f"- {finding['path']}:{finding['line']} -> {finding['match']}"
        )


def _render_json(findings: list[dict[str, str]]) -> None:
    payload = {
        "count": len(findings),
        "findings": findings,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))


def main() -> None:
    args = _parse_args()
    root = Path(args.path).resolve()
    if not root.exists():
        print(f"ERROR: Path not found: {root}", file=sys.stderr)
        sys.exit(1)

    all_findings: list[dict[str, str]] = []
    for file_path in _iter_files(root):
        all_findings.extend(_scan_file(file_path))

    if args.json:
        _render_json(all_findings)
    else:
        _render_text(all_findings)

    if all_findings and not args.no_fail:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
