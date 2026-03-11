#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

# Scan the repository for non-approved MAC addresses.

from __future__ import annotations

import argparse
import os
import re
import sys
from typing import Iterable, List, Set, Tuple


# -----------------------------------------------------------------------------
# Configuration: Approved MAC Address Allowlist
# -----------------------------------------------------------------------------
# Add any MAC addresses here that are allowed to appear in the repository.
# They will be normalized to lowercase with ':' separators before comparison,
# so "AA-BB-CC-DD-EE-FF" and "aa:bb:cc:dd:ee:ff" are considered equivalent.
#
# Example entries you might add over time:
#   "aa:bb:cc:dd:ee:ff"  - generic example MAC (preferred default).
#   "00:11:22:33:44:55"  - alternate generic example, if ever needed in docs.
#
APPROVED_MACS: Set[str] = {
    "aa:bb:cc:dd:ee:ff",
    "00:11:22:33:44:55",
    "00:00:00:00:00:01",
    "00:00:00:00:00:00",
    "00:1a:2b:3c:4d:5e",
    "ff-ff-ff-ff-ff-ff",
    "10-23-45-67-89-ab",
    "01:00:5e:00:00:00",
    "de:ad:be:ef:00:01",
    "de:ad:be:ef:00:bb",
    "00:00:ca:12:03:60",
    "00:00:00-23:00:00",
}


# -----------------------------------------------------------------------------
# Configuration: Directory Ignore List
# -----------------------------------------------------------------------------
IGNORE_DIRS: Set[str] = {
    ".git",
    ".env",
    ".venv",
    ".pytest_cache",
    "__pycache__",
    ".data",
    "dist",
    "build",
    "logs",
    "release-log",
    ".mypy_cache",
    ".ruff_cache",
}


MAC_REGEX = re.compile(r"\b(?:(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}|[0-9A-Fa-f]{12})\b")

MACMatch = Tuple[str, int, int, str]  # (path, line_no, col, mac)


def _normalize_mac(mac: str) -> str:
    """
    Normalize MAC Address For Comparison.

    Converts to lowercase and replaces '-' with ':' so patterns such as
    'AA-BB-CC-DD-EE-FF' and 'aa:bb:cc:dd:ee:ff' are treated equivalently.
    """
    compact = mac.lower().replace("-", "").replace(":", "")
    if len(compact) == 12 and all(c in "0123456789abcdef" for c in compact):
        return ":".join([compact[i:i + 2] for i in range(0, 12, 2)])
    return mac.lower().replace("-", ":")


# Precompute normalized allowlist once
APPROVED_MACS_NORMALIZED: Set[str] = {_normalize_mac(m) for m in APPROVED_MACS}


def _is_approved(mac: str) -> bool:
    """
    Return True If The MAC Address Is In The Approved Allowlist.
    """
    normalized = _normalize_mac(mac)
    return normalized in APPROVED_MACS_NORMALIZED or normalized.startswith("00:00:00:")


def _clear_oui(mac: str) -> str:
    """
    Replace the OUI (first 3 octets) with zeros while preserving separator style.
    """
    compact = mac.lower().replace("-", "").replace(":", "")
    if len(compact) == 12 and all(c in "0123456789abcdef" for c in compact):
        return "000000" + compact[6:]
    separator = "-" if "-" in mac else ":"
    parts = re.split(r"[:-]", mac)
    if len(parts) != 6:
        return mac
    return separator.join(["00", "00", "00", parts[3].lower(), parts[4].lower(), parts[5].lower()])


def _clear_oui_in_file(path: str) -> int:
    """
    Rewrite non-approved MAC addresses in a file with zeroed OUI.

    Returns number of replacements written.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
    except OSError:
        return 0

    replacements = 0

    def _replace(match: re.Match[str]) -> str:
        nonlocal replacements
        mac = match.group(0)
        if _is_approved(mac):
            return mac
        replacements += 1
        return _clear_oui(mac)

    updated = MAC_REGEX.sub(_replace, content)
    if replacements > 0 and updated != content:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(updated)
    return replacements


def _iter_files(root: str) -> Iterable[str]:
    """
    Yield Text File Candidates Under The Given Root Directory.

    Skips common virtualenv and build directories using IGNORE_DIRS.
    """
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]

        for name in filenames:
            path = os.path.join(dirpath, name)
            yield path


def _scan_file(path: str) -> List[MACMatch]:
    """
    Scan A Single File For Non-Approved MAC Addresses.

    Returns
    -------
    list[MACMatch]
        A list of (path, line_number, column, mac_string) tuples.
    """
    matches: List[MACMatch] = []

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line_no, line in enumerate(fh, start=1):
                for match in MAC_REGEX.finditer(line):
                    mac = match.group(0)
                    if _is_approved(mac):
                        continue
                    col = match.start() + 1
                    matches.append((path, line_no, col, mac))
    except (OSError, UnicodeDecodeError):
        return matches

    return matches


def _parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan the repository tree for non-approved MAC addresses."
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Root directory to scan (default: current directory).",
    )
    parser.add_argument(
        "--fail-on-found",
        action="store_true",
        help="Exit with non-zero status if any MAC addresses are found.",
    )
    parser.add_argument(
        "--clear-oui",
        action="store_true",
        help="Rewrite non-approved MAC OUI to 00:00:00 before scanning.",
    )
    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> None:
    """
    Scan Repository For Non-Approved MAC Addresses And Report Any Findings.

    Exit Codes
    ----------
    0 : No non-approved MAC addresses found, or only warnings printed.
    2 : Non-approved MAC addresses were found and --fail-on-found is set.
    """
    if argv is None:
        argv = sys.argv[1:]

    args = _parse_args(argv)

    root = os.path.abspath(args.root)
    print(f"Scanning for MAC addresses under: {root}")
    print(f"Approved MACs: {sorted(APPROVED_MACS_NORMALIZED)}")

    if args.clear_oui:
        replaced = 0
        for path in _iter_files(root):
            replaced += _clear_oui_in_file(path)
        if replaced:
            print(f"Sanitized OUI in {replaced} MAC occurrence(s).")

    all_matches: List[MACMatch] = []

    for path in _iter_files(root):
        file_matches = _scan_file(path)
        all_matches.extend(file_matches)

    if not all_matches:
        print("No non-approved MAC addresses found.")
        sys.exit(0)

    print("\nNon-approved MAC addresses found:")
    for path, line_no, col, mac in all_matches:
        print(f"{path}:{line_no}:{col}: {mac}")

    if args.fail_on_found:
        print(
            f"\nTotal non-approved MAC occurrences: {len(all_matches)} "
            "(failing due to --fail-on-found)."
        )
        sys.exit(2)

    print(f"\nTotal non-approved MAC occurrences: {len(all_matches)}")
    sys.exit(0)


if __name__ == "__main__":
    main()
