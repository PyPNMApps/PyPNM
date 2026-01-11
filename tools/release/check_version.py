#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia


from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


class VersionCheckTool:
    """Verify version consistency between src/pypnm/version.py and pyproject.toml."""

    MAX_ROOT_SEARCH_DEPTH: int = 6
    VERSION_FILE_RELATIVE: str = "src/pypnm/version.py"
    PYPROJECT_RELATIVE: str = "pyproject.toml"
    VERSION_PATTERN: str = r'__version__\s*(?::\s*[^=]+)?=\s*"([^"]+)"'
    PYPROJECT_PATTERN: str = r'^\s*version\s*=\s*"([^"]+)"\s*$'
    EXIT_OK: int = 0
    EXIT_ERROR: int = 1
    EXIT_MISMATCH: int = 2

    @staticmethod
    def _read_text(path: Path) -> str:
        """Read a file as UTF-8 text; return empty string when unavailable."""
        try:
            return path.read_text(encoding="utf-8")
        except OSError:
            return ""

    @staticmethod
    def _find_project_root(start_path: Path) -> Path:
        """Walk upwards to locate pyproject.toml, fallback to start path."""
        current = start_path
        for _ in range(VersionCheckTool.MAX_ROOT_SEARCH_DEPTH):
            if (current / VersionCheckTool.PYPROJECT_RELATIVE).is_file():
                return current
            if current.parent == current:
                break
            current = current.parent
        return start_path

    @staticmethod
    def _read_version_from_file(path: Path) -> str:
        """Extract the __version__ value from src/pypnm/version.py."""
        text = VersionCheckTool._read_text(path)
        if not text:
            return ""
        match = re.search(VersionCheckTool.VERSION_PATTERN, text)
        if not match:
            return ""
        return match.group(1)

    @staticmethod
    def _read_version_from_pyproject(path: Path) -> str:
        """Extract the project version value from pyproject.toml."""
        text = VersionCheckTool._read_text(path)
        if not text:
            return ""
        match = re.search(VersionCheckTool.PYPROJECT_PATTERN, text, re.MULTILINE)
        if not match:
            return ""
        return match.group(1)

    @staticmethod
    def _build_parser() -> argparse.ArgumentParser:
        """Build the CLI parser for the version check tool."""
        parser = argparse.ArgumentParser(
            description=(
                "Verify that src/pypnm/version.py and pyproject.toml carry the same version."
            )
        )
        parser.add_argument(
            "--json",
            action="store_true",
            help="Print results as JSON.",
        )
        return parser

    @staticmethod
    def _emit_text(version_file_version: str, pyproject_version: str, status: str) -> None:
        """Emit human-readable output."""
        if status == "error":
            print("Version check failed: unable to read one or more version values.")
        print(f"version.py: {version_file_version or 'missing'}")
        print(f"pyproject.toml: {pyproject_version or 'missing'}")
        if status == "mismatch":
            print("Version mismatch detected.")
        if status == "ok":
            print("Version match confirmed.")

    @staticmethod
    def _emit_json(version_file_version: str, pyproject_version: str, status: str) -> None:
        """Emit JSON output."""
        payload = {
            "version_py": version_file_version,
            "pyproject": pyproject_version,
            "match": status == "ok",
            "status": status,
        }
        print(json.dumps(payload, ensure_ascii=True))

    @staticmethod
    def run(options: argparse.Namespace) -> int:
        """Print versions from tracked files and return a status code."""
        script_dir = Path(__file__).resolve().parent
        root_path = VersionCheckTool._find_project_root(script_dir)
        version_path = root_path / VersionCheckTool.VERSION_FILE_RELATIVE
        pyproject_path = root_path / VersionCheckTool.PYPROJECT_RELATIVE

        version_file_version = VersionCheckTool._read_version_from_file(version_path)
        pyproject_version = VersionCheckTool._read_version_from_pyproject(pyproject_path)

        if not version_file_version or not pyproject_version:
            if options.json:
                VersionCheckTool._emit_json(version_file_version, pyproject_version, "error")
            else:
                VersionCheckTool._emit_text(version_file_version, pyproject_version, "error")
            return VersionCheckTool.EXIT_ERROR

        if version_file_version != pyproject_version:
            if options.json:
                VersionCheckTool._emit_json(version_file_version, pyproject_version, "mismatch")
            else:
                VersionCheckTool._emit_text(version_file_version, pyproject_version, "mismatch")
            return VersionCheckTool.EXIT_MISMATCH

        if options.json:
            VersionCheckTool._emit_json(version_file_version, pyproject_version, "ok")
        else:
            VersionCheckTool._emit_text(version_file_version, pyproject_version, "ok")
        return VersionCheckTool.EXIT_OK


if __name__ == "__main__":
    parser = VersionCheckTool._build_parser()
    args = parser.parse_args()
    sys.exit(VersionCheckTool.run(args))
