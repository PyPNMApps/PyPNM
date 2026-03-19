#!/usr/bin/env python3
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Final, List


VERSION_FILE_PATH: Final[Path]               = Path("src/pypnm/version.py")
PYPROJECT_FILE_PATH: Final[Path]             = Path("pyproject.toml")
VERSION_PART_SEPARATOR: Final[str]           = "."
EXPECTED_VERSION_PARTS: Final[int]           = 4
DEFAULT_SANITIZE_CONFIG: Final[bool]         = True
GOLDEN_CONFIG_PATHS: Final[tuple[Path, Path]] = (
    Path("deploy/docker/config/system.json"),
    Path("src/pypnm/settings/system.json"),
)
DOC_TAG_ROOT: Final[Path] = Path("docs")
BANNER_BADGE_PATTERN: Final[re.Pattern[str]] = re.compile(r'https://img.shields.io/badge/Docker-[^-]+-2496ED')

MAJOR_INDEX: Final[int]                      = 0
MINOR_INDEX: Final[int]                      = 1
MAINTENANCE_INDEX: Final[int]                = 2
BUILD_INDEX: Final[int]                      = 3


def _validate_version_string(version: str) -> None:
    """Validate that the version string matches MAJOR.MINOR.MAINTENANCE.BUILD."""
    if not all(part.isdigit() for part in version.split(VERSION_PART_SEPARATOR)):
        print(
            f"ERROR: Invalid version '{version}'. Expected numeric MAJOR.MINOR.MAINTENANCE.BUILD.",
            file=sys.stderr,
        )
        sys.exit(1)

    parts = version.split(VERSION_PART_SEPARATOR)
    if len(parts) != EXPECTED_VERSION_PARTS:
        print(
            f"ERROR: Version '{version}' has {len(parts)} parts, expected {EXPECTED_VERSION_PARTS}.",
            file=sys.stderr,
        )
        sys.exit(1)


def _read_current_version(version_file: Path) -> str:
    """Read the current __version__ value from the version file."""
    if not version_file.exists():
        print(f"ERROR: Version file not found: {version_file}", file=sys.stderr)
        sys.exit(1)

    text = version_file.read_text(encoding="utf-8")
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("__version__"):
            first_quote = line.find('"')
            second_quote = line.find('"', first_quote + 1)
            if first_quote == -1 or second_quote == -1:
                print(
                    f"ERROR: Malformed __version__ line in {version_file}: {line!r}",
                    file=sys.stderr,
                )
                sys.exit(1)
            return line[first_quote + 1 : second_quote]

    print(
        f"ERROR: Could not find __version__ assignment in {version_file}.",
        file=sys.stderr,
    )
    sys.exit(1)


def _write_new_version(version_file: Path, new_version: str) -> None:
    """Write the new version into the version file, replacing the existing assignment line."""
    text = version_file.read_text(encoding="utf-8")
    lines: List[str] = text.splitlines()
    updated_lines: List[str] = []
    replaced = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("__version__"):
            first_quote = line.find('"')
            second_quote = line.find('"', first_quote + 1)
            if first_quote == -1 or second_quote == -1:
                print(
                    f"ERROR: Malformed __version__ line in {version_file}: {line!r}",
                    file=sys.stderr,
                )
                sys.exit(1)
            new_line = line[: first_quote + 1] + new_version + line[second_quote:]
            updated_lines.append(new_line)
            replaced = True
        else:
            updated_lines.append(line)

    if not replaced:
        print(
            f"ERROR: Could not find __version__ assignment to replace in {version_file}.",
            file=sys.stderr,
        )
        sys.exit(1)

    version_file.write_text(
        "\n".join(updated_lines) + ("\n" if text.endswith("\n") else ""),
        encoding="utf-8",
    )


def _write_new_pyproject_version(pyproject_file: Path, new_version: str) -> None:
    """Write the new version into pyproject.toml [project].version."""
    if not pyproject_file.exists():
        print(f"ERROR: pyproject.toml not found: {pyproject_file}", file=sys.stderr)
        sys.exit(1)

    text = pyproject_file.read_text(encoding="utf-8")
    lines: List[str] = text.splitlines()
    updated_lines: List[str] = []
    replaced = False

    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith("version") and "=" in line and '"' in line:
            first_quote = line.find('"')
            second_quote = line.find('"', first_quote + 1)
            if first_quote == -1 or second_quote == -1:
                print(
                    f"ERROR: Malformed version line in {pyproject_file}: {line!r}",
                    file=sys.stderr,
                )
                sys.exit(1)
            new_line = line[: first_quote + 1] + new_version + line[second_quote:]
            updated_lines.append(new_line)
            replaced = True
        else:
            updated_lines.append(line)

    if not replaced:
        print(
            f"ERROR: Could not find [project].version assignment to replace in {pyproject_file}.",
            file=sys.stderr,
        )
        sys.exit(1)

    pyproject_file.write_text(
        "\n".join(updated_lines) + ("\n" if text.endswith("\n") else ""),
        encoding="utf-8",
    )

def _sanitize_system_config(config_path: Path) -> None:
    """
    Reset sensitive fields in deploy/docker/config/system.json to defaults for release.

    This prevents accidental leakage of environment-specific credentials.
    """
    if not config_path.exists():
        print(f"WARNING: Config file not found for sanitization: {config_path}", file=sys.stderr)
        return

    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except Exception as exc:  # pragma: no cover - IO/parsing
        print(f"WARNING: Failed to load {config_path} for sanitization: {exc}", file=sys.stderr)
        return

    pnm = data.setdefault("PnmFileRetrieval", {}).setdefault("retrieval_method", {})
    methods = pnm.setdefault("methods", {})
    for method in methods.values():
        if isinstance(method, dict):
            method["password_enc"] = ""
            method["password"] = ""

    if "FastApiRequestDefault" in data and isinstance(data["FastApiRequestDefault"], dict):
        data["FastApiRequestDefault"].pop("jwt_token", None)

    snmp = data.get("SNMP")
    if isinstance(snmp, dict):
        v3 = snmp.get("version", {}).get("3", {})
        if isinstance(v3, dict):
            v3["username"] = "user"
            v3["authPassword"] = ""
            v3["privPassword"] = ""

    config_path.write_text(json.dumps(data, indent=4) + "\n", encoding="utf-8")


def _update_tag_tokens(tag: str) -> None:
    """
    Rewrite TAG="vX.Y.Z.W" occurrences in README and all docs/*.md files.
    """
    pattern = re.compile(r'TAG="v\d+\.\d+\.\d+\.\d+"')
    replacement = f'TAG="{tag}"'
    paths = [Path("README.md")]
    if DOC_TAG_ROOT.exists():
        paths.extend([p for p in DOC_TAG_ROOT.rglob("*.md") if p.is_file()])

    for path in paths:
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            continue
        new_text, count = pattern.subn(replacement, text)
        if count > 0 or new_text != text:
            path.write_text(new_text, encoding="utf-8")


def _compute_next_version(current_version: str, mode: str) -> str:
    """Compute the next version string by incrementing the requested component."""
    _validate_version_string(current_version)
    parts_str = current_version.split(VERSION_PART_SEPARATOR)
    parts_int = [int(part) for part in parts_str]

    match mode:
        case "major":
            parts_int[MAJOR_INDEX]       = parts_int[MAJOR_INDEX] + 1
            parts_int[MINOR_INDEX]       = 0
            parts_int[MAINTENANCE_INDEX] = 0
            parts_int[BUILD_INDEX]       = 0
        case "minor":
            parts_int[MINOR_INDEX]       = parts_int[MINOR_INDEX] + 1
            parts_int[MAINTENANCE_INDEX] = 0
            parts_int[BUILD_INDEX]       = 0
        case "maintenance":
            parts_int[MAINTENANCE_INDEX] = parts_int[MAINTENANCE_INDEX] + 1
            parts_int[BUILD_INDEX]       = 0
        case "build":
            parts_int[BUILD_INDEX]       = parts_int[BUILD_INDEX] + 1
        case _:
            print(f"ERROR: Unsupported --next mode '{mode}'.", file=sys.stderr)
            sys.exit(1)

    return VERSION_PART_SEPARATOR.join(str(part) for part in parts_int)


def main() -> None:
    """CLI entry point for inspecting or updating the PyPNM version.

    This updates both src/pypnm/version.py and pyproject.toml [project].version.

    Modes
    -----
    1) Show current version:
       tools/bump_version.py --current

    2) Compute and apply the next version:
       tools/bump_version.py --next major
       tools/bump_version.py --next minor
       tools/bump_version.py --next maintenance
       tools/bump_version.py --next build

    3) Explicitly set the version:
       tools/bump_version.py 1.3.1.0
    """
    parser = argparse.ArgumentParser(
        description=(
            "Inspect or update the __version__ string in src/pypnm/version.py and "
            "the [project].version field in pyproject.toml. "
            "Version format: MAJOR.MINOR.MAINTENANCE.BUILD (e.g. 1.3.1.0)."
        )
    )
    parser.add_argument(
        "version",
        nargs="?",
        help="Explicit version to set (MAJOR.MINOR.MAINTENANCE.BUILD), e.g. 1.3.1.0.",
    )
    parser.add_argument(
        "--current",
        action="store_true",
        help="Show the current version and exit.",
    )
    parser.add_argument(
        "--next",
        choices=["major", "minor", "maintenance", "build"],
        help="Compute and apply the next version by incrementing the selected component.",
    )
    parser.add_argument(
        "--sanitize-config",
        action=argparse.BooleanOptionalAction,
        default=DEFAULT_SANITIZE_CONFIG,
        help="Sanitize deploy/docker/config/system.json before running tests (default: True).",
    )
    parser.add_argument(
        "--version-files-only",
        action="store_true",
        help="Update only src/pypnm/version.py and pyproject.toml; skip README/docs tag rewrites.",
    )

    args = parser.parse_args()
    explicit_version: str | None = args.version
    show_current: bool           = args.current
    next_mode: str | None        = args.next
    sanitize_config: bool        = args.sanitize_config
    version_files_only: bool     = args.version_files_only

    if show_current:
        if explicit_version is not None or next_mode is not None:
            print("ERROR: --current cannot be combined with a version argument or --next.", file=sys.stderr)
            sys.exit(1)

        current = _read_current_version(VERSION_FILE_PATH)
        print(f"Current version: {current}")
        sys.exit(0)

    if next_mode is not None:
        if explicit_version is not None:
            print("ERROR: --next cannot be combined with an explicit version argument.", file=sys.stderr)
            sys.exit(1)

        current = _read_current_version(VERSION_FILE_PATH)
        next_version = _compute_next_version(current, next_mode)

        if next_version == current:
            print(f"No change: computed next version is the same as current: {current}.")
            sys.exit(0)

        _write_new_version(VERSION_FILE_PATH, next_version)
        _write_new_pyproject_version(PYPROJECT_FILE_PATH, next_version)
        if sanitize_config:
            for cfg_path in GOLDEN_CONFIG_PATHS:
                _sanitize_system_config(cfg_path)
        if not version_files_only:
            _update_tag_tokens(f"v{next_version}")
        print(f"Updated version: {current} -> {next_version}")
        sys.exit(0)

    if explicit_version is None:
        print(
            "ERROR: You must specify one of: --current, --next <mode>, or an explicit version.",
            file=sys.stderr,
        )
        sys.exit(1)

    new_version = explicit_version
    _validate_version_string(new_version)
    current = _read_current_version(VERSION_FILE_PATH)

    if current == new_version:
        print(f"No change: version is already {current}.")
        sys.exit(0)

    _write_new_version(VERSION_FILE_PATH, new_version)
    _write_new_pyproject_version(PYPROJECT_FILE_PATH, new_version)
    if sanitize_config:
        for cfg_path in GOLDEN_CONFIG_PATHS:
            _sanitize_system_config(cfg_path)
    if not version_files_only:
        _update_tag_tokens(f"v{new_version}")
    print(f"Updated version: {current} -> {new_version}")


if __name__ == "__main__":
    main()
