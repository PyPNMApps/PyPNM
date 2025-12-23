#!/usr/bin/env python3
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

import argparse
import json
import sys
from pathlib import Path

from common import DEFAULT_CONFIG_PATH, JSON_INDENT_WIDTH
from pypnm.lib.types import ExitCode, JsonObject, StringArray


class ConfigApplier:
    """Apply non-interactive JSON updates to system.json."""

    EXIT_OK: ExitCode       = ExitCode(0)
    EXIT_USAGE: ExitCode    = ExitCode(2)
    EXIT_FAILURE: ExitCode  = ExitCode(1)

    @staticmethod
    def _load_json(path: Path) -> JsonObject:
        """Read a JSON file into a JsonObject."""
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def _deep_merge(target: JsonObject, source: JsonObject) -> JsonObject:
        """Recursively merge source into target."""
        for key, value in source.items():
            if isinstance(value, dict) and isinstance(target.get(key), dict):
                ConfigApplier._deep_merge(target[key], value)
            else:
                target[key] = value
        return target

    @staticmethod
    def _read_input(input_path: Path | None, use_stdin: bool) -> JsonObject:
        """Load the input JSON from --input or stdin."""
        if use_stdin:
            raw = sys.stdin.read()
            if not raw.strip():
                raise ValueError("stdin input is empty")
            return json.loads(raw)
        if input_path is None:
            raise ValueError("no input provided")
        return ConfigApplier._load_json(input_path)

    @staticmethod
    def run(argv: StringArray) -> ExitCode:
        """
        Apply JSON updates to system.json in a non-interactive flow.

        Returns an ExitCode to allow automation to detect success or failure.
        """
        parser = argparse.ArgumentParser(
            description="Apply non-interactive updates to system.json."
        )
        parser.add_argument(
            "--config",
            type=Path,
            default=DEFAULT_CONFIG_PATH,
            help=f"Target system.json path (default: {DEFAULT_CONFIG_PATH})",
        )
        parser.add_argument(
            "--input",
            type=Path,
            help="JSON file containing config updates to apply.",
        )
        parser.add_argument(
            "--stdin",
            action="store_true",
            help="Read JSON updates from stdin instead of --input.",
        )
        parser.add_argument(
            "--replace",
            action="store_true",
            help="Replace the entire config instead of merging.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show the resulting config without writing to disk.",
        )
        parser.add_argument(
            "--print",
            action="store_true",
            help="Print the resulting config to stdout.",
        )

        args = parser.parse_args(argv)
        if args.stdin and args.input is not None:
            print("ERROR: use only one of --stdin or --input.", file=sys.stderr)
            return ConfigApplier.EXIT_USAGE

        try:
            incoming = ConfigApplier._read_input(args.input, args.stdin)
        except Exception as exc:
            print(f"ERROR: failed to read input JSON: {exc}", file=sys.stderr)
            return ConfigApplier.EXIT_USAGE

        config_path: Path = args.config
        base = (
            ConfigApplier._load_json(config_path)
            if config_path.exists()
            else {}
        )

        updated = incoming if args.replace else ConfigApplier._deep_merge(base, incoming)

        if args.print or args.dry_run:
            print(json.dumps(updated, indent=JSON_INDENT_WIDTH, sort_keys=True))

        if args.dry_run:
            return ConfigApplier.EXIT_OK

        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            json.dumps(updated, indent=JSON_INDENT_WIDTH, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"Updated {config_path}")
        return ConfigApplier.EXIT_OK


if __name__ == "__main__":
    raise SystemExit(ConfigApplier.run(sys.argv[1:]))
