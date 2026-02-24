#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia


from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple


SYSTEM_DESCRIPTION: Dict[str, str] = {
    "HW_REV":  "1.0",
    "VENDOR":  "LANCity",
    "BOOTR":   "NONE",
    "SW_REV":  "1.0.0",
    "MODEL":   "LCPET-3",
}


MAC_PATTERN = re.compile(r"(?:[0-9a-f]{2}[:\-_]?){5}[0-9a-f]{2}", re.IGNORECASE)


class DemoSanitizer:
    """
    Demonstration Dataset Sanitizer For PyPNM Using Transactions As Ground Truth.

    For each transaction entry:
    - Locate the capture file by its 'filename' under demo_root.
    - Rewrite the binary MAC using pnm-mac-updater.py --mac-address NEW.
    - Rename the file so the MAC chunk in the filename uses the new MAC.
    - Update the JSON entry's mac_address, filename, and system_description.
    - Sanitize canonical API response identity blocks under `device` when present.

    Modes:
    - Targeted: --old-mac + --new-mac updates only entries whose mac_address
      matches --old-mac (normalized).
    - Force: --force-new-mac + --new-mac updates all entries regardless of the
      original mac_address.

    Use --verbose to print per-entry details; otherwise only a summary is shown.
    """

    def __init__(
        self,
        demo_root: Path,
        new_mac: str,
        old_mac: Optional[str],
        force_new_mac: bool,
        mac_updater: Optional[Path],
        project_root: Optional[Path],
        verbose: bool,
    ) -> None:
        self.demo_root: Path            = demo_root
        self.project_root: Path         = project_root if project_root is not None else demo_root.parent
        self.new_mac_raw: str           = new_mac.strip().lower()
        self.old_mac_raw: Optional[str] = old_mac.strip().lower() if old_mac is not None else None
        self.force_new_mac: bool        = force_new_mac
        self.mac_updater: Optional[Path] = mac_updater
        self.verbose: bool              = verbose

        self.new_mac_variants: Tuple[str, str, str, str] = self._build_mac_variants(self.new_mac_raw)

    def _vprint(self, message: str) -> None:
        if self.verbose:
            print(message)

    def _sanitize_sysdesc_dict(self, container: dict, key: str = "system_description") -> bool:
        """Sanitize a parsed sysDescr model dict in-place if present."""
        if key not in container or not isinstance(container[key], dict):
            return False

        changed = False
        sysdesc = container[key]
        for sys_key, value in SYSTEM_DESCRIPTION.items():
            if sysdesc.get(sys_key) != value:
                sysdesc[sys_key] = value
                changed = True
        container[key] = sysdesc
        return changed

    def _sanitize_device_block(self, container: dict) -> bool:
        """
        Sanitize canonical top-level device identity blocks in API JSON.

        Expected shape:
          {"device": {"mac_address": "...", "system_description": {...}}}
        """
        if "device" not in container or not isinstance(container["device"], dict):
            return False

        changed = False
        device = container["device"]

        if device.get("mac_address") != self.new_mac_variants[0]:
            device["mac_address"] = self.new_mac_variants[0]
            changed = True

        if self._sanitize_sysdesc_dict(device):
            changed = True

        container["device"] = device
        return changed

    @staticmethod
    def _build_mac_variants(mac: str) -> Tuple[str, str, str, str]:
        compact = mac.replace(":", "").replace("-", "").replace("_", "")
        if len(compact) != 12:
            raise ValueError(f"Expected 12 hex characters for MAC, got '{compact}'")

        colon      = ":".join(compact[i:i + 2] for i in range(0, 12, 2))
        dash       = "-".join(compact[i:i + 2] for i in range(0, 12, 2))
        underscore = "_".join(compact[i:i + 2] for i in range(0, 12, 2))

        return colon, dash, underscore, compact

    @staticmethod
    def _normalize_mac_str(mac: str) -> str:
        compact = mac.replace(":", "").replace("-", "").replace("_", "").lower()
        if len(compact) != 12:
            return mac
        return ":".join(compact[i:i + 2] for i in range(0, 12, 2))

    def _rewrite_filename_mac(self, filename: str, old_mac: str) -> str:
        """
        Rewrite The MAC Portion Of A Filename Using Old MAC As Anchor.

        If no exact match is found for the old MAC variants, falls back to
        replacing the first MAC-like token in the filename with the new MAC.
        """
        new_name     = filename
        old_norm     = self._normalize_mac_str(old_mac)
        old_variants = self._build_mac_variants(old_norm)
        new_variants = self.new_mac_variants

        for old_variant, new_variant in zip(old_variants, new_variants):
            pattern = re.compile(re.escape(old_variant), re.IGNORECASE)
            new_name, count = pattern.subn(new_variant, new_name)
            if count > 0:
                return new_name

        def _force_replace(match: re.Match) -> str:
            token = match.group(0)
            if ":" in token:
                return new_variants[0]
            if "-" in token:
                return new_variants[1]
            if "_" in token:
                return new_variants[2]
            return new_variants[3]

        forced_name = MAC_PATTERN.sub(_force_replace, new_name)
        return forced_name

    def _resolve_capture_path(self, filename: str) -> Optional[Path]:
        """
        Resolve A Capture File Path From A Transaction Filename.

        Searches under demo_root for a file whose basename matches the given
        filename. Returns the first match, or None if not found.
        """
        candidates: List[Path] = [p for p in self.demo_root.rglob(filename) if p.is_file()]
        if not candidates:
            return None
        if len(candidates) > 1:
            print(f"WARNING: Multiple matches for '{filename}', using '{candidates[0]}'", file=sys.stderr)
        return candidates[0]

    def _run_mac_updater(self, capture_path: Path) -> bool:
        """
        Invoke pnm-mac-updater.py To Rewrite The Binary MAC For A Single Capture.

        Uses:
            pnm-mac-updater.py --mac-address NEW_MAC --file CAPTURE

        Returns True if the updater was invoked successfully, False otherwise.
        """
        if self.mac_updater is None:
            print(
                f"WARNING: pnm-mac-updater.py not available; "
                f"skipping binary MAC update for '{capture_path}'.",
                file=sys.stderr,
            )
            return False

        if not self.mac_updater.exists():
            print(
                f"WARNING: pnm-mac-updater.py not found at '{self.mac_updater}'; "
                f"skipping binary MAC update for '{capture_path}'.",
                file=sys.stderr,
            )
            return False

        cmd: List[str] = [
            sys.executable,
            str(self.mac_updater),
            "--mac-address",
            self.new_mac_raw,
            "--file",
            str(capture_path),
        ]
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as exc:
            print(
                f"ERROR: pnm-mac-updater failed for '{capture_path}': {exc}",
                file=sys.stderr,
            )
            return False

        self._vprint(f"Updated capture MAC via pnm-mac-updater: {capture_path}")
        return True

    def _process_transaction_json(self, json_path: Path) -> Tuple[int, int]:
        """
        Process A Single Transaction JSON File.

        Returns:
            (number_of_transaction_entries_updated, number_of_capture_files_touched)
        """
        try:
            text = json_path.read_text(encoding="utf-8")
            data = json.loads(text)
        except (OSError, json.JSONDecodeError):
            return 0, 0

        if not isinstance(data, dict):
            return 0, 0

        updated_entries: int  = 0
        updated_captures: int = 0
        changed: bool         = False

        for _, entry in list(data.items()):
            if not isinstance(entry, dict):
                continue

            if "filename" not in entry or "mac_address" not in entry:
                continue

            entry_mac      = str(entry["mac_address"])
            entry_mac_norm = self._normalize_mac_str(entry_mac)

            if not self.force_new_mac:
                if self.old_mac_raw is None:
                    continue
                if entry_mac_norm.lower() != self.old_mac_raw:
                    continue

            filename     = str(entry["filename"])
            capture_path = self._resolve_capture_path(filename)
            if capture_path is None:
                print(
                    f"WARNING: Capture file '{filename}' referenced in '{json_path}' "
                    f"was not found under '{self.demo_root}'.",
                    file=sys.stderr,
                )
                continue

            if self._run_mac_updater(capture_path):
                updated_captures += 1

            new_filename = self._rewrite_filename_mac(filename, entry_mac_norm)
            new_path     = capture_path.with_name(new_filename)
            if new_path != capture_path:
                if not new_path.exists():
                    capture_path.rename(new_path)
                entry["filename"] = new_filename
                updated_entries += 1
                changed = True
                self._vprint(f"Renamed capture: {capture_path} -> {new_path}")
            else:
                entry["filename"] = filename

            entry["mac_address"] = self.new_mac_variants[0]
            changed = True

            if "device_details" in entry and isinstance(entry["device_details"], dict):
                dev = entry["device_details"]
                if self._sanitize_sysdesc_dict(dev):
                    changed = True
                    entry["device_details"] = dev

            # Canonical API response shape support (new identity location)
            if self._sanitize_device_block(entry):
                changed = True

        # Legacy top-level response shape support (older JSON exports)
        if self._sanitize_sysdesc_dict(data):
            changed = True

        # Canonical top-level response shape support
        if self._sanitize_device_block(data):
            changed = True

        if changed:
            json_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
            self._vprint(f"Sanitized transaction JSON: {json_path}")

        return updated_entries, updated_captures

    @staticmethod
    def copy_data_tree(project_root: Path, demo_root: Path) -> List[Path]:
        """
        Copy Core PNM Demo Data Into The Demo Dataset Root.

        This helper mirrors the `.data/pnm` and `.data/db` directories into
        `demo_root/.demo`, skipping the top-level `json_transactions.json`
        file so that a curated or sanitized transaction database can be used
        instead.

        Only these directories are copied:
        - .data/pnm  →  demo/.demo/pnm
        - .data/db   →  demo/.demo/db (excluding json_transactions.json)

        Returns the list of top-level paths that were copied or merged.
        """
        copied: List[Path] = []

        src_root = project_root / ".data"
        dst_root = demo_root / ".demo"

        if not src_root.exists():
            return copied

        dst_root.mkdir(parents=True, exist_ok=True)

        for entry in src_root.iterdir():
            if not entry.is_dir():
                continue

            if entry.name == "pnm":
                src_path = entry
                dst_path = dst_root / entry.name
                shutil.copytree(src_path, dst_path, dirs_exist_ok=True)
                copied.append(dst_path)

            elif entry.name == "db":
                src_path = entry
                dst_path = dst_root / entry.name
                shutil.copytree(
                    src_path,
                    dst_path,
                    dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("json_transactions.json"),
                )
                copied.append(dst_path)

        return copied

    @staticmethod
    def clean_demo_tree(demo_root: Path, verbose: bool) -> List[Path]:
        """
        Remove All Subdirectories Under The Demo Dataset Root.

        The dataset root is resolved as:
        - demo_root/.demo if it exists, otherwise
        - demo_root

        Only immediate child directories are removed; files at the root are left
        intact. Returns the list of directories that were removed.
        """
        dataset_root = demo_root / ".demo"
        if not dataset_root.exists():
            dataset_root = demo_root

        removed: List[Path] = []
        if not dataset_root.exists():
            return removed

        for entry in dataset_root.iterdir():
            if entry.is_dir():
                shutil.rmtree(entry)
                removed.append(entry)
                if verbose:
                    print(f"Removed demo directory: {entry}")

        return removed

    def run(self, copy_data: bool = False) -> int:
        copied: List[Path] = []
        if copy_data:
            copied = DemoSanitizer.copy_data_tree(self.project_root, self.demo_root)
            if self.verbose:
                for path in copied:
                    self._vprint(f"Copied data entry: {path}")

        updated_entries_total: int  = 0
        updated_captures_total: int = 0

        for json_path in self.demo_root.rglob("*.json"):
            entries, captures = self._process_transaction_json(json_path)
            updated_entries_total  += entries
            updated_captures_total += captures

        print("Demo sanitizer summary:")
        print(f"  Transaction entries updated:   {updated_entries_total}")
        print(f"  Capture files updated/renamed: {updated_captures_total}")
        print(f"  .data entries copied:          {len(copied)}")

        return 0


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Sanitize a PyPNM demo dataset using transaction JSON files as ground truth.\n"
            "For each transaction entry, the tool locates the capture file by filename, "
            "rewrites the binary MAC using pnm-mac-updater.py, renames the file to "
            "use the new MAC, and updates the JSON metadata."
        ),
    )
    parser.add_argument(
        "--old-mac",
        help="Original MAC address to be sanitized (for targeted mode, example: aa:bb:cc:dd:ee:ff).",
    )
    parser.add_argument(
        "--new-mac",
        help="New MAC address to embed in filenames and JSON payloads (for example: aa:bb:cc:dd:ee:ff).",
    )
    parser.add_argument(
        "--force-new-mac",
        action="store_true",
        help=(
            "Force replacement for all transaction entries, regardless of their "
            "current mac_address. All entries are rewritten to --new-mac."
        ),
    )
    parser.add_argument(
        "--demo-root",
        type=Path,
        default=Path("demo"),
        help="Root directory of the demo tree (for example: demo or demo/.demo).",
    )
    parser.add_argument(
        "--mac-updater",
        type=Path,
        default=None,
        help=(
            "Optional path to pnm-mac-updater.py for binary MAC rewriting. "
            "If omitted, the script assumes pnm-mac-updater.py is in the same "
            "directory as this script, when present."
        ),
    )
    parser.add_argument(
        "--copy-data",
        action="store_true",
        help=(
            "Copy the contents of .data/* into demo/.demo for a self-contained "
            "demo dataset. Can be combined with MAC options, or used alone."
        ),
    )
    parser.add_argument(
        "--clean-demo",
        action="store_true",
        help=(
            "Remove all subdirectories under the demo dataset root "
            "(demo_root/.demo/* if it exists, otherwise demo_root/*) before "
            "any other operations."
        ),
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose per-file logging (renames, JSON updates, MAC updates).",
    )
    return parser.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)

    project_root = Path.cwd()

    removed: List[Path] = []
    if args.clean_demo:
        removed = DemoSanitizer.clean_demo_tree(args.demo_root, args.verbose)
        print(
            f"Cleaned demo dataset under '{args.demo_root}'; "
            f"removed {len(removed)} subdirectories."
        )

    if args.new_mac is None:
        if not args.copy_data and not args.clean_demo:
            print(
                "ERROR: --new-mac is required for MAC sanitization. "
                "Use --copy-data and/or --clean-demo alone if you only want to "
                "manage the demo tree.",
                file=sys.stderr,
            )
            return 1

        copied: List[Path] = []
        if args.copy_data:
            copied = DemoSanitizer.copy_data_tree(project_root=project_root, demo_root=args.demo_root)
            if args.verbose:
                for path in copied:
                    print(f"Copied data entry: {path}")

        print("Demo sanitizer summary:")
        print(f"  Transaction entries updated:   0")
        print(f"  Capture files updated/renamed: 0")
        print(f"  .data entries copied:          {len(copied)}")
        print(f"  Demo directories removed:      {len(removed)}")
        return 0

    if not args.force_new_mac and args.old_mac is None:
        print(
            "ERROR: Either --old-mac or --force-new-mac must be provided when using --new-mac.",
            file=sys.stderr,
        )
        return 1

    script_dir       = Path(__file__).resolve().parent
    mac_updater_path = args.mac_updater if args.mac_updater is not None else script_dir / "pnm-mac-updater.py"
    if args.mac_updater is None and not mac_updater_path.exists():
        mac_updater_path = None

    sanitizer = DemoSanitizer(
        demo_root     = args.demo_root,
        new_mac       = args.new_mac,
        old_mac       = args.old_mac,
        force_new_mac = args.force_new_mac,
        mac_updater   = mac_updater_path,
        project_root  = project_root,
        verbose       = args.verbose,
    )
    rc = sanitizer.run(copy_data=args.copy_data)

    if args.clean_demo:
        print(f"  Demo directories removed (earlier in run): {len(removed)}")

    return rc


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
