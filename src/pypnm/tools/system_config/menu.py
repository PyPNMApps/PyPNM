#!/usr/bin/env python3
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia


import subprocess
import sys
from pathlib import Path


class SystemConfigMenu:
    """
    Interactive Wrapper For PyPNM System Configuration Tools.

    Provides a text-based menu for invoking individual system.json
    editors and the PnmFileRetrieval setup helper. Each menu item
    launches the corresponding script using the current Python
    interpreter, preserving the existing interactive behavior of the
    underlying tools.
    """

    def __init__(self) -> None:
        self.base_dir  = Path(__file__).resolve().parent
        self.tools_dir = self.base_dir.parent

        self.fastapi_request_default = self.base_dir / "fastapi_request_default.py"
        self.snmp                    = self.base_dir / "snmp.py"
        self.pnm_bulk_data_transfer  = self.base_dir / "pnm_bulk_data_transfer.py"
        self.pnm_file_retrieval      = self.base_dir / "pnm_file_retrieval.py"
        self.logging_config          = self.base_dir / "logging_config.py"
        self.testmode                = self.base_dir / "testmode.py"

        # pnm_file_retrieval_setup.py sits one level up in tools/
        self.pnm_file_setup          = self.tools_dir / "pnm_file_retrieval_setup.py"
        # Resolve config via shared helper (handles deploy vs baked-in paths)
        try:
            from .common import _default_config_path  # type: ignore[attr-defined]
        except Exception:
            # Allow running as a script without package context
            sys.path.insert(0, str(self.base_dir))
            from common import _default_config_path  # type: ignore[attr-defined]

        self.config_path             = _default_config_path()

    def _print_header(self) -> None:
        print("\nPyPNM System Configuration Menu")
        print("================================")

    def _print_menu(self) -> None:
        self._print_header()
        print("Select an option:")
        print("  1) Edit FastApiRequestDefault")
        print("  2) Edit SNMP")
        print("  3) Edit PnmBulkDataTransfer")
        print("  4) Edit PnmFileRetrieval (retrival_method only)")
        print("  5) Edit Logging")
        print("  6) Edit TestMode")
        print("  7) Run PnmFileRetrieval Setup (directory initialization)")
        print("  p) Print current system.json")
        print("  q) Quit")

    def _run_script(self, script_path: Path) -> int:
        """
        Execute A Child Script Using The Current Python Interpreter.

        Parameters
        ----------
        script_path:
            Full path to the script that should be invoked.

        Returns
        -------
        int
            Exit code returned by the child process.
        """
        if not script_path.exists():
            print(f"\nError: script not found: {script_path}\n")
            return 1

        print(f"\nRunning: {script_path}\n")
        result = subprocess.run(
            [sys.executable, str(script_path)],
            check=False,
        )
        if result.returncode != 0:
            print(f"\nScript exited with code {result.returncode}\n")
        else:
            print("\nScript completed successfully.\n")
        return result.returncode

    def run(self) -> int:
        """
        Run The Interactive System Configuration Menu.

        Presents a numbered menu, accepts user selections, and dispatches
        to the corresponding configuration helper script until the user
        chooses to quit.
        """
        while True:
            self._print_menu()
            try:
                choice = input("Enter selection: ").strip().lower()
            except KeyboardInterrupt:
                print("\n(CTRL-C ignored; use 'q' or Ctrl-D to exit)\n")
                continue
            except EOFError:
                choice = ""  # Ctrl-D

            if choice in ("\x1b", ""):  # Esc or empty -> exit
                print("Exiting System Configuration Menu.")
                self._print_post_hint()
                return 0

            if choice in ("q", "quit", "x"):
                print("Exiting System Configuration Menu.")
                self._print_post_hint()
                return 0

            if choice == "1":
                self._run_script(self.fastapi_request_default)
                continue

            if choice == "2":
                self._run_script(self.snmp)
                continue

            if choice == "3":
                self._run_script(self.pnm_bulk_data_transfer)
                continue

            if choice == "4":
                self._run_script(self.pnm_file_retrieval)
                continue

            if choice == "5":
                self._run_script(self.logging_config)
                continue

            if choice == "6":
                self._run_script(self.testmode)
                continue

            if choice == "7":
                self._run_script(self.pnm_file_setup)
                continue

            if choice == "p":
                self._print_config()
                continue

            print("Invalid selection, please try again.\n")

        return 0

    def _print_config(self) -> None:
        """
        Print the current system.json contents to the console.
        """
        if not self.config_path.exists():
            print(f"\nConfig file not found at {self.config_path}\n")
            return

        try:
            content = self.config_path.read_text(encoding="utf-8")
        except Exception as exc:
            print(f"\nFailed to read config: {exc}\n")
            return

        print("\nCurrent system.json:\n")
        print(content)
        print()

        self._print_post_hint()

    def _print_post_hint(self) -> None:
        cfg = str(self.config_path)
        if cfg.startswith("/app/"):
            print("Next step: sudo docker compose restart pypnm-api\n")
        else:
            print("Reminder: reload PyPNM after changes, e.g.:")
            print("  curl -X GET http://127.0.0.1:8000/pypnm/system/webService/reload -H 'accept: application/json'\n")


def main() -> int:
    """
    Main Entry Point For The System Configuration Menu.

    Constructs the menu wrapper and starts the interactive loop that
    allows the user to launch individual configuration tools.
    """
    menu = SystemConfigMenu()
    return menu.run()


if __name__ == "__main__":
    raise SystemExit(main())
7
