#!/usr/bin/env python3
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia


import json
import sys
from pathlib import Path
from typing import Any

from common import (
    JsonObject,
    JSON_INDENT_WIDTH,
    DEFAULT_CONFIG_PATH,
    SystemJsonEditorBase,
)

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))


class FastApiRequestDefaultEditor(SystemJsonEditorBase):
    """
    Interactive Editor For FastApiRequestDefault.

    Allows editing of the default MAC and IP address used by FastAPI
    request models. Shows current values, prompts for new values, and
    applies changes only after explicit confirmation.
    """

    def _section(self) -> JsonObject:
        section = self.data.get("FastApiRequestDefault")
        if not isinstance(section, dict):
            section = {}
            self.data["FastApiRequestDefault"] = section
        return section

    def run(self) -> int:
        """
        Run The Interactive FastApiRequestDefault Editor.

        Loads the FastApiRequestDefault section, prompts for updated MAC
        and IP values, and writes the changes back to system.json when
        the user confirms the proposed configuration.
        """
        section     = self._section()
        current_mac = section.get("mac_address")
        current_ip  = section.get("ip_address")

        print("Editing FastApiRequestDefault in system.json\n")

        new_mac = self.prompt_str("Default MAC address", current_mac)
        new_ip  = self.prompt_str("Default IP address", current_ip)

        if new_mac is None and new_ip is None:
            print("No changes requested. Exiting without modification.")
            return 0

        if new_mac is not None:
            section["mac_address"] = new_mac
        if new_ip is not None:
            section["ip_address"] = new_ip

        print("\nProposed changes:")
        print(json.dumps({"FastApiRequestDefault": section}, indent=JSON_INDENT_WIDTH))

        confirm = input("\nApply these changes? [y/N]: ").strip().lower()
        if confirm != "y":
            print("Changes discarded.")
            return 0

        self._save()
        print(f"Updated {self.config_path}")
        return 0


def main() -> int:
    """
    Main Entry Point For The FastApiRequestDefault Editor.

    Prompts for the configuration path (defaulting to config/system.json)
    and runs the interactive editor for the FastApiRequestDefault section.
    """
    config_path = SystemJsonEditorBase.prompt_config_path(DEFAULT_CONFIG_PATH)
    editor      = FastApiRequestDefaultEditor(config_path)
    return editor.run()


if __name__ == "__main__":
    raise SystemExit(main())
