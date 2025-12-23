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

class LoggingEditor(SystemJsonEditorBase):
    """
    Interactive Editor For The Logging Section.

    Updates the logging level, directory, and filename. Shows current
    values, prompts for replacements, and applies changes after user
    confirmation.
    """

    def _section(self) -> JsonObject:
        section = self.data.get("logging")
        if not isinstance(section, dict):
            section = {}
            self.data["logging"] = section
        return section

    def run(self) -> int:
        """
        Run The Interactive Logging Editor.

        Prompts for log_level, log_dir, and log_filename, then displays
        and writes the updated logging section when confirmed.
        """
        section = self._section()

        print("Editing logging in system.json\n")

        level_new = self.prompt_str("Log level (DEBUG/INFO/WARN/ERROR)", section.get("log_level"))
        dir_new   = self.prompt_str("Log directory", section.get("log_dir"))
        file_new  = self.prompt_str("Log filename", section.get("log_filename"))

        if level_new is None and dir_new is None and file_new is None:
            print("No changes requested. Exiting without modification.")
            return 0

        if level_new is not None:
            section["log_level"] = level_new
        if dir_new is not None:
            section["log_dir"] = dir_new
        if file_new is not None:
            section["log_filename"] = file_new

        print("\nProposed changes:")
        print(json.dumps({"logging": section}, indent=JSON_INDENT_WIDTH))

        confirm = input("\nApply these changes? [y/N]: ").strip().lower()
        if confirm != "y":
            print("Changes discarded.")
            return 0

        self._save()
        print(f"Updated {self.config_path}")
        return 0


def main() -> int:
    """
    Main Entry Point For The Logging Editor.

    Prompts for the configuration path and runs the interactive logging
    editor for the selected system.json file.
    """
    config_path = SystemJsonEditorBase.prompt_config_path(DEFAULT_CONFIG_PATH)
    editor      = LoggingEditor(config_path)
    return editor.run()


if __name__ == "__main__":
    raise SystemExit(main())
