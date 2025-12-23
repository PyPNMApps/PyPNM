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


class TestModeEditor(SystemJsonEditorBase):
    """
    Interactive Editor For The TestMode Section.

    Updates the global test mode flag and a single class-level override
    per invocation. Existing structure is preserved and only explicitly
    changed values are written back to system.json.
    """

    def _section(self) -> JsonObject:
        section = self.data.get("TestMode")
        if not isinstance(section, dict):
            section = {}
            self.data["TestMode"] = section
        return section

    def run(self) -> int:
        """
        Run The Interactive TestMode Editor.

        Prompts for the global test-mode enable flag and an optional
        class-specific override, then displays and applies the proposed
        changes when confirmed.
        """
        section = self._section()

        global_section = section.get("global")
        if not isinstance(global_section, dict):
            global_section = {}
            section["global"] = global_section

        global_mode = global_section.get("mode")
        if not isinstance(global_mode, dict):
            global_mode = {}
            global_section["mode"] = global_mode

        class_section = section.get("class_name")
        if not isinstance(class_section, dict):
            class_section = {}
            section["class_name"] = class_section

        print("Editing TestMode in system.json\n")

        global_enable_new = self.prompt_bool(
            "Global test mode enable",
            global_mode.get("enable"),
        )

        class_name_new = self.prompt_str(
            "Class name for per-class test mode (blank to skip)",
            None,
        )

        class_enable_new: bool | None = None
        if class_name_new is not None:
            existing      = class_section.get(class_name_new)
            existing_mode = None
            if isinstance(existing, dict):
                existing_mode = existing.get("mode")
            existing_enable = None
            if isinstance(existing_mode, dict):
                existing_enable = existing_mode.get("enable")

            class_enable_new = self.prompt_bool(
                f"Enable test mode for {class_name_new}",
                existing_enable,
            )

        if global_enable_new is None and class_name_new is None:
            print("No changes requested. Exiting without modification.")
            return 0

        if global_enable_new is not None:
            global_mode["enable"] = global_enable_new

        if class_name_new is not None and class_enable_new is not None:
            per_class = class_section.get(class_name_new)
            if not isinstance(per_class, dict):
                per_class = {}
                class_section[class_name_new] = per_class

            per_class_mode = per_class.get("mode")
            if not isinstance(per_class_mode, dict):
                per_class_mode = {}
                per_class["mode"] = per_class_mode

            per_class_mode["enable"] = class_enable_new

        print("\nProposed changes:")
        print(json.dumps({"TestMode": section}, indent=JSON_INDENT_WIDTH))

        confirm = input("\nApply these changes? [y/N]: ").strip().lower()
        if confirm != "y":
            print("Changes discarded.")
            return 0

        self._save()
        print(f"Updated {self.config_path}")
        return 0


def main() -> int:
    """
    Main Entry Point For The TestMode Editor.

    Prompts for the configuration path and runs the interactive editor
    for the TestMode section.
    """
    config_path = SystemJsonEditorBase.prompt_config_path(DEFAULT_CONFIG_PATH)
    editor      = TestModeEditor(config_path)
    return editor.run()


if __name__ == "__main__":
    raise SystemExit(main())
