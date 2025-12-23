#!/usr/bin/env python3
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia


import json
import sys
from pathlib import Path

JSON_INDENT_WIDTH = 4

# Resolve project root and add src/ to sys.path so pypnm can be imported
HERE         = Path(__file__).resolve()
PROJECT_ROOT = HERE.parents[2]
SRC_ROOT     = PROJECT_ROOT / "src"
DEPLOY_CONFIG = PROJECT_ROOT / "deploy" / "docker" / "config" / "system.json"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from pypnm.lib.types import JsonObject

try:
    from pypnm.config.config_manager import ConfigManager  # type: ignore[attr-defined]
except ImportError:
    ConfigManager = None  # type: ignore[assignment]

def _default_config_path() -> Path:
    # Candidate paths in preference order
    candidates = [
        PROJECT_ROOT / "config" / "system.json",          # runtime bind mount (/app/config) if present
        SRC_ROOT / "pypnm" / "settings" / "system.json",  # repo default (symlink)
        DEPLOY_CONFIG,                                    # deploy bundle config
    ]

    # Use ConfigManager resolution as a fallback (do not override higher-priority paths)
    if ConfigManager is not None:
        try:
            resolved = Path(ConfigManager().get_config_path())
            if resolved not in candidates:
                candidates.append(resolved)
        except FileNotFoundError:
            pass

    for candidate in candidates:
        if candidate.exists():
            return candidate

    # Last resort: seed deploy config from template if present
    deploy_template = PROJECT_ROOT / "deploy" / "docker" / "config" / "system.json.template"
    deploy_target = PROJECT_ROOT / "deploy" / "docker" / "config" / "system.json"
    if deploy_template.exists():
        deploy_target.parent.mkdir(parents=True, exist_ok=True)
        deploy_target.write_text(deploy_template.read_text())
        return deploy_target

    # Fallback to last candidate even if missing
    return candidates[-1]


DEFAULT_CONFIG_PATH = _default_config_path()


class SystemJsonEditorBase:
    """
    Base Class For Interactive system.json Editors.

    Provides loading and saving helpers plus common interactive prompt
    methods for string, integer, and boolean values. Subclasses should
    implement a run() method that performs section-specific editing.
    """

    def __init__(self, config_path: Path) -> None:
        self.config_path = config_path
        self.data: JsonObject = {}
        self._load()

    def _load(self) -> None:
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config file not found: {self.config_path}")
        text = self.config_path.read_text(encoding="utf-8")
        self.data = json.loads(text)

    def _save(self) -> None:
        text = json.dumps(self.data, indent=JSON_INDENT_WIDTH, sort_keys=True)
        self.config_path.write_text(f"{text}\n", encoding="utf-8")

    @staticmethod
    def prompt_config_path(default_path: Path) -> Path:
        """
        Prompt For The Path To system.json.

        Returns the user-specified path or the provided default_path
        when the input is empty.
        """
        default_str = str(default_path)
        user_input  = input(f"Path to system.json [{default_str}]: ").strip()
        if user_input == "":
            return default_path
        return Path(user_input)

    @staticmethod
    def prompt_str(label: str, current: str | None) -> str | None:
        """
        Prompt For A String Value With A Current Default.

        Returns None when the user presses Enter, indicating that the
        current value should be kept unchanged.
        """
        if current is None:
            prompt = f"{label} (currently unset, Enter to keep unset): "
        else:
            prompt = f"{label} [current: {current}] (Enter to keep): "
        value = input(prompt).strip()
        if value == "":
            return None
        return value

    @staticmethod
    def prompt_int(label: str, current: int | None) -> int | None:
        """
        Prompt For An Integer Value With A Current Default.

        Returns None when the user presses Enter. Invalid integer input
        is reported and ignored.
        """
        if current is None:
            prompt = f"{label} (currently unset, Enter to keep unset): "
        else:
            prompt = f"{label} [current: {current}] (Enter to keep): "
        value = input(prompt).strip()
        if value == "":
            return None
        try:
            return int(value)
        except ValueError:
            print("Invalid integer input; ignoring change.")
            return None

    @staticmethod
    def prompt_bool(label: str, current: bool | None) -> bool | None:
        """
        Prompt For A Boolean Value With A Current Default.

        Returns None when the user presses Enter. Accepts y/n style
        responses and prints a warning when input is invalid.
        """
        if current is None:
            current_str = "unset"
        elif current:
            current_str = "true"
        else:
            current_str = "false"
        prompt = f"{label} [current: {current_str}] (y/n, Enter to keep): "
        value  = input(prompt).strip().lower()
        if value == "":
            return None
        if value in ("y", "yes", "1", "true"):
            return True
        if value in ("n", "no", "0", "false"):
            return False
        print("Invalid boolean input; ignoring change.")
        return None
