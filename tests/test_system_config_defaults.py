
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def test_config_files_exist() -> None:
    settings_cfg = Path("src/pypnm/settings/system.json")
    deploy_cfg = Path("deploy/docker/config/system.json")

    assert settings_cfg.exists(), "src/pypnm/settings/system.json must exist (symlink to deploy config)"
    assert deploy_cfg.exists(), "deploy/docker/config/system.json must exist for runtime config"
    assert settings_cfg.is_symlink(), "src/pypnm/settings/system.json must be a symlink"
    assert settings_cfg.resolve() == deploy_cfg.resolve(), "system.json symlink must target deploy/docker/config/system.json"


def test_no_extra_system_json_files() -> None:
    allowed = {
        Path("deploy/docker/config/system.json").resolve(),
        Path("deploy/docker/config/system.json.template").resolve(),
        Path("src/pypnm/settings/system.json").resolve(),
        Path("src/pypnm/examples/settings/system.json").resolve(),
        Path("demo/settings/system.json").resolve(),
        Path("demo/settings/system.json.template").resolve(),
    }

    for path in Path(".").rglob("system.json"):
        if "backup" in path.parts:
            continue
        resolved = path.resolve()
        if resolved in allowed:
            continue
        raise AssertionError(f"Unexpected system.json found: {path}")


def test_default_config_path_resolves() -> None:
    from tools.system_config.common import DEFAULT_CONFIG_PATH

    assert DEFAULT_CONFIG_PATH.exists(), f"DEFAULT_CONFIG_PATH must exist: {DEFAULT_CONFIG_PATH}"
