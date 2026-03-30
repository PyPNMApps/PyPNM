# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCAN_SCRIPT = REPO_ROOT / "tools" / "security" / "scan-hardcoded-data-paths.py"


def test_scan_hardcoded_data_paths_reports_runtime_literal(tmp_path: Path) -> None:
    src_dir = tmp_path / "src" / "example"
    src_dir.mkdir(parents=True)
    (src_dir / "service.py").write_text('DATA_DIR = ".data/pnm"\n', encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(SCAN_SCRIPT), "--root", str(tmp_path), "--fail-on-found"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "hardcoded .data path literal" in result.stdout


def test_scan_hardcoded_data_paths_skips_allowlisted_config_file(tmp_path: Path) -> None:
    config_path = tmp_path / "src" / "pypnm" / "config"
    config_path.mkdir(parents=True)
    (config_path / "system_config_settings.py").write_text(
        '_DEFAULT_PNM_DIR = ".data/pnm"\n',
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, str(SCAN_SCRIPT), "--root", str(tmp_path), "--fail-on-found"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "No hardcoded .data path literals found" in result.stdout
