# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "tools" / "maintenance" / "kill-pypnm.py"
SPEC = importlib.util.spec_from_file_location("kill_pypnm_script", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
kill_script = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = kill_script
SPEC.loader.exec_module(kill_script)


def test_collect_processes_includes_background_pidfile_row(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    pidfile = runtime_dir / "pypnm.serve.pid"
    pidfile.write_text("4242\n", encoding="utf-8")

    monkeypatch.setattr(kill_script.SystemConfigSettings, "runtime_dir", classmethod(lambda cls: str(runtime_dir)))
    monkeypatch.setattr(kill_script, "_ps_stat", lambda pid: (111, "00:42", "python /tmp/fake-pypnm"))
    monkeypatch.setattr(
        kill_script.subprocess,
        "run",
        lambda *args, **kwargs: type("Completed", (), {"stdout": ""})(),
    )

    rows = kill_script.collect_processes()

    assert len(rows) == 1
    row = rows[0]
    assert row.pid == 4242
    assert row.source == "background_pidfile"
    assert "pidfile=" in row.command
