# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
import subprocess
from collections.abc import Callable
from typing import NoReturn

import pytest

from pypnm.lib.ping import Ping


class DummyCompleted:
    def __init__(self, returncode: int) -> None:
        self.returncode = returncode


def _mock_run_factory(
    expected_cmd_out: list[str], rc: int = 0
) -> Callable[..., DummyCompleted]:
    captured: dict[str, object] = {}

    def _mock_run(cmd: list[str], *args: object, **kwargs: object) -> DummyCompleted:
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs

        if "stdout" in kwargs:
            assert kwargs["stdout"] is subprocess.DEVNULL
        if "stderr" in kwargs:
            assert kwargs["stderr"] is subprocess.DEVNULL

        return DummyCompleted(rc)

    _mock_run.captured = captured  # type: ignore[attr-defined]
    _mock_run.expected = expected_cmd_out  # type: ignore[attr-defined]
    return _mock_run


def test_linux_mac_builds_correct_command_and_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("platform.system", lambda: "Linux")

    expected_cmd = ["ping", "-c", "3", "-W", "2", "host.example"]
    mock_run = _mock_run_factory(expected_cmd, rc=0)
    monkeypatch.setattr("subprocess.run", mock_run)

    ok = Ping.is_reachable("host.example", timeout=2, count=3)
    assert ok is True
    assert mock_run.captured["cmd"] == expected_cmd


def test_linux_mac_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("platform.system", lambda: "Darwin")

    expected_cmd = ["ping", "-c", "1", "-W", "1", "8.8.8.8"]
    mock_run = _mock_run_factory(expected_cmd, rc=1)
    monkeypatch.setattr("subprocess.run", mock_run)

    ok = Ping.is_reachable("8.8.8.8")
    assert ok is False
    assert mock_run.captured["cmd"] == expected_cmd


def test_windows_builds_correct_command_and_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("platform.system", lambda: "Windows")

    expected_cmd = ["ping", "-n", "4", "-w", "3000", "10.0.0.1"]
    mock_run = _mock_run_factory(expected_cmd, rc=0)
    monkeypatch.setattr("subprocess.run", mock_run)

    ok = Ping.is_reachable("10.0.0.1", timeout=3, count=4)
    assert ok is True
    assert mock_run.captured["cmd"] == expected_cmd


def test_subprocess_exception_returns_false(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr("platform.system", lambda: "Linux")

    def boom(*args: object, **kwargs: object) -> NoReturn:
        raise OSError("no ping here")

    monkeypatch.setattr("subprocess.run", boom)

    with caplog.at_level(logging.ERROR):
        ok = Ping.is_reachable("nowhere.invalid", timeout=1, count=1)

    assert ok is False
    # Optional: assert we actually logged the error
    assert "[Ping Error] no ping here" in caplog.text
