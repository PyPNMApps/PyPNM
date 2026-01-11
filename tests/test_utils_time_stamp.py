# tests/test_utils_time_stamp.py
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
import time

import pytest

from pypnm.lib.utils import Generate, TimeUnit


def test_time_unit_values() -> None:
    """
    Verify that TimeUnit enum members have the expected string values.
    """
    assert TimeUnit.SECONDS.value      == "s"
    assert TimeUnit.MILLISECONDS.value == "ms"
    assert TimeUnit.NANOSECONDS.value  == "ns"


def test_time_stamp_default_is_seconds(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Ensure the default time_stamp() call uses seconds and int(time.time()).
    """
    calls = {"time": 0, "time_ns": 0}

    def fake_time() -> float:
        calls["time"] += 1
        return 1_234.567

    def fake_time_ns() -> int:
        calls["time_ns"] += 1
        return 999_999_999

    monkeypatch.setattr(time, "time", fake_time)
    monkeypatch.setattr(time, "time_ns", fake_time_ns)

    ts = Generate.time_stamp()
    assert ts == 1_234
    assert calls["time"] == 1
    assert calls["time_ns"] == 0


def test_time_stamp_seconds(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Verify explicit TimeUnit.SECONDS returns truncated seconds from time.time().
    """
    calls = {"time": 0, "time_ns": 0}

    def fake_time() -> float:
        calls["time"] += 1
        return 2_000.999

    def fake_time_ns() -> int:
        calls["time_ns"] += 1
        return 0

    monkeypatch.setattr(time, "time", fake_time)
    monkeypatch.setattr(time, "time_ns", fake_time_ns)

    ts = Generate.time_stamp(TimeUnit.SECONDS)
    assert ts == 2_000
    assert calls["time"] == 1
    assert calls["time_ns"] == 0


def test_time_stamp_milliseconds(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Verify TimeUnit.MILLISECONDS uses time.time_ns() and converts to ms.
    """
    calls = {"time": 0, "time_ns": 0}

    def fake_time() -> float:
        calls["time"] += 1
        return 0.0

    def fake_time_ns() -> int:
        calls["time_ns"] += 1
        return 1_234_567_890  # ns

    monkeypatch.setattr(time, "time", fake_time)
    monkeypatch.setattr(time, "time_ns", fake_time_ns)

    ts = Generate.time_stamp(TimeUnit.MILLISECONDS)
    assert ts == 1_234_567_890 // 1_000_000
    assert calls["time_ns"] == 1
    # time() is never used in this branch
    assert calls["time"] == 0


def test_time_stamp_nanoseconds(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Verify TimeUnit.NANOSECONDS returns the raw value from time.time_ns().
    """
    calls = {"time": 0, "time_ns": 0}

    def fake_time() -> float:
        calls["time"] += 1
        return 0.0

    def fake_time_ns() -> int:
        calls["time_ns"] += 1
        return 987_654_321

    monkeypatch.setattr(time, "time", fake_time)
    monkeypatch.setattr(time, "time_ns", fake_time_ns)

    ts = Generate.time_stamp(TimeUnit.NANOSECONDS)
    assert ts == 987_654_321
    assert calls["time_ns"] == 1
    # time() is never used in this branch
    assert calls["time"] == 0
