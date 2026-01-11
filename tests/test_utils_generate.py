# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025

from __future__ import annotations

import re

import pytest

from pypnm.lib.types import TimeStamp, TransactionId
from pypnm.lib.utils import Generate, TimeUnit

HEX_RE = re.compile(r"^[0-9a-f]+$")


def test_time_stamp_units(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Verify Generate.time_stamp respects the requested TimeUnit and returns
    integer-based TimeStamp values.
    """
    fixed_ns: int = 1_700_000_000_123_456_789
    fixed_s: int = 1_700_000_000

    monkeypatch.setattr("pypnm.lib.utils.time.time_ns", lambda: fixed_ns)
    monkeypatch.setattr("pypnm.lib.utils.time.time", lambda: fixed_s)

    ts_sec: TimeStamp = Generate.time_stamp(TimeUnit.SECONDS)
    ts_ms: TimeStamp = Generate.time_stamp(TimeUnit.MILLISECONDS)
    ts_ns: TimeStamp = Generate.time_stamp(TimeUnit.NANOSECONDS)

    assert isinstance(ts_sec, int)
    assert isinstance(ts_ms, int)
    assert isinstance(ts_ns, int)

    assert ts_sec == fixed_s
    assert ts_ms == fixed_ns // 1_000_000
    assert ts_ns == fixed_ns


def test_transaction_id_length_and_hex(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    transaction_id should honor the requested length (with clamping) and
    return a hex-encoded TransactionId.
    """
    fixed_ns: int = 1_700_000_000_123_456_789
    fixed_s: int = 1_700_000_000

    monkeypatch.setattr("pypnm.lib.utils.time.time_ns", lambda: fixed_ns)
    monkeypatch.setattr("pypnm.lib.utils.time.time", lambda: fixed_s)

    tid_default: TransactionId = Generate.transaction_id(seed=123)
    assert isinstance(tid_default, str)
    assert len(tid_default) == 24
    assert HEX_RE.match(tid_default)

    tid_short: TransactionId = Generate.transaction_id(seed=123, length=8)
    assert len(tid_short) == 8
    assert HEX_RE.match(tid_short)

    tid_zero: TransactionId = Generate.transaction_id(seed=123, length=0)
    tid_large: TransactionId = Generate.transaction_id(seed=123, length=10_000)
    # clamped to full SHA-256 hex length
    assert len(tid_zero) == 64
    assert len(tid_large) == 64

    assert HEX_RE.match(tid_zero)
    assert HEX_RE.match(tid_large)


def test_transaction_id_deterministic_with_seed(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    With fixed time and seed, transaction_id must be deterministic; different
    seeds should produce different IDs.
    """
    fixed_ns: int = 1_700_000_000_222_222_222
    fixed_s: int = 1_700_000_000

    monkeypatch.setattr("pypnm.lib.utils.time.time_ns", lambda: fixed_ns)
    monkeypatch.setattr("pypnm.lib.utils.time.time", lambda: fixed_s)

    tid_a1: TransactionId = Generate.transaction_id(seed=1, length=24)
    tid_a2: TransactionId = Generate.transaction_id(seed=1, length=24)
    tid_b: TransactionId = Generate.transaction_id(seed=2, length=24)

    assert tid_a1 == tid_a2
    assert tid_a1 != tid_b


def test_group_id_generates_series_with_seed(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    group_id should return a list of TransactionId values, using an incremented
    seed when provided, and be deterministic for fixed time/seed.
    """
    fixed_ns: int = 1_700_000_000_333_333_333
    fixed_s: int = 1_700_000_000

    monkeypatch.setattr("pypnm.lib.utils.time.time_ns", lambda: fixed_ns)
    monkeypatch.setattr("pypnm.lib.utils.time.time", lambda: fixed_s)

    count: int = 5
    seed: int = 100

    group1: list[TransactionId] = Generate.group_id(count=count, seed=seed, length=16)
    group2: list[TransactionId] = Generate.group_id(count=count, seed=seed, length=16)

    assert len(group1) == count
    assert len(group2) == count
    assert group1 == group2  # deterministic for fixed time/seed

    for tid in group1:
        assert isinstance(tid, str)
        assert len(tid) == 16
        assert HEX_RE.match(tid)

    # IDs should be distinct within the group when seed is provided
    assert len(set(group1)) == count


def test_group_id_without_seed(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    group_id without a seed should still return the requested number of
    hex-encoded IDs with the requested length.
    """
    fixed_ns: int = 1_700_000_000_444_444_444
    fixed_s: int = 1_700_000_000

    monkeypatch.setattr("pypnm.lib.utils.time.time_ns", lambda: fixed_ns)
    monkeypatch.setattr("pypnm.lib.utils.time.time", lambda: fixed_s)

    count: int = 3
    group: list[TransactionId] = Generate.group_id(count=count, seed=None, length=20)

    assert len(group) == count
    for tid in group:
        assert isinstance(tid, str)
        assert len(tid) == 20
        assert HEX_RE.match(tid)


def test_operation_id_matches_transaction_id(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    operation_id is a thin wrapper around transaction_id and must produce the
    same value for identical arguments.
    """
    fixed_ns: int = 1_700_000_000_555_555_555
    fixed_s: int = 1_700_000_000

    monkeypatch.setattr("pypnm.lib.utils.time.time_ns", lambda: fixed_ns)
    monkeypatch.setattr("pypnm.lib.utils.time.time", lambda: fixed_s)

    seed: int = 42
    length: int = 24

    tid: TransactionId = Generate.transaction_id(seed=seed, length=length)
    op_id: TransactionId = Generate.operation_id(seed=seed, length=length)

    assert op_id == tid
    assert len(op_id) == length
    assert HEX_RE.match(op_id)
