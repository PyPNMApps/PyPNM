# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025

from __future__ import annotations

import hashlib

import pytest

from pypnm.lib.types import TransactionId
from pypnm.lib.utils import Generate, TimeUnit


def _patch_time_stamp(monkeypatch: pytest.MonkeyPatch, fixed_value: int) -> None:
    """
    Helper To Patch Generate.time_stamp To A Fixed Nanosecond Value.
    """
    def _fixed_time_stamp(unit: TimeUnit = TimeUnit.SECONDS) -> int:
        return fixed_value

    monkeypatch.setattr(
        "pypnm.lib.utils.Generate.time_stamp",
        _fixed_time_stamp,
        raising=True,
    )


def test_transaction_id_default_length(monkeypatch: pytest.MonkeyPatch) -> None:
    fixed_ns: int = 1_700_000_000_000_000_000
    _patch_time_stamp(monkeypatch, fixed_ns)

    tx_id: TransactionId = Generate.transaction_id()
    assert isinstance(tx_id, str)
    assert len(tx_id) == 24


def test_transaction_id_custom_length(monkeypatch: pytest.MonkeyPatch) -> None:
    fixed_ns: int = 1_700_000_000_000_000_001
    _patch_time_stamp(monkeypatch, fixed_ns)

    length: int            = 12
    seed: int              = 42
    tx_id: TransactionId   = Generate.transaction_id(seed=seed, length=length)

    raw_value: str         = f"{fixed_ns}:{seed}"
    digest_full: str       = hashlib.sha256(raw_value.encode("utf-8")).hexdigest()
    expected: str          = digest_full[:length]

    assert isinstance(tx_id, str)
    assert len(tx_id) == length
    assert tx_id == expected


def test_transaction_id_length_clamped_low(monkeypatch: pytest.MonkeyPatch) -> None:
    fixed_ns: int = 1_700_000_000_000_000_002
    _patch_time_stamp(monkeypatch, fixed_ns)

    seed: int              = 7
    length: int            = 0
    tx_id: TransactionId   = Generate.transaction_id(seed=seed, length=length)

    raw_value: str         = f"{fixed_ns}:{seed}"
    digest_full: str       = hashlib.sha256(raw_value.encode("utf-8")).hexdigest()
    max_len: int           = len(digest_full)

    assert isinstance(tx_id, str)
    assert len(tx_id) == max_len
    assert tx_id == digest_full


def test_transaction_id_length_clamped_high(monkeypatch: pytest.MonkeyPatch) -> None:
    fixed_ns: int = 1_700_000_000_000_000_003
    _patch_time_stamp(monkeypatch, fixed_ns)

    seed: int              = 11
    requested_length: int  = 10_000
    tx_id: TransactionId   = Generate.transaction_id(seed=seed, length=requested_length)

    raw_value: str         = f"{fixed_ns}:{seed}"
    digest_full: str       = hashlib.sha256(raw_value.encode("utf-8")).hexdigest()
    max_len: int           = len(digest_full)

    assert isinstance(tx_id, str)
    assert len(tx_id) == max_len
    assert tx_id == digest_full


def test_transaction_id_seed_deterministic(monkeypatch: pytest.MonkeyPatch) -> None:
    fixed_ns: int = 1_700_000_000_000_000_004
    _patch_time_stamp(monkeypatch, fixed_ns)

    seed: int              = 99
    length: int            = 24

    tx_id_1: TransactionId = Generate.transaction_id(seed=seed, length=length)
    tx_id_2: TransactionId = Generate.transaction_id(seed=seed, length=length)

    assert isinstance(tx_id_1, str)
    assert isinstance(tx_id_2, str)
    assert tx_id_1 == tx_id_2


def test_transaction_id_different_seeds_produce_different_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    fixed_ns: int = 1_700_000_000_000_000_005
    _patch_time_stamp(monkeypatch, fixed_ns)

    length: int             = 24
    tx_id_seed_1: TransactionId = Generate.transaction_id(seed=1, length=length)
    tx_id_seed_2: TransactionId = Generate.transaction_id(seed=2, length=length)

    assert isinstance(tx_id_seed_1, str)
    assert isinstance(tx_id_seed_2, str)
    assert tx_id_seed_1 != tx_id_seed_2


def test_transaction_id_no_seed_uses_timestamp(monkeypatch: pytest.MonkeyPatch) -> None:
    fixed_ns: int = 1_700_000_000_000_000_006
    _patch_time_stamp(monkeypatch, fixed_ns)

    length: int            = 16
    tx_id: TransactionId   = Generate.transaction_id(length=length)

    raw_value: str         = str(fixed_ns)
    digest_full: str       = hashlib.sha256(raw_value.encode("utf-8")).hexdigest()
    expected: str          = digest_full[:length]

    assert isinstance(tx_id, str)
    assert len(tx_id) == length
    assert tx_id == expected
