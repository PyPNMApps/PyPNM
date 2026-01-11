# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

# tests/test_docs_pnm_rxmer_entry_casts.py
from __future__ import annotations

import pytest

from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmRxMerEntry import (
    DocsPnmCmDsOfdmRxMerEntry,
    DocsPnmCmDsOfdmRxMerFields,
    MeasStatusType,  # enum whose str() returns the lowercase name
)
from pypnm.snmp.snmp_v2c import Snmp_v2c


class _FakeSnmp:
    def __init__(self, idx: int, table: dict[str, object]) -> None:
        self._idx = idx
        self._t = table

    async def get(self, oq: str) -> object:
        sym, _, sfx = oq.rpartition(".")
        assert int(sfx) == self._idx
        return self._t[sym]


@pytest.mark.asyncio
async def test_from_snmp_scaling_and_types(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Happy-path test:
      • get_result_value is pass-through
      • integer fixed-point fields scale by /100.0
      • status is mapped to its lowercase string name
      • frequency is left as plain integer-ish Hz
    """
    monkeypatch.setattr(Snmp_v2c, "get_result_value", staticmethod(lambda x: x))

    idx = 7
    fake = _FakeSnmp(
        idx,
        {
            "docsPnmCmDsOfdmRxMerFileEnable": 1,
            "docsPnmCmDsOfdmRxMerMeasStatus": 4,  # -> "sample_ready"
            "docsPnmCmDsOfdmRxMerFileName": "ds_ofdm_rxmer.bin",
            "docsPnmCmDsOfdmRxMerPercentile": 2,  # -> 0.02
            "docsPnmCmDsOfdmRxMerMean": 3323,  # -> 33.23
            "docsPnmCmDsOfdmRxMerStdDev": 631,  # -> 6.31
            "docsPnmCmDsOfdmRxMerThrVal": 92,  # -> 0.92
            "docsPnmCmDsOfdmRxMerThrHighestFreq": 314_800_000,  # -> 314800000
        },
    )

    e = await DocsPnmCmDsOfdmRxMerEntry.from_snmp(idx, fake)  # type: ignore[arg-type]
    assert e.index == idx and e.channel_id == idx
    f: DocsPnmCmDsOfdmRxMerFields = e.entry

    assert f.docsPnmCmDsOfdmRxMerFileEnable is True
    assert f.docsPnmCmDsOfdmRxMerMeasStatus == "sample_ready"  # string name now
    assert f.docsPnmCmDsOfdmRxMerFileName == "ds_ofdm_rxmer.bin"

    assert f.docsPnmCmDsOfdmRxMerPercentile == pytest.approx(0.02, abs=0.0)
    assert f.docsPnmCmDsOfdmRxMerMean == pytest.approx(33.23, abs=0.0)
    assert f.docsPnmCmDsOfdmRxMerStdDev == pytest.approx(6.31, abs=0.0)
    assert f.docsPnmCmDsOfdmRxMerThrVal == pytest.approx(0.92, abs=0.0)

    # Frequency Hz remains an integer-ish value (typed alias), compare numerically
    assert f.docsPnmCmDsOfdmRxMerThrHighestFreq == pytest.approx(314_800_000, abs=0.0)


@pytest.mark.asyncio
async def test_from_snmp_missing_required_fields_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Since the entry class enforces non-optional fields, missing any of them should raise ValueError.
    Here we omit several fields and verify the error message lists them.
    """
    monkeypatch.setattr(Snmp_v2c, "get_result_value", staticmethod(lambda x: x))

    idx = 1
    # Missing file_name + all float fields → should raise
    fake = _FakeSnmp(
        idx,
        {
            "docsPnmCmDsOfdmRxMerFileEnable": 0,
            "docsPnmCmDsOfdmRxMerMeasStatus": 3,  # "busy"
            # "docsPnmCmDsOfdmRxMerFileName": ... MISSING ...
            # float-ish fields MISSING:
            # "docsPnmCmDsOfdmRxMerPercentile"
            # "docsPnmCmDsOfdmRxMerMean"
            # "docsPnmCmDsOfdmRxMerStdDev"
            # "docsPnmCmDsOfdmRxMerThrVal"
            "docsPnmCmDsOfdmRxMerThrHighestFreq": 100_000_000,
        },
    )

    with pytest.raises(ValueError) as exc:
        await DocsPnmCmDsOfdmRxMerEntry.from_snmp(idx, fake)  # type: ignore[arg-type]

    msg = str(exc.value)
    # Ensure the expected keys are called out
    for missing_key in ("file_name", "perc", "mean", "stddev", "thr_val"):
        assert missing_key in msg


@pytest.mark.asyncio
async def test_get_empty_indices_returns_empty_list() -> None:
    out = await DocsPnmCmDsOfdmRxMerEntry.get(snmp=None, indices=[])  # type: ignore[arg-type]
    assert out == []


@pytest.mark.parametrize(
    "code, expected",
    [
        (1, "other"),
        (2, "inactive"),
        (3, "busy"),
        (4, "sample_ready"),
        (5, "error"),
        (6, "resource_unavailable"),
        (7, "sample_truncated"),
        (8, "interface_modification"),
    ],
)
def test_status_enum_string_names(code: int, expected: str) -> None:
    # Sanity-check the enum-to-string behavior used by the entry class
    assert str(MeasStatusType(code)) == expected


@pytest.mark.asyncio
async def test_debug_toggle_does_not_break(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Flip the ClassVar DEBUG flag to True and run a fetch to ensure no exceptions are thrown
    (we're not asserting logs here, just that it still works).
    """
    monkeypatch.setattr(Snmp_v2c, "get_result_value", staticmethod(lambda x: x))

    idx = 2
    fake = _FakeSnmp(
        idx,
        {
            "docsPnmCmDsOfdmRxMerFileEnable": 1,
            "docsPnmCmDsOfdmRxMerMeasStatus": 2,  # "inactive"
            "docsPnmCmDsOfdmRxMerFileName": "foo.bin",
            "docsPnmCmDsOfdmRxMerPercentile": 10,  # -> 0.10
            "docsPnmCmDsOfdmRxMerMean": 1234,  # -> 12.34
            "docsPnmCmDsOfdmRxMerStdDev": 5,  # -> 0.05
            "docsPnmCmDsOfdmRxMerThrVal": 200,  # -> 2.00
            "docsPnmCmDsOfdmRxMerThrHighestFreq": 765_000_000,
        },
    )

    # flip DEBUG on for the class during this test
    prev = DocsPnmCmDsOfdmRxMerEntry.DEBUG
    DocsPnmCmDsOfdmRxMerEntry.DEBUG = True
    try:
        e = await DocsPnmCmDsOfdmRxMerEntry.from_snmp(idx, fake)  # type: ignore[arg-type]
        f = e.entry
        assert f.docsPnmCmDsOfdmRxMerMeasStatus == "inactive"
        assert f.docsPnmCmDsOfdmRxMerPercentile == pytest.approx(0.10, abs=0.0)
        assert f.docsPnmCmDsOfdmRxMerMean == pytest.approx(12.34, abs=0.0)
        assert f.docsPnmCmDsOfdmRxMerStdDev == pytest.approx(0.05, abs=0.0)
        assert f.docsPnmCmDsOfdmRxMerThrVal == pytest.approx(2.00, abs=0.0)
        assert f.docsPnmCmDsOfdmRxMerThrHighestFreq == 765_000_000
    finally:
        DocsPnmCmDsOfdmRxMerEntry.DEBUG = prev
