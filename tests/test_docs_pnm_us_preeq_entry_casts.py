# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026

from __future__ import annotations

import pytest

from pypnm.docsis.data_type.pnm.DocsPnmCmUsPreEqEntry import (
    DocsPnmCmUsPreEqEntry,
    DocsPnmCmUsPreEqFields,
)
from pypnm.snmp.snmp_v2c import Snmp_v2c


class _FakeSnmp:
    def __init__(self, idx: int, table: dict[str, object]) -> None:
        self._idx = idx
        self._t = table

    async def get(self, oq: str):
        sym, _, sfx = oq.rpartition(".")
        assert int(sfx) == self._idx
        return self._t[sym]


@pytest.mark.asyncio
async def test_from_snmp_scaling_and_types(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Happy-path test:
      • get_result_value is pass-through
      • fixed-point fields scale by /1000.0
      • status values are mapped to lowercase strings
      • channel_id pulls from OFDMA channel ID when present
    """
    monkeypatch.setattr(Snmp_v2c, "get_result_value", staticmethod(lambda x: x))

    idx = 83
    fake = _FakeSnmp(idx, {
        "docsPnmCmUsPreEqFileEnable": 1,
        "docsPnmCmUsPreEqAmpRipplePkToPk": 12345,
        "docsPnmCmUsPreEqAmpRippleRms": 2000,
        "docsPnmCmUsPreEqAmpSlope": 500,
        "docsPnmCmUsPreEqGrpDelayRipplePkToPk": 9000,
        "docsPnmCmUsPreEqGrpDelayRippleRms": 11000,
        "docsPnmCmUsPreEqPreEqCoAdjStatus": 2,
        "docsPnmCmUsPreEqMeasStatus": 4,
        "docsPnmCmUsPreEqLastUpdateFileName": "pre_eq_last.bin",
        "docsPnmCmUsPreEqFileName": "pre_eq.bin",
        "docsPnmCmUsPreEqAmpMean": 4000,
        "docsPnmCmUsPreEqGrpDelaySlope": 2500,
        "docsPnmCmUsPreEqGrpDelayMean": 3000,
        "docsIf31CmUsOfdmaChanChannelId": 9,
    })

    entry = await DocsPnmCmUsPreEqEntry.from_snmp(idx, fake)  # type: ignore[arg-type]
    assert entry.index == idx
    assert entry.channel_id == 9

    fields: DocsPnmCmUsPreEqFields = entry.entry
    assert fields.docsPnmCmUsPreEqFileEnable is True
    assert fields.docsPnmCmUsPreEqPreEqCoAdjStatus == "success"
    assert fields.docsPnmCmUsPreEqMeasStatus == "sample_ready"
    assert fields.docsPnmCmUsPreEqLastUpdateFileName == "pre_eq_last.bin"
    assert fields.docsPnmCmUsPreEqFileName == "pre_eq.bin"

    assert fields.docsPnmCmUsPreEqAmpRipplePkToPk == pytest.approx(12.345, abs=0.0)
    assert fields.docsPnmCmUsPreEqAmpRippleRms == pytest.approx(2.0, abs=0.0)
    assert fields.docsPnmCmUsPreEqAmpSlope == pytest.approx(0.5, abs=0.0)
    assert fields.docsPnmCmUsPreEqGrpDelayRipplePkToPk == pytest.approx(9.0, abs=0.0)
    assert fields.docsPnmCmUsPreEqGrpDelayRippleRms == pytest.approx(11.0, abs=0.0)
    assert fields.docsPnmCmUsPreEqAmpMean == pytest.approx(4.0, abs=0.0)
    assert fields.docsPnmCmUsPreEqGrpDelaySlope == pytest.approx(2.5, abs=0.0)
    assert fields.docsPnmCmUsPreEqGrpDelayMean == pytest.approx(3.0, abs=0.0)


@pytest.mark.asyncio
async def test_from_snmp_missing_required_fields_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Missing any required SNMP field should raise ValueError and skip the entry.
    """
    monkeypatch.setattr(Snmp_v2c, "get_result_value", staticmethod(lambda x: x))

    idx = 3
    fake = _FakeSnmp(idx, {
        "docsPnmCmUsPreEqFileEnable": 1,
        "docsPnmCmUsPreEqAmpRipplePkToPk": 1000,
        "docsPnmCmUsPreEqAmpRippleRms": 2000,
        # Missing docsPnmCmUsPreEqAmpSlope
        "docsPnmCmUsPreEqGrpDelayRipplePkToPk": 1000,
        "docsPnmCmUsPreEqGrpDelayRippleRms": 1000,
        "docsPnmCmUsPreEqPreEqCoAdjStatus": 1,
        "docsPnmCmUsPreEqMeasStatus": 2,
        "docsPnmCmUsPreEqLastUpdateFileName": "pre_eq_last.bin",
        "docsPnmCmUsPreEqFileName": "pre_eq.bin",
        "docsPnmCmUsPreEqAmpMean": 1000,
        "docsPnmCmUsPreEqGrpDelaySlope": 1000,
        "docsPnmCmUsPreEqGrpDelayMean": 1000,
    })

    with pytest.raises(ValueError) as exc:
        await DocsPnmCmUsPreEqEntry.from_snmp(idx, fake)  # type: ignore[arg-type]

    assert "docsPnmCmUsPreEqAmpSlope" in str(exc.value)
