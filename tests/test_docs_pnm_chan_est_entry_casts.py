# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import pytest

from pypnm.docsis.cm_snmp_operation import MeasStatusType
from pypnm.docsis.data_type.pnm.DocsPnmCmOfdmChanEstCoefEntry import (
    DocsPnmCmOfdmChanEstCoefEntry,
    DocsPnmCmOfdmChanEstCoefFields,
)
from pypnm.snmp.snmp_v2c import Snmp_v2c


class _FakeSnmp:
    def __init__(self, idx: int, table: dict[str, object]) -> None:
        self._idx, self._t = idx, table

    async def get(self, oq: str):
        sym, _, sfx = oq.rpartition(".")
        assert int(sfx) == self._idx
        # return None if the OID isn't present (simulate missing field)
        return self._t.get(sym)


@pytest.mark.asyncio
async def test_chan_est_from_snmp_scaling_and_types(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Snmp_v2c, "get_result_value", staticmethod(lambda x: x))

    idx = 11
    fake = _FakeSnmp(idx, {
        "docsPnmCmOfdmChEstCoefTrigEnable": 1,               # -> True
        "docsPnmCmOfdmChEstCoefAmpRipplePkToPk": 3323,       # -> 33.23
        "docsPnmCmOfdmChEstCoefAmpRippleRms": 631,           # -> 6.31
        "docsPnmCmOfdmChEstCoefAmpSlope": 92,                # -> 0.92
        "docsPnmCmOfdmChEstCoefGrpDelayRipplePkToPk": 7,     # int
        "docsPnmCmOfdmChEstCoefGrpDelayRippleRms": 5,        # int
        "docsPnmCmOfdmChEstCoefMeasStatus": 4,               # -> "sample_ready"
        "docsPnmCmOfdmChEstCoefFileName": "chan_est.bin",
        "docsPnmCmOfdmChEstCoefAmpMean": 4288,               # -> 42.88
        "docsPnmCmOfdmChEstCoefGrpDelaySlope": 3,            # int
        "docsPnmCmOfdmChEstCoefGrpDelayMean": 12,            # int
    })

    e = await DocsPnmCmOfdmChanEstCoefEntry.from_snmp(idx, fake)  # type: ignore[arg-type]
    assert e.index == idx and e.channel_id == idx
    f: DocsPnmCmOfdmChanEstCoefFields = e.entry

    assert f.docsPnmCmOfdmChEstCoefTrigEnable is True
    assert f.docsPnmCmOfdmChEstCoefMeasStatus == str(MeasStatusType(4))  # "sample_ready"
    assert f.docsPnmCmOfdmChEstCoefFileName == "chan_est.bin"

    assert f.docsPnmCmOfdmChEstCoefAmpRipplePkToPk == pytest.approx(33.23, abs=0.0)
    assert f.docsPnmCmOfdmChEstCoefAmpRippleRms == pytest.approx(6.31, abs=0.0)
    assert f.docsPnmCmOfdmChEstCoefAmpSlope == pytest.approx(0.92, abs=0.0)
    assert f.docsPnmCmOfdmChEstCoefAmpMean == pytest.approx(42.88, abs=0.0)

    assert f.docsPnmCmOfdmChEstCoefGrpDelayRipplePkToPk == 7
    assert f.docsPnmCmOfdmChEstCoefGrpDelayRippleRms == 5
    assert f.docsPnmCmOfdmChEstCoefGrpDelaySlope == 3
    assert f.docsPnmCmOfdmChEstCoefGrpDelayMean == 12


@pytest.mark.asyncio
async def test_chan_est_missing_field_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Snmp_v2c, "get_result_value", staticmethod(lambda x: x))
    idx = 2
    fake = _FakeSnmp(idx, {
        "docsPnmCmOfdmChEstCoefTrigEnable": 1,
        "docsPnmCmOfdmChEstCoefAmpRipplePkToPk": 100,       # 1.00
        "docsPnmCmOfdmChEstCoefAmpRippleRms": 200,          # 2.00
        "docsPnmCmOfdmChEstCoefAmpSlope": 50,               # 0.50
        "docsPnmCmOfdmChEstCoefGrpDelayRipplePkToPk": 1,
        "docsPnmCmOfdmChEstCoefGrpDelayRippleRms": 1,
        "docsPnmCmOfdmChEstCoefMeasStatus": 3,
        "docsPnmCmOfdmChEstCoefFileName": "x.bin",
        # "docsPnmCmOfdmChEstCoefAmpMean": MISSING -> should raise
        "docsPnmCmOfdmChEstCoefGrpDelaySlope": 1,
        "docsPnmCmOfdmChEstCoefGrpDelayMean": 1,
    })
    with pytest.raises(ValueError):
        await DocsPnmCmOfdmChanEstCoefEntry.from_snmp(idx, fake)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_chan_est_get_empty_indices_returns_empty_list() -> None:
    out = await DocsPnmCmOfdmChanEstCoefEntry.get(snmp=None, indices=[])  # type: ignore[arg-type]
    assert out == []
