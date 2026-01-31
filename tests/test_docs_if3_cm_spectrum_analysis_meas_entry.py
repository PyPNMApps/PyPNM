# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import pytest

from pypnm.docsis.data_type.DocsIf3CmSpectrumAnalysisMeasEntry import (
    DocsIf3CmSpectrumAnalysisMeasEntry,
)
from pypnm.snmp.snmp_v2c import Snmp_v2c


class _FakeSnmp:
    def __init__(self, idx: int, table: dict[str, object]) -> None:
        self._idx = idx
        self._table = table

    async def get(self, oid: str) -> object:
        sym, _, sfx = oid.rpartition(".")
        assert int(sfx) == self._idx
        return self._table[sym]


@pytest.mark.asyncio
async def test_from_snmp_scales_total_segment_power(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Snmp_v2c, "get_result_value", staticmethod(lambda x: x))
    monkeypatch.setattr(Snmp_v2c, "snmp_get_result_bytes", staticmethod(lambda x: x))

    idx = 3
    fake = _FakeSnmp(idx, {
        "docsIf3CmSpectrumAnalysisMeasFrequency": ["1000"],
        "docsIf3CmSpectrumAnalysisMeasAmplitudeData": [b"\x01\x02"],
        "docsIf3CmSpectrumAnalysisMeasTotalSegmentPower": ["35"],
    })

    entry = await DocsIf3CmSpectrumAnalysisMeasEntry.from_snmp(idx, fake)  # type: ignore[arg-type]

    assert entry.index == idx
    assert entry.entry.docsIf3CmSpectrumAnalysisMeasFrequency == 1000
    assert entry.entry.docsIf3CmSpectrumAnalysisMeasAmplitudeData == b"\x01\x02"
    assert entry.entry.docsIf3CmSpectrumAnalysisMeasTotalSegmentPower == pytest.approx(3.5, abs=1e-12)


@pytest.mark.asyncio
async def test_from_snmp_missing_fields_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Snmp_v2c, "get_result_value", staticmethod(lambda x: x))
    monkeypatch.setattr(Snmp_v2c, "snmp_get_result_bytes", staticmethod(lambda x: x))

    idx = 1
    fake = _FakeSnmp(idx, {
        "docsIf3CmSpectrumAnalysisMeasFrequency": ["1000"],
        "docsIf3CmSpectrumAnalysisMeasAmplitudeData": [b"\x01"],
        # Missing total segment power
    })

    with pytest.raises(ValueError) as exc:
        await DocsIf3CmSpectrumAnalysisMeasEntry.from_snmp(idx, fake)  # type: ignore[arg-type]

    assert "total_segment_power" in str(exc.value)
