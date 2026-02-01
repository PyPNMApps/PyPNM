# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import pytest

from pypnm.docsis.data_type.DocsIfDownstreamChannel import DocsIfDownstreamChannelEntry
from pypnm.snmp.snmp_v2c import Snmp_v2c


class _FakeSnmp:
    def __init__(self, values: dict[str, str]) -> None:
        self._values = values

    async def get(self, oid: str) -> tuple[str, str]:
        return (oid, self._values.get(oid, ""))


@pytest.mark.asyncio
async def test_docs_if3_signal_quality_ext_rxmer_scales_tenthdB(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {
        "docsIf3SignalQualityExtRxMER.1": "386",
        "docsIfDownChannelId.1": "1",
    }

    fake = _FakeSnmp(values)
    monkeypatch.setattr(Snmp_v2c, "get_result_value", lambda res: res[1])

    result = await DocsIfDownstreamChannelEntry.from_snmp(1, fake)
    assert result.entry.docsIf3SignalQualityExtRxMER == 38.6
