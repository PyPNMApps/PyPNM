# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import pytest

from pypnm.docsis.data_type.DocsIf31CmDsOfdmChanEntry import DocsIf31CmDsOfdmChanChannelEntry
from pypnm.lib.constants import DocsIf31CmDsOfdmChanIndicator
from pypnm.snmp.snmp_v2c import Snmp_v2c


class _FakeSnmp:
    def __init__(self, values: dict[str, str]) -> None:
        self._values = values

    async def get(self, oid: str) -> tuple[str, str]:
        return (oid, self._values.get(oid, ""))


@pytest.mark.asyncio
async def test_docs_if31_cm_ds_ofdm_chan_indicator_maps_nonprimary(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {
        "docsIf31CmDsOfdmChanChanIndicator.1": "4",
        "docsIf31CmDsOfdmChanChannelId.1": "1",
        "docsIf31CmDsOfdmChanSubcarrierSpacing.1": "25",
    }

    fake = _FakeSnmp(values)
    monkeypatch.setattr(Snmp_v2c, "get_result_value", lambda res: res[1])

    result = await DocsIf31CmDsOfdmChanChannelEntry.from_snmp(1, fake)
    assert result.entry.docsIf31CmDsOfdmChanChanIndicator == DocsIf31CmDsOfdmChanIndicator.NON_PRIMARY
