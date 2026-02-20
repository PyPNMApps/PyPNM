# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest

from pypnm.api.routes.docs.pnm.spectrumAnalyzer.router import SpectrumAnalyzerRouter
from pypnm.api.routes.docs.pnm.spectrumAnalyzer.schemas import SpecAnCaptureParaFullBand
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.DocsIf31CmSystemCfgState import DocsIf31CmSystemCfgDiplexState
from pypnm.lib.types import FrequencyHz


class _FakeCableModem:
    def __init__(
        self,
        if31_state: object,
        fdd_state: object | None,
    ) -> None:
        self._if31_state = if31_state
        self._fdd_state = fdd_state

    async def getDocsIf31CmSystemCfgDiplexState(self) -> object:
        return self._if31_state

    async def getDocsFddCmFddSystemCfgState(self) -> object | None:
        return self._fdd_state


def test_full_band_direction_defaults_to_downstream() -> None:
    params = SpecAnCaptureParaFullBand()
    assert params.direction == "downstream"


def test_full_band_direction_accepts_upstream() -> None:
    params = SpecAnCaptureParaFullBand(direction="upstream")
    assert params.direction == "upstream"


def test_resolve_if31_band_returns_hz_edges() -> None:
    state = SimpleNamespace(
        docsIf31CmSystemCfgStateDiplexerCfgDsLowerBandEdge=258,
        docsIf31CmSystemCfgStateDiplexerCfgDsUpperBandEdge=1218,
    )

    band = SpectrumAnalyzerRouter._resolve_if31_band(
        cast(DocsIf31CmSystemCfgDiplexState, state),
    )

    assert band == (FrequencyHz(258_000_000), FrequencyHz(1_218_000_000))


@pytest.mark.asyncio
async def test_full_band_prefers_if31_band_when_valid() -> None:
    if31_state = SimpleNamespace(
        docsIf31CmSystemCfgStateDiplexerCfgDsLowerBandEdge=300,
        docsIf31CmSystemCfgStateDiplexerCfgDsUpperBandEdge=1200,
    )
    fdd_state = SimpleNamespace(
        docsFddCmFddSystemCfgStateDiplexerDsLowerBandEdgeCfg=684,
        docsFddCmFddSystemCfgStateDiplexerDsUpperBandEdgeCfg=1794,
    )
    cm = _FakeCableModem(if31_state=if31_state, fdd_state=fdd_state)

    band = await SpectrumAnalyzerRouter._resolve_full_band_capture_edges(
        cast(CableModem, cm),
    )

    assert band == (FrequencyHz(300_000_000), FrequencyHz(1_200_000_000))


@pytest.mark.asyncio
async def test_full_band_falls_back_to_fdd_when_if31_invalid() -> None:
    if31_state = SimpleNamespace(
        docsIf31CmSystemCfgStateDiplexerCfgDsLowerBandEdge=0,
        docsIf31CmSystemCfgStateDiplexerCfgDsUpperBandEdge=0,
    )
    fdd_state = SimpleNamespace(
        docsFddCmFddSystemCfgStateDiplexerDsLowerBandEdgeCfg=684,
        docsFddCmFddSystemCfgStateDiplexerDsUpperBandEdgeCfg=1794,
    )
    cm = _FakeCableModem(if31_state=if31_state, fdd_state=fdd_state)

    band = await SpectrumAnalyzerRouter._resolve_full_band_capture_edges(
        cast(CableModem, cm),
    )

    assert band == (FrequencyHz(684_000_000), FrequencyHz(1_794_000_000))


@pytest.mark.asyncio
async def test_full_band_returns_none_when_no_valid_band() -> None:
    if31_state = SimpleNamespace(
        docsIf31CmSystemCfgStateDiplexerCfgDsLowerBandEdge=None,
        docsIf31CmSystemCfgStateDiplexerCfgDsUpperBandEdge=None,
    )
    fdd_state = SimpleNamespace(
        docsFddCmFddSystemCfgStateDiplexerDsLowerBandEdgeCfg=0,
        docsFddCmFddSystemCfgStateDiplexerDsUpperBandEdgeCfg=0,
    )
    cm = _FakeCableModem(if31_state=if31_state, fdd_state=fdd_state)

    band = await SpectrumAnalyzerRouter._resolve_full_band_capture_edges(
        cast(CableModem, cm),
    )

    assert band is None
