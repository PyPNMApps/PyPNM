# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pypnm.api.routes.advance.multi_us_ofdma_pre_eq.router import MultiUsOfdmaPreEqRouter
from pypnm.api.routes.common.extended.common_measure_schema import UpstreamOfdmaParameters
from pypnm.lib.types import ChannelId


def test_multi_us_ofdma_preeq_router_resolves_channel_ids() -> None:
    router = MultiUsOfdmaPreEqRouter()
    assert router._resolve_interface_parameters(None) is None
    assert router._resolve_interface_parameters([]) is None

    params = router._resolve_interface_parameters([ChannelId(4)])
    assert isinstance(params, UpstreamOfdmaParameters)
    assert params.channel_id == [ChannelId(4)]
