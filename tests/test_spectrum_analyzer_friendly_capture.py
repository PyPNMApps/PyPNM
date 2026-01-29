# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import pytest

from pypnm.api.routes.docs.pnm.spectrumAnalyzer.schemas import (
    SpecAnCaptureParaFriendly,
)
from pypnm.api.routes.docs.pnm.spectrumAnalyzer.service import (
    SpectrumAnalyzerFriendlyCaptureBuilder,
)
from pypnm.lib.types import FrequencyHz, ResolutionBw


def test_friendly_capture_builder_matches_helper_tool_example() -> None:
    friendly = SpecAnCaptureParaFriendly(
        inactivity_timeout=60,
        first_segment_center_freq=FrequencyHz(300_000_000),
        last_segment_center_freq=FrequencyHz(900_000_000),
        resolution_bw=ResolutionBw(30_000),
        noise_bw=150,
        window_function=1,
        num_averages=1,
        spectrum_retrieval_type=1,
    )

    capture = SpectrumAnalyzerFriendlyCaptureBuilder.build(friendly)

    assert capture.segment_freq_span == FrequencyHz(3_000_000)
    assert capture.num_bins_per_segment == 100
    assert capture.first_segment_center_freq == FrequencyHz(301_500_000)
    assert capture.last_segment_center_freq == FrequencyHz(898_500_000)


def test_friendly_capture_builder_rejects_invalid_range() -> None:
    friendly = SpecAnCaptureParaFriendly(
        inactivity_timeout=60,
        first_segment_center_freq=FrequencyHz(900_000_000),
        last_segment_center_freq=FrequencyHz(300_000_000),
        resolution_bw=ResolutionBw(30_000),
        noise_bw=150,
        window_function=1,
        num_averages=1,
        spectrum_retrieval_type=1,
    )

    with pytest.raises(ValueError, match="last_segment_center_freq"):
        SpectrumAnalyzerFriendlyCaptureBuilder.build(friendly)
