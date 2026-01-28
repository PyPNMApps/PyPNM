# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import pytest
from pydantic import ValidationError

from pypnm.api.routes.advance.analysis.signal_analysis.multi_ofdma_pre_eq_signal_analysis import (
    MultiOfdmaPreEqAnalysisType,
)
from pypnm.api.routes.advance.multi_us_ofdma_pre_eq.schemas import (
    MultiUsOfdmaPreEqAnalysisContainerModel,
)


def test_ofdma_pre_eq_analysis_type_values() -> None:
    values = {item.value for item in MultiOfdmaPreEqAnalysisType}
    assert values == {"min-avg-max", "group-delay", "echo-detection-ifft"}
    assert "lte-detection-phase-slope" not in values


def test_ofdma_pre_eq_analysis_schema_rejects_lte() -> None:
    with pytest.raises(ValidationError):
        MultiUsOfdmaPreEqAnalysisContainerModel(type="lte-detection-phase-slope")
