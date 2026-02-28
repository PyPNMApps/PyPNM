# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import numpy as np
import pytest

from pypnm.api.routes.common.classes.analysis.analysis import Analysis
from pypnm.lib.file_processor import FileProcessor
from pypnm.lib.signal_processing.butterworth import MagnitudeButterworthFilter
from pypnm.pnm.parser.CmUsOfdmaPreEq import CmUsOfdmaPreEq, CmUsOfdmaPreEqModel

DATA_DIR: Path = Path(__file__).parent / "files"
US_PREEQ_PATH: Path = DATA_DIR / "us_pre_equalizer_coef.bin"


def _load_us_preeq_model() -> CmUsOfdmaPreEqModel:
    raw_payload = FileProcessor(US_PREEQ_PATH).read_file()
    return CmUsOfdmaPreEq(raw_payload).to_model()


def _measurement_from_model(model: CmUsOfdmaPreEqModel) -> dict[str, Any]:
    return {
        "channel_id": model.channel_id,
        "subcarrier_spacing": model.subcarrier_spacing,
        "first_active_subcarrier_index": model.first_active_subcarrier_index,
        "subcarrier_zero_frequency": model.subcarrier_zero_frequency,
        "occupied_channel_bandwidth": model.occupied_channel_bandwidth,
        "values": model.values,
        "device_details": {},
        "pnm_header": model.pnm_header.model_dump() if hasattr(model.pnm_header, "model_dump") else model.pnm_header,
        "mac_address": model.mac_address,
    }


@pytest.mark.pnm
def test_us_ofdma_pre_eq_dict_and_model_paths_are_parity() -> None:
    assert US_PREEQ_PATH.is_file()
    model = _load_us_preeq_model()
    measurement = _measurement_from_model(model)

    from_dict = Analysis.basic_analysis_us_ofdma_pre_equalization(measurement)
    from_model = Analysis.basic_analysis_us_ofdma_pre_equalization_from_model(model)

    assert from_dict.carrier_values.carrier_count > 0
    assert from_model.carrier_values.carrier_count > 0
    assert from_dict.carrier_values.carrier_count == from_model.carrier_values.carrier_count

    assert len(from_dict.carrier_values.frequency) == len(from_model.carrier_values.frequency)
    assert len(from_dict.carrier_values.magnitudes) == len(from_model.carrier_values.magnitudes)

    assert np.allclose(
        np.asarray(from_dict.carrier_values.magnitudes, dtype=np.float64),
        np.asarray(from_model.carrier_values.magnitudes, dtype=np.float64),
        atol=1e-12,
    )


@pytest.mark.pnm
def test_us_ofdma_pre_eq_frequency_axis_start_and_spacing() -> None:
    assert US_PREEQ_PATH.is_file()
    model = _load_us_preeq_model()
    measurement = _measurement_from_model(model)

    result = Analysis.basic_analysis_us_ofdma_pre_equalization(measurement)
    freqs = result.carrier_values.frequency

    assert len(freqs) > 1
    expected_start = int(model.subcarrier_spacing) * int(model.first_active_subcarrier_index) + int(model.subcarrier_zero_frequency)

    assert int(freqs[0]) == expected_start
    assert int(freqs[1]) - int(freqs[0]) == int(model.subcarrier_spacing)


@pytest.mark.pnm
def test_us_ofdma_pre_eq_magnitude_floor_before_smoothing(monkeypatch: pytest.MonkeyPatch) -> None:
    assert US_PREEQ_PATH.is_file()
    model = _load_us_preeq_model()
    measurement = _measurement_from_model(model)

    captured: dict[str, np.ndarray] = {}
    original_apply = MagnitudeButterworthFilter.apply

    def _capture_apply(self: MagnitudeButterworthFilter, values: np.ndarray) -> SimpleNamespace:
        captured["input"] = np.asarray(values, dtype=np.float64).copy()
        return SimpleNamespace(filtered_values=np.asarray(values, dtype=np.float64))

    monkeypatch.setattr(MagnitudeButterworthFilter, "apply", _capture_apply)
    try:
        _ = Analysis.basic_analysis_us_ofdma_pre_equalization(measurement)
    finally:
        monkeypatch.setattr(MagnitudeButterworthFilter, "apply", original_apply)

    assert "input" in captured
    assert captured["input"].size > 0
    assert float(np.min(captured["input"])) >= -120.0
