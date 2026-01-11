# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typing_extensions import assert_type

from pypnm.lib.types import ComplexArray, ComplexSeries
from pypnm.pnm.parser.CmDsOfdmChanEstimateCoef import CmDsOfdmChanEstimateCoef

DATA_DIR = Path(__file__).parent / "files"
CE_PATH = DATA_DIR / "channel_estimation.bin"
NON_CE_PATH = DATA_DIR / "rxmer.bin"  # negative test: valid PNM but wrong type

MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")


def _is_pair_seq(x: object) -> bool:
    """Return True for [re, im] where both are number-like."""
    return (
        isinstance(x, (list, tuple))
        and len(x) == 2
        and all(isinstance(v, (int, float)) for v in x)
    )


@pytest.fixture(scope="session")
def ce_bytes() -> bytes:
    return CE_PATH.read_bytes()


@pytest.mark.pnm
def test_ce_parses_and_model_shape(ce_bytes: bytes) -> None:
    ce_model = CmDsOfdmChanEstimateCoef(ce_bytes).to_model()

    # Basic header fields
    assert isinstance(ce_model.channel_id, int)
    assert MAC_RE.match(ce_model.mac_address)

    # Subcarrier metadata sane
    assert (
        isinstance(ce_model.subcarrier_spacing, int) and ce_model.subcarrier_spacing > 0
    )
    assert isinstance(ce_model.first_active_subcarrier_index, int)
    assert ce_model.first_active_subcarrier_index >= 0

    # Data length is raw bytes; must be multiple of 4 (2B real + 2B imag per complex)
    assert ce_model.data_length % 4 == 0

    # Number of complex points = data_length / 4
    num_points = ce_model.data_length // 4
    assert isinstance(ce_model.values, list) and len(ce_model.values) == num_points
    assert all(_is_pair_seq(p) for p in ce_model.values)

    # Units
    assert ce_model.value_units == "complex"

    # OBW equals (#points) * spacing
    assert (
        ce_model.occupied_channel_bandwidth == num_points * ce_model.subcarrier_spacing
    )


@pytest.mark.pnm
def test_ce_coeff_rounding_and_raw_access(ce_bytes: bytes) -> None:
    parser = CmDsOfdmChanEstimateCoef(ce_bytes)

    # Rounded → ComplexArray: list[[re, im], ...]
    rounded = parser.get_coefficients("rounded")
    assert isinstance(rounded, list)
    assert all(_is_pair_seq(v) for v in rounded)

    # Raw → ComplexSeries: list[complex]
    raw = parser.get_coefficients("raw")
    assert isinstance(raw, list)
    assert all(isinstance(v, complex) for v in raw)

    # Same length views
    assert len(raw) == len(rounded)

    # ---- Static typing assertions (validate overloads) ----
    assert_type(
        parser.get_coefficients("rounded"), ComplexArray
    )  # Literal["rounded"] → ComplexArray
    assert_type(
        parser.get_coefficients("raw"), ComplexSeries
    )  # Literal["raw"] → ComplexSeries
    assert_type(parser.get_coefficients(), ComplexArray)  # default → ComplexArray


@pytest.mark.pnm
def test_ce_serialization_roundtrip(ce_bytes: bytes) -> None:
    parser = CmDsOfdmChanEstimateCoef(ce_bytes)

    d = parser.to_dict()
    j = parser.to_json()

    parsed = json.loads(j)
    # Top-level keys must match dict export
    assert set(parsed.keys()) == set(d.keys())


@pytest.mark.pnm
def test_non_ce_file_rejected() -> None:
    with pytest.raises(ValueError):
        _ = CmDsOfdmChanEstimateCoef(NON_CE_PATH.read_bytes())
