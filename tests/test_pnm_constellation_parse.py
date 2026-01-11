# tests/test_pnm_constellation_parse.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia


from __future__ import annotations

import math
from pathlib import Path

import pytest

from pypnm.pnm.parser.CmDsConstDispMeas import CmDsConstDispMeas

DATA_DIR = Path(__file__).parent / "files"
CONST_PATH = DATA_DIR / "const_display.bin"
NON_CONST_PATH = DATA_DIR / "fec_summary.bin"  # negative test sample


@pytest.fixture(scope="session")
def const_bytes() -> bytes:
    return CONST_PATH.read_bytes()


@pytest.mark.pnm
def test_constellation_file_parses_and_model_shape(const_bytes: bytes) -> None:
    cm = CmDsConstDispMeas(const_bytes)
    m = cm.to_model()

    # basic header presence
    assert m.pnm_header is not None
    # required top-level fields
    assert isinstance(m.channel_id, int)
    assert isinstance(m.mac_address, str) and len(m.mac_address) >= 11  # "aa:bb:cc:dd:ee:ff"
    assert isinstance(m.subcarrier_zero_frequency, int)
    assert isinstance(m.subcarrier_spacing, int) and m.subcarrier_spacing > 0

    # model semantics
    assert m.sample_units == "[Real(I), Imaginary(Q)]"
    assert isinstance(m.actual_modulation_order, int) and m.actual_modulation_order >= 0
    assert isinstance(m.num_sample_symbols, int) and m.num_sample_symbols >= 0
    assert isinstance(m.sample_length, int) and m.sample_length >= 0

    # samples shape: list of [I, Q] float pairs
    assert isinstance(m.samples, list)
    assert all(isinstance(pair, (list, tuple)) and len(pair) == 2 for pair in m.samples)
    assert all(all(isinstance(v, (int, float)) and math.isfinite(v) for v in pair) for pair in m.samples)


    # length consistency: payload bytes / 4 => number of complex pairs
    assert len(m.samples) == m.sample_length // 4


@pytest.mark.pnm
def test_constellation_samples_decoded_nonempty_and_reasonable_range() -> None:
    cm = CmDsConstDispMeas(CONST_PATH.read_bytes())
    m = cm.to_model()

    # Must have some content
    assert len(m.samples) > 0

    # Values should be small (fixed-point 2.13 typical ranges); don't over-constrain:
    # just ensure not absurd. (Avoid strict bounds—device-dependent.)
    flat = [v for pair in m.samples for v in pair]
    assert all(math.isfinite(v) for v in flat)
    # Very loose sanity: within a few standard units
    assert all(-10.0 <= v <= 10.0 for v in flat)


@pytest.mark.pnm
def test_constellation_serialization_roundtrip() -> None:
    cm = CmDsConstDispMeas(CONST_PATH.read_bytes())

    d = cm.to_dict()
    j = cm.to_json()

    # Ensure core keys exist and JSON serializes without error
    for key in ("pnm_header", "channel_id", "mac_address", "samples", "sample_length"):
        assert key in d

    import json
    parsed = json.loads(j)
    assert set(parsed.keys()) == set(d.keys())


@pytest.mark.pnm
def test_non_constellation_file_is_rejected() -> None:
    with pytest.raises(ValueError):
        _ = CmDsConstDispMeas(NON_CONST_PATH.read_bytes())
