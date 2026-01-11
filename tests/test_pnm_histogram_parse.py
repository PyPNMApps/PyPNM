# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia


from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from pypnm.pnm.parser.CmDsHist import CmDsHist

DATA_DIR = Path(__file__).parent / "files"
HIST_PATH = DATA_DIR / "histogram.bin"
NON_HIST_PATH = DATA_DIR / "rxmer.bin"  # valid PNM but wrong type -> negative test

MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


@pytest.fixture(scope="session")
def hist_bytes() -> bytes:
    return HIST_PATH.read_bytes()


@pytest.mark.pnm
def test_hist_parses_and_model_shape(hist_bytes: bytes) -> None:
    m = CmDsHist(hist_bytes).to_model()

    # Header present
    assert m.pnm_header is not None

    # MAC format from parser is hex with colons
    assert isinstance(m.mac_address, str) and MAC_RE.match(m.mac_address)

    # Symmetry is a single byte -> int
    assert isinstance(m.symmetry, int)
    assert m.symmetry >= 0  # don’t assume meaning, just non-negative

    # Length fields are consistent with arrays
    assert m.dwell_count_values_length == len(m.dwell_count_values) * 4
    assert m.hit_count_values_length == len(m.hit_count_values) * 4

    # Non-empty arrays expected for a real capture
    assert len(m.dwell_count_values) > 0
    assert len(m.hit_count_values) > 0

    # Values are non-negative integers (stored as 32-bit big-endian)
    assert all(isinstance(v, (int, float)) and v >= 0 for v in m.dwell_count_values)
    assert all(isinstance(v, (int, float)) and v >= 0 for v in m.hit_count_values)


@pytest.mark.pnm
def test_hist_serialization_roundtrip(hist_bytes: bytes) -> None:
    h = CmDsHist(hist_bytes)
    d = h.to_dict()
    j = h.to_json()

    parsed = json.loads(j)
    # Top-level keys should match
    assert set(parsed.keys()) == set(d.keys())

    # Spot-check nested keys exist
    for k in (
        "pnm_header",
        "mac_address",
        "symmetry",
        "dwell_count_values_length",
        "dwell_count_values",
        "hit_count_values_length",
        "hit_count_values",
    ):
        assert k in d and k in parsed


@pytest.mark.pnm
def test_non_hist_file_rejected() -> None:
    with pytest.raises(ValueError):
        _ = CmDsHist(NON_HIST_PATH.read_bytes())
