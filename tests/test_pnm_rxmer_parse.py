# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pypnm.pnm.parser.CmDsOfdmRxMer import CmDsOfdmRxMer

DATA_DIR = Path(__file__).parent / "files"
RXMER_PATH = DATA_DIR / "rxmer.bin"
NON_RXMER_PATH = DATA_DIR / "fec_summary.bin"  # negative test sample


@pytest.fixture(scope="session")
def rxmer_bytes() -> bytes:
    return RXMER_PATH.read_bytes()


@pytest.mark.pnm
def test_rxmer_file_loads_and_models_ok(rxmer_bytes: bytes) -> None:
    rx = CmDsOfdmRxMer(rxmer_bytes).to_model()

    # basic shape
    assert rx.data_length == len(rx.values)
    assert rx.value_units == "dB"
    assert rx.occupied_channel_bandwidth == rx.data_length * rx.subcarrier_spacing

    # stats: Pydantic -> dict for key checks
    stats = rx.signal_statistics.model_dump()
    assert "mean" in stats
    mean = stats["mean"]

    # Some implementations expose min/max directly; others via quantiles; fall back to computed.
    if "min" in stats and "max" in stats:
        smin, smax = stats["min"], stats["max"]
    elif "quantiles" in stats and isinstance(stats["quantiles"], dict):
        q = stats["quantiles"]
        # try common keys, else fallback to computed
        smin = q.get("min", min(rx.values))
        smax = q.get("max", max(rx.values))
    else:
        smin, smax = min(rx.values), max(rx.values)

    assert smin <= mean <= smax

    # modulation stats is already a dict
    mod = rx.modulation_statistics
    assert isinstance(mod, dict) and mod


@pytest.mark.pnm
def test_rxmer_values_in_range_and_cached() -> None:
    raw = RXMER_PATH.read_bytes()
    rxmer = CmDsOfdmRxMer(raw)

    vals1 = rxmer.get_rxmer_values()
    # Quarter-dB decoded and clamped [0.0, 63.5]
    assert all((0.0 <= v <= 63.5) for v in vals1)

    # Cached behavior: second call returns identical content
    vals2 = rxmer.get_rxmer_values()
    assert vals1 is vals2 or vals1 == vals2  # either same object or same content


@pytest.mark.pnm
def test_rxmer_frequencies_monotonic_and_sized() -> None:
    raw = RXMER_PATH.read_bytes()
    rxmer = CmDsOfdmRxMer(raw)
    model = rxmer.to_model()

    freqs = rxmer.get_frequencies()
    assert len(freqs) == model.data_length

    # Monotonic ascending with step == subcarrier spacing
    if len(freqs) >= 2:
        step = freqs[1] - freqs[0]
        assert step == model.subcarrier_spacing
        assert all(freqs[i] < freqs[i + 1] for i in range(len(freqs) - 1))


@pytest.mark.pnm
def test_rxmer_serialization_roundtrip() -> None:
    raw = RXMER_PATH.read_bytes()
    rxmer = CmDsOfdmRxMer(raw)

    d = rxmer.to_dict()
    j = rxmer.to_json()

    # JSON should be valid and represent same keys as dict (at least top-level)
    parsed = json.loads(j)
    assert set(parsed.keys()) == set(d.keys())


@pytest.mark.pnm
def test_non_rxmer_file_rejected() -> None:
    raw = NON_RXMER_PATH.read_bytes()
    with pytest.raises(ValueError):
        _ = CmDsOfdmRxMer(raw)
