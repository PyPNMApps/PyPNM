# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

# tests/test_shannon_series.py
from __future__ import annotations

import json
import math

import pytest

from pypnm.lib.signal_processing.shan.series import ShannonSeries
from pypnm.lib.signal_processing.shan.shannon import Shannon


def test_invalid_inputs_raise() -> None:
    with pytest.raises(ValueError):
        ShannonSeries([-1.0])
    with pytest.raises(ValueError):
        ShannonSeries([float("nan")])
    with pytest.raises(ValueError):
        ShannonSeries([float("inf")])


def test_basic_series_outputs() -> None:
    snrs = [0.0, 3.0, 10.0, 30.0]
    series = ShannonSeries(snrs)

    # lengths
    assert len(series.snr_db_values) == len(snrs)
    assert len(series.bits_list) == len(snrs)
    assert len(series.modulations) == len(snrs)
    assert len(series.limit()) == len(snrs)

    # per-element expectations via Shannon
    exp_bits = [Shannon(s).bits for s in snrs]
    exp_mods = [Shannon(s).get_modulation() for s in snrs]
    assert series.bits_list == exp_bits
    assert series.modulations == exp_mods

    # average bits within bounds
    avg = series.average_bits()
    assert isinstance(avg, float)
    assert min(exp_bits) <= avg <= max(exp_bits)

    # max modulation matches the highest bits entry
    assert series.max_modulation() == exp_mods[exp_bits.index(max(exp_bits))]


def test_supported_modulation_counts_and_model() -> None:
    snrs = [0.0, 6.0, 12.0, 18.0, 24.0, 30.0]
    series = ShannonSeries(snrs)

    # counts should include all known modulations from Shannon.QAM_MODULATIONS
    known_mods = set(Shannon.QAM_MODULATIONS.values())
    counts = series.supported_modulation_counts()
    assert set(counts.keys()) == known_mods

    # monotonic: higher-order modulations cannot have higher counts than lower-order ones
    # build a list sorted by bits (ascending)
    bits_sorted = sorted(Shannon.QAM_MODULATIONS.items(), key=lambda kv: kv[0])
    prev = math.inf
    for _bits, name in bits_sorted:
        c = counts[name]
        assert isinstance(c, int) and 0 <= c <= len(snrs)
        assert c <= prev
        prev = c

    # model / dict / json shapes
    model = series.to_model()
    d = series.to_dict()
    j = series.to_json()
    j_obj = json.loads(j)

    assert model.bits_per_symbol == series.bits_list
    assert model.modulations == series.modulations
    assert model.snr_db_values == series.snr_db_values
    assert set(model.supported_modulation_counts.keys()) == known_mods
    assert d["bits_per_symbol"] == series.bits_list
    assert set(d["supported_modulation_counts"].keys()) == known_mods
    assert j_obj.get("avg", True)  # tolerate additional fields if present


def test_repr_and_str() -> None:
    snrs = [0.0, 10.0]
    series = ShannonSeries(snrs)
    r = repr(series)
    s = str(series)
    assert "ShannonSeries" in r
    assert "SNR values" in s
