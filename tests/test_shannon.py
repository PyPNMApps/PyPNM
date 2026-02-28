# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

# tests/test_shannon.py
from __future__ import annotations

import math

import numpy as np
import pytest

from pypnm.lib.signal_processing.shan.shannon import Shannon
from pypnm.pnm.parser.CmDsOfdmModulationProfile import ModulationOrderType


def test_snr_to_bits_examples() -> None:
    assert Shannon._snr_to_bits(0.0) == 1
    assert Shannon._snr_to_bits(3.0) == 1
    assert Shannon._snr_to_bits(10.0) == 3
    assert Shannon._snr_to_bits(30.0) == 9


def test_bits_to_snr_and_inverse_relations() -> None:
    expected_db = 10.0 * math.log10((2**8) - 1)
    assert Shannon.bits_to_snr(8) == pytest.approx(expected_db, rel=1e-12)
    with pytest.raises(ValueError):
        Shannon.bits_to_snr(0)


def test_bits_from_symbol_count() -> None:
    assert Shannon.bits_from_symbol_count(1) == 0
    assert Shannon.bits_from_symbol_count(2) == 1
    assert Shannon.bits_from_symbol_count(256) == 8
    with pytest.raises(ValueError):
        Shannon.bits_from_symbol_count(0)


def test_from_modulation_and_getters() -> None:
    sh = Shannon.from_modulation("qam_256")
    target_bits = 8
    # Allow one-bit drop due to FP rounding of 10*log10(2**bits - 1)
    assert sh.bits in (target_bits, target_bits - 1)
    # SNR should match theoretical for target_bits
    assert sh.get_snr_db() == pytest.approx(Shannon.bits_to_snr(target_bits), rel=1e-12)


def test_from_modulation_type_enum() -> None:
    sh = Shannon.from_modulation_type(ModulationOrderType.qam_256)
    target_bits = 8
    assert sh.bits in (target_bits, target_bits - 1)
    assert sh.get_snr_db() == pytest.approx(Shannon.bits_to_snr(target_bits), rel=1e-12)


def test_snr_from_modulation_matches_bits_to_snr() -> None:
    by_name = Shannon.snr_from_modulation("qam_256")
    by_bits = Shannon.bits_to_snr(8)
    assert by_name == pytest.approx(by_bits, rel=1e-12)
    with pytest.raises(ValueError):
        Shannon.snr_from_modulation("qam_999")


def test_snr_to_limit_vectorized_and_scalar() -> None:
    snrs = [0.0, 3.0, 10.0, 30.0]
    expected = [Shannon._snr_to_bits(s) for s in snrs]
    assert Shannon.snr_to_limit(snrs) == expected
    arr = np.array(snrs, dtype=float)
    assert Shannon.snr_to_limit(arr) == expected
    assert Shannon.snr_to_limit(10.0) == [Shannon._snr_to_bits(10.0)]


def test_snr_to_snr_limit_roundtrip() -> None:
    snrs = [0.0, 10.0, 24.0, 30.0]
    bits_limits = Shannon.snr_to_limit(snrs)
    expected_db_limits = [Shannon.bits_to_snr(b) for b in bits_limits]
    got = Shannon.snr_to_snr_limit(snrs)
    assert len(got) == len(expected_db_limits)
    for g, e in zip(got, expected_db_limits, strict=False):
        assert g == pytest.approx(e, rel=1e-12)
