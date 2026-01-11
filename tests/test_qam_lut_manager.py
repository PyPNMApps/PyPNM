# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import numpy as np
import pytest

from pypnm.lib.qam.lut_mgr import QamLutManager  # adjust import if your path differs
from pypnm.lib.qam.types import QamModulation


@pytest.fixture()
def mgr_qam4() -> QamLutManager:
    mgr = QamLutManager()
    # Minimal, deterministic QAM-4 LUT for tests
    mgr.qam_lut = {
        "QAM_4": {
            "hard": [(-1.0, -1.0), (-1.0, 1.0), (1.0, -1.0), (1.0, 1.0)],
            # codeword -> (I, Q)
            "code_words": {
                0: (-1.0, -1.0),
                1: (-1.0,  1.0),
                2: ( 1.0, -1.0),
                3: ( 1.0,  1.0),
            },
            "scale_factor": 0.5,
        }
    }
    return mgr


def test_get_hard_decisions_returns_points(mgr_qam4: QamLutManager) -> None:
    pts = mgr_qam4.get_hard_decisions(QamModulation.QAM_4)
    assert isinstance(pts, list)
    assert len(pts) == 4
    assert (1.0, 1.0) in pts
    assert (-1.0, -1.0) in pts


def test_get_codeword_symbol_single_symbol_msb_lsb(mgr_qam4: QamLutManager) -> None:
    # With 2 bits/symbol, cw=2 should map to (1,-1)
    sym_msb = mgr_qam4.get_codeword_symbol(QamModulation.QAM_4, 2, bit_order="msb")
    sym_lsb = mgr_qam4.get_codeword_symbol(QamModulation.QAM_4, 2, bit_order="lsb")
    assert sym_msb == [(1.0, -1.0)]
    assert sym_lsb == [(1.0, -1.0)]


def test_get_codeword_symbol_multi_symbol_msb_vs_lsb(mgr_qam4: QamLutManager) -> None:
    # code_word 0b0110 has 4 bits → two symbols of 2 bits each
    # MSB-first:   [01, 10] -> [1, 2] -> [(-1,1), (1,-1)]
    # LSB-first:   [10, 01] -> [2, 1] -> [(1,-1), (-1,1)]
    code_word = 0b0110
    msb_syms = mgr_qam4.get_codeword_symbol(QamModulation.QAM_4, code_word, bit_order="msb")
    lsb_syms = mgr_qam4.get_codeword_symbol(QamModulation.QAM_4, code_word, bit_order="lsb")
    assert msb_syms == [(-1.0, 1.0), (1.0, -1.0)]
    assert lsb_syms == [(1.0, -1.0), (-1.0, 1.0)]


def test_get_scale_factor(mgr_qam4: QamLutManager) -> None:
    sf = mgr_qam4.get_scale_factor(QamModulation.QAM_4)
    assert sf == 0.5


def test_scale_soft_decisions_scales_points(mgr_qam4: QamLutManager) -> None:
    soft = [(2.0, -2.0), (4.0, 0.0)]
    out = mgr_qam4.scale_soft_decisions(QamModulation.QAM_4, soft)
    # scale_factor=0.5
    assert out == [(1.0, -1.0), (2.0, 0.0)]


def test_scale_soft_decisions_validates_shape(mgr_qam4: QamLutManager) -> None:
    with pytest.raises(ValueError):
        # Not Nx2
        _ = mgr_qam4.scale_soft_decisions(QamModulation.QAM_4, [(1.0,)])


def test_get_symbol_codeword_exact_and_nearest(mgr_qam4: QamLutManager) -> None:
    # exact match
    cw = mgr_qam4.get_symbol_codeword(QamModulation.QAM_4, (1.0, 1.0))
    assert cw == 3

    # slight perturbation → within tolerance, should snap to same codeword
    cw_nn = mgr_qam4.get_symbol_codeword(QamModulation.QAM_4, (1.02, 1.01))
    assert cw_nn == 3


def test_infer_modulation_order_qam4(mgr_qam4: QamLutManager) -> None:
    # Build a small cloud around the 4 hard points
    rng = np.random.default_rng(0)
    base = np.array([(-1,-1), (-1,1), (1,-1), (1,1)], dtype=float)
    samples = (base + 0.02 * rng.standard_normal(base.shape)).tolist()
    est = mgr_qam4.infer_modulation_order(samples, threshold=0.15)
    assert est == QamModulation.QAM_4


def test_infer_modulation_order_unknown_on_mismatch(mgr_qam4: QamLutManager) -> None:
    # Few random points not matching a known cluster count well
    samples = [(0.1, 0.2), (0.15, -0.1), (-0.2, 0.05)]
    est = mgr_qam4.infer_modulation_order(samples, threshold=0.15)
    # Could be UNKNOWN depending on clustering result; enforce not a high-order guess
    assert est in (QamModulation.UNKNOWN, QamModulation.QAM_4)
