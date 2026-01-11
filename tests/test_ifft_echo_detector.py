# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import numpy as np
import pytest

from pypnm.api.routes.advance.analysis.signal_analysis.detection.echo.ifft import (
    IfftEchoDetector,
)
from pypnm.lib.constants import SPEED_OF_LIGHT as C0


@pytest.mark.pnm
def test_to_model_detects_single_echo_basic() -> None:
    # Build a simple time response: impulse at 0 and smaller echo at bin d
    N = 256
    d = 10                       # echo at 10 samples
    fs = 1_000_000.0             # 1 MHz sample rate -> 1 us per sample
    vf = 0.87                    # velocity factor for to_model() (used in detector ctor)

    h = np.zeros(N, dtype=np.complex128)
    h[0] = 1.0 + 0j
    h[d] = 0.4 + 0j

    H = np.fft.fft(h)            # detector expects frequency-domain data
    det = IfftEchoDetector(H, sample_rate=fs, prop_speed_frac=vf)

    m = det.to_model(threshold_frac=0.2, guard_bins=1, max_delay_s=None, n_fft=None)

    # Indices
    assert m.reflection.direct_index == 0
    assert m.reflection.echo_index == d

    # Delay and distance
    expected_delay = d / fs
    expected_dist_m = expected_delay * (C0 * vf) / 2.0
    assert m.reflection.reflection_delay_s == pytest.approx(expected_delay, rel=1e-6)
    assert m.reflection.reflection_distance_m == pytest.approx(expected_dist_m, rel=1e-6)

    # Amplitude ratio ~ 0.4
    assert m.reflection.amp_ratio == pytest.approx(0.4, rel=1e-3)

    # Model shape fields
    assert m.dataset_info.subcarriers == N
    assert m.dataset_info.snapshots == 1
    assert m.sample_rate_hz == fs
    assert m.prop_speed_mps == pytest.approx(C0 * vf, rel=1e-12)

    # Optional time block present by default
    assert m.time_response is not None
    assert m.time_response.n_fft == N
    assert len(m.time_response.time_axis_s) == N
    assert len(m.time_response.time_response) == N


@pytest.mark.pnm
def test_detect_multiple_reflections_with_spacing_and_padding() -> None:
    N = 512
    fs = 2_000_000.0
    vf = 0.82

    h = np.zeros(N, dtype=np.complex128)
    h[0] = 1.0
    h[15] = 0.6
    h[40] = 0.5
    H = np.fft.fft(h)

    det = IfftEchoDetector(H, sample_rate=fs, prop_speed_frac=vf)

    nfft = 1024
    rpt = det.detect_multiple_reflections(
        cable_type="RG59",
        velocity_factor=None,
        threshold_frac=0.2,
        guard_bins=1,
        min_separation_s=0.0,
        max_delay_s=None,
        max_peaks=5,
        n_fft=nfft,
        include_time_response=True,
    )

    scale = nfft // N  # 2
    expected_bins = [15 * scale, 40 * scale]
    assert [e.bin_index for e in rpt.echoes[:2]] == expected_bins

    # distance sanity remains the same
    dists = [e.distance_m for e in rpt.echoes]
    assert all(d > 0 for d in dists)
    assert dists[0] < dists[1]

    assert rpt.time_response is not None
    assert rpt.time_response.n_fft == nfft
    assert len(rpt.time_response.time_axis_s) == nfft
    assert len(rpt.time_response.time_response) == nfft


@pytest.mark.pnm
def test_accepts_real_imag_pair_inputs_shapes() -> None:
    N = 128
    fs = 500_000.0

    # Build simple time response and FFT to get H
    h = np.zeros(N, dtype=np.complex128)
    h[0] = 1.0
    h[8] = 0.25
    H = np.fft.fft(h)

    # (N,2) real/imag input (single snapshot)
    H_pairs = np.column_stack((H.real, H.imag))
    det_single = IfftEchoDetector(H_pairs, sample_rate=fs)
    m_single = det_single.to_model()
    assert m_single.dataset_info.snapshots == 1
    assert m_single.dataset_info.subcarriers == N

    # (M,N,2) real/imag input (two snapshots, identical)
    H_pairs2 = np.stack([H_pairs, H_pairs], axis=0)
    det_multi = IfftEchoDetector(H_pairs2, sample_rate=fs)
    m_multi = det_multi.to_model()
    assert m_multi.dataset_info.snapshots == 2
    assert m_multi.dataset_info.subcarriers == N


@pytest.mark.pnm
def test_compute_time_response_raises_when_nfft_too_small() -> None:
    N = 64
    fs = 1e6
    h = np.zeros(N, dtype=np.complex128)
    h[0] = 1.0
    H = np.fft.fft(h)

    det = IfftEchoDetector(H, sample_rate=fs)
    with pytest.raises(ValueError):
        det.compute_time_response(n_fft=N - 1)  # must be >= N


@pytest.mark.pnm
def test_no_echo_found_when_threshold_too_high() -> None:
    N = 128
    fs = 1e6
    h = np.zeros(N, dtype=np.complex128)
    h[0] = 1.0
    h[20] = 0.05  # small echo

    H = np.fft.fft(h)
    det = IfftEchoDetector(H, sample_rate=fs)

    # Threshold above 5% echo → expect failure
    with pytest.raises(RuntimeError):
        det.to_model(threshold_frac=0.2)  # 20% > 5%, so no echo should be found
