# test_echo_detector.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import numpy as np
import pytest

# Import your detector from its project path
from pypnm.api.routes.advance.analysis.signal_analysis.detection.echo.echo_detector import (
    EchoDetector,
)
from pypnm.lib.types import ChannelId

# Fixed PHY/Test parameters
DF_HZ = 50_000.0               # subcarrier spacing (Hz)
NFFT = 4096                    # IFFT length
FS = NFFT * DF_HZ              # sample rate (Hz) = 204.8 MHz
VF = 0.87                      # RG6 default
C0 = 299_792_458.0             # m/s
V = C0 * VF                    # propagation speed in the cable
FEET_PER_METER = 3.280839895013123


def _bins_for_distance_ft(distance_ft: float, fs: float = FS, v: float = V) -> int:
    """
    Convert a one-way distance (ft) to the echo bin index after the direct path
    using round-trip time t = 2d / v and bin = t * fs.
    """
    d_m = distance_ft / FEET_PER_METER
    t = (2.0 * d_m) / v
    return int(round(t * fs))


def _make_freq_response_from_impulses(pulses: list[tuple[int, float]], nfft: int = NFFT) -> np.ndarray:
    """
    Build H(f) by FFT of h[n] with time-domain impulses:
    pulses = [(bin_index, amplitude), ...]
    """
    h = np.zeros(nfft, dtype=np.complex128)
    for idx, amp in pulses:
        h[idx % nfft] += complex(float(amp), 0.0)
    H = np.fft.fft(h, n=nfft)
    return H.astype(np.complex128)


def test_direct_plus_known_echo_bin_and_distance() -> None:
    """
    Create a direct path at bin 0 and a single echo at ~20 ft.
    Validate that the detector finds the echo near the expected bin and that
    echo distances increase (monotonic) relative to the direct path.
    """
    distance_ft = 20.0
    echo_bin = _bins_for_distance_ft(distance_ft)
    # A modest echo amplitude (linear)
    echo_amp = 0.25

    H = _make_freq_response_from_impulses([(0, 1.0), (echo_bin, echo_amp)], nfft=NFFT)
    det = EchoDetector(
        freq_data=H,
        subcarrier_spacing_hz=DF_HZ,
        n_fft=NFFT,
        cable_type="RG6",
        channel_id=ChannelId(197),
    )

    rep = det.multi_echo(
        threshold_mode="fractional",
        threshold_frac=0.05,            # 5% of direct amplitude
        guard_bins=0,                   # allow immediate search; detector also has 10-ft guard by default
        min_separation_s=8.0 / det.fs,  # ~8 bins
        max_delay_s=3.5e-6,
        max_peaks=3,
        include_time_response=False,
        direct_at_zero=True,
        window="hann",
        normalize_power=True,
        edge_guard_bins=8,
        # keep default min_detect_distance_ft=10.0
    )

    # Must have at least one echo
    assert len(rep.echoes) >= 1, "Expected at least one echo to be detected."

    first = rep.echoes[0]
    # Bin check: within ±1 bin of expected
    assert first.bin_index == pytest.approx(echo_bin, abs=1), (
        f"First echo bin {first.bin_index} not close to expected {echo_bin}"
    )

    # Time/Distance sanity: > 0
    assert first.time_s > 0.0
    assert first.distance_m > 0.0
    # Distance close to 20 ft (±1 ft tolerance)
    assert first.distance_ft == pytest.approx(distance_ft, abs=1.0)

    # If more echoes somehow cross threshold, ensure distances are non-decreasing
    dists = [e.distance_m for e in rep.echoes]
    assert dists == sorted(dists), "Echo distances should be non-decreasing."


def test_snapshot_average_with_guard_and_min_separation() -> None:
    """
    Two-snapshot average case:
      - A strong artifact at 2 bins (inside the 10-ft guard → should be ignored)
      - A valid echo beyond the guard (e.g., ~15 ft) that should be detected
    Also enforces min-separation (~8 bins).
    """
    # Near artifact within ~10 ft guard
    near_ft = 5.0
    near_bin = _bins_for_distance_ft(near_ft)

    # Valid echo beyond guard
    valid_ft = 15.0
    valid_bin = _bins_for_distance_ft(valid_ft)

    # Build two snapshots with slight amplitude variation
    H1 = _make_freq_response_from_impulses([(0, 1.0), (near_bin, 0.5), (valid_bin, 0.25)], nfft=NFFT)
    H2 = _make_freq_response_from_impulses([(0, 1.0), (near_bin, 0.45), (valid_bin, 0.3)], nfft=NFFT)
    H_snapshots = np.vstack([H1, H2])  # shape (2, NFFT), complex

    det = EchoDetector(
        freq_data=H_snapshots,          # (M, N) complex → averaged internally
        subcarrier_spacing_hz=DF_HZ,
        n_fft=NFFT,
        cable_type="RG6",
        channel_id=194,
    )

    rep = det.multi_echo(
        threshold_mode="fractional",
        threshold_frac=0.05,
        guard_bins=0,                    # leave explicit guard at 0; detector uses 10-ft min distance guard
        min_separation_s=8.0 / det.fs,   # ~8 bins
        max_delay_s=3.5e-6,
        max_peaks=3,
        include_time_response=False,
        direct_at_zero=True,
        window="hann",
        normalize_power=True,
        edge_guard_bins=8,
        # keep default min_detect_distance_ft=10.0
    )

    # We expect the near artifact to be rejected by min_detect_distance_ft (~5 bins)
    # and the valid echo beyond ~10 ft to be included.
    bins = [e.bin_index for e in rep.echoes]

    # Valid echo must be present (±1 bin)
    assert any(abs(b - valid_bin) <= 1 for b in bins), (
        f"Valid echo near bin {valid_bin} not detected; got bins {bins}"
    )

    # Near artifact must be absent
    assert all(abs(b - near_bin) > 1 for b in bins), (
        f"Near artifact within guard (bin {near_bin}) should have been rejected; got bins {bins}"
    )

    # Min separation: all selected bins spaced by ≥ ~8 bins
    bins_sorted = sorted(bins)
    for i in range(1, len(bins_sorted)):
        assert (bins_sorted[i] - bins_sorted[i - 1]) >= 8 - 1, "Echo picks violate min separation constraint"
