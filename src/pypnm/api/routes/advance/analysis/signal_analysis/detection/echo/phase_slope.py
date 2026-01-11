# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import numpy as np


class PhaseSlopeEchoDetector:
    """
    Two-path echo detector via phase-slope estimation on per-subcarrier data.

    Supports input H in the following formats:
      - 1D array of complex channel estimates (length K)
      - 2D array of complex snapshots (M x K)
      - ND array of real/imag pairs (..., K, 2)
      - ND array of complex values (..., K)

    Methods:
      - estimate_delay() -> float: raw round-trip delay (s)
      - detect_echo()   -> dict: {'delay_rt_s', 'delay_s', 'distance_m'} with positive delays
      - dataset_info()  -> dict: {'subcarriers', 'snapshots'}
      - to_dict()       -> dict: comprehensive dump of inputs and outputs
    """

    # Speed of light in vacuum (m/s)
    c0 = 299_792_458

    def __init__(
        self,
        H: Sequence | np.ndarray,
        f: Sequence[float],
        prop_speed_frac: float = 0.87,
    ) -> None:
        """
        Initialize the PhaseSlopeEchoDetector.

        Parameters:
        -----------
        H : array-like
            Channel estimates. Supported shapes:
            - (K,) or (M, K) complex arrays
            - any shape ending in (K, 2) for real/imag pairs
        f : sequence of float
            Subcarrier frequencies in Hz (length K). Must match H's last dim.
        prop_speed_frac : float, optional
            Fraction of c0 for propagation speed. Default 0.87.
        """
        # Frequency vector
        self.f = np.asarray(f, dtype=float).flatten()
        if self.f.ndim != 1:
            raise ValueError("f must be a 1D sequence of frequencies.")
        K = self.f.size

        # Convert H to complex array
        H_arr = np.asarray(H)
        if H_arr.ndim >= 2 and H_arr.shape[-1] == 2 and not np.iscomplexobj(H_arr):
            H_complex = H_arr[..., 0] + 1j * H_arr[..., 1]
        else:
            H_complex = H_arr.astype(np.complex128)

        # Collapse leading dims into snapshots
        if H_complex.ndim == 1:
            if H_complex.size != K:
                raise ValueError(f"Length of H ({H_complex.size}) must match f ({K}).")
            H_snap = H_complex.reshape(1, K)
        elif H_complex.ndim == 2 and H_complex.shape[1] == K:
            H_snap = H_complex
        elif H_complex.ndim > 2 and H_complex.shape[-1] == K:
            H_snap = H_complex.reshape(-1, K)
        else:
            raise ValueError(
                f"Unsupported H dimensions {H_complex.shape}; last axis must be length {K}."
            )

        # Store raw snapshots and average
        self.H_raw = H_snap
        self.H = H_snap.mean(axis=0)

        # Propagation speed in medium
        self.v = self.c0 * prop_speed_frac

    def estimate_delay(self) -> float:
        """
        Estimate raw round-trip delay τ (seconds) via phase-slope.
        """
        phi = np.unwrap(np.angle(self.H))
        A = np.vstack([self.f, np.ones_like(self.f)]).T
        a, _ = np.linalg.lstsq(A, phi, rcond=None)[0]
        return -a / (2 * np.pi)

    def detect_echo(self) -> dict[str, Any]:
        """
        Perform echo detection and return both signed and positive delays.

        Returns:
        --------
        result : dict
            'delay_rt_s': signed round-trip delay (s)
            'delay_s'   : positive one-way delay (s)
            'distance_m': positive one-way distance (m)
        """
        tau_rt = self.estimate_delay()
        tau_oneway = abs(tau_rt) / 2
        distance = self.v * tau_oneway
        return {"delay_rt_s": tau_rt, "delay_s": tau_oneway, "distance_m": distance}

    def dataset_info(self) -> dict[str, int]:
        """
        Metadata on number of subcarriers and snapshots.
        """
        M, K = self.H_raw.shape
        info = {"subcarriers": K}
        if M > 1:
            info["snapshots"] = M
        return info

    def to_dict(self) -> dict[str, Any]:
        """
        Return all inputs and computed outputs as a dictionary.
        """
        data = {
            "f": self.f.tolist(),
            "H_raw": [row.tolist() for row in self.H_raw],
            "H_avg": self.H.tolist(),
            "dataset_info": self.dataset_info(),
        }
        data.update(self.detect_echo())
        return data
