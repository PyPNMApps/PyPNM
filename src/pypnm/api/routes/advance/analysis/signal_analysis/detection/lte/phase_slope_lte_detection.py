# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from typing import Any

import numpy as np


class GroupDelayAnomalyDetector:
    """
    Detects in-band disturbances (e.g., LTE) by analyzing group-delay flatness
    over multiple captured OFDM channel-estimate snapshots.

    Given a series of frequency-domain channel estimates (H_snapshots)
    and their corresponding subcarrier frequencies (freqs), this class
    computes per-subcarrier group delays, evaluates their global flatness,
    and flags frequency bins where local variability exceeds a threshold.
    """

    def __init__(
        self,
        H_snapshots: np.ndarray | list,
        freqs: np.ndarray | list[float],
        prop_speed_frac: float = 1.0,
    ) -> None:
        """
        Initialize the detector with raw channel-estimate snapshots.

        Parameters
        ----------
        H_snapshots : array-like
            A collection of channel-estimate snapshots, which can be:
              - 1D complex array of length K (single snapshot),
              - 2D complex array of shape (M, K) (M snapshots),
              - ND array ending in (..., K, 2) real/imag pairs.
            All leading dimensions are collapsed into a single snapshot axis.
        freqs : array-like of float
            Subcarrier center frequencies in Hz. Must be 1D of length K and
            match the last dimension of H_snapshots.
        prop_speed_frac : float, optional
            Fraction of the speed of light in vacuum to use as propagation
            velocity (v = c0 * prop_speed_frac). Default is 1.0 (speed of light).

        Raises
        ------
        ValueError
            If `freqs` is not 1D or if `H_snapshots` cannot be reshaped
            to (M, K) where K = len(freqs).
        """
        # Convert and validate frequencies
        self.f = np.asarray(freqs, dtype=float).flatten()
        if self.f.ndim != 1:
            raise ValueError("freqs must be a 1D sequence of frequencies.")
        self.K = self.f.size

        # Convert snapshots to numpy array and handle real/imag pairs
        H_arr = np.asarray(H_snapshots)
        if H_arr.ndim >= 3 and H_arr.shape[-1] == 2 and not np.iscomplexobj(H_arr):
            H_arr = H_arr[..., 0] + 1j * H_arr[..., 1]
        H_complex = H_arr.astype(np.complex128)

        # Collapse leading dims into snapshots axis
        if H_complex.ndim == 1:
            if H_complex.size != self.K:
                raise ValueError(
                    f"H_snapshots length {H_complex.size} != freqs length {self.K}."
                )
            self.H_snap = H_complex.reshape(1, self.K)
        elif H_complex.ndim >= 2 and H_complex.shape[-1] == self.K:
            self.H_snap = H_complex.reshape(-1, self.K)
        else:
            raise ValueError(
                f"Unsupported H_snapshots dimensions {H_complex.shape}; last axis must be length {self.K}."
            )

        # Propagation speed in medium
        self.v = 299_792_458 * prop_speed_frac

    def compute_group_delay(self, H: np.ndarray | None = None) -> np.ndarray:
        """
        Compute the per-subcarrier one-way group delay via finite differences.

        Parameters
        ----------
        H : np.ndarray, optional
            A single channel estimate of shape (K,). If not provided,
            the mean across snapshots is used.

        Returns
        -------
        tau : np.ndarray
            One-way delay values in seconds for each subcarrier (length K).
        """
        if H is None:
            H = self.H_snap.mean(axis=0)
        phi = np.unwrap(np.angle(H))
        tau = np.zeros(self.K)
        df = np.diff(self.f)
        # forward difference for first point
        tau[0] = -(phi[1] - phi[0]) / (2 * np.pi * df[0])
        # central differences
        for k in range(1, self.K - 1):
            tau[k] = -(phi[k + 1] - phi[k - 1]) / (
                2 * np.pi * (self.f[k + 1] - self.f[k - 1])
            )
        # backward difference for last point
        tau[-1] = -(phi[-1] - phi[-2]) / (2 * np.pi * df[-1])
        # convert round-trip to one-way and ensure positivity
        return np.abs(tau) / 2

    def global_flatness(self, tau: np.ndarray) -> float:
        """
        Compute the global standard deviation of the group-delay curve.

        Parameters
        ----------
        tau : np.ndarray
            One-way delay values for all subcarriers.

        Returns
        -------
        sigma_total : float
            Standard deviation of the delay values (seconds).
        """
        return np.std(tau, ddof=1)

    def local_variability(
        self, tau: np.ndarray, bin_width: float
    ) -> dict[tuple[float, float], float]:
        """
        Partition the frequency band into bins and compute local delay variability.

        Parameters
        ----------
        tau : np.ndarray
            One-way delay values for all subcarriers.
        bin_width : float
            Width of each frequency bin in Hz.

        Returns
        -------
        local_sigma : dict
            Mapping from (start_freq, end_freq) to the standard deviation
            of delays within that bin.
        """
        f_min, f_max = self.f[0], self.f[-1]
        edges = np.arange(f_min, f_max + bin_width, bin_width)
        local_sigma: dict[tuple[float, float], float] = {}
        for start, end in zip(edges[:-1], edges[1:], strict=False):
            idx = (self.f >= start) & (self.f < end)
            if np.sum(idx) < 2:
                continue
            local_sigma[(start, end)] = np.std(tau[idx], ddof=1)
        return local_sigma

    def detect_anomalies(
        self, tau: np.ndarray, threshold: float, bin_width: float
    ) -> list[tuple[float, float, float]]:
        """
        Identify frequency bins whose variability deviates from global flatness.

        Parameters
        ----------
        tau : np.ndarray
            One-way delay values for all subcarriers.
        threshold : float
            Minimum absolute difference from global std to flag an anomaly.
        bin_width : float
            Width of frequency bins in Hz for coarse scanning.

        Returns
        -------
        anomalies : list of tuples
            Each entry is (start_freq, end_freq, delta_sigma) where
            delta_sigma = |sigma_bin - sigma_global| > threshold.
        """
        sigma_total = self.global_flatness(tau)
        local_sigma = self.local_variability(tau, bin_width)
        anomalies: list[tuple[float, float, float]] = []
        for (start, end), sigma_j in local_sigma.items():
            delta = abs(sigma_j - sigma_total)
            if delta > threshold:
                anomalies.append((start, end, delta))
        return anomalies

    def multi_resolution_scan(
        self, threshold: float, initial_bin: float, refinements: list[float]
    ) -> dict[tuple[float, float], Any]:
        """
        Perform a hierarchical scan: start coarse, then refine flagged bins.

        Parameters
        ----------
        threshold : float
            Threshold for anomaly detection (seconds).
        initial_bin : float
            Coarse bin width in Hz.
        refinements : list of float
            Subsequent finer bin widths in Hz for flagged regions.

        Returns
        -------
        results : dict
            Mapping from coarse bin to a dict containing 'delta' and,
            for each refinement level, a list of finer anomalies.
        """
        results: dict[tuple[float, float], Any] = {}
        tau_global = self.compute_group_delay()
        anomalies = self.detect_anomalies(tau_global, threshold, initial_bin)
        for start, end, delta in anomalies:
            results[(start, end)] = {"delta": delta}
            mask = (self.f >= start) & (self.f < end)
            sub_freqs = self.f[mask]
            sub_H = self.H_snap[:, mask]
            for bw in refinements:
                sub_detector = GroupDelayAnomalyDetector(
                    sub_H, sub_freqs, self.v / 299_792_458
                )
                tau_sub = sub_detector.compute_group_delay()
                results[(start, end)][bw] = sub_detector.detect_anomalies(
                    tau_sub, threshold, bw
                )
        return results

    def run(self, threshold: float, bin_widths: list[float]) -> dict[str, Any]:
        """
        Execute the full analysis pipeline: global flatness and multi-resolution scan.

        Parameters
        ----------
        threshold : float
            Threshold for flagging anomalies in seconds.
        bin_widths : list of float
            List of bin widths in Hz. The first is the coarse scan width,
            subsequent entries are refinement widths.

        Returns
        -------
        summary : dict
            Contains:
              - 'global_sigma': global standard deviation (s)
              - 'coarse_anomalies': list of (start, end, delta)
              - 'detailed': multi-resolution scan results
        """
        tau = self.compute_group_delay()
        return {
            "global_sigma": self.global_flatness(tau),
            "coarse_anomalies": self.detect_anomalies(tau, threshold, bin_widths[0]),
            "detailed": self.multi_resolution_scan(
                threshold, bin_widths[0], bin_widths[1:]
            ),
        }
