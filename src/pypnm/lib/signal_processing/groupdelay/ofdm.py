# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import math
from enum import Enum

from pydantic import BaseModel, Field, PrivateAttr, field_validator

from pypnm.lib.types import (
    ComplexSeries,
    FloatSeries,
    FrequencyHz,
    FrequencySeriesHz,
    IntSeries,
)


class SignConvention(Enum):
    PLUS = (
        1  # τ = +(1/2π)·dφ/df  (house convention → non-negative for linear-phase delay)
    )
    MINUS = -1  # τ = −(1/2π)·dφ/df  (textbook for e^{-j2π f τ})


class SpacedFrequencyAxisHz(BaseModel):
    """Evenly spaced OFDM frequency axis in Hz: f[k] = f0_hz + k·df_hz."""

    f0_hz: FrequencyHz = Field(..., description="Absolute frequency of bin 0 (Hz).")
    df_hz: float = Field(..., description="Strictly positive subcarrier spacing (Hz).")

    @field_validator("df_hz")
    @classmethod
    def _validate_df_hz(cls, v: float) -> float:
        if not math.isfinite(v) or v <= 0.0:
            raise ValueError("df_hz must be finite and > 0.")
        return float(v)


class GroupDelayOptions(BaseModel):
    """Options controlling group-delay calculation and post-processing."""

    sign: SignConvention = Field(
        default=SignConvention.PLUS, description="PLUS or MINUS convention."
    )
    smooth_win: int | None = Field(
        default=None, description="Centered moving-average window (odd, ≥3)."
    )
    enforce_nonnegative: bool = Field(
        default=False, description="Clamp negative τ(s) to 0.0 if True."
    )

    @field_validator("smooth_win")
    @classmethod
    def _validate_smooth_win(cls, v: int | None) -> int | None:
        if v is None:
            return None
        if not isinstance(v, int) or v < 3 or (v % 2) == 0:
            raise ValueError("smooth_win must be odd and ≥ 3.")
        return v


class GroupDelayCompact(BaseModel):
    """Compact return payload: frequency axis (Hz) and group delay (s)."""

    freq_hz: FrequencySeriesHz = Field(
        ..., description="Frequency axis (Hz), integer-valued."
    )
    tau_s: FloatSeries = Field(..., description="Group delay per bin (seconds).")


class GroupDelayFull(BaseModel):
    """Full return payload including intermediate series and summary metric."""

    freq_hz: FrequencySeriesHz = Field(
        ..., description="Frequency axis (Hz), integer-valued."
    )
    wrapped_phase: FloatSeries = Field(
        ..., description="Wrapped phase φ[k] in radians."
    )
    unwrapped_phase: FloatSeries = Field(
        ..., description="Unwrapped phase φ[k] in radians."
    )
    dphi_df: FloatSeries = Field(..., description="Phase slope dφ/df (rad/Hz).")
    tau_s: FloatSeries = Field(..., description="Group delay τ[k] (seconds).")
    tau_us: FloatSeries = Field(..., description="Group delay τ[k] (microseconds).")
    valid_mask: IntSeries = Field(
        ..., description="1 where τ is finite and bin is active; else 0."
    )
    mean_group_delay_us: float = Field(
        default=math.nan, description="Mean τ over valid bins (microseconds)."
    )


class OFDMGroupDelay(BaseModel):
    """
    Per-subcarrier group delay for a DOCSIS-style OFDM channel using complex
    channel-estimation coefficients H[k] (linear complex).

    Steps
    -----
    1) Build frequency axis (Hz) from `axis`.
    2) Compute wrapped phase φ = atan2(im, re) on active & finite bins.
    3) Unwrap phase per contiguous active region.
    4) Differentiate: dφ/df via central differences (one-sided at edges).
    5) Convert to τ(s) = sign·(1/2π)·dφ/df, then τ(µs).
    6) Optional centered moving-average smoothing.
    7) Optional nonnegative clamp.
    8) Produce validity mask and mean τ(µs).
    """

    H: ComplexSeries = Field(
        ..., description="Channel estimate H[k] as Python complex list."
    )
    axis: SpacedFrequencyAxisHz = Field(
        ..., description="Frequency origin and uniform spacing (Hz)."
    )
    options: GroupDelayOptions = Field(
        default_factory=GroupDelayOptions, description="Computation options."
    )
    active_mask: IntSeries | None = Field(
        default=None, description="1=active bin, 0=inactive; defaults to all 1s."
    )

    # Private caches (Pydantic v2: use PrivateAttr for underscore names)
    _freq_hz: FrequencySeriesHz = PrivateAttr(default_factory=list)
    _work_mask: IntSeries = PrivateAttr(default_factory=list)
    _wrapped_phase: FloatSeries = PrivateAttr(default_factory=list)
    _unwrapped_phase: FloatSeries = PrivateAttr(default_factory=list)
    _dphi_df: FloatSeries = PrivateAttr(default_factory=list)
    _tau_s: FloatSeries = PrivateAttr(default_factory=list)
    _tau_us: FloatSeries = PrivateAttr(default_factory=list)
    _valid_mask: IntSeries = PrivateAttr(default_factory=list)
    _mean_us: float = PrivateAttr(default=math.nan)

    def model_post_init(self, _context: dict | None) -> None:
        """Run the computation pipeline after model creation."""
        self._compute()

    def series(self) -> GroupDelayCompact:
        """
        Get frequency axis (Hz) and group delay (s).

        Returns
        -------
        GroupDelayCompact
            Unit-aware compact result aligned per subcarrier/bin.
        """
        return GroupDelayCompact(freq_hz=self._freq_hz, tau_s=self._tau_s)

    def result(self) -> GroupDelayFull:
        """
        Get the full derivation with intermediate series and summary.

        Returns
        -------
        GroupDelayFull
            Frequencies, phases (wrapped/unwrapped), dφ/df, τ in s/µs,
            validity mask, and mean τ in µs.
        """
        return GroupDelayFull(
            freq_hz=self._freq_hz,
            wrapped_phase=self._wrapped_phase,
            unwrapped_phase=self._unwrapped_phase,
            dphi_df=self._dphi_df,
            tau_s=self._tau_s,
            tau_us=self._tau_us,
            valid_mask=self._valid_mask,
            mean_group_delay_us=self._mean_us,
        )

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _unwrap_on_mask(wrapped_phase: FloatSeries, mask: IntSeries) -> FloatSeries:
        """
        Unwrap phase only within contiguous regions where mask==1.
        Gaps (mask==0) remain NaN to avoid stitching across null/guard bands.
        """
        w, m, n = wrapped_phase, mask, len(wrapped_phase)
        out: FloatSeries = [float("nan")] * n
        i = 0
        while i < n:
            if m[i] == 1:
                j = i
                while j < n and m[j] == 1:
                    j += 1
                out[i:j] = OFDMGroupDelay._unwrap_segment(w[i:j])
                i = j
            else:
                i += 1
        return out

    @staticmethod
    def _unwrap_segment(segment: FloatSeries) -> FloatSeries:
        """
        Remove ±π jumps from a contiguous wrapped phase segment (radians).
        Keeps phase continuous by adding/subtracting 2π where needed.
        """
        if not segment:
            return []
        out: FloatSeries = [segment[0]]
        for k in range(1, len(segment)):
            prev = out[-1]
            cur = segment[k]
            diff = cur - prev
            while diff <= -math.pi:
                cur += 2.0 * math.pi
                diff = cur - prev
            while diff > math.pi:
                cur -= 2.0 * math.pi
                diff = cur - prev
            out.append(cur)
        return out

    @staticmethod
    def _central_gradient(
        phase_unwrapped: FloatSeries, df_hz: float, mask: IntSeries
    ) -> FloatSeries:
        """
        Compute dφ/df (rad/Hz) using finite differences:
          • interior bins → central difference
          • edges → one-sided difference
        Invalid centers or neighbors yield NaN to prevent spikes.
        """
        p, m, n = phase_unwrapped, mask, len(phase_unwrapped)
        out: FloatSeries = [float("nan")] * n

        def ok(idx: int) -> bool:
            return (m[idx] == 1) and math.isfinite(p[idx])

        for k in range(n):
            if not ok(k):
                continue
            if k == 0:
                if n > 1 and ok(1):
                    out[k] = (p[1] - p[0]) / df_hz
            elif k == n - 1:
                if ok(n - 2):
                    out[k] = (p[n - 1] - p[n - 2]) / df_hz
            else:
                if ok(k - 1) and ok(k + 1):
                    out[k] = (p[k + 1] - p[k - 1]) / (2.0 * df_hz)
        return out

    @staticmethod
    def _moving_average_masked(
        series_s: FloatSeries, mask: IntSeries, window: int
    ) -> FloatSeries:
        """
        Centered moving average of τ(s) over valid contributors only.
        Preserves NaN when the center is invalid or the window has no valid data.
        """
        n = len(series_s)
        out: FloatSeries = [float("nan")] * n
        half = window // 2
        for i in range(n):
            if mask[i] != 1 or not math.isfinite(series_s[i]):
                continue
            lo = max(0, i - half)
            hi = min(n, i + half + 1)
            acc = 0.0
            cnt = 0
            for j in range(lo, hi):
                if mask[j] == 1 and math.isfinite(series_s[j]):
                    acc += series_s[j]
                    cnt += 1
            if cnt > 0:
                out[i] = acc / cnt
        return out

    @staticmethod
    def _masked_mean_us(series_us: FloatSeries, mask: IntSeries) -> float:
        """
        Mean of τ(µs) across bins where mask==1 and values are finite.
        Returns NaN when there are no valid contributors.
        """
        acc = 0.0
        cnt = 0
        for v, ok in zip(series_us, mask, strict=False):
            if ok == 1 and math.isfinite(v):
                acc += v
                cnt += 1
        return (acc / cnt) if cnt > 0 else float("nan")

    # ── Pipeline ───────────────────────────────────────────────────────────────

    def _compute(self) -> None:
        """
        Build axis → mask → phase (wrap/unwrap) → dφ/df → τ(s)/τ(µs),
        then smooth/clip as requested and summarize validity + mean.
        """
        H_vals: ComplexSeries = self.H
        n_bins = len(H_vals)
        if n_bins < 2:
            raise ValueError("H must contain ≥ 2 complex bins.")

        df_hz = float(self.axis.df_hz)
        if not math.isfinite(df_hz) or df_hz <= 0.0:
            raise ValueError("axis.df_hz must be finite and > 0.")

        # Frequency axis (Hz) stored as integers by design
        f0 = int(self.axis.f0_hz)
        self._freq_hz = [FrequencyHz(int(round(f0 + k * df_hz))) for k in range(n_bins)]

        # Valid where both the complex sample is finite and bin is active
        finite_mask: IntSeries = [
            1 if (math.isfinite(h.real) and math.isfinite(h.imag)) else 0
            for h in H_vals
        ]
        if self.active_mask is None:
            active_mask: IntSeries = [1] * n_bins
        else:
            if len(self.active_mask) != n_bins:
                raise ValueError("active_mask length must match H length.")
            active_mask = [1 if bool(v) else 0 for v in self.active_mask]

        self._work_mask = [
            1 if (finite_mask[i] == 1 and active_mask[i] == 1) else 0
            for i in range(n_bins)
        ]

        # Wrapped phase; NaN for inactive/invalid bins maintains gaps
        self._wrapped_phase = [
            math.atan2(h.imag, h.real) if self._work_mask[i] == 1 else float("nan")
            for i, h in enumerate(H_vals)
        ]

        # Unwrap only within contiguous active runs
        self._unwrapped_phase = self._unwrap_on_mask(
            self._wrapped_phase, self._work_mask
        )

        # Phase slope dφ/df (rad/Hz)
        self._dphi_df = self._central_gradient(
            self._unwrapped_phase, df_hz, self._work_mask
        )

        # τ(s) = sign · (1 / 2π) · dφ/df
        sign = 1.0 if self.options.sign is SignConvention.PLUS else -1.0
        two_pi = 2.0 * math.pi
        tau_s: FloatSeries = [
            (sign * v / two_pi) if math.isfinite(v) else float("nan")
            for v in self._dphi_df
        ]

        # Optional smoothing
        if self.options.smooth_win is not None:
            tau_s = self._moving_average_masked(
                tau_s, self._work_mask, self.options.smooth_win
            )

        # Optional clamp (domain preference: no negative “time”)
        if self.options.enforce_nonnegative:
            tau_s = [max(v, 0.0) if math.isfinite(v) else float("nan") for v in tau_s]

        self._tau_s = tau_s
        self._tau_us = [(v * 1e6) if math.isfinite(v) else float("nan") for v in tau_s]

        # Valid where both work_mask is 1 and τ(s) is finite
        self._valid_mask = [
            1 if (self._work_mask[i] == 1 and math.isfinite(self._tau_s[i])) else 0
            for i in range(n_bins)
        ]

        # Summary statistic
        self._mean_us = self._masked_mean_us(self._tau_us, self._valid_mask)
