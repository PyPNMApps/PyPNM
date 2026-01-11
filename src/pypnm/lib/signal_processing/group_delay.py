# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from pypnm.lib.types import ArrayLikeF64, ComplexArray, Number


class GroupDelayResult(BaseModel):
    """
    Structured result container for per-subcarrier group delay.

    Attributes
    ----------
    freq_hz : ArrayLikeF64
        Frequency axis (Hz) per bin (includes any f0_hz offset).
    group_delay_s : ArrayLikeF64
        Group delay per bin in seconds.
    group_delay_us : ArrayLikeF64
        Group delay per bin in microseconds.
    valid_mask : List[bool]
        True where the output is valid (active bins & finite H).
    mean_group_delay_us : float
        Mean of `group_delay_us` over valid bins; NaN if no valid bins.
    params : dict
        Parameters used for computation (e.g., df_hz, f0_hz, unwrap, edge_order, smooth_win).
    """

    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)

    freq_hz: ArrayLikeF64 = Field(
        default_factory=list, description="Frequency axis (Hz) per bin."
    )
    group_delay_s: ArrayLikeF64 = Field(
        default_factory=list, description="Group delay per bin (seconds)."
    )
    group_delay_us: ArrayLikeF64 = Field(
        default_factory=list, description="Group delay per bin (microseconds)."
    )
    valid_mask: list[bool] = Field(
        default_factory=list,
        description="True where output is valid (active bins & finite H).",
    )
    mean_group_delay_us: float = Field(
        default=np.nan, description="Mean group delay over valid bins (microseconds)."
    )
    params: dict = Field(
        default_factory=dict,
        description="Computation parameters (df_hz, f0_hz, unwrap, edge_order, smooth_win).",
    )


class GroupDelay:
    """
    Compute group delay τ_g(f) from a complex channel estimate H(f).

    Definition
    ----------
    τ_g(f) = - dφ(f) / dω  = - (1 / (2π)) * dφ(f) / df   [seconds]

    Parameters
    ----------
    H : ComplexArray
        Complex frequency response per subcarrier/bin as `(real, imag)` float pairs,
        e.g., OFDM channel estimate \\hat{H}[k]. Length must be ≥ 2.
    freq_hz : Optional[ArrayLikeF64]
        Absolute frequency per bin in Hz (1-D, same length as `H`). Use either `freq_hz`
        or `df_hz`, not both.
    df_hz : Optional[Number]
        Constant subcarrier spacing in Hz when `freq_hz` is not provided.
    f0_hz : float, default 0.0
        Absolute start frequency (Hz) used **only** when `freq_hz` is not provided.
        The implied per-subcarrier frequency becomes `f0_hz + k * df_hz`.
    active_mask : Optional[ArrayLikeF64]
        Boolean mask (coerced) where True marks active (data/pilot) bins; inactives are
        ignored and set to NaN. Defaults to all True.
    unwrap : bool, default True
        If True, unwrap phase before differentiation.
    edge_order : int, default 2
        Edge order for `np.gradient` (1 or 2).
    smooth_win : Optional[int]
        If provided, odd integer ≥ 3 specifying a centered moving-average window
        applied to τ_g(f) over valid bins only.

    Notes
    -----
    - Group delay depends on phase slope vs. frequency; absolute gain is irrelevant.
    - Provide correct DOCSIS subcarrier spacing (`df_hz`) or a well-formed `freq_hz` vector.
    - Deep notches (|H| ≈ 0) destabilize phase; consider averaging H across symbols or use `active_mask`.

    Examples
    --------
    >>> # Constant spacing with absolute start frequency (f0_hz)
    >>> H_pairs = [(1.0, 0.0), (0.9, 0.1), (0.7, 0.2), (0.5, 0.3)]
    >>> gd = GroupDelay(H_pairs, df_hz=25_000.0, f0_hz=300e6)
    >>> f, tau_s = gd.to_tuple()
    >>> res = gd.to_result()
    """

    __slots__ = (
        "_H",
        "_freq_hz",
        "_df_hz",
        "_f0_hz",
        "_unwrap",
        "_edge_order",
        "_smooth_win",
        "_active_mask",
        "phase_rad",
        "group_delay_s",
        "group_delay_us",
    )

    def __init__(
        self,
        H: ComplexArray,
        *,
        freq_hz: ArrayLikeF64 | None = None,
        df_hz: Number | None = None,
        f0_hz: float = 0.0,
        active_mask: ArrayLikeF64 | None = None,
        unwrap: bool = True,
        edge_order: int = 2,
        smooth_win: int | None = None,
    ) -> None:
        """
        Initialize a GroupDelay computation.

        Parameters
        ----------
        H : ComplexArray
            Complex frequency response `H[k]` as `(re, im)` pairs (1-D length ≥ 2).
        freq_hz : Optional[ArrayLikeF64]
            Absolute frequency per bin in Hz (1-D, same length as `H`). Mutually exclusive with `df_hz`.
        df_hz : Optional[Number]
            Constant frequency spacing in Hz. Mutually exclusive with `freq_hz`.
        f0_hz : float, default 0.0
            Start frequency (Hz) used when `freq_hz` is not provided; `f[k]=f0_hz+k*df_hz`.
        active_mask : Optional[ArrayLikeF64]
            1-D mask of active bins; defaults to all True if not provided (coerced to bool).
        unwrap : bool, default True
            Unwrap phase before differentiation.
        edge_order : int, default 2
            Edge order for `np.gradient` (1 or 2); invalid values fall back to 2.
        smooth_win : Optional[int]
            Odd integer window size (≥3) for centered moving average over valid bins.

        Raises
        ------
        ValueError
            On dimensionality/length mismatches, invalid frequency inputs, or invalid smoothing window.
        """
        self._H = self._as_complex_array(
            H, name="H"
        )  # convert once; canonical complex128 vector
        n = self._H.size
        self._freq_hz, self._df_hz = self._resolve_freq_inputs(freq_hz, df_hz, n)
        self._f0_hz = float(f0_hz)
        self._active_mask = self._resolve_mask(active_mask, n)
        self._unwrap = bool(unwrap)
        self._edge_order = 2 if edge_order not in (1, 2) else edge_order
        self._smooth_win = self._validate_smooth_win(smooth_win)

        # Outputs
        self.phase_rad: np.ndarray
        self.group_delay_s: np.ndarray
        self.group_delay_us: np.ndarray

        self._compute()

    # ---------------------------
    # Public API
    # ---------------------------

    @classmethod
    def from_channel_estimate(
        cls,
        Hhat: ComplexArray,
        *,
        df_hz: float,
        f0_hz: float = 0.0,
        active_mask: ArrayLikeF64 | None = None,
        smooth_win: int | None = None,
        unwrap: bool = True,
        edge_order: int = 2,
    ) -> GroupDelay:
        """
        Construct from a standard OFDM channel estimate using constant spacing.

        Parameters
        ----------
        Hhat : ComplexArray
            Complex channel estimate per subcarrier as `(re, im)` pairs.
        df_hz : float
            Constant subcarrier spacing (Hz).
        f0_hz : float, default 0.0
            Absolute start frequency (Hz) so the x-axis is `f0_hz + k*df_hz`.
        active_mask : Optional[ArrayLikeF64]
            Optional active-bin mask; length must match `Hhat` if provided.
        smooth_win : Optional[int]
            Optional odd window (≥3) for centered moving average over valid bins.
        unwrap : bool, default True
            Unwrap phase before differentiation.
        edge_order : int, default 2
            Edge order for `np.gradient` (1 or 2).

        Returns
        -------
        GroupDelay
            Initialized instance ready with computed group delay.
        """
        if not np.isfinite(df_hz) or df_hz == 0.0:
            raise ValueError("df_hz must be finite and non-zero.")
        return cls(
            Hhat,
            df_hz=df_hz,
            f0_hz=f0_hz,
            freq_hz=None,
            active_mask=active_mask,
            unwrap=unwrap,
            edge_order=edge_order,
            smooth_win=smooth_win,
        )

    def to_result(self) -> GroupDelayResult:
        """
        Convert internal NumPy arrays to a serializable result model.

        Returns
        -------
        GroupDelayResult
            Pydantic model containing frequency axis (Hz), group delay (s and µs),
            valid mask, mean group delay (µs) over valid bins, and parameters.
        """
        f = self._get_freq_axis()
        gd_s = self.group_delay_s
        gd_us = self.group_delay_us
        mask = self._valid_mask()

        mean_us = float(np.nanmean(gd_us[mask])) if mask.any() else float("nan")

        return GroupDelayResult(
            freq_hz=f.tolist(),
            group_delay_s=gd_s.tolist(),
            group_delay_us=gd_us.tolist(),
            valid_mask=mask.tolist(),
            mean_group_delay_us=mean_us,
            params=dict(
                df_hz=(None if self._df_hz is None else float(self._df_hz)),
                f0_hz=(None if self._freq_hz is not None else float(self._f0_hz)),
                unwrap=self._unwrap,
                edge_order=self._edge_order,
                smooth_win=self._smooth_win,
            ),
        )

    def to_tuple(self) -> tuple[np.ndarray, np.ndarray]:
        """
        Get frequency axis and group delay in seconds as NumPy arrays.

        Returns
        -------
        (np.ndarray, np.ndarray)
            Tuple of `(freq_hz, group_delay_s)`.
        """
        return (self._get_freq_axis(), self.group_delay_s)

    def __repr__(self) -> str:
        """
        Developer-friendly representation summarizing point count and mean delay.

        Returns
        -------
        str
            Summary string like `GroupDelay(n=..., mean≈... µs)`.
        """
        arr = getattr(self, "group_delay_s", np.array([]))
        if arr.size:
            finite = np.isfinite(arr)
            mean_us = np.nanmean(arr[finite]) * 1e6 if finite.any() else np.nan
            return f"GroupDelay(n={arr.size}, mean≈{mean_us:.3f} µs)"
        return "GroupDelay(n=0)"

    # ---------------------------
    # Core computation
    # ---------------------------

    def _compute(self) -> None:
        """
        Execute the group delay pipeline:

        Steps
        -----
        1) Build working mask (finite(H) & active_mask).
        2) Compute phase (with optional unwrapping).
        3) Differentiate phase vs. frequency (`np.gradient`).
        4) Convert to τ_g(f) in seconds via `-(1/2π) * dφ/df`.
        5) Optionally apply masked moving average smoothing.
        6) Invalidate non-active/invalid bins and cache results (s and µs).
        """
        H = self._H.astype(np.complex128, copy=False)
        n = H.size

        # Build a working mask: finite(H) & active_mask
        finite_H = np.isfinite(H)
        active = self._active_mask
        work_mask = finite_H & active

        # Phase (unwrap globally; NaNs propagate)
        phase = np.full(n, np.nan, dtype=float)
        phase[work_mask] = np.angle(H[work_mask])
        if self._unwrap:
            phase = np.unwrap(phase)

        self.phase_rad = phase

        # Gradient dφ/df (rad/Hz) using either explicit freq or constant spacing
        if self._freq_hz is not None:
            dphi_df = np.gradient(
                self.phase_rad, self._freq_hz, edge_order=self._edge_order
            )
        else:
            dphi_df = np.gradient(
                self.phase_rad, float(self._df_hz), edge_order=self._edge_order
            )

        # τ_g(f) = -(1 / 2π) * dφ/df   [seconds]
        tau_s = -(1.0 / (2.0 * np.pi)) * dphi_df

        # Optional smoothing on valid samples only
        if self._smooth_win:
            tau_s = self._masked_moving_average(tau_s, work_mask, self._smooth_win)

        # Invalidate outputs where not active/finite
        tau_s[~work_mask] = np.nan

        self.group_delay_s = tau_s
        self.group_delay_us = tau_s * 1e6

    # ---------------------------
    # Helpers / validation
    # ---------------------------

    @staticmethod
    def _as_complex_array(x: ComplexArray, *, name: str) -> np.ndarray:
        """
        Convert `(real, imag)` pairs → 1-D complex128 with minimal overhead.

        Parameters
        ----------
        x : ComplexArray
            Sequence of `(re, im)` float pairs (length ≥ 2).
        name : str
            Field name used in error messages.

        Returns
        -------
        np.ndarray
            1-D complex128 array of shape (N,).

        Raises
        ------
        ValueError
            If `x` is not a 2-column float array of pairs or has fewer than 2 points.

        Notes
        -----
        - Fast-path view is used when memory is C-contiguous with strides (16, 8),
          mapping each (re, im) pair to a complex128 element without extra copy.
        - Falls back to a single allocation that combines `re + 1j*im`.
        """
        a = np.asarray(x, dtype=np.float64)
        if a.ndim != 2 or a.shape[1] != 2:
            raise ValueError(
                f"{name} must be a sequence of (real, imag) pairs; got shape {a.shape}"
            )
        if a.shape[0] < 2:
            raise ValueError(f"{name} must have at least 2 points; got {a.shape[0]}")

        # Fast path: if contiguous pairs of float64, view as complex128 (no new allocation)
        if a.flags.c_contiguous and a.strides == (16, 8):
            c = a.view(np.complex128).ravel()
            if not c.flags.writeable:  # guard against read-only views
                c = c.copy()
            return c

        # Safe path: allocate once and combine
        return (a[:, 0] + 1j * a[:, 1]).astype(np.complex128, copy=False)

    @staticmethod
    def _validate_smooth_win(win: int | None) -> int | None:
        """
        Validate the smoothing window.

        Parameters
        ----------
        win : Optional[int]
            Window length.

        Returns
        -------
        Optional[int]
            Validated window (odd integer ≥3) or None.

        Raises
        ------
        ValueError
            If `win` is not None and is not an odd integer ≥3.
        """
        if win is None:
            return None
        if not isinstance(win, (int, np.integer)):
            raise ValueError("smooth_win must be an integer or None.")
        win = int(win)
        if win < 3 or (win % 2) == 0:
            raise ValueError("smooth_win must be an odd integer ≥ 3.")
        return win

    @staticmethod
    def _resolve_mask(mask: ArrayLikeF64 | None, n: int) -> np.ndarray:
        """
        Normalize/validate the active-bin mask.

        Parameters
        ----------
        mask : Optional[ArrayLikeF64]
            Active-bin mask; if None, returns all-True mask (coerced to bool).
        n : int
            Expected length.

        Returns
        -------
        np.ndarray
            Boolean mask of length `n`.

        Raises
        ------
        ValueError
            If provided mask is not 1-D or length != `n`.
        """
        if mask is None:
            return np.ones(n, dtype=bool)
        m = np.asarray(mask, dtype=bool)
        if m.ndim != 1 or m.size != n:
            raise ValueError("active_mask must be 1-D and same length as H.")
        return m

    @staticmethod
    def _masked_moving_average(y: np.ndarray, mask: np.ndarray, win: int) -> np.ndarray:
        """
        Centered moving average over valid positions only.

        The output preserves NaN where `mask` is False or where the centered
        window has no valid (finite & masked) samples.

        Parameters
        ----------
        y : np.ndarray
            Input 1-D array.
        mask : np.ndarray
            Boolean mask specifying valid centers.
        win : int
            Odd window length (≥3).

        Returns
        -------
        np.ndarray
            Smoothed array with NaNs preserved outside valid positions.
        """
        if y.size < win:
            return y.copy()

        out = np.full_like(y, np.nan, dtype=float)
        half = win // 2
        idx = np.arange(y.size)

        valid_idx = idx[mask & np.isfinite(y)]
        if valid_idx.size == 0:
            return out

        # Sliding window average on valid indices
        for i in valid_idx:
            lo = max(0, i - half)
            hi = min(y.size, i + half + 1)
            seg = y[lo:hi]
            seg_mask = np.isfinite(seg) & mask[lo:hi]
            if np.any(seg_mask):
                out[i] = float(np.mean(seg[seg_mask]))
        return out

    @staticmethod
    def _resolve_freq_inputs(
        freq_hz: ArrayLikeF64 | None,
        df_hz: Number | None,
        n: int,
    ) -> tuple[np.ndarray | None, float | None]:
        """
        Validate and resolve frequency inputs (`freq_hz` XOR `df_hz`).

        Parameters
        ----------
        freq_hz : Optional[ArrayLikeF64]
            Absolute frequency vector (Hz), length `n`.
        df_hz : Optional[Number]
            Constant spacing (Hz).
        n : int
            Expected length.

        Returns
        -------
        (Optional[np.ndarray], Optional[float])
            Tuple `(freq_vector_or_None, df_or_None)`.

        Raises
        ------
        ValueError
            If both or neither of `freq_hz`/`df_hz` are provided, dimensionality/length
            issues exist, non-finite frequency values are present, or `df_hz` is invalid.

        Notes
        -----
        - Enforces “no duplicates” (strictly monotonic in the weak sense). If you require
          strictly increasing/decreasing, add an additional check at the call site.
        """
        if (freq_hz is None) == (df_hz is None):
            raise ValueError("Provide exactly one of freq_hz or df_hz.")
        if freq_hz is not None:
            f = np.asarray(freq_hz, dtype=float)
            if f.ndim != 1 or f.size != n:
                raise ValueError("freq_hz must be 1-D and same length as H.")
            if not np.all(np.isfinite(f)):
                raise ValueError("freq_hz contains non-finite values.")
            if np.any(np.diff(f) == 0.0):
                raise ValueError(
                    "freq_hz must be strictly monotonic (no duplicate frequencies)."
                )
            return f, None
        # constant spacing
        try:
            df = float(df_hz)
        except Exception as e:
            raise ValueError(f"df_hz must be a real number: {e}") from e
        if not np.isfinite(df) or df == 0.0:
            raise ValueError("df_hz must be finite and non-zero.")
        return None, df

    def _get_freq_axis(self) -> np.ndarray:
        """
        Produce the frequency axis (Hz) implied by inputs.

        Returns
        -------
        np.ndarray
            If `freq_hz` provided, returns it; otherwise returns `f0_hz + np.arange(N) * df_hz`.
        """
        if self._freq_hz is not None:
            return self._freq_hz
        idx = np.arange(self._H.size, dtype=float)
        return self._f0_hz + idx * float(self._df_hz)

    def _valid_mask(self) -> np.ndarray:
        """
        Compute final validity mask combining finite outputs and active bins.

        Returns
        -------
        np.ndarray
            Boolean mask where `group_delay_s` is finite and the bin was active.
        """
        return np.isfinite(self.group_delay_s) & self._active_mask
