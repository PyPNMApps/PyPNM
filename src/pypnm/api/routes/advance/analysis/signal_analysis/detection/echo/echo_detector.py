# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
from collections.abc import Sequence
from math import ceil, log2
from typing import Literal, TypeAlias

import numpy as np
from numpy.typing import NDArray
from pydantic import BaseModel, Field

from pypnm.lib.constants import (
    CABLE_VF,
    FEET_PER_METER,
    INVALID_CHANNEL_ID,
    SPEED_OF_LIGHT,
    CableTypes,
)
from pypnm.lib.types import ChannelId, IfftTimeResponse

LOG = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────────────────────────
# Constants (no magic numbers)
# ────────────────────────────────────────────────────────────────────────────────
MIN_NFFT: int = 1024
DEFAULT_THRESHOLD_FRAC: float = 0.10
DEFAULT_THRESHOLD_DB_DOWN: float = 20.0
DEFAULT_GUARD_BINS: int = 0
DEFAULT_EDGE_GUARD_BINS: int = 8
DEFAULT_MAX_PEAKS: int = 3
DEFAULT_MAX_DELAY_S: float = 3.5e-6
MIN_SEPARATION_BINS_FLOOR: int = 1
AMP_DB_SCALE: float = 20.0  # 20*log10(amplitude)

WindowMode: TypeAlias = Literal["hann", "none"]
ThresholdMode: TypeAlias = Literal["fractional", "db_down"]

NDArrayC128: TypeAlias = NDArray[np.complex128]
NDArrayF64: TypeAlias = NDArray[np.float64]


class EchoDataset(BaseModel):
    subcarriers: int = Field(
        ..., description="Number of subcarriers N in the provided frequency response"
    )
    snapshots: int = Field(
        ..., description="Number of snapshots M (after any averaging)"
    )
    subcarrier_spacing_hz: float = Field(
        ..., description="Δf between adjacent subcarriers (Hz)"
    )
    sample_rate_hz: float = Field(
        ..., description="IFFT time-domain sample rate fs = n_fft * Δf (Hz)"
    )


class DirectPath(BaseModel):
    bin_index: int = Field(
        ...,
        description="Time-domain index of the direct-path peak after optional rolling",
    )
    time_s: float = Field(
        ..., description="Direct-path time-of-arrival relative to index 0 (seconds)"
    )
    amplitude: float = Field(
        ..., description="Direct-path magnitude |h[i0]| (after any normalization)"
    )
    distance_m: float = Field(..., description="Estimated one-way distance (meters)")
    distance_ft: float = Field(..., description="Estimated one-way distance (feet)")


class EchoPath(BaseModel):
    bin_index: int = Field(..., description="Time-domain index of the echo peak")
    time_s: float = Field(
        ..., description="Echo time-of-arrival relative to index 0 (seconds)"
    )
    amplitude: float = Field(
        ..., description="Echo magnitude |h[i]| (after any normalization)"
    )
    distance_m: float = Field(..., description="Estimated one-way distance (meters)")
    distance_ft: float = Field(..., description="Estimated one-way distance (feet)")


class TimeResponse(BaseModel):
    n_fft: int = Field(..., description="Size of IFFT used to compute h(t)")
    time_axis_s: list[float] = Field(
        ..., description="Uniform time axis in seconds, length n_fft"
    )
    time_response: list[float] = Field(
        ..., description="Magnitude |h(t)| aligned per direct_at_zero"
    )


class EchoDetectorReport(BaseModel):
    channel_id: int = Field(..., description="User-provided channel identifier")
    dataset: EchoDataset = Field(..., description="Dataset shape and sampling metadata")
    cable_type: str = Field(
        ..., description='Coax type label (e.g., "RG6", "RG59", "RG11")'
    )
    velocity_factor: float = Field(
        ..., description="Velocity factor used for distance conversion"
    )
    prop_speed_mps: float = Field(..., description="Propagation speed v = c * VF (m/s)")
    direct_path: DirectPath = Field(..., description="Estimated direct-path parameters")
    echoes: list[EchoPath] = Field(
        ..., description="List of detected echo paths (may be empty)"
    )
    threshold_frac: float = Field(
        ..., description="Fraction of direct-path magnitude used as detection threshold"
    )
    guard_bins: int = Field(
        ..., description="Bins skipped immediately after direct path before echo search"
    )
    min_separation_s: float = Field(
        ...,
        description="Minimum separation enforced between accepted echo peaks (seconds)",
    )
    max_delay_s: float | None = Field(
        ..., description="Maximum echo time considered (seconds), None → full span"
    )
    max_peaks: int = Field(..., description="Maximum number of echo peaks returned")
    time_response: TimeResponse | None = Field(
        default=None, description="Optional time response output for plotting"
    )


class EchoDetector:
    """
    IFFT-based echo detector for DOCSIS downstream OFDM channel-estimation H(f).

    Steps
    -----
    1) Normalize input to H(f) with shape (N,) complex; supports (N,) complex, (N,2) real/imag, or (M,N) complex snapshots.
    2) Optional Hann window in frequency domain.
    3) Zero-pad/crop to n_fft (default: next pow2 ≥ N, min 1024).
    4) IFFT → h(t); compute magnitude |h|.
    5) Find direct path i0 = argmax |h|; optionally roll so i0 = 0.
    6) Threshold vs. direct-path (fractional or dB-down); greedy peak picking with spacing.
    """

    def __init__(
        self,
        freq_data: NDArrayF64 | NDArrayC128 | Sequence,
        subcarrier_spacing_hz: float,
        n_fft: int | None = None,
        cable_type: CableTypes = "RG6",
        channel_id: ChannelId | None = None,
    ) -> None:
        self.logger = logging.getLogger(f"{self.__class__.__name__}")
        if subcarrier_spacing_hz <= 0.0:
            raise ValueError("subcarrier_spacing_hz must be > 0")

        H, snapshots = self._coerce_freq_data(freq_data)
        N = int(H.shape[0])
        self.logger.debug("Input normalized: N=%d, snapshots=%d", N, snapshots)

        if n_fft is None:
            n_fft = max(MIN_NFFT, 1 << ceil(log2(max(1, N))))
        if n_fft <= 0:
            raise ValueError("n_fft must be positive")

        if channel_id is None:
            channel_id = ChannelId(INVALID_CHANNEL_ID)

        self._H_in: NDArrayC128 = H
        self._N: int = N
        self._snapshots: int = snapshots
        self._n_fft: int = int(n_fft)
        self._df: float = float(subcarrier_spacing_hz)
        self._fs: float = float(n_fft) * float(subcarrier_spacing_hz)
        self._cable_type: CableTypes = cable_type
        self._vf: float = float(CABLE_VF[cable_type])
        self._v: float = SPEED_OF_LIGHT * self._vf
        self._channel_id: int = int(channel_id)

        self.logger.debug(
            "Parameters: n_fft=%d, Δf=%.3f Hz, fs=%.6f MHz, cable=%s, vf=%.3f, v=%.3f Mm/s",
            self._n_fft,
            self._df,
            self._fs / 1e6,
            self._cable_type,
            self._vf,
            self._v / 1e6,
        )

    # ───────── Public properties (read-only) ─────────
    @property
    def fs(self) -> float:
        return self._fs

    @property
    def nfft(self) -> int:
        return self._n_fft

    @property
    def df(self) -> float:
        return self._df

    @property
    def velocity_factor(self) -> float:
        return self._vf

    @property
    def propagation_speed(self) -> float:
        return self._v

    @property
    def cable_type(self) -> CableTypes:
        return self._cable_type

    @property
    def channel_id(self) -> int:
        return self._channel_id

    # ───────────────────────────────────────────────────────────────────────
    # Public utility: generate |h(t)| without running echo selection
    # ───────────────────────────────────────────────────────────────────────
    def time_response(
        self,
        window: WindowMode = "hann",
        direct_at_zero: bool = True,
        normalize_power: bool = True,
        fs_time_hz: float | None = None,
    ) -> TimeResponse:
        """
        Compute the IFFT time response |h(t)| and return it for plotting.

        Parameters
        ----------
        window : {"hann","none"}
            Frequency-domain window applied prior to IFFT.
        direct_at_zero : bool
            If True, roll so the direct-path bin is at index 0.
        normalize_power : bool
            If True, divide |h| by the direct-path magnitude so |h[0]| = 1 (when rolled).
        fs_time_hz : float | None
            Optional override for *reporting* sample rate in time axis only. If None, uses fs = n_fft * Δf.

        Returns
        -------
        TimeResponse
            n_fft, time axis in seconds, and |h(t)| magnitude (linear).
        """
        self.logger.debug(
            "time_response: window=%s, direct_at_zero=%s, normalize=%s, fs_time=%s",
            window,
            direct_at_zero,
            normalize_power,
            "None" if fs_time_hz is None else f"{fs_time_hz:.3f}",
        )

        mag, i0 = self._compute_mag_time(
            window=window,
            direct_at_zero=direct_at_zero,
            normalize_power=normalize_power,
        )
        n_fft = self._n_fft
        fs_time = float(fs_time_hz) if fs_time_hz and fs_time_hz > 0 else self._fs
        time_axis = np.arange(n_fft, dtype=float) / fs_time

        self.logger.debug(
            "time_response: i0=%d, n_fft=%d, fs_time=%.6f MHz", i0, n_fft, fs_time / 1e6
        )
        return TimeResponse(
            n_fft=n_fft,
            time_axis_s=time_axis.tolist(),
            time_response=mag.astype(float).tolist(),
        )

    # ───────────────────────────────────────────────────────────────────────
    # Main detector
    # ───────────────────────────────────────────────────────────────────────
    def multi_echo(
        self,
        threshold_frac: float = DEFAULT_THRESHOLD_FRAC,
        threshold_mode: ThresholdMode = "fractional",
        threshold_db_down: float | None = None,
        guard_bins: int = DEFAULT_GUARD_BINS,
        min_separation_s: float = 0.0,
        max_delay_s: float | None = DEFAULT_MAX_DELAY_S,
        max_peaks: int = DEFAULT_MAX_PEAKS,
        include_time_response: bool = False,
        direct_at_zero: bool = True,
        window: WindowMode = "hann",
        normalize_power: bool = True,
        edge_guard_bins: int = DEFAULT_EDGE_GUARD_BINS,
        fs_time_hz: float | None = None,
        min_detect_distance_ft: float | None = 10.0,
    ) -> EchoDetectorReport:
        """
        Detect echo peaks via IFFT magnitude thresholding and greedy spacing.

        Parameters
        ----------
        threshold_frac : float
            Fraction of direct-path magnitude used as detection threshold (0,1].
        threshold_mode : {"fractional","db_down"}
            Threshold mode: linear fraction or amplitude dB-down relative to direct path.
        threshold_db_down : float | None
            If mode == "db_down", dB-down value (e.g., 20 → 0.1× amplitude).
        guard_bins : int
            Bins skipped immediately after the direct path before searching (0 allowed).
        min_separation_s : float
            Minimum time separation between accepted peaks; converted to bins with IFFT fs.
        max_delay_s : float | None
            Maximum echo time considered; None → full span (n_fft bins).
        max_peaks : int
            Maximum number of echoes returned.
        include_time_response : bool
            If True, include |h(t)| and time axis in the report.
        direct_at_zero : bool
            If True, roll |h| so direct path is at bin 0.
        window : {"hann","none"}
            Frequency-domain window selection.
        normalize_power : bool
            If True, divide |h| by direct-path amplitude.
        edge_guard_bins : int
            Drop candidates within this many bins of the stopping index.
        fs_time_hz : float | None
            Optional override of *reporting* sample rate used for time/distance conversion only.
        min_detect_distance_ft : float | None
            One-way minimum detection distance in feet; converted to guard bins and
            combined as max(user_guard, distance_guard). Use None to disable.

        Returns
        -------
        EchoDetectorReport
            Structured report including dataset metadata, direct path, and echoes.
        """
        n_fft = self._n_fft
        fs = self._fs
        fs_time = float(fs_time_hz) if fs_time_hz and fs_time_hz > 0 else fs

        self.logger.debug(
            "multi_echo: mode=%s, thr_frac=%.3f, thr_db=%s, guard=%d, min_sep_s=%.3e, "
            "max_delay_s=%s, max_peaks=%d, edge_guard=%d, window=%s, normalize=%s, "
            "direct_at_zero=%s, fs_time=%.6f MHz, min_detect_ft=%s",
            threshold_mode,
            threshold_frac,
            str(threshold_db_down),
            guard_bins,
            min_separation_s,
            str(max_delay_s),
            max_peaks,
            edge_guard_bins,
            window,
            normalize_power,
            direct_at_zero,
            fs_time / 1e6,
            str(min_detect_distance_ft),
        )

        # Compute |h(t)| once (shared by selection and optional export)
        mag, i0_unrolled = self._compute_mag_time(
            window=window,
            direct_at_zero=direct_at_zero,
            normalize_power=normalize_power,
        )
        self.logger.debug(
            "IFFT computed; magnitude prepared; direct_at_zero=%s, i0=%d",
            direct_at_zero,
            i0_unrolled,
        )

        # When rolled, direct path is bin 0; otherwise retain original i0
        i0 = 0 if direct_at_zero else int(i0_unrolled)
        direct_amp = float(mag[i0])

        # Resolve threshold
        if threshold_mode == "fractional":
            if not (0.0 < threshold_frac <= 1.0):
                raise ValueError("threshold_frac must be in (0, 1] for fractional mode")
            thr_frac_resolved = threshold_frac
        elif threshold_mode == "db_down":
            db = (
                DEFAULT_THRESHOLD_DB_DOWN
                if threshold_db_down is None
                else float(threshold_db_down)
            )
            thr_frac_resolved = float(10.0 ** (-db / AMP_DB_SCALE))
        else:
            raise ValueError('threshold_mode must be "fractional" or "db_down"')

        # Effective guard from explicit bins and minimum detectable distance
        min_sep_bins = max(0, int(round(min_separation_s * fs)))
        guard_bins_dist = (
            self._bins_for_min_distance(min_detect_distance_ft, fs)
            if min_detect_distance_ft
            else 0
        )
        effective_guard_bins = max(int(guard_bins), int(guard_bins_dist))
        start_idx = i0 + max(0, effective_guard_bins)

        # Stop index (max window), apply edge guard
        if max_delay_s is None:
            i_stop = n_fft
        else:
            i_stop = min(n_fft, int(np.ceil(max_delay_s * fs)))

        self.logger.debug(
            "Search window: start=%d, stop=%d (exclusive), min_sep_bins=%d, thr_frac=%.6f, "
            "guard_bins=%d (user=%d, dist=%d @ %.2f ft)",
            start_idx,
            i_stop,
            min_sep_bins,
            thr_frac_resolved,
            effective_guard_bins,
            int(guard_bins),
            int(guard_bins_dist),
            0.0 if (min_detect_distance_ft is None) else float(min_detect_distance_ft),
        )

        # Candidate selection
        if i_stop <= start_idx:
            candidates: list[int] = []
        else:
            thr = thr_frac_resolved * direct_amp
            idx_range = np.arange(start_idx, i_stop, dtype=int)
            if edge_guard_bins > 0:
                idx_range = idx_range[idx_range < (i_stop - edge_guard_bins)]
            idx_range = idx_range[
                idx_range != i0
            ]  # keep direct path out even if guard==0
            candidates = [int(i) for i in idx_range if mag[i] >= thr]
        self.logger.debug("Candidates above threshold: %d", len(candidates))

        # Greedy enforce spacing by amplitude
        candidates.sort(key=lambda i: float(mag[i]), reverse=True)
        selected: list[int] = []
        for i in candidates:
            if len(selected) >= max_peaks:
                break
            if all(
                abs(i - s) >= max(MIN_SEPARATION_BINS_FLOOR, min_sep_bins)
                for s in selected
            ):
                selected.append(i)
        selected.sort()
        self.logger.debug("Selected peaks: %s", selected)

        # Reporting conversions (time/distance) — may use fs_time override
        time_axis = np.arange(n_fft, dtype=float) / fs_time
        v = self._v

        def _mk_path(i: int, amp: float) -> tuple[int, float, float, float, float]:
            t = time_axis[i]
            d_m = 0.5 * v * t
            return i, t, amp, d_m, d_m * FEET_PER_METER

        di, dt, da, ddm, ddf = _mk_path(i0, direct_amp)
        direct = DirectPath(
            bin_index=di, time_s=dt, amplitude=da, distance_m=ddm, distance_ft=ddf
        )

        echoes: list[EchoPath] = []
        for i in selected:
            i_, t, a, dm, df = _mk_path(i, float(mag[i]))
            echoes.append(
                EchoPath(
                    bin_index=i_, time_s=t, amplitude=a, distance_m=dm, distance_ft=df
                )
            )
        self.logger.debug("Echo count: %d", len(echoes))

        tr: TimeResponse | None = None
        if include_time_response:
            tr = TimeResponse(
                n_fft=n_fft,
                time_axis_s=time_axis.tolist(),
                time_response=mag.astype(float).tolist(),
            )
            self.logger.debug("Time response included in report")

        dataset = EchoDataset(
            subcarriers=self._N,
            snapshots=self._snapshots,
            subcarrier_spacing_hz=self._df,
            sample_rate_hz=self._fs,
        )

        report = EchoDetectorReport(
            channel_id=self._channel_id,
            dataset=dataset,
            cable_type=self._cable_type,
            velocity_factor=self._vf,
            prop_speed_mps=v,
            direct_path=direct,
            echoes=echoes,
            threshold_frac=thr_frac_resolved,
            guard_bins=effective_guard_bins,
            min_separation_s=min_separation_s,
            max_delay_s=max_delay_s,
            max_peaks=max_peaks,
            time_response=tr,
        )
        self.logger.debug(
            "Report ready: channel_id=%d, direct_bin=%d, echoes=%d",
            report.channel_id,
            report.direct_path.bin_index,
            len(report.echoes),
        )
        return report

    def first_echo(self, **kwargs: float | int | bool | str | None) -> EchoPath:
        """
        Return the earliest echo from `multi_echo(..., max_peaks=1)`; raises if none.

        Parameters
        ----------
        **kwargs
            Any `multi_echo` keyword arguments (e.g., threshold_mode, threshold_db_down, etc.).

        Returns
        -------
        EchoPath
            The earliest (by bin/time) echo from `multi_echo(..., max_peaks=1)`.

        Raises
        ------
        ValueError
            If no echo meets the criteria under the provided settings.
        """
        rep = self.multi_echo(max_peaks=1, **kwargs)
        if not rep.echoes:
            raise ValueError("No echo peaks found under current settings.")
        self.logger.debug(
            "first_echo: bin=%d, amp=%.3f",
            rep.echoes[0].bin_index,
            rep.echoes[0].amplitude,
        )
        return rep.echoes[0]

    def ifft_time_series(
        self,
        window: WindowMode = "hann",
        direct_at_zero: bool = True,
        normalize_power: bool = True,
        fs_time_hz: float | None = None,
    ) -> IfftTimeResponse:
        """
        Compute the complex IFFT time series h(t) for external plotting.

        Parameters
        ----------
        window : {"hann","none"}
            Frequency-domain window applied prior to IFFT.
        direct_at_zero : bool
            If True, roll so the direct-path bin is at index 0.
        normalize_power : bool
            If True, divide h(t) by the direct-path magnitude so |h[0]| = 1
            (when rolled).
        fs_time_hz : float | None
            Optional override for the sample rate used in the time axis. If
            None, uses fs = n_fft * Δf.

        Returns
        -------
        time_axis_s : NDArrayF64
            1-D array of time samples in seconds, length n_fft.
        h_time : NDArrayC128
            1-D complex IFFT time series, aligned/normalized per arguments.
        """
        self.logger.debug(
            "ifft_time_series: window=%s, direct_at_zero=%s, normalize=%s, fs_time=%s",
            window,
            direct_at_zero,
            normalize_power,
            "None" if fs_time_hz is None else f"{fs_time_hz:.3f}",
        )

        # Apply window in frequency domain
        Hw = self._apply_window(self._H_in, window)
        self.logger.debug("ifft_time_series: window applied, mode=%s", window)

        # Pad/crop to n_fft
        Hn = self._pad_or_crop(Hw, self._n_fft)
        self.logger.debug(
            "ifft_time_series: length adjusted: input=%d → n_fft=%d",
            Hw.size,
            self._n_fft,
        )

        # IFFT and magnitude
        h_time = np.fft.ifft(Hn, n=self._n_fft).astype(np.complex128, copy=False)
        mag = np.abs(h_time)

        # Locate direct-path bin and optionally roll
        i0 = int(np.argmax(mag))
        if direct_at_zero:
            h_time = np.roll(h_time, -i0)
            mag = np.abs(h_time)
            i0 = 0
            self.logger.debug("ifft_time_series: direct-path rolled to zero")
        else:
            self.logger.debug("ifft_time_series: direct-path at bin=%d (no roll)", i0)

        # Optional power normalization
        if normalize_power and float(mag[i0]) > 0.0:
            h_time = h_time / float(mag[i0])
            self.logger.debug(
                "ifft_time_series: normalized to direct-path amplitude=1.0"
            )

        # Time axis (can override fs just for plotting)
        fs_time = float(fs_time_hz) if fs_time_hz and fs_time_hz > 0 else self._fs
        time_axis = (np.arange(self._n_fft, dtype=float) / fs_time).astype(
            np.float64, copy=False
        )

        self.logger.debug(
            "ifft_time_series: n_fft=%d, fs_time=%.6f MHz",
            self._n_fft,
            fs_time / 1e6,
        )
        return time_axis, h_time

    # ───────────────────────────────────────────────────────────────────────
    # Internals
    # ───────────────────────────────────────────────────────────────────────
    def _compute_mag_time(
        self,
        window: WindowMode,
        direct_at_zero: bool,
        normalize_power: bool,
    ) -> tuple[NDArrayF64, int]:
        """Compute |h(t)| magnitude and return (mag, direct_index_before_roll_or_zero)."""
        Hw = self._apply_window(self._H_in, window)
        self.logger.debug("Window applied: mode=%s", window)

        Hn = self._pad_or_crop(Hw, self._n_fft)
        self.logger.debug("Length adjusted: input=%d → n_fft=%d", Hw.size, self._n_fft)

        h_time = np.fft.ifft(Hn, n=self._n_fft)
        mag = np.abs(h_time)

        i0 = int(np.argmax(mag))
        if direct_at_zero:
            mag = np.abs(np.roll(h_time, -i0))
            i0 = 0
            self.logger.debug("Direct-path rolled to zero")
        else:
            self.logger.debug("Direct-path at bin=%d (no roll)", i0)

        if normalize_power and float(mag[i0]) > 0.0:
            mag = mag / float(mag[i0])
            self.logger.debug("Power normalized to direct-path amplitude=1.0")

        return mag.astype(np.float64, copy=False), i0

    def _bins_for_min_distance(self, distance_ft: float, fs: float) -> int:
        """Convert a one-way distance (feet) to guard bins using fs and v=c*VF."""
        if distance_ft <= 0.0:
            return 0
        d_m = float(distance_ft) / FEET_PER_METER  # ft → m
        t_min = (2.0 * d_m) / self._v  # round-trip time
        return int(np.ceil(t_min * fs))

    @staticmethod
    def _coerce_freq_data(
        freq_data: NDArrayF64 | NDArrayC128 | Sequence,
    ) -> tuple[NDArrayC128, int]:
        """Coerce input to a single complex H(f) of shape (N,) and return (H, snapshots)."""
        arr = np.asarray(freq_data)
        if arr.ndim == 1:
            if np.iscomplexobj(arr):
                return arr.astype(np.complex128, copy=False), 1
            raise ValueError(
                "1-D input must be complex. For real/imag pairs, use shape (N,2)."
            )
        if arr.ndim == 2:
            if arr.shape[1] == 2 and not np.iscomplexobj(arr):
                Hc = arr[:, 0].astype(np.float64) + 1j * arr[:, 1].astype(np.float64)
                return Hc.astype(np.complex128), 1
            if np.iscomplexobj(arr):
                if arr.shape[0] < 1:
                    raise ValueError("Empty snapshot dimension.")
                return np.mean(arr.astype(np.complex128), axis=0), int(arr.shape[0])
            raise ValueError(
                "2-D input must be (N,2) real/imag or (M,N) complex snapshots."
            )
        raise ValueError(
            "freq_data must be 1-D complex, (N,2) real/imag, or (M,N) complex snapshots."
        )

    @staticmethod
    def _apply_window(H: NDArrayC128, window: WindowMode) -> NDArrayC128:
        """Apply optional frequency-domain window."""
        if window == "none":
            return H
        if window == "hann":
            w = np.hanning(H.size).astype(np.float64)
            return (H * w).astype(np.complex128)
        raise ValueError('Unsupported window. Use "hann" or "none".')

    @staticmethod
    def _pad_or_crop(H: NDArrayC128, n_fft: int) -> NDArrayC128:
        """Zero-pad or crop H to length n_fft."""
        N = int(H.size)
        if n_fft == N:
            return H
        if n_fft > N:
            out = np.zeros(n_fft, dtype=np.complex128)
            out[:N] = H
            return out
        return H[:n_fft]
