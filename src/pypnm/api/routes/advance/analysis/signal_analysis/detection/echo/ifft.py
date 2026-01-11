# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from collections.abc import Sequence
from typing import Final, Literal

import numpy as np
from numpy.typing import NDArray
from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

from pypnm.lib.constants import FEET_PER_METER, SPEED_OF_LIGHT, CableTypes
from pypnm.lib.types import ChannelId, ComplexArray, FloatSeries

# ──────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────
C0: Final[float] = SPEED_OF_LIGHT
COMPLEX_LITERAL: Final[Literal["[Real, Imaginary]"]] = "[Real, Imaginary]"

# Typical velocity factors (fraction of c0); overridable
_CABLE_VF: dict[CableTypes, float] = {
    "RG6": 0.87,
    "RG59": 0.82,
    "RG11": 0.87,
}


# ──────────────────────────────────────────────────────────────
# Models (scoped to IFFT echo detection)
# ──────────────────────────────────────────────────────────────
class IfftEchoDetectorDatasetInfo(BaseModel):
    """Shape metadata for IFFT-based echo analysis.

    Parameters
    ----------
    subcarriers : int
        Number of frequency bins (N).
    snapshots : int
        Number of snapshots (M).
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    subcarriers: int = Field(..., description="Number of frequency bins (N)")
    snapshots: int = Field(..., description="Number of snapshots (M)")

    @field_validator("subcarriers", "snapshots")
    @classmethod
    def _positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError("Values must be >= 1.")
        return v


class IfftEchoReflectionModel(BaseModel):
    """Direct-path and first-echo metrics derived from |h(t)|.

    Notes
    -----
    The time-domain response is h(t) = IFFT{H(f)}.
    We locate the direct path (largest |h| peak) and the first echo peak whose
    magnitude exceeds `threshold_frac` × |h| at the direct path, after skipping
    `guard_bins` samples to avoid immediate sidelobes.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    # Peak indices (bins)
    direct_index: int = Field(..., description="Index of the direct-path peak in |h|")
    echo_index: int = Field(..., description="Index of the first echo peak in |h|")

    # Times (seconds)
    time_direct_s: float = Field(..., description="Time at direct-path peak (s)")
    time_echo_s: float = Field(..., description="Time at echo peak (s)")
    reflection_delay_s: float = Field(
        ..., description="Echo delay relative to direct path (s)"
    )

    # Distance (meters, two-way path converted to one-way distance)
    reflection_distance_m: float = Field(
        ..., description="Estimated echo distance (m, one-way)"
    )

    # Amplitudes
    amp_direct: float = Field(..., description="|h| at direct peak")
    amp_echo: float = Field(..., description="|h| at echo peak")
    amp_ratio: float = Field(..., description="amp_echo / amp_direct")

    # Parameters used
    threshold_frac: float = Field(
        ..., description="Fraction of main-peak magnitude used as threshold"
    )
    guard_bins: int = Field(..., description="Guard bins skipped after main peak")
    max_delay_s: float | None = Field(
        default=None, description="Optional max delay window for echo search (s)"
    )


class IfftEchoTimeResponseModel(BaseModel):
    """Time-domain impulse response via IFFT with optional zero-padding.

    If `n_fft > N`, zero-padding improves temporal sampling (same Δt = 1/fs).

    Attributes
    ----------
    n_fft : int
        IFFT length used.
    time_axis_s : list[float]
        Time axis (seconds), length n_fft, uniform spacing Δt = 1/fs.
    time_response : list[tuple[float, float]]
        Complex impulse response encoded as (re, im) pairs, length n_fft.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    n_fft: int = Field(..., description="IFFT length actually used")
    time_axis_s: FloatSeries = Field(
        ..., description="Time axis (seconds), length n_fft"
    )
    time_response: ComplexArray = Field(
        ..., description="Complex impulse response as (re, im) pairs, length n_fft"
    )

    @field_validator("time_axis_s", "time_response")
    @classmethod
    def _match_len(
        cls, v: FloatSeries | ComplexArray, info: ValidationInfo
    ) -> FloatSeries | ComplexArray:
        n_fft = info.data.get("n_fft")
        if n_fft is not None and len(v) != n_fft:
            raise ValueError(f"Length mismatch: expected {n_fft}, got {len(v)}")
        return v


class IfftEchoDetectorModel(BaseModel):
    """Canonical serialized payload for IFFT echo analysis (first-echo variant).

    Includes dataset shape, sampling/propagation params, complex encoding tag,
    raw channel snapshots (as (re, im) pairs), the coherent average, and the
    detected direct/first-echo metrics. Optionally includes the time response.
    """

    model_config = ConfigDict(str_strip_whitespace=True, populate_by_name=True)

    dataset_info: IfftEchoDetectorDatasetInfo = Field(
        ..., description="Dataset shape metadata"
    )
    sample_rate_hz: float = Field(..., description="Sampling rate used for IFFT (Hz)")
    prop_speed_mps: float = Field(..., description="Propagation speed used (m/s)")

    # complex encoding declaration (serialized with alias "complex")
    complex_unit: Literal["[Real, Imaginary]"] = Field(
        COMPLEX_LITERAL, alias="complex", description="Complex encoding tag"
    )

    H_snap: list[ComplexArray] = Field(
        ..., description="M×N snapshots of frequency response as (re, im) pairs"
    )
    H_avg: ComplexArray = Field(
        ..., description="N-length coherent average as (re, im) pairs"
    )

    reflection: IfftEchoReflectionModel = Field(
        ..., description="Detected direct path and first echo metrics"
    )
    time_response: IfftEchoTimeResponseModel | None = Field(
        default=None, description="IFFT impulse response and time axis"
    )

    # Validators to ensure shapes & pairs
    @staticmethod
    def _is_pair(x: object) -> bool:
        return (
            isinstance(x, (list, tuple))
            and len(x) == 2
            and isinstance(x[0], (int, float))
            and isinstance(x[1], (int, float))
        )

    @field_validator("H_avg")
    @classmethod
    def _coerce_avg(cls, v: ComplexArray, info: ValidationInfo) -> ComplexArray:
        out: ComplexArray = []
        for item in v:
            if not cls._is_pair(item):
                raise ValueError("H_avg must contain (re, im) numeric pairs.")
            out.append((float(item[0]), float(item[1])))
        di = info.data.get("dataset_info")
        if di is not None and hasattr(di, "subcarriers"):
            n = di.subcarriers
            if len(out) != n:
                raise ValueError(f"H_avg length {len(out)} must match subcarriers {n}.")
        return out

    @field_validator("H_snap")
    @classmethod
    def _coerce_snap(
        cls, v: list[ComplexArray], info: ValidationInfo
    ) -> list[ComplexArray]:
        if not v or not v[0]:
            raise ValueError("H_snap must be non-empty MxN.")
        n = len(v[0])
        out: list[ComplexArray] = []
        for row in v:
            if len(row) != n:
                raise ValueError("H_snap must be rectangular (all rows same length).")
            row_out: ComplexArray = []
            for item in row:
                if not cls._is_pair(item):
                    raise ValueError("H_snap must contain (re, im) numeric pairs.")
                row_out.append((float(item[0]), float(item[1])))
            out.append(row_out)
        di = info.data.get("dataset_info")
        if di is not None and hasattr(di, "subcarriers") and hasattr(di, "snapshots"):
            if di.subcarriers != n:
                raise ValueError(
                    f"H_snap N={n} must match dataset_info.subcarriers={di.subcarriers}."
                )
            if di.snapshots != len(out):
                raise ValueError(
                    f"H_snap M={len(out)} must match dataset_info.snapshots={di.snapshots}."
                )
        return out


class IfftEchoPathModel(BaseModel):
    """One echo/direct path sample in time with distance estimates.

    Distances are one-way, computed from Δt between the echo peak and direct
    peak using d = (v · Δt) / 2, where v is the propagation speed in the cable.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    bin_index: int = Field(..., description="Sample index into |h(t)|")
    time_s: float = Field(..., description="Time at this peak (s)")
    amplitude: float = Field(..., description="|h| amplitude at this peak")
    distance_m: float = Field(..., description="Estimated one-way distance (m)")
    distance_ft: float = Field(..., description="Estimated one-way distance (ft)")


class IfftMultiEchoDetectionModel(BaseModel):
    """Multi-echo report relative to the modem input.

    Contains the direct path and a list of echo peaks meeting threshold and
    spacing constraints, with distances in meters and feet. Includes the cable
    type (for VF lookup) and the exact VF/propagation speed used.
    """

    model_config = ConfigDict(str_strip_whitespace=True, populate_by_name=True)

    # NEW: persist the channel this result came from
    channel_id: ChannelId = Field(..., description="OFDM downstream channel ID")

    # Analysis context
    dataset_info: IfftEchoDetectorDatasetInfo = Field(
        ..., description="Dataset shape metadata (N, M)"
    )
    sample_rate_hz: float = Field(..., description="Sampling rate (Hz)")
    complex_unit: Literal["[Real, Imaginary]"] = Field(COMPLEX_LITERAL, alias="complex")

    # Cable / propagation
    cable_type: CableTypes = Field(
        ..., description="Cable type used to pick velocity factor"
    )
    velocity_factor: float = Field(
        ..., description="Velocity factor actually used (fraction of c0)"
    )
    prop_speed_mps: float = Field(..., description="Propagation speed used (m/s)")

    # Detected paths
    direct_path: IfftEchoPathModel = Field(..., description="Strongest (direct) path")
    echoes: list[IfftEchoPathModel] = Field(
        ..., description="Detected echo peaks (sorted by amplitude)"
    )

    # Parameters used
    threshold_frac: float = Field(
        ..., description="Threshold as fraction of |h| at direct path"
    )
    guard_bins: int = Field(..., description="Guard region after direct path (bins)")
    min_separation_s: float = Field(
        ..., description="Min separation between echoes (seconds)"
    )
    max_delay_s: float | None = Field(
        default=None, description="Optional max search window after direct (s)"
    )
    max_peaks: int = Field(
        ..., description="Maximum number of echoes to return (not counting direct)"
    )

    # Optional time response block (handy for clients that want to draw)
    time_response: IfftEchoTimeResponseModel | None = Field(default=None)


# ──────────────────────────────────────────────────────────────
# Utilities
# ──────────────────────────────────────────────────────────────
def _local_maxima_indices(mag: NDArray[np.float64]) -> list[int]:
    """Return indices i that are local maxima: mag[i] >= mag[i-1] and > mag[i+1]."""
    if mag.size < 3:
        return []
    return [
        i
        for i in range(1, mag.size - 1)
        if mag[i] >= mag[i - 1] and mag[i] > mag[i + 1]
    ]


# ──────────────────────────────────────────────────────────────
# IFFT Echo Detector (implementation)
# ──────────────────────────────────────────────────────────────
class IfftEchoDetector:
    """
    FFT/IFFT-based echo detector for OFDM channel estimates.

    Input Shapes
    ------------
    freq_data :
        - (N,) complex
        - (M, N) complex
        - (N, 2) real/imag pairs (single snapshot)
        - (M, N, 2) real/imag pairs (multiple snapshots)

    Math
    ----
    - Time response: h(t) = IFFT{H(f)} (optionally with zero padding)
    - Direct path: argmax |h(t)|
    - Echo peaks: local maxima of |h(t)| with |h| >= threshold_frac · |h|_direct,
      ignoring first `guard_bins` samples after the direct peak.
    - One-way distance: d = (v · Δt) / 2 where v = c0 · VF(cable).
    """

    def __init__(
        self,
        freq_data: Sequence[complex]
        | Sequence[Sequence[complex]]
        | Sequence[Sequence[float]],
        sample_rate: float,
        prop_speed_frac: float = 0.87,
    ) -> None:
        """
        Parameters
        ----------
        freq_data : array-like
            Frequency-domain channel estimates (complex or real/imag pairs).
        sample_rate : float
            Sampling rate in Hz (samples per second); Δt = 1 / sample_rate.
        prop_speed_frac : float
            Velocity factor (fraction of c0) used for the single-echo detector.
            (The multi-echo detector can override via cable type / VF.)
        """
        # Normalize to complex ndarray
        data = np.asarray(freq_data)

        if data.ndim == 3 and data.shape[2] == 2 and not np.iscomplexobj(data):
            H_complex = data[..., 0] + 1j * data[..., 1]  # (M, N)
        elif data.ndim == 2 and data.shape[1] == 2 and not np.iscomplexobj(data):
            H_complex = (
                data[np.newaxis, ..., 0] + 1j * data[np.newaxis, ..., 1]
            )  # (1, N)
        else:
            H_complex = data.astype(np.complex128)

        # Ensure snapshots 2D
        if H_complex.ndim == 1:
            H_snap = H_complex.reshape(1, -1)
        elif H_complex.ndim == 2:
            H_snap = H_complex
        else:
            raise ValueError(
                "freq_data must be 1D/2D complex, or real/imag (N,2) / (M,N,2)."
            )

        # Store
        self.H_snap: NDArray[np.complex128] = H_snap  # (M, N)
        self.H_avg: NDArray[np.complex128] = H_snap.mean(axis=0)  # (N,)
        self.freq_data: NDArray[np.complex128] = self.H_avg

        # Sampling / propagation
        self.sample_rate: float = float(sample_rate)
        self.prop_speed: float = float(C0 * prop_speed_frac)

        # Sizes
        self.M: int = int(self.H_snap.shape[0])
        self.N: int = int(self.H_snap.shape[1])

        # Time-domain cache
        self._time_axis: NDArray[np.float64] | None = None
        self._time_response: NDArray[np.complex128] | None = None
        self._n_fft: int | None = None

    # ──────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────
    @staticmethod
    def _vec_to_pairs(vec: NDArray[np.complex128]) -> ComplexArray:
        """Encode a complex vector as (re, im) pairs."""
        return [(float(np.real(v)), float(np.imag(v))) for v in vec]

    @staticmethod
    def _mat_to_pairs(mat: NDArray[np.complex128]) -> list[ComplexArray]:
        """Encode a complex matrix as (re, im) pairs, row-wise."""
        M, _ = mat.shape
        return [
            [(float(np.real(v)), float(np.imag(v))) for v in mat[m]] for m in range(M)
        ]

    # ──────────────────────────────────────────────────────────
    # Core operations
    # ──────────────────────────────────────────────────────────
    def compute_time_response(
        self, n_fft: int | None = None
    ) -> tuple[NDArray[np.float64], NDArray[np.complex128]]:
        """Compute h(t) = IFFT{H(f)} with optional zero-padding to n_fft.

        Returns
        -------
        (time_axis_s, time_response)
            time_axis_s : (n_fft,) in seconds with Δt = 1 / sample_rate
            time_response : (n_fft,) complex impulse response
        """
        n_use = int(n_fft) if n_fft is not None else self.N
        if n_use < self.N:
            raise ValueError(f"n_fft ({n_use}) must be >= N ({self.N}).")

        h = np.fft.ifft(self.freq_data, n=n_use)
        t = np.arange(n_use, dtype=np.float64) / self.sample_rate

        self._time_axis = t
        self._time_response = h.astype(np.complex128, copy=False)
        self._n_fft = n_use
        return t, self._time_response

    def detect_reflection(
        self,
        threshold_frac: float = 0.2,
        guard_bins: int = 1,
        max_delay_s: float | None = None,
    ) -> IfftEchoReflectionModel:
        """Locate the direct path and the first echo peak in |h(t)|.

        Strategy
        --------
        1) Find direct path = argmax |h|.
        2) Threshold = `threshold_frac` × |h|_direct; search after `guard_bins`.
        3) Optional search window: [i0 + guard_bins, i0 + max_delay_s·fs].

        Returns
        -------
        IfftEchoReflectionModel
            Indices/times of direct/echo, echo delay, one-way distance, and amplitudes.
        """
        # Ensure time response exists
        if self._time_response is None or self._time_axis is None:
            self.compute_time_response()

        h = self._time_response
        t = self._time_axis
        n = h.size

        mag = np.abs(h)
        i0 = int(np.argmax(mag))
        amp0 = float(mag[i0])
        if amp0 <= 0.0:
            raise RuntimeError("Direct-path magnitude is zero; cannot threshold.")

        thresh = float(threshold_frac) * amp0
        start = int(i0 + max(guard_bins, 0))

        if max_delay_s is not None and max_delay_s > 0:
            max_bins = int(np.ceil(max_delay_s * self.sample_rate))
            stop = min(n, i0 + max_bins + 1)
        else:
            stop = n

        ie: int | None = None
        for idx in range(start, stop):
            if mag[idx] >= thresh:
                ie = int(idx)
                break
        if ie is None:
            raise RuntimeError(
                "No echo found above threshold within the search window."
            )

        t0 = float(t[i0])
        te = float(t[ie])
        delay = float(te - t0)
        # For the single-echo detector, use self.prop_speed
        dist = float((delay * self.prop_speed) / 2.0)
        amp_e = float(mag[ie])
        ratio = float(amp_e / amp0) if amp0 > 0 else 0.0

        return IfftEchoReflectionModel(
            direct_index=i0,
            echo_index=ie,
            time_direct_s=t0,
            time_echo_s=te,
            reflection_delay_s=delay,
            reflection_distance_m=dist,
            amp_direct=amp0,
            amp_echo=amp_e,
            amp_ratio=ratio,
            threshold_frac=float(threshold_frac),
            guard_bins=int(guard_bins),
            max_delay_s=float(max_delay_s) if max_delay_s is not None else None,
        )

    def detect_multiple_reflections(
        self,
        *,
        cable_type: CableTypes = "RG6",
        velocity_factor: float | None = None,
        threshold_frac: float = 0.2,
        guard_bins: int = 1,
        min_separation_s: float = 0.0,
        max_delay_s: float | None = None,
        max_peaks: int = 5,
        n_fft: int | None = None,
        include_time_response: bool = True,
    ) -> IfftMultiEchoDetectionModel:
        """Detect multiple echoes using local maxima in |h(t)| above threshold.

        Parameters
        ----------
        cable_type : {'RG6','RG59','RG11'}
            Cable for VF lookup (overridden by `velocity_factor` if provided).
        velocity_factor : float or None
            Override VF (0..1). If None, uses `cable_type` default.
        threshold_frac : float
            Echo must be >= threshold_frac × |h(direct)|.
        guard_bins : int
            Bins to skip immediately after direct path (avoid mainlobe).
        min_separation_s : float
            Minimum Δt spacing between echoes (seconds).
        max_delay_s : float or None
            Optional search window (seconds) after direct peak.
        max_peaks : int
            Maximum number of echoes to report (not counting direct).
        n_fft : int or None
            If set and > N, zero-pad IFFT to n_fft.
        include_time_response : bool
            Include (t, h) block for plotting.

        Returns
        -------
        IfftMultiEchoDetectionModel
            Direct path and list of echoes with distances in m/ft.
            NOTE: `channel_id` must be attached by the caller/orchestrator.
        """
        # ensure time response exists (optionally zero-pad)
        if n_fft is not None or self._time_response is None or self._time_axis is None:
            self.compute_time_response(n_fft=n_fft)

        assert self._time_response is not None and self._time_axis is not None
        h = self._time_response
        t = self._time_axis
        n = h.size

        mag = np.abs(h).astype(np.float64, copy=False)
        i0 = int(np.argmax(mag))
        amp0 = float(mag[i0])
        if amp0 <= 0.0:
            raise RuntimeError("Direct-path magnitude is zero; cannot threshold.")

        thresh = float(threshold_frac) * amp0
        start = int(i0 + max(guard_bins, 0))

        if max_delay_s is not None and max_delay_s > 0:
            max_bins = int(np.ceil(max_delay_s * self.sample_rate))
            stop = min(n, i0 + max_bins + 1)
        else:
            stop = n

        # candidate local maxima above threshold within window
        cand_region = mag[start:stop]
        local_idxs = _local_maxima_indices(cand_region)
        cand_idxs = [start + i for i in local_idxs if cand_region[i] >= thresh]

        # sort by amplitude descending
        cand_idxs.sort(key=lambda i: mag[i], reverse=True)

        # enforce minimum separation in bins
        min_sep_bins = int(np.ceil(max(0.0, min_separation_s) * self.sample_rate))
        selected: list[int] = []
        for i in cand_idxs:
            if not selected or all(abs(i - j) >= min_sep_bins for j in selected):
                selected.append(i)
            if len(selected) >= max_peaks:
                break

        # propagation speed from cable type / override
        vf = (
            float(velocity_factor)
            if velocity_factor is not None
            else float(_CABLE_VF[cable_type])
        )
        prop_speed = float(C0 * vf)

        # direct path (reference at 0 distance)
        t0 = float(t[i0])
        direct = IfftEchoPathModel(
            bin_index=i0,
            time_s=t0,
            amplitude=amp0,
            distance_m=0.0,
            distance_ft=0.0,
        )

        # echoes
        echoes: list[IfftEchoPathModel] = []
        for ie in selected:
            te = float(t[ie])
            delay = float(te - t0)
            dist_m = (delay * prop_speed) / 2.0  # one-way distance
            dist_ft = dist_m * FEET_PER_METER
            echoes.append(
                IfftEchoPathModel(
                    bin_index=int(ie),
                    time_s=te,
                    amplitude=float(mag[ie]),
                    distance_m=float(dist_m),
                    distance_ft=float(dist_ft),
                )
            )

        # optional time-response block
        tr_block: IfftEchoTimeResponseModel | None = None
        if include_time_response and self._n_fft is not None:
            tr_block = IfftEchoTimeResponseModel(
                n_fft=int(self._n_fft),
                time_axis_s=[float(x) for x in t.tolist()],
                time_response=self._vec_to_pairs(h.astype(np.complex128, copy=False)),
            )

        # NOTE: channel_id is not known to the detector; the caller should stamp it
        return IfftMultiEchoDetectionModel(
            channel_id=ChannelId(-1),  # placeholder; orchestrator must update
            dataset_info=IfftEchoDetectorDatasetInfo(
                subcarriers=self.N, snapshots=self.M
            ),
            sample_rate_hz=float(self.sample_rate),
            complex=COMPLEX_LITERAL,  # alias
            cable_type=cable_type,
            velocity_factor=vf,
            prop_speed_mps=prop_speed,
            direct_path=direct,
            echoes=echoes,
            threshold_frac=float(threshold_frac),
            guard_bins=int(guard_bins),
            min_separation_s=float(min_separation_s),
            max_delay_s=float(max_delay_s) if max_delay_s is not None else None,
            max_peaks=int(max_peaks),
            time_response=tr_block,
        )

    def compute_freq_response(
        self, time_data: Sequence[complex]
    ) -> NDArray[np.complex128]:
        """Compute H(f) = FFT{x(t)} for a time-domain sequence x(t)."""
        td = np.asarray(time_data, dtype=np.complex128).reshape(-1)
        return np.fft.fft(td, n=td.size)

    # ──────────────────────────────────────────────────────────
    # Serialization (first-echo variant)
    # ──────────────────────────────────────────────────────────
    def to_model(
        self,
        *,
        n_fft: int | None = None,
        threshold_frac: float = 0.2,
        guard_bins: int = 1,
        max_delay_s: float | None = None,
        include_time_response: bool = True,
    ) -> IfftEchoDetectorModel:
        """Build a canonical model payload for IFFT echo analysis (first-echo variant)."""
        # Optionally recompute the time response
        if n_fft is not None or self._time_response is None or self._time_axis is None:
            self.compute_time_response(n_fft=n_fft)

        dataset = IfftEchoDetectorDatasetInfo(subcarriers=self.N, snapshots=self.M)

        H_snap_pairs: list[ComplexArray] = self._mat_to_pairs(self.H_snap)
        H_avg_pairs: ComplexArray = self._vec_to_pairs(self.H_avg)

        reflection = self.detect_reflection(
            threshold_frac=threshold_frac,
            guard_bins=guard_bins,
            max_delay_s=max_delay_s,
        )

        tr_block: IfftEchoTimeResponseModel | None = None
        if (
            include_time_response
            and self._time_axis is not None
            and self._time_response is not None
            and self._n_fft is not None
        ):
            tr_block = IfftEchoTimeResponseModel(
                n_fft=int(self._n_fft),
                time_axis_s=[float(x) for x in self._time_axis.tolist()],
                time_response=self._vec_to_pairs(self._time_response),
            )

        return IfftEchoDetectorModel(
            dataset_info=dataset,
            sample_rate_hz=float(self.sample_rate),
            prop_speed_mps=float(self.prop_speed),
            complex=COMPLEX_LITERAL,
            H_snap=H_snap_pairs,
            H_avg=H_avg_pairs,
            reflection=reflection,
            time_response=tr_block,
        )
