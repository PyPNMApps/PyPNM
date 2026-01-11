# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from collections.abc import Sequence
from typing import Final, Literal

import numpy as np
from numpy.typing import NDArray
from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

from pypnm.lib.types import ComplexArray, FloatSeries, FrequencyHz, TwoDFloatSeries

COMPLEX_LITERAL: Final[Literal["[Real, Imaginary]"]] = "[Real, Imaginary]"


class GroupDelayCalculatorDatasetInfo(BaseModel):
    """
    Dataset shape metadata for group delay computation.

    This model describes the logical dimensions of the channel-estimation
    dataset that feeds the calculator.

    Parameters
    ----------
    subcarriers : int
        Number of downstream OFDM subcarriers (K) in the channel estimate.
    snapshots : int
        Number of independent snapshots (M) captured for the same channel.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    subcarriers: int = Field(..., description="Number of subcarriers (K)")
    snapshots: int = Field(..., description="Number of snapshots (M)")

    @field_validator("subcarriers", "snapshots")
    @classmethod
    def _positive(cls, v: int) -> int:
        """Validate that all dimension sizes are strictly positive."""
        if v < 1:
            raise ValueError("Values must be >= 1.")
        return v


class GroupDelayCalculatorFullModel(BaseModel):
    """
    Per-subcarrier group delay for the averaged channel.

    This model represents τ_g(f) computed from the phase slope of the
    snapshot-averaged channel estimate across the frequency axis.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    freqs: list[FrequencyHz] = Field(..., description="K-length frequency axis (Hz)")
    tau_g: FloatSeries = Field(..., description="K-length group delay (s)")

    @field_validator("tau_g")
    @classmethod
    def _match_len(cls, tau_g: FloatSeries, info: ValidationInfo) -> FloatSeries:
        """Enforce that the group delay vector matches the frequency axis length."""
        freqs = info.data.get("freqs", [])
        if len(freqs) != len(tau_g):
            raise ValueError(
                f"Length mismatch: freqs={len(freqs)} vs tau_g={len(tau_g)}."
            )
        return tau_g


class GroupDelayCalculatorSnapshotModel(BaseModel):
    """
    Per-snapshot group delay matrix.

    This model carries τ_g(m, k) for each snapshot m and subcarrier k,
    preserving full time-variation across captures.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    taus: TwoDFloatSeries = Field(..., description="M×K group delay matrix (s)")

    @field_validator("taus")
    @classmethod
    def _rectangular(cls, v: TwoDFloatSeries) -> TwoDFloatSeries:
        """Ensure a non-empty, strictly rectangular M×K matrix."""
        if len(v) < 1 or len(v[0]) < 1:
            raise ValueError("Snapshot matrix must be non-empty M×K.")
        k = len(v[0])
        for row in v:
            if len(row) != k:
                raise ValueError(
                    "Snapshot matrix must be rectangular (all rows same length)."
                )
        return v

    def shape(self) -> tuple[int, int]:
        """Return the matrix shape as (snapshots M, subcarriers K)."""
        return len(self.taus), len(self.taus[0])


class GroupDelayCalculatorMedianModel(BaseModel):
    """
    Median group delay across snapshots for each subcarrier.

    This model reduces τ_g(m, k) along the snapshot dimension to a robust
    per-subcarrier statistic, useful for smoothing snapshot-to-snapshot noise.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    freqs: list[FrequencyHz] = Field(..., description="K-length frequency axis (Hz)")
    tau_med: FloatSeries = Field(..., description="K-length median group delay (s)")

    @field_validator("tau_med")
    @classmethod
    def _match_len(cls, tau_med: FloatSeries, info: ValidationInfo) -> FloatSeries:
        """Enforce that the median group delay vector matches the frequency axis length."""
        freqs = info.data.get("freqs", [])
        if len(freqs) != len(tau_med):
            raise ValueError(
                f"Length mismatch: freqs={len(freqs)} vs tau_med={len(tau_med)}."
            )
        return tau_med


class GroupDelayCalculatorModel(BaseModel):
    """
    Canonical serialized payload for group delay analysis.

    This model bundles the input metadata (dataset shape, frequency axis,
    complex channel estimates) with multiple derived views of group delay:
    - Full group delay on the snapshot-averaged channel
    - Per-snapshot group delay matrix
    - Median group delay across snapshots
    """

    model_config = ConfigDict(str_strip_whitespace=True, populate_by_name=True)

    dataset_info: GroupDelayCalculatorDatasetInfo = Field(
        ..., description="Dataset shape metadata"
    )
    freqs: list[FrequencyHz] = Field(..., description="K-length frequency axis (Hz)")
    complex_unit: Literal["[Real, Imaginary]"] = Field(
        "[Real, Imaginary]", description="Complex encoding"
    )
    H_raw: list[ComplexArray] = Field(
        ..., description="MxK complex channel estimates as (re, im)"
    )
    H_avg: ComplexArray = Field(
        ..., description="K complex average across snapshots as (re, im)"
    )
    group_delay_full: GroupDelayCalculatorFullModel = Field(
        ..., description="Per-subcarrier group delay for averaged channel"
    )
    snapshot_group_delay: GroupDelayCalculatorSnapshotModel = Field(
        ..., description="Per-snapshot group delay matrix"
    )
    median_group_delay: GroupDelayCalculatorMedianModel = Field(
        ..., description="Median group delay across snapshots"
    )

    @staticmethod
    def _is_pair(x: object) -> bool:
        """Return True if the object is a numeric (re, im) pair."""
        if isinstance(x, (list, tuple)) and len(x) == 2:
            a, b = x
            return isinstance(a, (int, float)) and isinstance(b, (int, float))
        return False

    @field_validator("H_avg")
    @classmethod
    def _coerce_and_check_avg(
        cls, v: ComplexArray, info: ValidationInfo
    ) -> ComplexArray:
        """Coerce average channel estimates into well-formed (re, im) pairs and validate length."""
        freqs = info.data.get("freqs", [])
        out: ComplexArray = []
        for item in v:
            if not cls._is_pair(item):
                raise ValueError(
                    "H_avg must contain (re, im) numeric pairs; no complex objects."
                )
            re, im = float(item[0]), float(item[1])  # type: ignore[index]
            out.append((re, im))
        if len(out) != len(freqs):
            raise ValueError(
                f"H_avg length {len(out)} must match freqs length {len(freqs)}."
            )
        return out

    @field_validator("H_raw")
    @classmethod
    def _coerce_and_check_raw(
        cls, v: list[ComplexArray], info: ValidationInfo
    ) -> list[ComplexArray]:
        """Coerce raw channel matrix into (re, im) pairs and validate its M×K shape."""
        freqs = info.data.get("freqs", [])
        if not v or not v[0]:
            raise ValueError("H_raw must be non-empty M×K.")
        K = len(freqs)
        out: list[ComplexArray] = []
        for row in v:
            if len(row) != K:
                raise ValueError(
                    "H_raw must be rectangular and match frequency axis length."
                )
            row_out: ComplexArray = []
            for item in row:
                if not cls._is_pair(item):
                    raise ValueError(
                        "H_raw must contain (re, im) numeric pairs; no complex objects."
                    )
                re, im = float(item[0]), float(item[1])  # type: ignore[index]
                row_out.append((re, im))
            out.append(row_out)
        return out

    @field_validator("snapshot_group_delay")
    @classmethod
    def _shape_match_snapshots(
        cls, v: GroupDelayCalculatorSnapshotModel, info: ValidationInfo
    ) -> GroupDelayCalculatorSnapshotModel:
        """Ensure snapshot group delay K dimension matches the frequency axis."""
        k = len(info.data.get("freqs", []))
        _, k_taus = v.shape()
        if k_taus != k:
            raise ValueError(
                f"snapshot_group_delay K={k_taus} must match freqs length {k}."
            )
        return v


# ──────────────────────────────────────────────────────────────
# Calculator
# ──────────────────────────────────────────────────────────────
class GroupDelayCalculator:
    """
    Compute group delay from per-subcarrier channel estimates.

    The calculator accepts either complex channel estimates or real/imaginary
    pairs, together with a 1D frequency axis. Group delay is derived via the
    negative slope of the unwrapped channel phase with respect to frequency.

    Supported input layouts
    -----------------------
    H : Union[
        Sequence[complex],
        Sequence[Sequence[complex]],
        Sequence[Sequence[float]],
    ]
        - 1D complex (K,)                 → single snapshot
        - 2D complex (M, K)              → multiple snapshots
        - 2D real/imag (M, K, 2)         → (re, im) pairs without native complex dtype

    The frequency axis is always interpreted as Hz and must be strictly
    1D with at least two distinct points.
    """

    def __init__(
        self,
        H: Sequence[complex] | Sequence[Sequence[complex]] | Sequence[Sequence[float]],
        freqs: Sequence[float],
    ) -> None:
        """
        Initialize the calculator with channel estimates and frequencies.

        Parameters
        ----------
        H :
            Channel-estimation data in one of the supported layouts:
            - 1D complex (K,)                   → single snapshot
            - 2D complex (M, K)                 → M snapshots of length K
            - Real/imag pairs shaped (K, 2)     → single snapshot as (re, im)
            - Real/imag pairs shaped (M, K, 2)  → M snapshots as (re, im)
        freqs : Sequence[float]
            Monotonic 1D frequency axis in Hz of length K.

        Raises
        ------
        ValueError
            If the frequency axis is not 1D, has fewer than two points,
            or the shape of H is incompatible with the frequency axis.
        """
        # Normalize the frequency axis into a 1D float64 array.
        freqs_arr: NDArray[np.float64] = np.asarray(freqs, dtype=np.float64)
        if freqs_arr.ndim != 1:
            raise ValueError("freqs must be a 1D sequence of frequencies.")
        if freqs_arr.size < 2:
            raise ValueError(
                "At least two frequency points are required to compute group delay."
            )
        # Store the frequency vector as a flat (K,) array.
        self.f: NDArray[np.float64] = freqs_arr.reshape(-1)

        # Convert input H into a NumPy array for shape inspection.
        H_arr_raw = np.asarray(H)

        # Case 1: (K, 2) real/imag pairs → treat as a single snapshot (1, K, 2).
        if (
            H_arr_raw.ndim == 2
            and H_arr_raw.shape[1] == 2
            and not np.iscomplexobj(H_arr_raw)
        ):
            H_arr_raw = H_arr_raw[np.newaxis, :, :]

        # Case 2: (M, K, 2) real/imag pairs → build complex array H_complex (M, K).
        if (
            H_arr_raw.ndim == 3
            and H_arr_raw.shape[2] == 2
            and not np.iscomplexobj(H_arr_raw)
        ):
            H_complex: NDArray[np.complex128] = (
                H_arr_raw[..., 0] + 1j * H_arr_raw[..., 1]
            )
        else:
            # Otherwise, interpret input directly as complex-valued data.
            H_complex = np.asarray(H_arr_raw, dtype=np.complex128)

        # Normalize shapes so that H_raw is always (M, K).
        if H_complex.ndim == 1:
            # Single snapshot: force shape to (1, K).
            if H_complex.size != self.f.size:
                raise ValueError("Length of H must match length of freqs.")
            self.H_raw: NDArray[np.complex128] = H_complex.reshape(1, -1)
        elif H_complex.ndim == 2:
            # Multiple snapshots: verify subcarrier count matches frequency axis.
            M, K = H_complex.shape
            if self.f.size != K:
                raise ValueError(
                    f"Each snapshot must have length {self.f.size}, got {K}"
                )
            self.H_raw = H_complex
        else:
            # Any other shape is unsupported.
            raise ValueError(
                "H must be 1D complex, 2D complex, or real/imag array of shape (K,2) or (M,K,2)."
            )

        # Precompute the snapshot-averaged channel (K,) for later use.
        self.H_avg: NDArray[np.complex128] = np.mean(self.H_raw, axis=0)

    def compute_group_delay_full(
        self,
    ) -> tuple[NDArray[np.float64], NDArray[np.float64]]:
        """
        Compute per-subcarrier group delay on the averaged channel.

        Returns
        -------
        Tuple[NDArray[np.float64], NDArray[np.float64]]
            A tuple ``(f, tau_g)`` where:
            - ``f`` is the 1D frequency axis in Hz (K,).
            - ``tau_g`` is the group delay in seconds for each subcarrier (K,).

        Raises
        ------
        ValueError
            If the frequency axis contains duplicate values, preventing
            a stable numerical derivative.
        """
        # Unwrap the phase of the averaged channel to avoid 2π discontinuities.
        phi = np.unwrap(np.angle(self.H_avg))

        # Number of subcarriers.
        K = self.f.size

        # Allocate output vector for group delay τ_g(f).
        tau_g: NDArray[np.float64] = np.zeros(K, dtype=np.float64)

        # Compute frequency spacing between neighboring subcarriers.
        df = np.diff(self.f)
        if np.any(df == 0.0):
            raise ValueError(
                "freqs contains duplicate values; cannot compute derivative."
            )

        # Left endpoint: use a forward difference approximation.
        tau_g[0] = -(phi[1] - phi[0]) / (2 * np.pi * df[0])

        # Interior points: use a centered difference approximation.
        for k in range(1, K - 1):
            tau_g[k] = -(phi[k + 1] - phi[k - 1]) / (
                2 * np.pi * (self.f[k + 1] - self.f[k - 1])
            )

        # Right endpoint: use a backward difference approximation.
        tau_g[-1] = -(phi[-1] - phi[-2]) / (2 * np.pi * df[-1])

        # Return the original frequency axis and the computed group delay.
        return self.f, tau_g

    def snapshot_group_delay(self) -> NDArray[np.float64]:
        """
        Compute group delay for each snapshot independently.

        Returns
        -------
        NDArray[np.float64]
            An array ``taus`` of shape (M, K) where each row contains the
            per-subcarrier group delay (seconds) for one snapshot.

        Raises
        ------
        ValueError
            If the frequency axis contains duplicate values, preventing
            a stable numerical derivative.
        """
        # Shape of the complex channel matrix.
        M, K = self.H_raw.shape

        # Allocate output matrix τ_g(m, k).
        taus: NDArray[np.float64] = np.zeros((M, K), dtype=np.float64)

        # Frequency spacing for derivative calculations.
        df = np.diff(self.f)
        if np.any(df == 0.0):
            raise ValueError(
                "freqs contains duplicate values; cannot compute derivative."
            )

        # Process each snapshot independently.
        for m in range(M):
            # Unwrap phase for snapshot m.
            phi = np.unwrap(np.angle(self.H_raw[m]))

            # Left endpoint (snapshot m).
            taus[m, 0] = -(phi[1] - phi[0]) / (2 * np.pi * df[0])

            # Interior points (snapshot m).
            for k in range(1, K - 1):
                taus[m, k] = -(phi[k + 1] - phi[k - 1]) / (
                    2 * np.pi * (self.f[k + 1] - self.f[k - 1])
                )

            # Right endpoint (snapshot m).
            taus[m, -1] = -(phi[-1] - phi[-2]) / (2 * np.pi * df[-1])

        # Return full M×K matrix of group delay.
        return taus

    def median_group_delay(self) -> tuple[NDArray[np.float64], NDArray[np.float64]]:
        """
        Compute the median group delay across snapshots for each subcarrier.

        Returns
        -------
        Tuple[NDArray[np.float64], NDArray[np.float64]]
            A tuple ``(f, tau_med)`` where:
            - ``f`` is the 1D frequency axis in Hz (K,).
            - ``tau_med`` is the per-subcarrier median group delay (seconds)
              across all snapshots (K,).
        """
        # First compute τ_g(m, k) for all snapshots.
        taus = self.snapshot_group_delay()

        # Reduce along the snapshot dimension (axis=0) to get the median per subcarrier.
        tau_med: NDArray[np.float64] = np.median(taus, axis=0)

        # Return frequency axis and median group delay.
        return self.f, tau_med

    @staticmethod
    def _complex_matrix_to_pairs(mat: NDArray[np.complex128]) -> list[ComplexArray]:
        """
        Encode a complex matrix as `(re, im)` pairs.

        Parameters
        ----------
        mat : NDArray[np.complex128]
            Complex-valued matrix of shape (M, K).

        Returns
        -------
        List[ComplexArray]
            Nested list of `(re, im)` pairs with shape M×K.
        """
        M, K = mat.shape
        out: list[ComplexArray] = []
        # Convert each complex element to its explicit real/imag tuple.
        for m in range(M):
            row: ComplexArray = [(float(np.real(v)), float(np.imag(v))) for v in mat[m]]
            out.append(row)
        return out

    @staticmethod
    def _complex_vector_to_pairs(vec: NDArray[np.complex128]) -> ComplexArray:
        """
        Encode a complex vector as `(re, im)` pairs.

        Parameters
        ----------
        vec : NDArray[np.complex128]
            Complex-valued vector of shape (K,).

        Returns
        -------
        ComplexArray
            List of `(re, im)` pairs of length K.
        """
        # Same conversion as above but for a 1D vector.
        return [(float(np.real(v)), float(np.imag(v))) for v in vec]

    def _process(self) -> GroupDelayCalculatorModel:
        """
        Build a `GroupDelayCalculatorModel` with all computed outputs.

        This method:
        - Normalizes input frequencies and complex channel estimates.
        - Computes full, per-snapshot, and median group delay.
        - Encodes all results into a single Pydantic model suitable for
          serialization, logging, or REST responses.

        Returns
        -------
        GroupDelayCalculatorModel
            Fully-populated model containing metadata, raw complex data,
            and all group delay views.
        """
        # Extract dimensions from the normalized channel matrix.
        M, K = self.H_raw.shape

        # Record dimensional metadata (K subcarriers, M snapshots).
        dataset = GroupDelayCalculatorDatasetInfo(subcarriers=K, snapshots=M)

        # Convert frequency axis to FrequencyHz wrappers for the model.
        freqs_list: list[FrequencyHz] = [FrequencyHz(f) for f in self.f.tolist()]

        # Encode raw and averaged complex data as (re, im) tuples.
        H_raw_pairs: list[ComplexArray] = self._complex_matrix_to_pairs(self.H_raw)
        H_avg_pairs: ComplexArray = self._complex_vector_to_pairs(self.H_avg)

        # Compute group delay views.
        f_full, tau_full = self.compute_group_delay_full()  # τ_g on averaged channel
        taus_snap = self.snapshot_group_delay()  # τ_g(m, k) per snapshot
        f_med, tau_med = self.median_group_delay()  # median τ_g across snapshots

        # Wrap full group delay view (averaged channel) into a model.
        full = GroupDelayCalculatorFullModel(
            freqs=[FrequencyHz(f) for f in f_full.tolist()],
            tau_g=[float(x) for x in tau_full.tolist()],
        )

        # Wrap per-snapshot group delay into its matrix model.
        snaps = GroupDelayCalculatorSnapshotModel(
            taus=[[float(x) for x in row] for row in taus_snap.tolist()],
        )

        # Wrap median group delay across snapshots into a model.
        med = GroupDelayCalculatorMedianModel(
            freqs=[FrequencyHz(f) for f in f_med.tolist()],
            tau_med=[float(x) for x in tau_med.tolist()],
        )

        # Pass the alias explicitly with a Literal-typed constant to satisfy Pylance.
        return GroupDelayCalculatorModel(
            dataset_info=dataset,
            freqs=freqs_list,
            complex_unit=COMPLEX_LITERAL,
            H_raw=H_raw_pairs,
            H_avg=H_avg_pairs,
            group_delay_full=full,
            snapshot_group_delay=snaps,
            median_group_delay=med,
        )

    def to_model(self) -> GroupDelayCalculatorModel:
        """
        Return the computed results as a `GroupDelayCalculatorModel`.

        This is the primary API for downstream consumers that want a fully
        typed representation of all group delay outputs without dealing
        with NumPy arrays directly.

        Returns
        -------
        GroupDelayCalculatorModel
            Fully-populated analysis model.
        """
        # Delegate to the internal processing pipeline.
        return self._process()

    def to_dict(self) -> dict:
        """
        Return the computed results as a dictionary.

        The dictionary is produced via Pydantic's ``model_dump`` using
        field aliases, making it suitable for JSON serialization and
        REST responses.

        Returns
        -------
        dict
            Dictionary representation of the `GroupDelayCalculatorModel`
            with aliases applied.
        """
        # Dump the Pydantic model into a plain dict with alias names.
        return self.to_model().model_dump(by_alias=True)
