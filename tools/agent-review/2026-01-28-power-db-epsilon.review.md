## Agent Review Bundle Summary
- Goal: Add power_db normalization options (mean or unit).
- Changes: Introduce power_db_normalized with mean/unit modes and tests; refresh SPDX years.
- Files: src/pypnm/lib/signal_processing/complex_array_ops.py; tests/test_complex_array_ops.py
- Tests: python3 -m compileall src; ruff check src; ruff format --check . (fails: repo drift); pytest -q
- Notes: Ruff format would reformat many existing files; no formatting applied. Pytest skipped 3 hardware integration tests (PNM_CM_IT not set).

# FILE: src/pypnm/lib/signal_processing/complex_array_ops.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import numpy as np

from pypnm.lib.types import ArrayLikeF64, ComplexArray, FloatSeries, Number


class ComplexArrayOps:
    """
    Utility for common signal-processing operations on ComplexArray.

    This class accepts your canonical `(re, im)` pairs, converts them ONCE to a
    1-D `np.complex128` vector, and provides power, RMS, magnitude/phase,
    conjugation, reciprocal (safe), FFT/IFFT, and normalization helpers.
    Methods return NumPy arrays or NEW ComplexArrayOps instances for chaining.

    Examples
    --------
    >>> x_pairs = [(1.0, 0.0), (0.0, 1.0), (-1.0, 0.0)]
    >>> ops = ComplexArrayOps(x_pairs)
    >>> p = ops.power()                   # |x[k]|^2 per subcarrier
    >>> rms = ops.rms()                   # sqrt(mean(|x[k]|^2))
    >>> p_db = ops.power_db()             # 10*log10(|x[k]|^2) with log floor
    >>> phi = ops.phase(unwrap=True)      # unwrapped phase
    >>> y = ops.conj().to_pairs()         # conjugated as (re, im) pairs
    >>> inv = ops.reciprocal(eps=1e-9)    # 1 / (x + j*0) with epsilon guard
    >>> td = ops.ifft()                   # time-domain (IFFT), still ComplexArrayOps
    >>> fd = td.fft()                     # back to frequency domain
    >>> norm = ops.normalize_rms(target=1.0)  # scaled to RMS = 1.0
    """

    __slots__ = ("_z",)

    # ---------------------------
    # Construction / conversion
    # ---------------------------

    def __init__(self, x: ComplexArray) -> None:
        """
        Initialize from `(re, im)` float pairs.

        Parameters
        ----------
        x : ComplexArray
            Sequence of `(real, imag)` pairs. Length must be ≥ 1.

        Raises
        ------
        ValueError
            If shape is not (N, 2) or N < 1.
        """
        self._z = self._to_complex1d(x, name="x")

    @staticmethod
    def _to_complex1d(x: ComplexArray, *, name: str) -> np.ndarray:
        """
        Convert `(re, im)` pairs → 1-D complex128 with minimal overhead.

        Fast-path uses a zero-copy view when memory is laid out as contiguous float64 pairs.

        Parameters
        ----------
        x : ComplexArray
            Input `(re, im)` pairs.
        name : str
            Field name for error messages.

        Returns
        -------
        np.ndarray
            1-D array of dtype complex128, shape (N,).

        Raises
        ------
        ValueError
            On invalid shape or empty input.
        """
        a = np.asarray(x, dtype=np.float64)
        if a.ndim != 2 or a.shape[1] != 2:
            raise ValueError(f"{name} must be a sequence of (real, imag) pairs; got shape {a.shape}")
        if a.shape[0] < 1:
            raise ValueError(f"{name} must have at least 1 pair; got {a.shape[0]}")

        # zero-copy view if possible
        if a.flags.c_contiguous and a.strides == (16, 8):
            c = a.view(np.complex128).ravel()
            if not c.flags.writeable:
                c = c.copy()
            return c

        return (a[:, 0] + 1j * a[:, 1]).astype(np.complex128, copy=False)

    def copy(self) -> ComplexArrayOps:
        """
        Return a deep copy.

        Returns
        -------
        ComplexArrayOps
            New instance with copied internal array.
        """
        obj = object.__new__(ComplexArrayOps)
        obj._z = self._z.copy()
        return obj

    def as_array(self) -> np.ndarray:
        """
        Get the internal native complex array.

        Returns
        -------
        np.ndarray
            1-D complex128 vector view (no copy).
        """
        return self._z

    def to_pairs(self) -> ComplexArray:
        """
        Convert the internal complex array back to `(re, im)` pairs.

        Returns
        -------
        ComplexArray
            List of `(float(real), float(imag))` tuples.
        """
        z = self._z
        # Allocate once; faster than Python loop for large N
        out = np.empty((z.size, 2), dtype=np.float64)
        out[:, 0] = z.real
        out[:, 1] = z.imag
        return [tuple(row) for row in out.tolist()]

    def __len__(self) -> int:
        """
        Number of complex samples.

        Returns
        -------
        int
            Length of the internal vector.
        """
        return self._z.size

    def __repr__(self) -> str:
        """
        Developer-friendly summary with RMS and mean power.

        Returns
        -------
        str
            Summary string.
        """
        if self._z.size == 0:
            return "ComplexArrayOps(n=0)"
        mp = float(np.mean(self._z.real**2 + self._z.imag**2))
        rms = float(np.sqrt(mp))
        return f"ComplexArrayOps(n={self._z.size}, RMS={rms:.6g}, MeanPwr={mp:.6g})"

    @staticmethod
    def to_list(arr_like: ArrayLikeF64) -> FloatSeries:
        """
        Coerce array-like to a 1-D list[float].
        """
        arr = np.asarray(arr_like, dtype=np.float64)
        if arr.ndim == 0:
            return [float(arr)]
        if arr.ndim != 1:
            raise ValueError(f"_to_list expects 1-D; got shape {arr.shape}")
        return arr.tolist()

    # ---------------------------
    # Per-subcarrier measures
    # ---------------------------

    def magnitude(self) -> ArrayLikeF64:
        """
        Magnitude per subcarrier.

        Returns
        -------
        np.ndarray
            |x[k]| for each k.
        """
        return np.abs(self._z)

    def power(self) -> ArrayLikeF64:
        """
        Linear power per subcarrier.

        Returns
        -------
        np.ndarray
            |x[k]|^2 for each k.
        """
        z = self._z
        return z.real * z.real + z.imag * z.imag

    def power_db(
        self,
        *,
        epsilon: float = float(np.finfo(np.float64).tiny),
        eps: float | None = None,
    ) -> ArrayLikeF64:
        """
        Power per subcarrier in dB.

        Parameters
        ----------
        epsilon : float, default np.finfo(float64).tiny
            Small positive floor added to power to avoid log(0).
        eps : float | None, default None
            Alias for epsilon.

        Returns
        -------
        np.ndarray
            10*log10(|x[k]|^2 + epsilon) for each k.
        """
        p = np.asarray(self.power(), dtype=np.float64)
        floor = float(epsilon)
        if eps is not None:
            floor = float(eps)
        return 10.0 * np.log10(p + floor)

    def power_db_normalized(
        self,
        *,
        normalize: str = "mean",
        mask: ArrayLikeF64 | None = None,
        epsilon: float = float(np.finfo(np.float64).tiny),
        eps: float | None = None,
    ) -> ArrayLikeF64:
        """
        Power per subcarrier in dB with optional normalization.

        Parameters
        ----------
        normalize : str, default "mean"
            Normalization mode. Supported values:
            - "mean": subtract mean of power_db over the masked subset.
            - "unit": normalize linear power to mean 1.0, then convert to dB.
        mask : Optional[ArrayLikeF64]
            Optional boolean mask to compute the normalization statistic.
        epsilon : float, default np.finfo(float64).tiny
            Small positive floor added before log(0) protection.
        eps : float | None, default None
            Alias for epsilon.

        Returns
        -------
        np.ndarray
            Normalized power in dB.
        """
        p = np.asarray(self.power(), dtype=np.float64)
        if mask is not None:
            m = np.asarray(mask, dtype=bool)
            if m.shape != p.shape:
                raise ValueError("mask must match the number of samples.")
            p_masked = p[m]
        else:
            p_masked = p

        if p_masked.size == 0:
            return self.power_db(epsilon=epsilon, eps=eps)

        match normalize:
            case "mean":
                p_db = self.power_db(epsilon=epsilon, eps=eps)
                mean_db = float(np.mean(p_db[m])) if mask is not None else float(np.mean(p_db))
                if not np.isfinite(mean_db):
                    return p_db
                return p_db - mean_db
            case "unit":
                mean_power = float(np.mean(p_masked))
                if not np.isfinite(mean_power) or mean_power <= 0.0:
                    return self.power_db(epsilon=epsilon, eps=eps)
                floor = float(epsilon)
                if eps is not None:
                    floor = float(eps)
                return 10.0 * np.log10((p / mean_power) + floor)
            case _:
                raise ValueError(f"normalize must be 'mean' or 'unit'; got {normalize!r}")

    def phase(self, *, unwrap: bool = False) -> ArrayLikeF64:
        """
        Phase per subcarrier.

        Parameters
        ----------
        unwrap : bool, default False
            If True, apply `np.unwrap` to the phase.

        Returns
        -------
        np.ndarray
            Angle of x[k] in radians (unwrapped if requested).
        """
        ph = np.angle(self._z)
        if unwrap:
            ph = np.unwrap(ph)
        return ph

    # ---------------------------
    # Aggregate measures
    # ---------------------------

    def rms(self, *, mask: ArrayLikeF64 | None = None) -> float:
        """
        Root-mean-square magnitude.

        Parameters
        ----------
        mask : Optional[ArrayLikeF64]
            Optional boolean mask to include only selected subcarriers.

        Returns
        -------
        float
            sqrt(mean(|x|^2)) over masked (or all) samples.
        """
        p = self.power()
        if mask is not None:
            m = np.asarray(mask, dtype=bool)
            if m.shape != p.shape:
                raise ValueError("mask must match the number of samples.")
            p = p[m]
        if p.size == 0:
            return float("nan")
        return float(np.sqrt(np.mean(p)))

    def mean_power(self, *, mask: ArrayLikeF64 | None = None) -> float:
        """
        Mean linear power.

        Parameters
        ----------
        mask : Optional[ArrayLikeF64]
            Optional boolean mask to include only selected subcarriers.

        Returns
        -------
        float
            mean(|x|^2) over masked (or all) samples.
        """
        p = self.power()
        if mask is not None:
            m = np.asarray(mask, dtype=bool)
            if m.shape != p.shape:
                raise ValueError("mask must match the number of samples.")
            p = p[m]
        if p.size == 0:
            return float("nan")
        return float(np.mean(p))

    # ---------------------------
    # Transformations (return NEW instances)
    # ---------------------------

    def conj(self) -> ComplexArrayOps:
        """
        Complex conjugate per subcarrier.

        Returns
        -------
        ComplexArrayOps
            New instance y where y[k] = conj(x[k]).
        """
        obj = object.__new__(ComplexArrayOps)
        obj._z = np.conjugate(self._z)
        return obj

    def reciprocal(self, *, eps: float = 0.0) -> ComplexArrayOps:
        """
        Pointwise complex reciprocal.

        If eps > 0, use exact 1/z for bins with power > eps, and a guarded form
        conj(z)/( |z|^2 + eps ) only for near-zero bins. Runtime warnings for
        divide/invalid are suppressed (results are unchanged).
        """
        z = self._z
        if eps <= 0.0:
            with np.errstate(divide="ignore", invalid="ignore"):
                y = 1.0 / z
        else:
            p = z.real * z.real + z.imag * z.imag
            y = np.empty_like(z)
            mask = p > float(eps)
            with np.errstate(divide="ignore", invalid="ignore"):
                y[mask] = 1.0 / z[mask]
            y[~mask] = np.conjugate(z[~mask]) / (p[~mask] + float(eps))
        obj = object.__new__(ComplexArrayOps)
        obj._z = y
        return obj

    def scale(self, gain: Number) -> ComplexArrayOps:
        """
        Scale the complex vector by a real or complex gain.

        Parameters
        ----------
        gain : Number
            Scalar multiplier (real or complex).

        Returns
        -------
        ComplexArrayOps
            New instance y = gain * x.
        """
        obj = object.__new__(ComplexArrayOps)
        obj._z = np.asarray(gain, dtype=np.complex128) * self._z
        return obj

    def normalize_rms(self, *, target: float = 1.0, mask: ArrayLikeF64 | None = None) -> ComplexArrayOps:
        """
        Scale the vector so that RMS magnitude equals `target`.

        Parameters
        ----------
        target : float, default 1.0
            Desired RMS after scaling (linear).
        mask : Optional[ArrayLikeF64]
            If provided, RMS is computed on the masked subset; scaling is applied to all samples.

        Returns
        -------
        ComplexArrayOps
            New instance y = (target / rms(x[mask])) * x.

        Notes
        -----
        - If RMS is zero or NaN, returns a copy without scaling.
        """
        r = self.rms(mask=mask)
        if not np.isfinite(r) or r == 0.0:
            return self.copy()
        g = float(target) / r
        return self.scale(g)

    # ---------------------------
    # Frequency / time transforms
    # ---------------------------

    def fft(self, *, n: int | None = None, norm: str | None = None) -> ComplexArrayOps:
        """
        Discrete Fourier Transform (forward), returning a NEW instance.

        Parameters
        ----------
        n : Optional[int], default None
            FFT length. If None, uses len(x). If n > len(x), zero-pads; if n < len(x), truncates.
        norm : {None, 'ortho'}, default None
            Normalization mode (passed to numpy.fft.fft).

        Returns
        -------
        ComplexArrayOps
            Frequency-domain vector X[k] = FFT{x[n]}.
        """
        obj = object.__new__(ComplexArrayOps)
        obj._z = np.fft.fft(self._z, n=n, norm=norm)
        return obj

    def ifft(self, *, n: int | None = None, norm: str | None = None) -> ComplexArrayOps:
        """
        Inverse Discrete Fourier Transform (inverse), returning a NEW instance.

        Parameters
        ----------
        n : Optional[int], default None
            IFFT length. If None, uses len(X). If n > len(X), zero-pads; if n < len(X), truncates.
        norm : {None, 'ortho'}, default None
            Normalization mode (passed to numpy.fft.ifft).

        Returns
        -------
        ComplexArrayOps
            Time-domain vector x[n] = IFFT{X[k]}.
        """
        obj = object.__new__(ComplexArrayOps)
        obj._z = np.fft.ifft(self._z, n=n, norm=norm)
        return obj

    # ---------------------------
    # Real/imag accessors
    # ---------------------------

    def real(self) -> ArrayLikeF64:
        """
        Real part per subcarrier.

        Returns
        -------
        np.ndarray
            Re{x[k]} for each k.
        """
        return self._z.real

    def imag(self) -> ArrayLikeF64:
        """
        Imaginary part per subcarrier.

        Returns
        -------
        np.ndarray
            Im{x[k]} for each k.
        """
        return self._z.imag

# FILE: tests/test_complex_array_ops.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

# tests/test_complex_array_ops.py
from __future__ import annotations

import math

import numpy as np
import pytest

from pypnm.lib.signal_processing.complex_array_ops import ComplexArrayOps


def pairs(*vals: float) -> list[tuple[float, float]]:
    """Build (re, im) pairs from flat numbers: r1,i1,r2,i2,..."""
    assert len(vals) % 2 == 0
    it = iter(vals)
    return [(float(r), float(i)) for r, i in zip(it, it)]


def test_init_and_len_and_repr() -> None:
    x = pairs(1, 0, 0, 1, -1, 0)
    ops = ComplexArrayOps(x)
    assert len(ops) == 3
    r = repr(ops)
    assert "ComplexArrayOps" in r
    assert "RMS=" in r and "MeanPwr=" in r


def test_invalid_shape_raises() -> None:
    with pytest.raises(ValueError):
        ComplexArrayOps([(1.0,)] * 2)
    with pytest.raises(ValueError):
        ComplexArrayOps([])


def test_as_array_and_to_pairs_roundtrip() -> None:
    x = pairs(1, 2, 3, 4, -5, 0)
    ops = ComplexArrayOps(x)
    arr = ops.as_array()
    assert arr.dtype == np.complex128
    assert np.allclose(arr.real, [1, 3, -5])
    assert np.allclose(arr.imag, [2, 4, 0])

    back = ops.to_pairs()
    assert back == x


def test_magnitude_power_and_db() -> None:
    x = pairs(3, 4, 0, 0)
    ops = ComplexArrayOps(x)

    mag = ops.magnitude()
    pwr = ops.power()
    pwr_db = ops.power_db()
    pwr_db_eps = ops.power_db(eps=1e-12)
    pwr_db_epsilon = ops.power_db(epsilon=1e-12)
    pwr_db_mean = ops.power_db_normalized(normalize="mean")
    pwr_db_unit = ops.power_db_normalized(normalize="unit")

    assert np.allclose(mag, [5.0, 0.0])
    assert np.allclose(pwr, [25.0, 0.0])

    assert np.isfinite(pwr_db[1])
    assert pwr_db[0] > pwr_db[1]
    assert np.allclose(pwr_db_eps, pwr_db_epsilon)
    assert np.isclose(float(np.mean(pwr_db_mean)), 0.0, atol=1e-12)
    assert np.isfinite(pwr_db_unit).all()


def test_phase_and_unwrap() -> None:
    # With default discont=π, unwrap does NOT add 2π for jump exactly π
    x = pairs(1, 0, -1, 0, 1, 0)
    ops = ComplexArrayOps(x)
    ph = ops.phase()
    ph_u = ops.phase(unwrap=True)

    assert np.allclose(ph, [0.0, np.pi, 0.0])
    assert np.allclose(ph_u, [0.0, np.pi, 0.0])


def test_power_db_normalized_unit_mean_matches_expected() -> None:
    x = pairs(1, 0, 2, 0)
    ops = ComplexArrayOps(x)

    pwr_db_unit = ops.power_db_normalized(normalize="unit", epsilon=1e-12)
    pwr_linear = 10.0 ** (pwr_db_unit / 10.0)
    assert np.isclose(float(np.mean(pwr_linear)), 1.0, atol=1e-12)

    with pytest.raises(ValueError):
        ops.power_db_normalized(normalize="bad-mode")


def test_rms_and_mean_power_with_mask() -> None:
    x = pairs(1, 0, 0, 2, 0, 0)  # powers: 1, 4, 0 → mean=5/3
    ops = ComplexArrayOps(x)

    assert ops.mean_power() == pytest.approx(5.0 / 3.0, abs=1e-12)
    assert ops.rms() == pytest.approx(math.sqrt(5.0 / 3.0), abs=1e-12)

    mask = np.array([True, False, True])
    assert ops.mean_power(mask=mask) == pytest.approx(0.5, abs=1e-12)
    assert ops.rms(mask=mask) == pytest.approx(math.sqrt(0.5), abs=1e-12)

    with pytest.raises(ValueError):
        ops.mean_power(mask=[True])


def test_conjugate_and_scale() -> None:
    x = pairs(1, -2, -3, 4)
    ops = ComplexArrayOps(x)

    conj = ops.conj()
    assert np.allclose(conj.as_array(), np.conjugate(ops.as_array()))
    assert not np.shares_memory(conj.as_array(), ops.as_array())

    scaled = ops.scale(2.0 - 1.0j)
    assert np.allclose(scaled.as_array(), (2.0 - 1.0j) * ops.as_array())

    def test_reciprocal_exact_and_eps() -> None:
        x = pairs(1, 0, 0, 1, 0, 0)
        ops = ComplexArrayOps(x)

        inv = ops.reciprocal()

        # Silence intentional divide-by-zero for the zero sample
        with np.errstate(divide="ignore", invalid="ignore"):
            target = 1.0 / ops.as_array()  # inf+nanj for the last zero sample

        assert np.allclose(inv.as_array(), target, equal_nan=True)

        inv_eps = ops.reciprocal(eps=1e-9)
        assert np.isfinite(inv_eps.as_array()[-1])
        assert np.allclose(inv_eps.as_array()[:-1], target[:-1], rtol=1e-12, atol=1e-12)

def test_normalize_rms_global_and_masked() -> None:
    x = pairs(3, 4, 0, 0)  # RMS = 5/sqrt(2)
    ops = ComplexArrayOps(x)

    target = 1.0
    norm = ops.normalize_rms(target=target)
    assert norm.rms() == pytest.approx(target, abs=1e-12)

    mask = np.array([True, False])
    norm_m = ops.normalize_rms(target=2.0, mask=mask)
    assert norm_m.rms(mask=mask) == pytest.approx(2.0, abs=1e-12)


def test_fft_ifft_roundtrip() -> None:
    x = np.zeros((8, 2), dtype=float)
    x[0] = (1.0, 0.0)
    ops = ComplexArrayOps([tuple(row) for row in x])

    X = ops.fft()
    x_rt = X.ifft()
    assert np.allclose(x_rt.as_array(), ops.as_array(), atol=1e-12)


def test_real_imag_accessors() -> None:
    x = pairs(1.2, -3.4, 5.6, 7.8)
    ops = ComplexArrayOps(x)
    assert np.allclose(ops.real(), [1.2, 5.6])
    assert np.allclose(ops.imag(), [-3.4, 7.8])


def test_copy_is_independent() -> None:
    x = pairs(1, 2, 3, 4)
    ops = ComplexArrayOps(x)
    cpy = ops.copy()
    assert np.allclose(cpy.as_array(), ops.as_array())
    cpy_scaled = cpy.scale(2.0)
    assert np.allclose(ops.as_array(), np.array([1 + 2j, 3 + 4j], dtype=np.complex128))
    assert np.allclose(cpy_scaled.as_array(), 2.0 * cpy.as_array())
