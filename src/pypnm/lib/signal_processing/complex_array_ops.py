# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

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
            raise ValueError(
                f"{name} must be a sequence of (real, imag) pairs; got shape {a.shape}"
            )
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
        self, *, eps: float = float(np.finfo(np.float64).tiny)
    ) -> ArrayLikeF64:
        """
        Power per subcarrier in dB.

        Parameters
        ----------
        eps : float, default np.finfo(float64).tiny
            Small positive floor added to power to avoid log(0).

        Returns
        -------
        np.ndarray
            10*log10(|x[k]|^2 + eps) for each k.
        """
        p = np.asarray(self.power(), dtype=np.float64)
        return 10.0 * np.log10(p + float(eps))

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

    def normalize_rms(
        self, *, target: float = 1.0, mask: ArrayLikeF64 | None = None
    ) -> ComplexArrayOps:
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
