# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Literal

import numpy as np

from pypnm.lib.types import ArrayLike, NDArrayF64, Number

__all__ = ["SignalCaptureAggregator"]


class SignalCaptureAggregator:
    """
    Aggregate (x, y) points from multiple spectrum-like captures onto a continuous grid.

    Features
    --------
    - Accepts floating-point x-values (e.g., frequency in Hz).
    - Fills gaps using a uniform grid (step inferred from data or provided by the user).
    - Handles duplicate/overlapping x-values with a configurable reducer.
    - Exposes NumPy float64 arrays for downstream analysis/plotting.

    Parameters
    ----------
    reducer : {"mean","max","min","sum"} | Callable[[NDArrayF64], float], optional
        How to reduce multiple y-values that map to the same grid x. Default: "mean".
    fill_value : float, optional
        Value to use for missing points when filling gaps. Default: 0.0.
    logger_name : str, optional
        Custom logger name. Defaults to class name.
    """

    __slots__ = (
        "logger",
        "_points",
        "_grid_x",
        "_grid_y",
        "_reconstructed",
        "_reducer",
        "_fill_value",
    )

    def __init__(
        self,
        *,
        reducer: Literal["mean", "max", "min", "sum"]
        | Callable[[NDArrayF64], float] = "mean",
        fill_value: float = 0.0,
        logger_name: str | None = None,
    ) -> None:
        self.logger = logging.getLogger(logger_name or self.__class__.__name__)
        # Store raw points: x -> list[y] (to allow duplicate inserts before reduction)
        self._points: dict[float, list[float]] = {}
        # Reconstructed grid (set by reconstruct)
        self._grid_x: NDArrayF64 | None = None
        self._grid_y: NDArrayF64 | None = None
        self._reconstructed: bool = False
        self._reducer = self._resolve_reducer(reducer)
        self._fill_value = float(fill_value)

    # --------------------------------------------------------------------- #
    # Public API
    # --------------------------------------------------------------------- #
    def add_coordinate(self, x: Number, y: Number) -> None:
        """
        Add a single (x, y) point. Multiple points at the same x are allowed.
        """
        try:
            xf = float(x)
            yf = float(y)
        except Exception as exc:
            self.logger.warning("Skipping non-numeric point (%r, %r): %s", x, y, exc)
            return

        if not (np.isfinite(xf) and np.isfinite(yf)):
            self.logger.warning("Skipping non-finite point (%r, %r)", x, y)
            return

        bucket = self._points.setdefault(xf, [])

        if bucket:
            self.logger.debug(
                "Adding additional sample at x=%s (existing %d)", xf, len(bucket)
            )

        bucket.append(yf)

        self.logger.debug(
            "Added point (%g, %g) to aggregator (total points: %d)",
            xf,
            yf,
            len(self._points),
        )

        self._reconstructed = False  # invalidates any prior grid

    def add_series(self, xs: ArrayLike, ys: ArrayLike) -> None:
        """
        Bulk add series of coordinates.
        """
        xa = np.asarray(xs, dtype=np.float64)
        ya = np.asarray(ys, dtype=np.float64)
        if xa.shape != ya.shape:
            raise ValueError("add_series: xs and ys must have same shape")
        mask = np.isfinite(xa) & np.isfinite(ya)
        if not mask.any():
            self.logger.warning("add_series: no finite points to add")
            return
        for xf, yf in zip(xa[mask], ya[mask], strict=False):
            self.add_coordinate(xf, yf)

    def reconstruct(
        self,
        *,
        step: float | None = None,
        tolerance: float | None = None,
        fill_value: float | None = None,
        reducer: Callable[[NDArrayF64], float] | None = None,
    ) -> tuple[NDArrayF64, NDArrayF64]:
        """
        Build a continuous (grid_x, grid_y) representation.

        Parameters
        ----------
        step : float, optional
            Grid spacing. If None, inferred from the median of positive diffs in sorted x.
        tolerance : float, optional
            Max absolute deviation allowed when snapping points to grid (default: step/2).
        fill_value : float, optional
            Override default fill value for missing bins.
        reducer : Callable, optional
            Override the configured reducer for this reconstruction only.

        Returns
        -------
        (grid_x, grid_y) : tuple of NDArrayF64
        """
        if not self._points:
            self.logger.info("reconstruct: no data points; returning empty arrays")
            self._grid_x = np.asarray([], dtype=np.float64)
            self._grid_y = np.asarray([], dtype=np.float64)
            self._reconstructed = True
            return self._grid_x, self._grid_y

        x_sorted = np.array(sorted(self._points.keys()), dtype=np.float64)

        # Infer step if not provided: robust to outliers via median of positive diffs
        if step is None:
            diffs = np.diff(x_sorted)
            pos = diffs[diffs > 0]
            if pos.size == 0:
                raise ValueError("Cannot infer step: all x are identical")
            step = float(np.median(pos))
            self.logger.info("reconstruct: inferred step = %g", step)

        if not np.isfinite(step) or step <= 0.0:
            raise ValueError(f"Invalid step: {step!r}")

        tol = float(step / 2.0) if tolerance is None else float(tolerance)
        if tol <= 0.0:
            raise ValueError(f"Invalid tolerance: {tol!r}")

        fill = self._fill_value if fill_value is None else float(fill_value)
        reduce_fn = self._reducer if reducer is None else reducer

        xmin, xmax = float(x_sorted[0]), float(x_sorted[-1])
        # Build grid; + step*0.5 guard to include the last point due to fp rounding
        n_bins = int(np.floor((xmax - xmin) / step + 0.5)) + 1
        grid_x = xmin + step * np.arange(n_bins, dtype=np.float64)
        grid_y = np.full_like(grid_x, fill, dtype=np.float64)

        # Accumulate samples per bin
        bins: list[list[float]] = [[] for _ in range(n_bins)]

        for x_val, y_list in self._points.items():
            # snap x to nearest grid index
            idx_float = (x_val - xmin) / step
            idx = int(np.rint(idx_float))
            # ensure within bounds and within tolerance
            if 0 <= idx < n_bins and abs(grid_x[idx] - x_val) <= tol:
                bins[idx].extend(y_list)
            else:
                # Out of tolerance: create a new bin if it falls just outside?
                # For now, log and skip to keep grid strict.
                self.logger.debug(
                    "Point x=%g did not fit grid (idx_float=%.3f, idx=%d, snap=%g, tol=%g)",
                    x_val,
                    idx_float,
                    idx,
                    grid_x[idx] if 0 <= idx < n_bins else float("nan"),
                    tol,
                )

        # Reduce each bin
        for i, bucket in enumerate(bins):
            if bucket:
                grid_y[i] = float(reduce_fn(np.asarray(bucket, dtype=np.float64)))

        self._grid_x, self._grid_y = grid_x, grid_y
        self._reconstructed = True
        self.logger.info(
            "Reconstruction complete: %d bins (step=%g, tol=%g)", n_bins, step, tol
        )
        return grid_x, grid_y

    def get_series(self) -> tuple[NDArrayF64, NDArrayF64]:
        """
        Return (x, y) as arrays.
        - If reconstruct() has been called: returns (grid_x, grid_y).
        - Else: returns raw sorted points (unique x), y reduced per x using the configured reducer.
        """
        if (
            self._reconstructed
            and self._grid_x is not None
            and self._grid_y is not None
        ):
            return self._grid_x, self._grid_y

        if not self._points:
            return np.asarray([], dtype=np.float64), np.asarray([], dtype=np.float64)

        xs = np.array(sorted(self._points.keys()), dtype=np.float64)
        ys = np.array(
            [self._reducer(np.asarray(self._points[x], dtype=np.float64)) for x in xs],
            dtype=np.float64,
        )
        return xs, ys

    def clear(self) -> None:
        """Remove all stored points and any reconstructed grid."""
        self._points.clear()
        self._grid_x = None
        self._grid_y = None
        self._reconstructed = False

    def __len__(self) -> int:
        """Number of unique x values currently stored (raw, before reconstruction)."""
        return len(self._points)

    # --------------------------------------------------------------------- #
    # Internals
    # --------------------------------------------------------------------- #
    @staticmethod
    def _resolve_reducer(
        reducer: Literal["mean", "max", "min", "sum"] | Callable[[NDArrayF64], float],
    ) -> Callable[[NDArrayF64], float]:
        if callable(reducer):
            return reducer
        table: dict[str, Callable[[NDArrayF64], float]] = {
            "mean": lambda a: float(np.mean(a)) if a.size else 0.0,
            "max": lambda a: float(np.max(a)) if a.size else 0.0,
            "min": lambda a: float(np.min(a)) if a.size else 0.0,
            "sum": lambda a: float(np.sum(a)) if a.size else 0.0,
        }
        try:
            return table[reducer]
        except KeyError as err:
            raise ValueError(f"Unknown reducer: {reducer!r}") from err
