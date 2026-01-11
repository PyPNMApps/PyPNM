# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

# (c) 2025 Maurice Garcia

from __future__ import annotations

from typing import Any

import numpy as np

from pypnm.lib.types import ArrayLike


class NumericScaler:
    """
    Scale numeric data for plotting (e.g., 300_000_000 -> 300 with 'M').

    Features
    --------
    - SI scaling: prefixes like k (1e3), M (1e6), G (1e9), etc.
    - Binary scaling (optional): Ki, Mi, Gi (powers of 1024)
    - Auto scaling to a readable magnitude using max/median strategy
    - Friendly metadata for axis labels (prefix symbol and ×10^n form)
    - Lightweight: minimal validation, tolerant of lists/np arrays/empty input

    Quick examples
    --------------
    >>> s = NumericScaler()
    >>> vals = [1200000, 300000000, 51000000]
    >>> scaled, meta = s.to_prefix(vals, target="M")  # divide by 1e6
    >>> scaled[:2], meta["prefix"], meta["exp"]
    ([1.2, 300.0], 'M', 6)

    Auto choose a nice scale:
    >>> scaled, meta = s.auto(vals)  # picks M here
    >>> meta
    {'system': 'si', 'prefix': 'M', 'exp': 6, 'factor': 1000000.0, 'style': 'prefix', 'label': 'M', 'power_label': '×10^6'}

    Make an axis label:
    >>> y_label = s.format_axis_label("Throughput", unit="bps", meta=meta, style="prefix")
    >>> y_label
    'Throughput (M bps)'
    """

    # SI exponents in steps of 3
    _SI_EXP_BY_PREFIX = {
        "y": -24,
        "z": -21,
        "a": -18,
        "f": -15,
        "p": -12,
        "n": -9,
        "µ": -6,
        "u": -6,
        "m": -3,
        "": 0,
        "k": 3,
        "K": 3,
        "M": 6,
        "G": 9,
        "T": 12,
        "P": 15,
    }
    _SI_SYNONYMS = {
        "thousand": "k",
        "kilo": "k",
        "meg": "M",
        "mega": "M",
        "million": "M",
        "giga": "G",
        "billion": "G",
        "tera": "T",
        "trillion": "T",
        "micro": "µ",
        "micros": "µ",
        "u": "µ",
    }

    # Binary (powers of 1024)
    _BIN_EXP_BY_PREFIX = {"": 0, "Ki": 10, "Mi": 20, "Gi": 30, "Ti": 40}

    def __init__(self, *, default_system: str = "si") -> None:
        """
        Args:
            default_system: 'si' or 'binary'
        """
        self.default_system = (
            "binary" if default_system.lower().startswith("bin") else "si"
        )

    # ----------------- core helpers -----------------
    @staticmethod
    def _to_1d(values: ArrayLike | None) -> np.ndarray:
        if values is None:
            return np.array([], dtype=float)
        return np.asarray(values, dtype=float).ravel()

    @staticmethod
    def _exp_to_factor(exp: int, base: int = 10) -> float:
        return float(base) ** exp

    @classmethod
    def _normalize_prefix(cls, p: str | None, system: str) -> tuple[str, int]:
        """Return (canonical_prefix, exponent) for given prefix/synonym."""
        if p is None or p == "":
            return ("", 0)

        if system == "binary":
            if p in cls._BIN_EXP_BY_PREFIX:
                return p, cls._BIN_EXP_BY_PREFIX[p]
            # Be forgiving: accept lower-cased 'mi', 'gi'
            p2 = p.strip()
            p2 = p2[0].upper() + "i" if len(p2) == 2 else p2
            exp = cls._BIN_EXP_BY_PREFIX.get(p2, 0)
            return (p2 if exp else "", exp)

        # SI
        p2 = p.strip()
        # synonyms like "meg", "million", etc.
        p2 = cls._SI_SYNONYMS.get(p2.lower(), p2)
        exp = cls._SI_EXP_BY_PREFIX.get(p2, 0)
        return (p2 if p2 in cls._SI_EXP_BY_PREFIX else "", exp)

    @staticmethod
    def _exp_to_prefix(exp: int, system: str) -> str:
        if system == "binary":
            table = {v: k for k, v in NumericScaler._BIN_EXP_BY_PREFIX.items()}
            return table.get(exp, "")
        table = {v: k for k, v in NumericScaler._SI_EXP_BY_PREFIX.items()}
        return table.get(exp, "")

    @staticmethod
    def _power_label(exp: int) -> str:
        return f"×10^{exp}"

    # ----------------- public API -----------------
    def to_prefix(
        self,
        values: ArrayLike,
        *,
        target: str | None = None,
        system: str | None = None,
    ) -> tuple[np.ndarray, dict[str, Any]]:
        """
        Scale `values` so numbers are expressed in the `target` prefix.

        Examples:
            300_000_000 -> 300 with target='M' (SI)
            8_388_608   -> 8 with target='Mi' (binary)
        """
        sys = (system or self.default_system).lower()
        sys = "binary" if sys.startswith("bin") else "si"
        _, exp = self._normalize_prefix(target, sys)
        if sys == "binary":
            factor = self._exp_to_factor(exp, base=2)
        else:
            factor = self._exp_to_factor(exp, base=10)
        arr = self._to_1d(values) / factor if factor else self._to_1d(values)

        meta = {
            "system": sys,
            "prefix": self._exp_to_prefix(exp, sys),
            "exp": exp if sys == "si" else exp,  # exp is bits for binary (10,20,30)
            "factor": factor if factor else 1.0,
            "style": "prefix",
            "label": self._exp_to_prefix(exp, sys),
            "power_label": self._power_label(exp if sys == "si" else 0)
            if sys == "si"
            else None,
        }
        return arr, meta

    def convert(
        self,
        values: ArrayLike,
        *,
        from_prefix: str | None = None,
        to_prefix: str | None = None,
        system: str | None = None,
    ) -> tuple[np.ndarray, dict[str, Any]]:
        """
        Convert from one prefix to another (e.g., from 'M' to 'k').

        Example:
            values are in 'M' (millions) and you want 'k' (thousands):
            convert(vals, from_prefix='M', to_prefix='k')  # multiply by 1e6 / 1e3 = 1e3
        """
        sys = (system or self.default_system).lower()
        sys = "binary" if sys.startswith("bin") else "si"

        fp, fexp = self._normalize_prefix(from_prefix, sys)
        tp, texp = self._normalize_prefix(to_prefix, sys)

        if sys == "binary":
            f_factor = self._exp_to_factor(fexp, base=2)
            t_factor = self._exp_to_factor(texp, base=2)
        else:
            f_factor = self._exp_to_factor(fexp, base=10)
            t_factor = self._exp_to_factor(texp, base=10)

        arr = self._to_1d(values) * (f_factor / (t_factor or 1.0))

        meta = {
            "system": sys,
            "from_prefix": fp,
            "to_prefix": tp,
            "exp_delta": (fexp - texp),
            "factor": (f_factor / (t_factor or 1.0)),
            "style": "prefix",
            "label": tp,
            "power_label": self._power_label(texp)
            if (sys == "si" and tp != "")
            else ("" if sys == "si" else None),
        }
        return arr, meta

    def auto(
        self,
        values: ArrayLike,
        *,
        system: str | None = None,
        target_range: tuple[float, float] = (1.0, 999.9),
        strategy: str = "max",
    ) -> tuple[np.ndarray, dict[str, Any]]:
        """
        Choose a prefix so scaled data falls into `target_range`.

        Args:
            system: 'si' or 'binary' (defaults to self.default_system)
            target_range: desired [min, max] for |data| using chosen prefix
            strategy: 'max' (use max abs) or 'median' (use median abs)

        Returns:
            (scaled_values, meta)
        """
        sys = (system or self.default_system).lower()
        sys = "binary" if sys.startswith("bin") else "si"

        arr = self._to_1d(values)
        if arr.size == 0:
            return arr, {
                "system": sys,
                "prefix": "",
                "exp": 0,
                "factor": 1.0,
                "style": "prefix",
                "label": "",
                "power_label": "",
            }

        mag = np.nanmax(np.abs(arr)) if strategy == "max" else np.nanmedian(np.abs(arr))
        if mag == 0 or not np.isfinite(mag):
            exp = 0
        else:
            if sys == "binary":
                # base 2, snap to multiples of 10 for Ki, Mi, Gi
                exp = int(np.floor(np.log2(mag)))
                exp = int(np.floor(exp / 10) * 10)
                exp = np.clip(exp, 0, 40)  # "", Ki, Mi, Gi, Ti
                factor = 2.0**exp
            else:
                # base 10, step by 3 (…, k=1e3, M=1e6, G=1e9, …)
                exp = int(np.floor(np.log10(mag)))
                exp = int(np.floor(exp / 3) * 3)
                exp = int(np.clip(exp, -24, 15))
                factor = 10.0**exp

            # If after scaling the max is still outside target_range, nudge exp
            scaled_peak = mag / factor
            if scaled_peak < target_range[0] and sys == "si":
                exp = max(exp - 3, -24)
            elif scaled_peak > target_range[1] and sys == "si":
                exp = min(exp + 3, 15)
            elif sys == "binary":
                if scaled_peak < target_range[0]:
                    exp = max(exp - 10, 0)
                elif scaled_peak > target_range[1]:
                    exp = min(exp + 10, 40)

        factor = 2.0**exp if sys == "binary" else 10.0**exp

        scaled = arr / factor
        meta = {
            "system": sys,
            "prefix": self._exp_to_prefix(exp, sys),
            "exp": exp,
            "factor": factor,
            "style": "prefix",
            "label": self._exp_to_prefix(exp, sys),
            "power_label": self._power_label(exp)
            if sys == "si" and exp != 0
            else ("" if sys == "si" else None),
        }
        return scaled, meta

    # ----------------- labels -----------------
    @staticmethod
    def format_axis_label(
        base: str,
        *,
        unit: str | None = None,
        meta: dict[str, Any] | None = None,
        style: str = "prefix",
    ) -> str:
        """
        Build a human-friendly axis label using scaling metadata.

        Args:
            base: base label, e.g. 'Throughput'
            unit: optional unit, e.g. 'bps'
            meta: dict returned by to_prefix/convert/auto
            style: 'prefix' => '(M bps)', 'power' => '(×10^6 bps)'

        Returns:
            Combined label string.
        """
        if not meta:
            return f"{base}" + (f" ({unit})" if unit else "")
        if style == "power" and meta.get("power_label"):
            suffix = f"{meta['power_label']}" + (f" {unit}" if unit else "")
        else:
            lab = meta.get("label") or ""
            suffix = (lab + (f" {unit}" if unit else "")).strip()
        return f"{base}" + (f" ({suffix})" if suffix else "")
