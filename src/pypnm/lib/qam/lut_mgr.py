# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from typing import Literal, cast

import numpy as np

from pypnm.lib.qam.code_generator.auto_gen_qam_lut import QamScale
from pypnm.lib.qam.qam_lut import QAM_SYMBOL_CODEWORD_LUT
from pypnm.lib.qam.types import (
    CodeWord,
    HardDecisionArray,
    LutDict,
    QamModulation,
    SoftDecisionArray,
    SymbolArray,
)


class QamLutManager:
    """
    Accessor/utility for QAM constellation lookup tables (LUTs).

    This manager exposes:
      - Hard-decision reference points per modulation.
      - Codeword→symbol and symbol→codeword mappings.
      - A per-modulation normalization scale factor.
      - Soft-decision scaling helpers.
      - A simple heuristic to infer the likely modulation order from samples.

    Attributes
    ----------
    qam_lut : LutDict
        Global LUT mapping modulation keys (e.g., "QAM_256") to dictionaries
        containing:
          * "hard": List[(I, Q)]
          * "code_words": Dict[int, (I, Q)]
          * "scale_factor": float-like
    """

    def __init__(self) -> None:
        """
        Initialize the QAM LUT manager.

        Notes
        -----
        The instance binds to the global `QAM_SYMBOL_CODEWORD_LUT`. It does not
        copy or mutate the LUT.
        """
        self.qam_lut: LutDict = QAM_SYMBOL_CODEWORD_LUT

    def _lut_key(self, qam_mod: QamModulation) -> str:
        """
        Return the canonical LUT key for a modulation enum.

        Parameters
        ----------
        qam_mod : QamModulation
            Modulation order enum (e.g., QamModulation.QAM_256).

        Returns
        -------
        str
            LUT key string (e.g., "QAM_256").

        Notes
        -----
        The current LUT is keyed by `Enum.name`, not the integer value.
        """
        return str(qam_mod.name)

    def get_hard_decisions(self, qam_mod: QamModulation) -> HardDecisionArray:
        """
        Get the hard-decision (reference) constellation points for a modulation.

        Parameters
        ----------
        qam_mod : QamModulation
            Modulation order enum.

        Returns
        -------
        HardDecisionArray
            List of reference points [(I, Q), ...]. Empty if not present.

        Raises
        ------
        KeyError
            If the LUT does not contain the specified modulation key.
        """
        key = self._lut_key(qam_mod)
        return self.qam_lut[key].get("hard", [])

    def get_codeword_symbol(
        self,
        qam_mod: QamModulation,
        code_word: CodeWord,
        *,
        bit_order: Literal["msb", "lsb"] = "msb",
    ) -> SymbolArray:
        """
        Map a packed integer codeword to one or more constellation symbols.

        Parameters
        ----------
        qam_mod : QamModulation
            Modulation order enum.
        code_word : CodeWord
            Packed bits representing one or more symbols.
        bit_order : {"msb", "lsb"}, default "msb"
            Chunking order when splitting the packed bits into `bits_per_symbol`
            fields. "msb" consumes the most-significant bits first; "lsb" consumes
            the least-significant bits first.

        Returns
        -------
        SymbolArray
            List of (I, Q) tuples (one per derived symbol).

        Raises
        ------
        ValueError
            If the LUT entry is missing or malformed.
        KeyError
            If a derived per-symbol codeword is not found in the LUT.

        Notes
        -----
        `bits_per_symbol` is inferred from the LUT codeword keys. If the key
        set is dense (0..2^k-1), `k` is used; otherwise falls back to the bit
        length of the maximum key.
        """
        key = self._lut_key(qam_mod)
        entry = self.qam_lut.get(key)
        if not entry or "code_words" not in entry:
            raise ValueError(f"Missing 'code_words' LUT for {qam_mod.name}")

        lut = entry["code_words"]
        if not isinstance(lut, dict) or not lut:
            raise ValueError(f"Empty or invalid 'code_words' LUT for {qam_mod.name}")

        keys_sorted = sorted(lut.keys())
        bits_per_symbol = self._infer_bits_per_symbol(keys_sorted)

        mask = (1 << bits_per_symbol) - 1
        total_bits = max(1, code_word.bit_length())
        n_syms = (total_bits + bits_per_symbol - 1) // bits_per_symbol

        symbols: SymbolArray = []

        if bit_order == "msb":
            s = bin(code_word)[2:]
            total_bits_padded = n_syms * bits_per_symbol
            if len(s) < total_bits_padded:
                s = "0" * (total_bits_padded - len(s)) + s
            for i in range(n_syms):
                chunk = s[i * bits_per_symbol : (i + 1) * bits_per_symbol]
                cw = int(chunk, 2)
                symbols.append(self._lookup_symbol(lut, cw))
        else:
            value = code_word
            for i in range(n_syms):
                cw = (value >> (i * bits_per_symbol)) & mask
                symbols.append(self._lookup_symbol(lut, cw))

        return symbols

    def get_scale_factor(self, qam_mod: QamModulation) -> QamScale:
        """
        Return the modulation-specific normalization scale factor.

        Parameters
        ----------
        qam_mod : QamModulation
            Modulation order enum.

        Returns
        -------
        QamScale
            Scale factor stored in the LUT for the given modulation.

        Raises
        ------
        KeyError
            If the LUT does not contain the specified modulation key.
        """
        key = self._lut_key(qam_mod)
        entry = self.qam_lut.get(key)
        return cast(QamScale, entry["scale_factor"])

    def scale_soft_decisions(
        self, qam_mod: QamModulation, soft: SoftDecisionArray
    ) -> SoftDecisionArray:
        """
        Scale soft-decision points using the LUT's scale_factor.

        Accepts both conventions:
        - Multiplier convention (≤1): values are multiplied directly.
        - Amplitude convention (>1): values are divided (invert to multiplier).

        Returns normalized (I, Q) pairs.
        """
        if not soft:
            return []
        raw_scale = float(self.get_scale_factor(qam_mod))
        scale = (1.0 / raw_scale) if raw_scale > 1.0 else raw_scale
        a = np.asarray(soft, dtype=np.float64)
        if a.ndim != 2 or a.shape[1] != 2:
            raise ValueError(
                f"soft must be a sequence of (I, Q) pairs; got shape {a.shape}"
            )
        a = a * scale
        return [(float(re), float(im)) for re, im in a]

    def get_symbol_codeword(
        self, qam_mod: QamModulation, symbol: tuple[float, float]
    ) -> CodeWord | None:
        """
        Reverse-map a constellation point to the nearest LUT codeword.

        Parameters
        ----------
        qam_mod : QamModulation
            Modulation order enum.
        symbol : tuple[float, float]
            (I, Q) coordinate to resolve.

        Returns
        -------
        Optional[CodeWord]
            Matching codeword if an exact or near-exact hit is found; otherwise `None`.

        Raises
        ------
        ValueError
            If the LUT for the modulation is missing or malformed.

        Notes
        -----
        The method first tries an exact match. If none is found, it searches the
        nearest neighbor in Euclidean distance and accepts it when within a small
        tolerance derived from the mean step between unique axis levels.
        """
        key = self._lut_key(qam_mod)
        entry = self.qam_lut.get(key)
        if not entry or "code_words" not in entry:
            raise ValueError(f"No LUT 'code_words' found for {qam_mod.name}")

        lut = entry["code_words"]
        if not lut:
            return None

        i_in, q_in = float(symbol[0]), float(symbol[1])
        for codeword, (i_ref, q_ref) in lut.items():
            if i_in == i_ref and q_in == q_ref:
                return codeword

        ref_points = np.array(list(lut.values()), dtype=np.float64)
        code_keys = np.array(list(lut.keys()), dtype=np.int32)
        deltas = ref_points - np.array([i_in, q_in])
        dist_sq = np.sum(deltas**2, axis=1)
        nearest_idx = int(np.argmin(dist_sq))
        min_dist = float(np.sqrt(dist_sq[nearest_idx]))

        flat = np.unique(ref_points.flatten())
        if flat.size >= 2:
            spacing = np.mean(np.diff(flat))
            tol = spacing * 0.05
        else:
            tol = 0.0

        if min_dist <= tol:
            return int(code_keys[nearest_idx])
        return None

    def infer_modulation_order(
        self, samples: SymbolArray, threshold: float = 0.15
    ) -> QamModulation:
        """
        Heuristically infer the QAM order from observed constellation samples.

        Parameters
        ----------
        samples : SymbolArray
            Observed soft or hard constellation samples [(I, Q), ...].
        threshold : float, default 0.15
            Grid step (post-normalization) used to quantize samples for cluster
            counting. Larger values produce fewer clusters; smaller values
            produce more.

        Returns
        -------
        QamModulation
            The closest standard order by cluster count, or UNKNOWN if the
            deviation is too large.

        Notes
        -----
        This is a coarse heuristic:
          1) Normalize samples by mean radius.
          2) Snap to a coarse grid (`threshold` step).
          3) Count unique positions as clusters.
          4) Choose the order with cluster count nearest to a known size.

        If the relative error exceeds 25%, the method returns UNKNOWN.
        """
        if not samples:
            return QamModulation.UNKNOWN

        pts = np.asarray(samples, dtype=np.float64)
        if pts.ndim != 2 or pts.shape[1] != 2:
            return QamModulation.UNKNOWN

        norms = np.sqrt(np.sum(pts**2, axis=1))
        m = float(np.mean(norms)) if norms.size else 0.0
        if not np.isfinite(m) or m <= 0.0:
            return QamModulation.UNKNOWN
        pts = pts / m

        grid = np.round(pts / threshold) * threshold
        unique_clusters = int(len(np.unique(grid, axis=0)))

        mapping = {
            2: QamModulation.QAM_2,
            4: QamModulation.QAM_4,
            8: QamModulation.QAM_8,
            16: QamModulation.QAM_16,
            32: QamModulation.QAM_32,
            64: QamModulation.QAM_64,
            128: QamModulation.QAM_128,
            256: QamModulation.QAM_256,
            512: QamModulation.QAM_512,
            1024: QamModulation.QAM_1024,
            2048: QamModulation.QAM_2048,
            4096: QamModulation.QAM_4096,
            8192: QamModulation.QAM_8192,
            16384: QamModulation.QAM_16384,
            32768: QamModulation.QAM_32768,
            65536: QamModulation.QAM_65536,
        }

        closest_order, est_mod = min(
            mapping.items(), key=lambda kv: abs(unique_clusters - kv[0])
        )

        diff_ratio = abs(unique_clusters - closest_order) / float(closest_order)
        if diff_ratio > 0.25:
            return QamModulation.UNKNOWN
        return est_mod

    @staticmethod
    def _infer_bits_per_symbol(keys_sorted: list[int]) -> int:
        """
        Infer bits-per-symbol from the LUT codeword key set.

        Parameters
        ----------
        keys_sorted : list[int]
            Sorted list of integer codeword keys present in the LUT.

        Returns
        -------
        int
            Bits per symbol (`k`).

        Raises
        ------
        ValueError
            If the key list is empty.

        Notes
        -----
        If keys form a dense range [0 .. 2^k − 1], return `k`. Otherwise,
        fall back to the bit length of the largest key.
        """
        if not keys_sorted:
            raise ValueError("Cannot infer bits/symbol from empty key set")

        m = len(keys_sorted)
        max_key = keys_sorted[-1]

        if (m & (m - 1)) == 0 and keys_sorted[0] == 0 and max_key == m - 1:
            return (m - 1).bit_length()

        return max(1, max_key.bit_length())

    @staticmethod
    def _lookup_symbol(
        lut: dict[int, tuple[float, float]], cw: int
    ) -> tuple[float, float]:
        """
        Resolve a codeword to its (I, Q) symbol tuple.

        Parameters
        ----------
        lut : dict[int, tuple[float, float]]
            Mapping of codeword → (I, Q) reference.
        cw : int
            Codeword to resolve.

        Returns
        -------
        tuple[float, float]
            The referenced (I, Q) pair.

        Raises
        ------
        KeyError
            If the codeword is not present in the LUT.
        """
        try:
            return lut[cw]
        except KeyError:
            raise KeyError(f"Codeword {cw} not found in LUT") from None
