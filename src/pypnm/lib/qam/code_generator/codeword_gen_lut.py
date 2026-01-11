# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025

from __future__ import annotations

import math
from typing import Literal

from pypnm.lib.qam.types import CodeWordLut
from pypnm.lib.types import ComplexArray


class CodeWordLutGenerator:
    """
    Build a codeword → (I, Q) LUT from a given hard-decision constellation.

    Modes
    -----
    - Rectangular (square or non-square, e.g., 64×32): uses Gray coding on each axis:
        codeword = (gray(I_index) << bits_Q) | gray(Q_index)   (axis_order="IQ")
      or
        codeword = (gray(Q_index) << bits_I) | gray(I_index)   (axis_order="QI")

    - Non-rectangular (e.g., cross 2048-QAM): falls back to *sequential Gray*:
        codeword = gray(rank), where rank is the sorted index of the point.
      This ensures a deterministic, dense mapping 0..(N-1). Adjacency is not
      guaranteed like the rectangular case, but your build will succeed.

    Parameters
    ----------
    hard_decision : ComplexArray
        Constellation points as (I, Q) tuples.
    axis_order : {"IQ", "QI"}, default "IQ"
        Axis packing used for the rectangular case.
    q_invert : bool, default False
        If True, flips the sign of Q.
    strict : bool, default True
        Rectangular case: require powers of two per axis. Ignored in non-rect.
    nonrect_strategy : {"gray-seq", "error"}, default "gray-seq"
        Fallback for non-rectangular constellations:
          - "gray-seq": assign codeword = gray(rank) over sorted points.
          - "error": raise ValueError (previous behavior).
    """

    def __init__(
        self,
        hard_decision: ComplexArray,
        *,
        axis_order: Literal["IQ", "QI"] = "IQ",
        q_invert: bool = False,
        strict: bool = True,
        nonrect_strategy: Literal["gray-seq", "error"] = "gray-seq",
    ) -> None:
        self.hard_decision: ComplexArray = list(hard_decision)
        self.axis_order: Literal["IQ", "QI"] = axis_order
        self.q_invert: bool = q_invert
        self.strict: bool = strict
        self.nonrect_strategy: Literal["gray-seq", "error"] = nonrect_strategy

        self.codeword_dict: CodeWordLut = {}

    # ----------------------------
    # Public API
    # ----------------------------
    def build(self) -> CodeWordLutGenerator:
        """
        Generate the codeword mapping (rectangular Gray-on-axes or non-rect fallback).
        """
        self._validate_nonempty()
        self._validate_no_duplicates()

        # Unique sorted levels per axis
        i_levels = sorted({p[0] for p in self.hard_decision})
        q_levels = sorted({p[1] for p in self.hard_decision})

        n_i = len(i_levels)
        n_q = len(q_levels)
        m = len(self.hard_decision)

        rectangular = n_i * n_q == m

        if rectangular:
            # Rectangular mapping with Gray per axis
            if self.strict:
                self._require_power_of_two(n_i, "I")
                self._require_power_of_two(n_q, "Q")
                bits_i = int(math.log2(n_i))
                bits_q = int(math.log2(n_q))
            else:
                bits_i = math.ceil(math.log2(n_i)) if n_i > 1 else 1
                bits_q = math.ceil(math.log2(n_q)) if n_q > 1 else 1

            i_index_of = {lvl: idx for idx, lvl in enumerate(i_levels)}
            q_index_of = {lvl: idx for idx, lvl in enumerate(q_levels)}

            lut: CodeWordLut = {}
            if self.axis_order == "IQ":
                # I bits are MSBs
                for i, Q0 in sorted(self.hard_decision, key=lambda t: (t[0], t[1])):
                    ii = i_index_of[i]
                    qi = q_index_of[Q0]
                    gi = self._gray(ii)
                    gq = self._gray(qi)
                    Q = -Q0 if self.q_invert else Q0
                    cw = (gi << bits_q) | gq
                    lut[cw] = (i, Q)
            else:
                # Q bits are MSBs
                for i, Q0 in sorted(self.hard_decision, key=lambda t: (t[1], t[0])):
                    ii = i_index_of[i]
                    qi = q_index_of[Q0]
                    gi = self._gray(ii)
                    gq = self._gray(qi)
                    Q = -Q0 if self.q_invert else Q0
                    cw = (gq << bits_i) | gi
                    lut[cw] = (i, Q)

            self.codeword_dict = lut
            return self

        # ---------- Non-rectangular fallback ----------
        if self.nonrect_strategy == "error":
            raise ValueError(
                f"Constellation is not rectangular: |I|={n_i}, |Q|={n_q}, total={m}"
            )

        # gray-seq: assign Gray(code) to sorted rank
        points = sorted(self.hard_decision, key=lambda t: (t[0], t[1]))

        lut: CodeWordLut = {}
        for rank, (i, Q0) in enumerate(points):
            Q = -Q0 if self.q_invert else Q0
            cw = self._gray(rank)  # 0..(m-1) mapped via Gray sequence
            lut[cw] = (i, Q)

        self.codeword_dict = lut
        return self

    def to_dict(self) -> CodeWordLut:
        """Return the generated LUT (codeword → (I, Q))."""
        return self.codeword_dict

    # ----------------------------
    # Helpers / Validation
    # ----------------------------
    @staticmethod
    def _gray(n: int) -> int:
        """Reflected Gray code: g = n ^ (n >> 1)."""
        return n ^ (n >> 1)

    @staticmethod
    def _is_power_of_two(n: int) -> bool:
        return n > 0 and (n & (n - 1)) == 0

    def _require_power_of_two(self, n: int, axis_name: str) -> None:
        if not self._is_power_of_two(n):
            raise ValueError(
                f"|{axis_name}_levels| must be a power of two in strict mode; got {n}"
            )

    def _validate_nonempty(self) -> None:
        if not self.hard_decision:
            raise ValueError("hard_decision cannot be empty")

    def _validate_no_duplicates(self) -> None:
        if len(self.hard_decision) != len(set(self.hard_decision)):
            raise ValueError("hard_decision contains duplicate points")
