# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Literal

import numpy as np

from pypnm.lib.qam.types import CodeWordLut
from pypnm.lib.types import Complex


class QamByteToSymbolMapper:
    """
    Map a stream of bytes to QAM **(I, Q)** symbols using a provided codeword→symbol LUT.

    The LUT's keys are the **codeword integers** that correspond to the transmitter's
    on-wire bit patterns for each symbol. For typical rectangular M-QAM with Gray
    mapping per axis, keys are Gray-coded compositions. Non-rectangular LUTs with
    sequential-Gray keys are also supported.

    Parameters
    ----------
    codeword_lut : Dict[int, Tuple[float, float]]
        Mapping from codeword (int) to constellation point (I, Q).
    bits_per_symbol : Optional[int], default None
        If None, inferred:
          - if LUT keys are dense [0..2^k-1], use k
          - else, use bit_length(max_key).
    require_dense : bool, default True
        Require LUT keys to be dense [0..2^k-1]. Ensures every k-bit chunk maps.
    pad : {"drop", "zero"}, default "drop"
        Handling for trailing bits not forming a full symbol:
          - "drop": discard leftovers
          - "zero": zero-pad to next full symbol
    bit_order : {"msb", "lsb"}, default "msb"
        Bit extraction order within the byte stream.
    on_unknown : {"error", "skip", "mod"}, default "error"
        Action if a chunk codeword is not in LUT (only when require_dense=False).

    Notes
    -----
    - Use `iter_symbols()` for streaming; `map_bytes()` returns a list.
    - `map_bytes_array()` returns a NumPy array: (N,2) float64 or 1-D complex128.
    """

    __slots__ = (
        "_lut",
        "_keys_sorted",
        "bits_per_symbol",
        "require_dense",
        "pad",
        "bit_order",
        "on_unknown",
        "_mask",
    )

    def __init__(
        self,
        codeword_lut: CodeWordLut,
        *,
        bits_per_symbol: int | None = None,
        require_dense: bool = True,
        pad: Literal["drop", "zero"] = "drop",
        bit_order: Literal["msb", "lsb"] = "msb",
        on_unknown: Literal["error", "skip", "mod"] = "error",
    ) -> None:
        if not codeword_lut:
            raise ValueError("codeword_lut cannot be empty")

        self._lut: CodeWordLut = dict(codeword_lut)
        self._keys_sorted: list[int] = sorted(self._lut.keys())

        # Infer bits/symbol if not provided
        if bits_per_symbol is None:
            dense = self._is_dense_power_of_two(self._keys_sorted)
            if dense:
                M = len(self._keys_sorted)
                self.bits_per_symbol = (M - 1).bit_length()  # == int(log2(M))
            else:
                self.bits_per_symbol = max(1, self._keys_sorted[-1].bit_length())
        else:
            if bits_per_symbol <= 0:
                raise ValueError("bits_per_symbol must be positive")
            self.bits_per_symbol = bits_per_symbol

        self.require_dense = require_dense
        self.pad = pad
        self.bit_order = bit_order
        self.on_unknown = on_unknown

        self._mask = (1 << self.bits_per_symbol) - 1

        if self.require_dense and not self._is_dense_power_of_two(self._keys_sorted):
            raise ValueError(
                "LUT is not a dense power-of-two key set but require_dense=True. "
                "Pass require_dense=False or adjust bits_per_symbol."
            )

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------
    def map_bytes(self, data: bytes) -> list[Complex]:
        """
        Convert a byte stream to a list of QAM constellation points (I, Q).

        Returns
        -------
        List[Tuple[float, float]]
            Symbols mapped in stream order.
        """
        return list(self.iter_symbols(data))

    def iter_symbols(self, data: bytes) -> Iterator[Complex]:
        """
        Stream symbols as (I, Q) tuples without building intermediate lists.

        Parameters
        ----------
        data : bytes
            Input bitstream.

        Yields
        ------
        Tuple[float, float]
            Constellation points in modulation order.

        Raises
        ------
        KeyError
            If a parsed codeword is not in the LUT and `on_unknown="error"`.
        """
        if not data:
            return
        # Choose chunker by bit order
        codewords = (
            self._chunks_msb_first(data)
            if self.bit_order == "msb"
            else self._chunks_lsb_first(data)
        )
        keys = self._keys_sorted  # local alias
        lut = self._lut
        require_dense = self.require_dense
        on_unknown = self.on_unknown

        for cw in codewords:
            if cw in lut:
                yield lut[cw]
                continue

            if require_dense:
                raise KeyError(f"Codeword {cw} not found in LUT (require_dense=True).")

            if on_unknown == "skip":
                continue
            elif on_unknown == "mod":
                mapped_cw = keys[cw % len(keys)]
                yield lut[mapped_cw]
            else:  # "error"
                raise KeyError(f"Codeword {cw} not found in LUT.")

    def map_bytes_array(self, data: bytes, *, as_complex: bool = False) -> np.ndarray:
        """
        Convert a byte stream to a NumPy array of symbols.

        Parameters
        ----------
        data : bytes
            Input bitstream.
        as_complex : bool, default False
            - False: return shape (N, 2) float64 array with columns [I, Q].
            - True : return 1-D complex128 array of length N (I + 1j*Q).

        Returns
        -------
        numpy.ndarray
            Array of symbols as specified by `as_complex`.
        """
        n_syms = self._symbol_count(len(data))
        if n_syms == 0:
            return (
                np.empty((0, 2), dtype=np.float64)
                if not as_complex
                else np.empty((0,), dtype=np.complex128)
            )

        if not as_complex:
            out = np.empty((n_syms, 2), dtype=np.float64)
            i = 0
            for I, Q in self.iter_symbols(data):  # noqa: E741
                out[i, 0] = I
                out[i, 1] = Q
                i += 1
            # If on_unknown="skip", i may be < n_syms; trim
            if i != n_syms:
                out = out[:i, :]
            return out

        # complex128
        outc = np.empty((n_syms,), dtype=np.complex128)
        i = 0
        for I, Q in self.iter_symbols(data):  # noqa: E741
            outc[i] = complex(I, Q)
            i += 1
        if i != n_syms:
            outc = outc[:i]
        return outc

    # -------------------------------------------------------------------------
    # Internal: bit chunkers
    # -------------------------------------------------------------------------
    def _chunks_msb_first(self, data: bytes) -> Iterable[int]:
        """
        Yield codeword-sized chunks, MSB-first, honoring pad policy.
        """
        total_bits = 8 * len(data)
        value = int.from_bytes(data, byteorder="big", signed=False)

        # Padding
        if self.pad == "zero" and (total_bits % self.bits_per_symbol):
            pad_bits = self.bits_per_symbol - (total_bits % self.bits_per_symbol)
            value <<= pad_bits
            total_bits += pad_bits

        full_syms = total_bits // self.bits_per_symbol
        for i in range(full_syms):
            shift = total_bits - (i + 1) * self.bits_per_symbol
            yield (value >> shift) & self._mask

        # "drop" leaves leftovers ignored; "zero" already padded to multiple

    def _chunks_lsb_first(self, data: bytes) -> Iterable[int]:
        """
        Yield codeword-sized chunks, LSB-first, honoring pad policy.
        """
        total_bits = 8 * len(data)
        value = int.from_bytes(data, byteorder="little", signed=False)

        # Padding
        if self.pad == "zero" and (total_bits % self.bits_per_symbol):
            pad_bits = self.bits_per_symbol - (total_bits % self.bits_per_symbol)
            # For LSB-first, zero-padding adds zeros to the high side (no change needed).
            total_bits += pad_bits

        full_syms = total_bits // self.bits_per_symbol
        for i in range(full_syms):
            shift = i * self.bits_per_symbol
            yield (value >> shift) & self._mask

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------
    def _symbol_count(self, nbytes: int) -> int:
        """
        Number of full symbols produced from `nbytes` under current pad policy.
        """
        total_bits = 8 * nbytes
        if self.pad == "zero" and (total_bits % self.bits_per_symbol):
            total_bits += self.bits_per_symbol - (total_bits % self.bits_per_symbol)
        return total_bits // self.bits_per_symbol

    @staticmethod
    def _is_dense_power_of_two(keys_sorted: list[int]) -> bool:
        """
        True if keys are exactly [0 .. 2^k - 1] for some k≥1.
        """
        if not keys_sorted:
            return False
        M = len(keys_sorted)
        if M & (M - 1):
            return False
        if keys_sorted[0] != 0 or keys_sorted[-1] != M - 1:
            return False
        # contiguous check
        return all(k == i for i, k in enumerate(keys_sorted))
