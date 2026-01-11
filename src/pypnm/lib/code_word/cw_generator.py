# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from pypnm.lib.qam.types import CodeWordArray, QamModulation
from pypnm.lib.types import ByteArray, Number


class CodeWordGenerator:
    """
    Generate codewords for QAM modulation schemes.

    - `generate(qam_mod, num_of_symbols)` returns a SymbolArray of integer codewords
      in the range [0, 2^bps - 1], where bps = qam_mod.get_bit_per_symbol().
    - Codewords are formed by grouping a PRBS bitstream into bps-bit chunks,
      **LSB-first per symbol** (i.e., the first generated bit is bit 0 of the symbol).
    - `prbs(byte_length)` returns a ByteArray of pseudo-random bytes generated
      by an 8-bit LFSR with polynomial taps x^8 + x^6 + x^5 + x^4 + 1.
    """

    PRBS = list[Number]

    def __init__(self, *, seed: int = 0xA5, taps: int = 0b10110111) -> None:
        """
        Args:
            seed: Initial non-zero 8-bit LFSR state (lower 8 bits are used).
            taps: Tap mask for 8-bit LFSR (default: x^8+x^6+x^5+x^4+1 => 0b10110111).
        """
        self._seed = seed & 0xFF or 0xA5  # avoid zero state
        self._taps = taps & 0xFF

    # ──────────────────────────── public API ────────────────────────────
    def generate(self, qam_mod: QamModulation, num_of_symbols: int) -> CodeWordArray:
        """
        Generate QAM codewords as integers by packing PRBS bits.

        Packing order: LSB-first per symbol. For bps = bits per symbol,
        the first generated bit becomes bit 0 of the symbol, the next bit -> bit 1, etc.

        Args:
            qam_mod: QAM modulation enum (must expose get_bit_per_symbol()).
            num_of_symbols: number of codewords to produce (>= 0).

        Returns:
            CodeWordArray: list of integers in [0, (1<<bps)-1] of length num_of_symbols.
        """
        if num_of_symbols <= 0:
            return []

        bps: int = int(qam_mod.get_bit_per_symbol())
        if bps <= 0:
            return []

        max_codeword = (1 << bps) - 1

        # Local LFSR state so multiple calls to generate() are deterministic and independent
        state = self._seed

        def lfsr_step(s: int) -> tuple[int, int]:
            """One 8-bit LFSR step (right-shift). Returns (new_state, output_bit)."""
            out = s & 0x01  # LSB as the generated bit
            s >>= 1
            if out:
                s ^= self._taps
            return s & 0xFF, out

        code_words: CodeWordArray = []
        for _ in range(num_of_symbols):
            sym = 0
            # LSB-first fill
            for bit_pos in range(bps):
                state, bit = lfsr_step(state)
                if bit:
                    sym |= 1 << bit_pos
            # (Optional) mask to be safe, although sym is already bounded by construction
            sym &= max_codeword
            code_words.append(sym)

        return code_words

    def prbs(self, byte_length: int = 1) -> ByteArray:
        """
        Generate a pseudo-random bit sequence as bytes using an 8-bit LFSR.

        Args:
            byte_length: Number of bytes to produce (>= 0).

        Returns:
            ByteArray: list of integers (0..255) of length `byte_length`.
        """
        if byte_length <= 0:
            return []

        state = self._seed
        out: ByteArray = []

        for _ in range(byte_length):
            b = 0
            # Produce 8 bits per byte; pack MSB-first in the byte for conventional display
            for bit_idx in range(8):
                state, bit = self._lfsr_step(state)
                # Place newest bit at position (7 - bit_idx) to yield MSB-first in the byte
                if bit:
                    b |= 1 << (7 - bit_idx)
            out.append(b & 0xFF)

        return out

    # ──────────────────────────── internals ────────────────────────────
    def _lfsr_step(self, s: int) -> tuple[int, int]:
        """
        One 8-bit LFSR step using the configured taps.
        Returns (new_state, output_bit), where output_bit is the LSB of prior state.
        """
        bit = s & 0x01
        s >>= 1
        if bit:
            s ^= self._taps
        return s & 0xFF, bit
