# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import math
from typing import ClassVar, cast

import numpy as np

from pypnm.lib.types import FloatSeries, SNRdB, SNRln
from pypnm.pnm.parser.CmDsOfdmModulationProfile import ModulationOrderType

BitsPerSymbol = int
BitPerSymToQamMod = dict[BitsPerSymbol, str]


class Shannon:
    QAM_MODULATIONS: ClassVar[BitPerSymToQamMod] = {
        1: "qam_2",
        2: "qam_4",
        3: "qam_8",
        4: "qam_16",
        5: "qam_32",
        6: "qam_64",
        7: "qam_128",
        8: "qam_256",
        9: "qam_512",
        10: "qam_1024",
        11: "qam_2048",
        12: "qam_4096",
        13: "qam_8192",
        14: "qam_16384",
        15: "qam_32768",
        16: "qam_65536",
    }

    def __init__(self, snr_db: float) -> None:
        self.snr_db = snr_db
        self.bits = self._snr_to_bits(snr_db)

    def get_modulation(self) -> str:
        return self.QAM_MODULATIONS.get(self.bits, "unknown")

    def get_snr_db(self) -> float:
        return self.snr_db

    @classmethod
    def from_modulation(cls, modulation_name: str) -> Shannon:
        """
        Create a ModulationEstimator instance from a known modulation name (e.g., "qam_256").
        Assumes ideal Shannon conditions to reverse-calculate approximate SNR (dB).
        """
        mod_map = {v: k for k, v in cls.QAM_MODULATIONS.items()}
        bits = mod_map.get(modulation_name.lower())

        if bits is None:
            raise ValueError(f"Unsupported modulation type: {modulation_name}")

        # Reverse Shannon formula: SNR_linear = 2^bits - 1 → SNR_dB = 10 * log10(2^bits - 1)
        snr_linear = (2**bits) - 1
        snr_db = 10 * math.log10(snr_linear)

        return cls(snr_db)

    @classmethod
    def from_modulation_type(cls, mod_ord_type: ModulationOrderType) -> Shannon:
        """
        Create a ModulationEstimator instance from a known modulation name (e.g., "qam_256").
        Assumes ideal Shannon conditions to reverse-calculate approximate SNR (dB).
        """
        mod_map = {v: k for k, v in cls.QAM_MODULATIONS.items()}
        bits = mod_map.get(mod_ord_type.name)

        if bits is None:
            raise ValueError(f"Unsupported modulation type: {mod_ord_type.name}")

        # Reverse Shannon formula: SNR_linear = 2^bits - 1 → SNR_dB = 10 * log10(2^bits - 1)
        snr_linear = (2**bits) - 1
        snr_db = 10 * math.log10(snr_linear)

        return cls(snr_db)

    @staticmethod
    def _snr_to_bits(snr_db: float) -> BitsPerSymbol:
        """Convert SNR in dB to bits (modulation order) by Shannon formula, floored."""
        snr_linear = 10 ** (snr_db / 10)
        bits = math.floor(math.log2(snr_linear + 1))
        return bits

    @staticmethod
    def bits_from_symbol_count(symbol_count: int) -> BitsPerSymbol:
        """
        Convert the number of symbols to bits per symbol using the Shannon formula.
        """
        if symbol_count <= 0:
            raise ValueError("Symbol count must be positive.")

        return int(math.floor(math.log2(float(symbol_count))))

    @staticmethod
    def snr_from_modulation(modulation_name: str) -> SNRdB:
        """
        Calculate the Shannon-limit SNR (dB) required for the given modulation name.
        Raises ValueError if modulation is unsupported.
        """
        mod_map = {v: k for k, v in Shannon.QAM_MODULATIONS.items()}
        bits = mod_map.get(modulation_name.lower())

        if bits is None:
            raise ValueError(f"Unsupported modulation type: {modulation_name}")

        snr_linear: SNRln = (2**bits) - 1
        return cast(SNRdB, 10 * math.log10(snr_linear))

    @staticmethod
    def bits_to_snr(bits: int) -> SNRdB:
        """
        Calculate the ideal Shannon-limit SNR (dB) for a given number of bits per symbol.

        Parameters:
            bits (int): Number of bits per symbol (e.g., 8 for QAM256).

        Returns:
            float: SNR in dB required under Shannon conditions.
        """
        if bits <= 0:
            raise ValueError("Bit value must be positive.")
        snr_linear = (2**bits) - 1
        return cast(SNRdB, 10 * math.log10(snr_linear))

    @staticmethod
    def snr_to_limit(snr: float | FloatSeries | np.ndarray) -> list[BitsPerSymbol]:
        """
        Calculate the Shannon capacity limit (bits/s/Hz) for given SNR value(s),
        rounding down to the nearest whole bit (since fractional bits aren't realizable).

        Args:
            snr: Single SNR in dB, a list of SNRs, or a NumPy array of SNRs.

        Returns:
            A list of integer capacity limits (bits/s/Hz), one per input value.
        """
        # Ensure a 1D float array (scalar → length-1 array)
        arr = np.atleast_1d(np.asarray(snr, dtype=float))

        # Vectorized computation
        linear = 10 ** (arr / 10)
        capacity = np.log2(1 + linear)

        # Always round down to the nearest integer
        limits = np.floor(capacity).astype(int)

        return limits.tolist()

    @staticmethod
    def snr_to_snr_limit(snr_db: list[SNRdB]) -> list[SNRdB]:
        """
        Take the SNR and Calculate the closest supported modulation limit.
        Returns:
            The Shannon limit in dB for the current SNR.
        """
        if not isinstance(snr_db, list):
            raise TypeError("Input must be a list of SNR values in dB.")

        # Convert to numpy array for vectorized operations
        snr_array = np.array(snr_db, dtype=float)

        # Calculate Shannon limits for each SNR value
        limits: list[BitsPerSymbol] = Shannon.snr_to_limit(snr_array)

        # Convert bits back to dB
        shannon_limits: list[SNRdB] = [Shannon.bits_to_snr(bits) for bits in limits]

        return shannon_limits
