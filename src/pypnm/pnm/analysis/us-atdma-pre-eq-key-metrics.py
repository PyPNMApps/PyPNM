# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import math


class EqualizerMetrics:
    def __init__(
        self,
        coefficients: list[tuple[int, int]],
        nominal_amplitude: int = 2047,
        main_tap_index: int = 7,
    ) -> None:
        """
        Initialize EqualizerMetrics.

        Args:
            coefficients (List[Tuple[int, int]]): A list of 24 (real, imag) coefficient pairs.
            nominal_amplitude (int): CM implementation nominal amplitude. Defaults to 2047.
            main_tap_index (int): Main tap index (0-based). Defaults to 7 for F8.
        """
        if len(coefficients) != 24:
            raise ValueError(
                "Exactly 24 complex (real, imag) coefficients are required."
            )
        self.coefficients = coefficients
        self.nominal_amplitude = nominal_amplitude
        self.main_tap_index = main_tap_index

    def _tap_energy(self, tap: tuple[int, int]) -> float:
        """Compute energy of a single tap."""
        real, imag = tap
        return real**2 + imag**2

    def main_tap_energy(self) -> float:
        """6.3.1: Main Tap Energy (MTE)."""
        return self._tap_energy(self.coefficients[self.main_tap_index])

    def main_tap_nominal_energy(self) -> float:
        """6.3.2: Main Tap Nominal Energy (MTNE)."""
        return self.nominal_amplitude**2 * 2

    def pre_main_tap_energy(self) -> float:
        """6.3.3: Pre-Main Tap Energy (PreMTE)."""
        return sum(
            self._tap_energy(tap) for tap in self.coefficients[: self.main_tap_index]
        )

    def post_main_tap_energy(self) -> float:
        """6.3.4: Post-Main Tap Energy (PostMTE)."""
        return sum(
            self._tap_energy(tap)
            for tap in self.coefficients[self.main_tap_index + 1 :]
        )

    def total_tap_energy(self) -> float:
        """6.3.5: Total Tap Energy (TTE)."""
        return sum(self._tap_energy(tap) for tap in self.coefficients)

    def main_tap_compression(self) -> float:
        """6.3.6: Main Tap Compression (MTC), in dB."""
        mte = self.main_tap_energy()
        tte = self.total_tap_energy()
        return 10 * math.log10(tte / mte) if mte != 0 else float("inf")

    def main_tap_ratio(self) -> float:
        """6.3.7: Main Tap Ratio (MTR), in dB."""
        mte = self.main_tap_energy()
        other = self.total_tap_energy() - mte
        return 10 * math.log10(mte / other) if other != 0 else float("inf")

    def non_main_tap_energy_ratio(self) -> float:
        """6.3.8: Non-Main Tap to Total Energy Ratio (NMTER), in dB."""
        non_main = self.pre_main_tap_energy() + self.post_main_tap_energy()
        tte = self.total_tap_energy()
        return 10 * math.log10(non_main / tte) if tte != 0 else float("-inf")

    def pre_main_tap_total_energy_ratio(self) -> float:
        """6.3.9: Pre-Main Tap to Total Energy Ratio (PreMTTER), in dB."""
        pre = self.pre_main_tap_energy()
        tte = self.total_tap_energy()
        return 10 * math.log10(pre / tte) if tte != 0 else float("-inf")

    def post_main_tap_total_energy_ratio(self) -> float:
        """6.3.10: Post-Main Tap to Total Energy Ratio (PostMTTER), in dB."""
        post = self.post_main_tap_energy()
        tte = self.total_tap_energy()
        return 10 * math.log10(post / tte) if tte != 0 else float("-inf")

    def pre_post_energy_symmetry_ratio(self) -> float:
        """6.3.11: Pre-Post Energy Symmetry Ratio (PPESR), in dB."""
        pre = self.pre_main_tap_energy()
        post = self.post_main_tap_energy()
        return 10 * math.log10(post / pre) if pre != 0 else float("inf")

    def pre_post_tap_symmetry_ratio(self) -> float:
        """6.3.11 (approx): Pre-Post Tap Symmetry Ratio (PPTSR), in dB.

        Uses only taps adjacent to main tap: F7 and F9.
        """
        idx_prev = self.main_tap_index - 1
        idx_next = self.main_tap_index + 1
        if idx_prev < 0 or idx_next >= len(self.coefficients):
            return float("nan")  # Not enough data around main tap

        energy_prev = self._tap_energy(self.coefficients[idx_prev])
        energy_next = self._tap_energy(self.coefficients[idx_next])
        return (
            10 * math.log10(energy_next / energy_prev)
            if energy_prev != 0
            else float("inf")
        )
