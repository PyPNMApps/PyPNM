# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import math
from collections.abc import Mapping
from enum import IntEnum
from typing import TYPE_CHECKING

from pypnm.lib.types import Complex

if TYPE_CHECKING:
    # Only for type checking; avoids import-time cycles
    from pypnm.pnm.data_type.DsOfdmModulationType import DsOfdmModulationType

# ---- Public type aliases ----
LutDict = Mapping[str, Mapping[str, object]]
CodeWord = int
CodeWordArray = list[CodeWord]
QamSymbol = Complex
CodeWordLut = dict[CodeWord, QamSymbol]
QamSymCwLut = dict[str, CodeWordLut]
HardDecisionArray = list[QamSymbol]
SoftDecisionArray = list[QamSymbol]
SymbolArray = list[QamSymbol]

__all__ = [
    "LutDict",
    "CodeWord",
    "QamSymbol",
    "CodeWordLut",
    "QamSymCwLut",
    "HardDecisionArray",
    "SoftDecisionArray",
    "SymbolArray",
    "QamModulation",
]


class QamModulation(IntEnum):
    """Enumeration of supported QAM modulation orders."""

    UNKNOWN = 0
    QAM_2 = 2
    QAM_4 = 4
    QAM_8 = 8
    QAM_16 = 16
    QAM_32 = 32
    QAM_64 = 64
    QAM_128 = 128
    QAM_256 = 256
    QAM_512 = 512
    QAM_1024 = 1024
    QAM_2048 = 2048
    QAM_4096 = 4096
    QAM_8192 = 8192
    QAM_16384 = 16384
    QAM_32768 = 32768
    QAM_65536 = 65536

    @classmethod
    def from_value(cls, value: int) -> QamModulation:
        """Return the enum from its integer order (e.g., 64 -> QAM_64)."""
        try:
            return cls(value)
        except ValueError:
            return cls.UNKNOWN

    @classmethod
    def from_DsOfdmModulationType(
        cls, mod_type: DsOfdmModulationType | int | str
    ) -> QamModulation:
        """
        Map a DsOfdmModulationType (enum/int/string) to a QamModulation.

        Accepts
        -------
        mod_type : DsOfdmModulationType | int | str
            - DsOfdmModulationType enum member (e.g., DsOfdmModulationType.qam256)
            - Its integer code (e.g., 7 for qam256 in that enum layout)
            - A string label like "qam256", "QAM-256", "qpsk"

        Returns
        -------
        QamModulation
            The modulation order enum (e.g., QamModulation.QAM_256),
            or QamModulation.UNKNOWN if unsupported.
        """
        # 1) Strings like "qam256", "QAM-256", "qam_1024", "qpsk"
        if isinstance(mod_type, str):
            s = mod_type.strip().lower().replace("_", "").replace("-", "")
            if s == "qpsk":
                return cls.QAM_4
            if s.startswith("qam") and s[3:].isdigit():
                n = int(s[3:])
                return cls.from_value(n)
            return cls.UNKNOWN

        # 2) Enum-like with .name (e.g., DsOfdmModulationType.qam256)
        name = getattr(mod_type, "name", None)
        if isinstance(name, str):
            key = name.lower()
            name_map = {
                "qpsk": cls.QAM_4,
                "qam16": cls.QAM_16,
                "qam64": cls.QAM_64,
                "qam128": cls.QAM_128,
                "qam256": cls.QAM_256,
                "qam512": cls.QAM_512,
                "qam1024": cls.QAM_1024,
                "qam2048": cls.QAM_2048,
                "qam4096": cls.QAM_4096,
                "qam8192": cls.QAM_8192,
                "qam16384": cls.QAM_16384,
                "qam32768": cls.QAM_32768,
                "qam65536": cls.QAM_65536,
            }
            return name_map.get(key, cls.UNKNOWN)

        # 3) Fallback: treat it as the integer code from DsOfdmModulationType
        # Earlier layout (for reference):
        #   qpsk=3, qam16=4, qam64=5, qam128=6, qam256=7, qam512=8,
        #   qam1024=9, qam2048=10, qam4096=11, qam8192=12
        try:
            code = int(mod_type)  # type: ignore[arg-type]
        except Exception:
            return cls.UNKNOWN

        code_map: dict[int, QamModulation] = {
            3: cls.QAM_4,
            4: cls.QAM_16,
            5: cls.QAM_64,
            6: cls.QAM_128,
            7: cls.QAM_256,
            8: cls.QAM_512,
            9: cls.QAM_1024,
            10: cls.QAM_2048,
            11: cls.QAM_4096,
            12: cls.QAM_8192,
        }
        return code_map.get(code, cls.UNKNOWN)

    def get_bit_per_symbol(self) -> int:
        """Return the number of bits per symbol for the modulation scheme."""
        # Caller should not request bps for UNKNOWN; guard anyway.
        if self.value <= 0:
            return 0
        return int(math.log2(self.value))

    def __str__(self) -> str:
        """Return lowercase name like 'qam_64'."""
        return f"qam_{self.value}"
