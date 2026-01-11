from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
import logging
import math
import pprint
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from pypnm.lib.collector.complex import ComplexCollector
from pypnm.lib.file_processor import FileProcessor
from pypnm.lib.qam.code_generator.codeword_gen_lut import CodeWordLutGenerator
from pypnm.lib.qam.types import QamModulation
from pypnm.lib.types import Complex, ComplexArray, PathArray, PathLike

BitLoad = int
QamScale = float
QamLutDict = dict[str, dict[Any, Any]]
QamScaleLutDict = dict[BitLoad, QamScale]

Hard = list[tuple[float, float]]


class GenerateQamLut:
    """
    High-level entry point to generate a QAM Lookup Table (LUT).
    Validates inputs, compiles QAM tables, and writes a Python LUT module.
    """

    def __init__(
        self,
        src_qam_table: Path = Path("src/pypnm/support/qam-table"),
        dst_qam_lut: Path = Path("src/pypnm/lib/qam"),
    ) -> None:
        self.logger = logging.getLogger("GenerateQamLut")
        self.path_to_qam_table = Path(src_qam_table)
        self.path_to_qam_lut = Path(dst_qam_lut)

        # Build immediately to preserve original behavior
        self.build()

    def build(self) -> Path | None:
        """
        Compile the QAM LUT from the specified QAM table files and write it.

        Returns:
            The path to the generated LUT file on success; otherwise None.
        """
        if not self.path_to_qam_table.exists():
            self.logger.error(
                "QAM table path does not exist: %s", self.path_to_qam_table
            )
            return None

        lut = QamLut(
            src_qam_table=self.path_to_qam_table, dst_qam_lut=self.path_to_qam_lut
        )
        out_path = lut.write()
        self.logger.debug("QAM LUT generated successfully at %s", out_path)
        return out_path


class QamLutDb(BaseModel):
    """
    Pydantic model for a single QAM LUT entry.

    Attributes
    ----------
    symbol_count : int
        Number of modulation symbols in this LUT (equals the QAM order).
    hard : ComplexArray
        List of symbol points as (real, imag) coordinates.
    code_words : Dict[int, Complex]
        Mapping of encoded codeword integers to constellation coordinates.
    """

    symbol_count: int
    hard: ComplexArray
    code_words: dict[int, Complex]
    scale_factor: float


class QamLut:
    """
    Compiler for QAM Lookup Tables (LUTs).

    Reads raw text-based constellation tables, applies per-order scaling from
    ConstellationScalingFactors.txt, and emits a Python module with the LUT.
    """

    QAM_LUT_FNAME = "qam_lut.py"
    QAM_SCALE_LUT_FNAME = "qam_scale_lut.py"

    def __init__(self, src_qam_table: PathLike, dst_qam_lut: PathLike) -> None:
        self.logger = logging.getLogger("QamLut")
        self._path_to_qam_table: Path = Path(src_qam_table)
        self._lut_dir: Path = Path(dst_qam_lut)
        self._lut_path: Path = self._lut_dir / self.QAM_LUT_FNAME

        self._qam_cc: dict[QamModulation, ComplexCollector] = {}
        self._qam_lut: QamLutDict = {}
        self._scaling_factors: QamScaleLutDict = self._load_scaling_factors()

        self._compile()

    # ---------------- Public API ----------------

    def write(self) -> Path:
        """
        Write the compiled QAM LUT to a Python file.

        The file defines a global variable ``QAM_SYMBOL_CODEWORD_LUT`` that maps
        QAM order names (e.g., "QAM_16") to their LUT dict.
        """
        self._lut_dir.mkdir(parents=True, exist_ok=True)
        fp = FileProcessor(self._lut_path)
        fp.write_file(self._qam_lut_template())
        return self._lut_path

    # ---------------- Compilation Steps ----------------

    def _compile(self) -> None:
        """Compile all QAM tables into the internal LUT structure."""
        for f in self._get_qam_tables():
            self.logger.debug("Loading %s to compile QAM LUT", f)
            cc, qm = self._load_table(f)
            self._update_qam_lut(qm, cc)

        self._build_qam_lut()

    def _update_qam_lut(self, order: QamModulation, cc: ComplexCollector) -> None:
        """Update internal storage with a new QAM constellation collector."""
        self._qam_cc[order] = cc

    # ---------------- I/O Helpers ----------------

    def _get_qam_tables(self, skip_files: list[str] | None = None) -> PathArray:
        """
        Discover available QAM table files.
        Skips ConstellationScalingFactors.txt by default.
        """
        if skip_files is None:
            skip_files = ["ConstellationScalingFactors.txt"]
        return [
            p
            for p in self._path_to_qam_table.glob("*.txt")
            if p.is_file() and p.name not in skip_files
        ]

    def _load_scaling_factors(self) -> QamScaleLutDict:
        """
        Load bits-per-symbol -> scaling factor (Es) from ConstellationScalingFactors.txt.
        Ignores blank lines and comments ('#', '//'). Returns {} if missing.
        """
        factors_path = self._path_to_qam_table / "ConstellationScalingFactors.txt"
        factors: dict[int, float] = {}
        if not factors_path.exists():
            self.logger.warning(
                "Scaling factors file not found: %s (defaulting to no scaling)",
                factors_path,
            )
            return factors

        with open(factors_path) as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#") or s.startswith("//"):
                    continue
                parts = s.split()
                if len(parts) != 2:
                    self.logger.warning("Malformed scaling row: %s", s)
                    continue
                try:
                    bps = int(parts[0])
                    factor = float(parts[1])
                    factors[bps] = factor
                except ValueError:
                    self.logger.warning("Invalid numeric scaling row: %s", s)
                    continue
        return factors

    def _load_table(
        self, path_to_qam_table: Path
    ) -> tuple[ComplexCollector, QamModulation]:
        """
        Load a single QAM table file and scale points per ConstellationScalingFactors.txt.

        File format: each non-comment, non-empty line contains two floats: "<real> <imag>"
        """
        raw_cc = ComplexCollector()

        with open(path_to_qam_table) as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#") or s.startswith("//"):
                    continue
                parts = s.split()
                if len(parts) != 2:
                    self.logger.warning(
                        "Malformed line in QAM table %s: %s", path_to_qam_table.name, s
                    )
                    continue
                r, i = map(float, parts)
                raw_cc.add(r, i)

        symbol_count = len(raw_cc)
        try:
            qm = QamModulation(symbol_count)  # avoids eval; enum-by-value
        except ValueError as e:
            raise ValueError(
                f"Unsupported QAM order from {path_to_qam_table.name}: {symbol_count}"
            ) from e

        # Determine bits-per-symbol and scale by 1/sqrt(Es) if provided
        bps = int(math.log2(symbol_count))
        Es = self._scaling_factors.get(bps)
        if Es is None:
            self.logger.debug(
                "No scaling factor for %d bits/symbol; leaving points unscaled.", bps
            )
            return raw_cc, qm

        scale = 1.0 / math.sqrt(Es)

        scaled_cc = ComplexCollector()
        for r, i in raw_cc.to_complex_array():
            scaled_cc.add(r * scale, i * scale)

        self.logger.debug(
            "Loaded %s with %d symbols from %s (scaled by 1/sqrt(%s))",
            qm,
            symbol_count,
            path_to_qam_table,
            Es,
        )
        return scaled_cc, qm

    def _get_scale_factor(self, order: QamModulation) -> QamScale:
        return 1.0 / math.sqrt(self._scaling_factors[order.get_bit_per_symbol()])

    # ---------------- LUT Assembly & Emission ----------------

    def _build_qam_lut(self) -> QamLutDict:
        """
        Construct the internal LUT dictionary:

        {
          "<QAM_ORDER>": {
            "symbol_count": int,
            "hard": [(real, imag), ...],
            "code_words": {int: (real, imag), ...},
            "scale_factor: float
          },
          ...
        }
        """
        for order, cc in self._qam_cc.items():
            self.logger.debug("Compiling QAM LUT for %s", order)

            cw_lut = CodeWordLutGenerator(cc.to_complex_array()).build().to_dict()

            qld = QamLutDb(
                symbol_count=len(cc),
                hard=cc.to_complex_array(),
                code_words=cw_lut,
                scale_factor=self._get_scale_factor(order),
            )

            self._qam_lut[order.name] = qld.model_dump()

        return self._qam_lut

    def _qam_lut_template(self) -> str:
        """
        Render the Python source template for the LUT file.

        Defines a global ``QAM_SYMBOL_CODEWORD_LUT`` with the compiled dict.
        """
        formatted = pprint.pformat(self._qam_lut, indent=2, width=100, sort_dicts=True)

        header = (
            "# SPDX-License-Identifier: Apache-2.0\n"
            f"# Do not modify manually. AutoGenerated: {datetime.now(timezone.utc).isoformat()}\n"
            "# Generated by QamLut compiler\n\n"
        )

        return f"{header}QAM_SYMBOL_CODEWORD_LUT = {formatted}\n"
