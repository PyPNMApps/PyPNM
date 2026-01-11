# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import time
from pathlib import Path

import pytest

from pypnm.lib.constants import DEFAULT_CAPTURE_TIME
from pypnm.lib.types import CaptureTime
from pypnm.pnm.parser.pnm_file_type import PnmFileType
from pypnm.pnm.parser.pnm_header import PnmHeader

DATA_DIR = Path(__file__).parent / "files"

ALL_FILES = [
    "channel_estimation.bin",
    "const_display.bin",
    "fec_summary.bin",
    "histogram.bin",
    "modulation_profile.bin",
    "rxmer.bin",
    "spectrum_analyzer.bin",
]

MISSING_CAPTURE = {"fec_summary.bin"}  # PNN8 → no capture_time in header


def _p(name: str) -> Path:
    return DATA_DIR / name


@pytest.mark.pnm
def test_data_files_present() -> None:
    assert DATA_DIR.is_dir()
    for f in ALL_FILES:
        assert _p(f).is_file(), f"Missing test file: {f}"


@pytest.mark.pnm
@pytest.mark.parametrize("fname", ALL_FILES)
def test_pnm_header_per_file(fname: str) -> None:
    """Exercise PnmHeader parsing for each file and validate invariants."""
    data = _p(fname).read_bytes()
    hdr = PnmHeader.from_bytes(data)
    params = hdr.getPnmHeaderParameterModel()

    # Basic invariants for every file
    assert params.file_type is not None and len(params.file_type) == 3
    assert params.file_type_version >= 0
    assert params.major_version >= 0
    assert params.minor_version >= 0
    # payload is captured
    assert isinstance(hdr.pnm_data, (bytes, bytearray))

    # Header dict behavior
    d_full = hdr.getPnmHeader(header_only=False)
    d_hdr = hdr.getPnmHeader(header_only=True)
    assert "pnm_header" in d_full and "pnm_header" in d_hdr
    assert "data" in d_full and "data" not in d_hdr

    # File-type resolution should produce something (may be None if unknown)
    # This doesn’t force a specific enum—just tries to resolve it.
    _ = hdr.get_pnm_file_type()

    # capture_time semantics:
    if fname in MISSING_CAPTURE:
        # FEC summary omits capture_time → override must succeed
        ts = int(time.time())
        changed = hdr.override_capture_time(CaptureTime(ts))
        assert changed is True
        assert hdr.getPnmHeaderParameterModel().capture_time == ts
        assert hdr.getPnmHeaderParameterModel().capture_time != DEFAULT_CAPTURE_TIME
        # Sanity: if enum resolves, it must be the FEC summary type
        et = hdr.get_pnm_file_type()
        if et is not None:
            assert et == PnmFileType.OFDM_FEC_SUMMARY
    else:
        # Others should keep their original capture_time; override should be rejected
        before = hdr.getPnmHeaderParameterModel().capture_time
        changed = hdr.override_capture_time(CaptureTime(int(time.time())))
        after = hdr.getPnmHeaderParameterModel().capture_time
        assert changed is False
        assert after == before
