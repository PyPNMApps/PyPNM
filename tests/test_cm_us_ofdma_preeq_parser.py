# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path

import pytest

from pypnm.lib.file_processor import FileProcessor
from pypnm.pnm.parser.CmUsOfdmaPreEq import CmUsOfdmaPreEq, CmUsOfdmaPreEqModel

DATA_DIR: Path = Path(__file__).parent / "files"
US_PREEQ_PATH: Path = DATA_DIR / "us_pre_equalizer_coef.bin"
RXMER_PATH: Path = DATA_DIR / "rxmer.bin"

MAC_RE: re.Pattern[str] = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")


@pytest.mark.pnm
def test_cm_us_ofdma_preeq_parses_and_populates_core_fields() -> None:
    """
    Ensure CmUsOfdmaPreEq Parses The Upstream OFDMA Pre-Equalization Capture.

    This test verifies that:

    1. The reference binary file exists and can be read.
    2. The payload decodes into a CmUsOfdmaPreEqModel instance.
    3. Core metadata fields (channel_id, MAC addresses, spacing) are sane.
    4. The decoded coefficient list is non-empty and structurally valid.
    """
    assert US_PREEQ_PATH.is_file()

    raw_payload: bytes = FileProcessor(US_PREEQ_PATH).read_file()
    parser = CmUsOfdmaPreEq(raw_payload)
    model: CmUsOfdmaPreEqModel = parser.to_model()

    dumped = model.model_dump()
    assert isinstance(dumped, dict)
    assert dumped

    # Channel and MAC sanity
    assert model.channel_id >= 0
    assert isinstance(model.mac_address, str)
    assert MAC_RE.match(model.mac_address) is not None
    assert isinstance(model.cmts_mac_address, str)
    assert MAC_RE.match(model.cmts_mac_address) is not None

    # Frequency / spacing sanity
    assert model.subcarrier_zero_frequency > 0
    assert model.subcarrier_spacing > 0
    assert model.first_active_subcarrier_index >= 0

    # Coefficients: non-empty and [re, im] pairs (allow list or tuple)
    assert model.values
    for pair in model.values:
        assert isinstance(pair, (list, tuple))
        assert len(pair) == 2
        assert all(isinstance(x, (int, float)) for x in pair)


@pytest.mark.pnm
def test_cm_us_ofdma_preeq_bandwidth_matches_coefficients_and_spacing() -> None:
    """
    Verify Occupied Channel Bandwidth Matches Tap Count And Subcarrier Spacing.

    The parser's model reports:
      - ``occupied_channel_bandwidth`` (Hz)
      - ``subcarrier_spacing`` (Hz)
      - ``values`` containing one complex coefficient per active subcarrier

    This test ensures the relationship:
        occupied_channel_bandwidth == len(values) * subcarrier_spacing
    holds for the reference capture.
    """
    assert US_PREEQ_PATH.is_file()

    raw_payload: bytes = FileProcessor(US_PREEQ_PATH).read_file()
    parser = CmUsOfdmaPreEq(raw_payload)
    model: CmUsOfdmaPreEqModel = parser.to_model()

    taps: Sequence[Sequence[float]] = model.values
    tap_count: int = len(taps)
    assert tap_count > 0

    expected_bw: int = tap_count * int(model.subcarrier_spacing)
    assert int(model.occupied_channel_bandwidth) == expected_bw


@pytest.mark.pnm
def test_cm_us_ofdma_preeq_rejects_non_preeq_pnm_files() -> None:
    """
    Ensure CmUsOfdmaPreEq Raises ValueError For Non-PreEq PNM Streams.

    A downstream RxMER capture is used as a negative test input to confirm
    that CmUsOfdmaPreEq validates the PNM file type and rejects mismatched
    PNM streams.
    """
    assert RXMER_PATH.is_file()

    raw_payload: bytes = FileProcessor(RXMER_PATH).read_file()

    with pytest.raises(ValueError) as excinfo:
        CmUsOfdmaPreEq(raw_payload)

    msg: str = str(excinfo.value)
    assert "PNM File Stream is not file type" in msg
