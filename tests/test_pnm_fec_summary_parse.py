# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pypnm.pnm.parser.CmDsOfdmFecSummary import CmDsOfdmFecSummary
from pypnm.pnm.parser.model.parser_rtn_models import CmDsOfdmFecSummaryModel

DATA_DIR = Path(__file__).parent / "files"
FEC_PATH = DATA_DIR / "fec_summary.bin"


@pytest.fixture(scope="session")
def fec_bytes() -> bytes:
    return FEC_PATH.read_bytes()


@pytest.mark.pnm
def test_fec_summary_parses_and_model_shape(fec_bytes: bytes) -> None:
    """Basic parse + model shape."""
    fec = CmDsOfdmFecSummary(fec_bytes).to_model()
    assert isinstance(fec, CmDsOfdmFecSummaryModel)

    # top-level fields exist
    assert fec.channel_id >= 0
    assert (
        isinstance(fec.mac_address, str) and len(fec.mac_address) >= 11
    )  # "aa:bb:cc:dd:ee:ff"
    assert fec.num_profiles >= 0
    assert len(fec.fec_summary_data) == fec.num_profiles


@pytest.mark.pnm
def test_profiles_and_sets_are_consistent(fec_bytes: bytes) -> None:
    """Each profile has number_of_sets matching entry arrays, and values are sane."""
    model = CmDsOfdmFecSummary(fec_bytes).to_model()

    for p in model.fec_summary_data:
        assert p.number_of_sets == len(p.codeword_entries.timestamp)
        assert (
            len(p.codeword_entries.timestamp)
            == len(p.codeword_entries.total_codewords)
            == len(p.codeword_entries.corrected)
            == len(p.codeword_entries.uncorrectable)
        )

        # timestamps monotonic non-decreasing
        ts = p.codeword_entries.timestamp
        assert all(ts[i] <= ts[i + 1] for i in range(len(ts) - 1))

        # counts are non-negative and totals >= corrected + uncorrectable (best-effort sanity)
        tot = p.codeword_entries.total_codewords
        cor = p.codeword_entries.corrected
        unc = p.codeword_entries.uncorrectable
        assert all(x >= 0 for x in tot)
        assert all(x >= 0 for x in cor)
        assert all(x >= 0 for x in unc)
        assert all(t >= c + u for t, c, u in zip(tot, cor, unc, strict=False))


@pytest.mark.pnm
def test_capture_time_overridden_from_first_timestamp(fec_bytes: bytes) -> None:
    """
    FEC Summary PNN8 omits header capture_time; the parser should override it
    from the first timestamp in the first profile.
    """
    obj = CmDsOfdmFecSummary(fec_bytes)
    model = obj.to_model()

    # pull first timestamp actually parsed
    first_ts = model.fec_summary_data[0].codeword_entries.timestamp[0]
    assert model.pnm_header.capture_time == first_ts


@pytest.mark.pnm
def test_summary_type_label_is_readable(fec_bytes: bytes) -> None:
    model = CmDsOfdmFecSummary(fec_bytes).to_model()
    # label should be a non-empty string; known mapping currently has "24-hour interval" for type 2
    assert isinstance(model.summary_type_label, str) and model.summary_type_label


@pytest.mark.pnm
def test_serialization_roundtrip(fec_bytes: bytes) -> None:
    obj = CmDsOfdmFecSummary(fec_bytes)

    d = obj.to_dict()
    j = obj.to_model().model_dump_json()
    parsed = json.loads(j)

    # top-level keys should match
    assert set(parsed.keys()) == set(d.keys())


@pytest.mark.pnm
def test_wrong_type_rejected() -> None:
    """Smoke check: feeding a non-FEC file should raise ValueError."""
    # Use another PNM sample as a negative test if present; fallback to rxmer.bin
    alt_path = DATA_DIR / "rxmer.bin"
    raw = alt_path.read_bytes()
    with pytest.raises(ValueError):
        _ = CmDsOfdmFecSummary(raw)
