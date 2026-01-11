# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pypnm.pnm.parser.CmDsOfdmModulationProfile import CmDsOfdmModulationProfile
from pypnm.pnm.parser.model.parser_rtn_models import CmDsOfdmModulationProfileModel

DATA_DIR = Path(__file__).parent / "files"
MODPROF_PATH = DATA_DIR / "modulation_profile.bin"
NON_MODPROF_PATH = DATA_DIR / "rxmer.bin"  # negative test sample


@pytest.fixture(scope="session")
def modprof_bytes() -> bytes:
    return MODPROF_PATH.read_bytes()


@pytest.mark.pnm
def test_modprof_parses_and_model_shape(modprof_bytes: bytes) -> None:
    mp = CmDsOfdmModulationProfile(modprof_bytes).to_model()
    assert isinstance(mp, CmDsOfdmModulationProfileModel)

    # Header & core fields
    assert mp.num_profiles >= 0
    assert mp.profile_data_length_bytes >= 0
    assert isinstance(mp.mac_address, str) and len(mp.mac_address) >= 11  # "aa:bb:cc:dd:ee:ff"
    assert mp.subcarrier_spacing > 0
    assert mp.first_active_subcarrier_index >= 0
    assert mp.subcarrier_zero_frequency >= 0

    # Profiles container aligns with count
    assert len(mp.profiles) == mp.num_profiles


@pytest.mark.pnm
def test_profile_schemes_valid_and_decoded(modprof_bytes: bytes) -> None:
    mp = CmDsOfdmModulationProfile(modprof_bytes).to_model()

    for profile in mp.profiles:
        # profile ids are non-negative
        assert profile.profile_id >= 0

        # schemes should be a list; if present, each has required fields
        assert isinstance(profile.schemes, list)
        for sch in profile.schemes:
            # Discriminated union: schema_type is 0 (range) or 1 (skip)
            assert sch.schema_type in (0, 1)
            if sch.schema_type == 0:
                # Range schema
                assert hasattr(sch, "modulation_order")
                assert isinstance(sch.modulation_order, str) and sch.modulation_order
                assert sch.num_subcarriers >= 0
            else:
                # Skip schema
                assert hasattr(sch, "main_modulation_order")
                assert hasattr(sch, "skip_modulation_order")
                assert isinstance(sch.main_modulation_order, str) and sch.main_modulation_order
                assert isinstance(sch.skip_modulation_order, str) and sch.skip_modulation_order
                assert sch.num_subcarriers >= 0


@pytest.mark.pnm
def test_serialization_roundtrip(modprof_bytes: bytes) -> None:
    obj = CmDsOfdmModulationProfile(modprof_bytes)

    d = obj.to_dict()
    j = obj.to_model().model_dump_json()
    parsed = json.loads(j)

    # Top-level keys parity
    assert set(parsed.keys()) == set(d.keys())


@pytest.mark.pnm
def test_get_frequencies_current_behavior_is_empty(modprof_bytes: bytes) -> None:
    """
    get_frequencies currently returns [] (TODO noted in implementation).
    Keep this as a behavioral check until the TODO is implemented.
    """
    obj = CmDsOfdmModulationProfile(modprof_bytes)
    freqs = obj.get_frequencies()
    assert isinstance(freqs, list)
    assert len(freqs) == 0


@pytest.mark.pnm
def test_wrong_type_rejected() -> None:
    """Feeding a non-modulation-profile file should raise ValueError."""
    raw = NON_MODPROF_PATH.read_bytes()
    with pytest.raises(ValueError):
        _ = CmDsOfdmModulationProfile(raw)
