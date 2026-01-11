# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest

from pypnm.lib.mac_address import MacAddress
from pypnm.pnm.parser.CmDsConstDispMeas import CmDsConstDispMeas
from pypnm.pnm.parser.CmDsHist import CmDsHist
from pypnm.pnm.parser.CmDsOfdmChanEstimateCoef import CmDsOfdmChanEstimateCoef
from pypnm.pnm.parser.CmDsOfdmFecSummary import CmDsOfdmFecSummary
from pypnm.pnm.parser.CmDsOfdmModulationProfile import CmDsOfdmModulationProfile
from pypnm.pnm.parser.CmDsOfdmRxMer import CmDsOfdmRxMer
from pypnm.pnm.parser.pnm_file_type import PnmFileType
from pypnm.pnm.parser.pnm_parameter import GetPnmParserAndParameters

DATA_DIR = Path(__file__).parent / "files"

# fname, supported, expected parser class (or None when unsupported)
CASES = [
    ("channel_estimation.bin", True, CmDsOfdmChanEstimateCoef),
    ("const_display.bin", True, CmDsConstDispMeas),
    ("fec_summary.bin", True, CmDsOfdmFecSummary),
    ("modulation_profile.bin", True, CmDsOfdmModulationProfile),
    ("rxmer.bin", True, CmDsOfdmRxMer),
    ("histogram.bin", True, CmDsHist),
    ("spectrum_analyzer.bin", False, None),
]


@pytest.mark.pnm
@pytest.mark.parametrize("fname,supported,parser_cls", CASES)
def test_get_pnm_parser_and_parameters_and_models(
    fname: str,
    supported: bool,
    parser_cls: type[object] | None,
) -> None:
    blob = (DATA_DIR / fname).read_bytes()
    wrapper = GetPnmParserAndParameters(blob)

    if not supported:
        with pytest.raises(NotImplementedError):
            _ = wrapper.to_model()
        with pytest.raises(NotImplementedError):
            _ = wrapper.get_parser()
        return

    # 1) High-level parameter model
    params = wrapper.to_model()
    assert isinstance(params.file_type, PnmFileType)
    assert isinstance(params.mac_address, str)

    params_dict = wrapper.to_dict()

    # file_type should be a PnmFileType enum in the dict as well
    assert "file_type" in params_dict
    ft = params_dict["file_type"]
    assert isinstance(ft, PnmFileType)
    assert ft is params.file_type

    # Canonical string like "PNN2", "PNN4", etc.
    ft_str = ft.value
    assert isinstance(ft_str, str)
    assert len(ft_str) >= 3

    # mac_address must be present and a string
    assert "mac_address" in params_dict
    assert isinstance(params_dict["mac_address"], str)

    # MAC sanity when formatted as aa:bb:...
    mac = params_dict["mac_address"]
    if mac:
        parts = mac.split(":")
        if all(len(p) == 2 for p in parts):
            assert all(0 <= int(p, 16) <= 0xFF for p in parts)

    # 2) Concrete parser + its own model
    parser, params_again = wrapper.get_parser()

    # Wrapper must return the same params instance/data
    assert params_again.file_type == params.file_type
    assert params_again.mac_address == params.mac_address

    # Concrete parser type must match the expected parser for this file
    assert isinstance(parser, parser_cls)

    # All concrete parsers must expose .to_model()
    model = parser.to_model()

    # Every measurement model should have mac_address and pnm_header
    assert hasattr(model, "mac_address")
    assert hasattr(model, "pnm_header")

    assert isinstance(model.mac_address, str)

    # If the top-level params has a non-null MAC, it must match the model MAC.
    # For file types where we intentionally don't propagate MAC (e.g. some headers),
    # params.mac_address will be the null MAC and we don't enforce equality.
    if params.mac_address != MacAddress.null():
        assert model.mac_address == params.mac_address

    # pnm_header should have file_type and file_type_version so we can reconstruct the PNM code
    header = model.pnm_header
    assert hasattr(header, "file_type")
    assert hasattr(header, "file_type_version")

    header_code = f"{header.file_type}{header.file_type_version}"
    assert header_code == ft_str
