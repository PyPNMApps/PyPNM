# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from struct import pack

import pytest

from pypnm.pnm.parser.CmDsOfdmChanEstimateCoef import CmDsOfdmChanEstimateCoef
from pypnm.pnm.parser.CmUsOfdmaPreEq import CmUsOfdmaPreEq
from pypnm.pnm.parser.pnm_file_type import PnmFileType

PNM_MAJOR_VERSION = 1
PNM_MINOR_VERSION = 0
PNM_CAPTURE_TIME = 0

CHAN_ID = 1
MAC_ADDR = b"\x00\x50\xf1\x12\x03\x60"
CMTS_MAC_ADDR = b"\x00\x11\x22\x33\x44\x55"
SUBCARRIER_ZERO_FREQ = 100_000_000
FIRST_ACTIVE_SUBCARRIER_INDEX = 0
SUBCARRIER_SPACING_KHZ = 50
COEFFICIENT_BYTE_LENGTH = 4

REAL_VALUE = 1.0
IMAG_VALUE = -0.5

CHAN_EST_INT_BITS = 2
CHAN_EST_FRAC_BITS = 13
PRE_EQ_INT_BITS = 2
PRE_EQ_FRAC_BITS = 13
PRE_EQ_LAST_INT_BITS = 1
PRE_EQ_LAST_FRAC_BITS = 14


def _pnm_header(file_type: PnmFileType) -> bytes:
    cann = file_type.get_pnm_cann()
    return pack(
        "!3sBBBI",
        cann[:3].encode("ascii"),
        int(cann[3:]),
        PNM_MAJOR_VERSION,
        PNM_MINOR_VERSION,
        PNM_CAPTURE_TIME,
    )


def _to_twos_complement(value: int, bits: int) -> int:
    if value < 0:
        return (1 << bits) + value
    return value


def _encode_fixed(value: float, frac_bits: int) -> int:
    scaled = int(value * (1 << frac_bits))
    return _to_twos_complement(scaled, 16)


def _complex_coeff_bytes(real: float, imag: float, frac_bits: int) -> bytes:
    real_raw = _encode_fixed(real, frac_bits)
    imag_raw = _encode_fixed(imag, frac_bits)
    return pack(">HH", real_raw, imag_raw)


def _channel_est_payload() -> bytes:
    header = pack(
        ">B6sIHBI",
        CHAN_ID,
        MAC_ADDR,
        SUBCARRIER_ZERO_FREQ,
        FIRST_ACTIVE_SUBCARRIER_INDEX,
        SUBCARRIER_SPACING_KHZ,
        COEFFICIENT_BYTE_LENGTH,
    )
    coeffs = _complex_coeff_bytes(REAL_VALUE, IMAG_VALUE, CHAN_EST_FRAC_BITS)
    return header + coeffs


def _pre_eq_payload(frac_bits: int) -> bytes:
    header = pack(
        ">B6s6sIHBI",
        CHAN_ID,
        MAC_ADDR,
        CMTS_MAC_ADDR,
        SUBCARRIER_ZERO_FREQ,
        FIRST_ACTIVE_SUBCARRIER_INDEX,
        SUBCARRIER_SPACING_KHZ,
        COEFFICIENT_BYTE_LENGTH,
    )
    coeffs = _complex_coeff_bytes(REAL_VALUE, IMAG_VALUE, frac_bits)
    return header + coeffs


@pytest.mark.pnm
def test_channel_estimation_uses_q2_13_first_coeff() -> None:
    blob = _pnm_header(PnmFileType.OFDM_CHANNEL_ESTIMATE_COEFFICIENT) + _channel_est_payload()
    model = CmDsOfdmChanEstimateCoef(blob).to_model()

    first = model.values[0]
    assert first[0] == pytest.approx(REAL_VALUE)
    assert first[1] == pytest.approx(IMAG_VALUE)


@pytest.mark.pnm
def test_ofdma_pre_eq_uses_q2_13_first_coeff() -> None:
    blob = _pnm_header(PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS) + _pre_eq_payload(PRE_EQ_FRAC_BITS)
    model = CmUsOfdmaPreEq(blob).to_model()

    first = model.values[0]
    assert first[0] == pytest.approx(REAL_VALUE)
    assert first[1] == pytest.approx(IMAG_VALUE)


@pytest.mark.pnm
def test_ofdma_pre_eq_last_update_uses_q1_14_first_coeff() -> None:
    blob = _pnm_header(PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE) + _pre_eq_payload(PRE_EQ_LAST_FRAC_BITS)
    model = CmUsOfdmaPreEq(blob).to_model()

    first = model.values[0]
    assert first[0] == pytest.approx(REAL_VALUE)
    assert first[1] == pytest.approx(IMAG_VALUE)
