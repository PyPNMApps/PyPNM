# tests/test_docs_pnm_cm_ctl_test.py
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest


def test_enum_numeric_values() -> None:
    """
    Verify that DocsPnmCmCtlTest members are bound to the expected integer values.
    """
    assert DocsPnmCmCtlTest.SPECTRUM_ANALYZER.value                 == 2
    assert DocsPnmCmCtlTest.DS_OFDM_SYMBOL_CAPTURE.value            == 3
    assert DocsPnmCmCtlTest.DS_OFDM_CHAN_EST_COEF.value             == 4
    assert DocsPnmCmCtlTest.DS_CONSTELLATION_DISP.value             == 5
    assert DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR.value          == 6
    assert DocsPnmCmCtlTest.DS_OFDM_CODEWORD_ERROR_RATE.value       == 7
    assert DocsPnmCmCtlTest.DS_HISTOGRAM.value                      == 8
    assert DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF.value             == 9
    assert DocsPnmCmCtlTest.DS_OFDM_MODULATION_PROFILE.value        == 10
    assert DocsPnmCmCtlTest.LATENCY_REPORT.value                    == 11
    assert DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA.value   == 200
    assert DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF_LAST_UPDATE.value == 201
    assert DocsPnmCmCtlTest.UNKNOWN.value                           == 255


def test_enum_str_representation_is_lowercase_name() -> None:
    """
    Verify that __str__ returns the enum member name in lowercase.
    """
    for member in DocsPnmCmCtlTest:
        assert str(member) == member.name.lower()


def test_enum_values_are_unique() -> None:
    """
    Ensure that all DocsPnmCmCtlTest enum values are unique.
    """
    values = [m.value for m in DocsPnmCmCtlTest]
    assert len(values) == len(set(values))
