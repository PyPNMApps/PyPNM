# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from enum import Enum


class DocsPnmCmCtlTest(Enum):
    """
    Enumeration of DOCSIS PNM control test types (docsPnmCmCtlTest).
    Represents the current or last attempted test.

    docsPnmCmCtlTest   OBJECT-TYPE
        SYNTAX      INTEGER {other(1),
                            dsSpectrumAnalyzer(2),
                            dsOfdmSymbolCapture(3),
                            dsOfdmChanEstCoef(4),
                            dsConstellationDisp(5),
                            dsOfdmRxMERPerSubCar(6),
                            dsOfdmCodewordErrorRate(7),
                            dsHistogram(8),
                            usPreEqualizerCoef(9)
                            }

    """

    SPECTRUM_ANALYZER = 2  # Downstream Spectrum Analyzer
    DS_OFDM_SYMBOL_CAPTURE = 3  # Downstream OFDM Symbol Capture
    DS_OFDM_CHAN_EST_COEF = 4  # Downstream OFDM Channel Estimate Coefficient
    DS_CONSTELLATION_DISP = 5  # Downstream Constellation Display
    DS_OFDM_RXMER_PER_SUBCAR = 6  # Downstream OFDM RxMER per Subcarrier
    DS_OFDM_CODEWORD_ERROR_RATE = 7  # Downstream OFDM Codeword Error Rate
    DS_HISTOGRAM = 8  # Downstream Histogram
    US_PRE_EQUALIZER_COEF = (
        9  # Upstream Pre-equalizer Coefficients and Last-Pre-equalizer
    )
    DS_OFDM_MODULATION_PROFILE = 10  # Not in MIB
    LATENCY_REPORT = 11  # Not in MIB
    SPECTRUM_ANALYZER_SNMP_AMP_DATA = (
        200  # Not in MIB -> SPECTRUM_ANALYZER (SNMP Amplitude Data)
    )
    US_PRE_EQUALIZER_COEF_LAST_UPDATE = (
        201  # Not in MIB -> US_PRE_EQUALIZER_COEF (Last Update Time)
    )
    UNKNOWN = 255  # Unknown

    def __str__(self) -> str:
        return self.name.lower()
