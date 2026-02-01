# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pypnm.docsis.data_type.enums import MeasStatusType
from pypnm.lib.types import ScalarValue


def measurement_status(v: ScalarValue) -> str:
    """
    Return The Measurement Status Name For A Numeric Code.

    Attempts To Interpret ``v`` As An Integer And Map It To
    ``MeasStatusType``. If Conversion Or Import Fails, ``"other"``
    Is Returned As A Fallback.
    """
    try:
        code = int(v)
        return str(MeasStatusType(code))
    except (ValueError, TypeError):
        return "other"
    except ImportError:
        return "other"


def as_bool(v: ScalarValue) -> bool:
    """
    Convert A Scalar Value To Bool With Integer Preference.

    The Function First Attempts To Interpret ``v`` As An Integer
    And Uses ``bool(int(v))``. If That Fails, It Falls Back To
    Python's Native ``bool(v)`` Semantics.
    """
    try:
        return bool(int(v))
    except (ValueError, TypeError):
        return bool(v)


def as_int(v: ScalarValue) -> int:
    """
    Convert A Scalar Value To Int.

    This Is A Thin Wrapper Around ``int(v)`` To Provide A
    Consistent Conversion Surface For SNMP And Parser Helpers.
    """
    return int(v)


def as_str(v: ScalarValue) -> str:
    """
    Convert A Scalar Value To Str.

    Ensures All SNMP/Parser Scalars Can Be Safely Rendered
    As Text Without Relying On Implicit Conversions.
    """
    return str(v)


def as_float0(v: ScalarValue) -> float:
    """
    Convert A Scalar Value To Float Without Scaling.

    This Is Typically Used For Values That Are Already
    In Engineering Units And Do Not Require Fixed-Point
    Normalization.
    """
    return float(v)


def as_float2(v: ScalarValue, /) -> float:
    """
    Convert A Fixed-Point Scalar To A Two-Decimal Float.

    SNMP Often Encodes Values In 1/100 Units. This Helper
    Divides By ``100.0`` And Rounds To Two Decimal Places.
    """
    return round(float(v) / 100.0, 2)


def scale(v: ScalarValue, *, factor: float, ndigits: int | None = None) -> float:
    """
    Scale A Scalar Value By A Factor With Optional Rounding.

    Parameters
    ----------
    v:
        Input Scalar To Be Converted To ``float`` Before Scaling.
    factor:
        Multiplicative Scale Factor (For Example, 0.001 For
        Thousandths Or 0.1 For Tenths).
    ndigits:
        Optional Number Of Decimal Places For ``round``. When
        ``None``, No Rounding Is Applied.

    Returns
    -------
    float
        The Scaled (And Optionally Rounded) Value.
    """
    x = float(v) * factor
    return round(x, ndigits) if ndigits is not None else x


def per_hundred(v: ScalarValue, *, ndigits: int = 2) -> float:
    """
    Normalize A Scalar Expressed In 1/100 Units.

    Divides ``v`` By ``100.0`` And Rounds To ``ndigits`` Decimal
    Places. Commonly Used For Percentage-Like Fixed-Point Fields.
    """
    return round(float(v) / 100.0, ndigits)


def per_thousand(v: ScalarValue, *, ndigits: int = 3) -> float:
    """
    Normalize A Scalar Expressed In 1/1000 Units.

    Generic Helper For MIB Units Expressed In 0.001 Steps
    (ThousandthdB, ThousandthNsec, ThousandthdB/MHz,
    ThousandthNsec/MHz). Divides ``v`` By ``1000.0`` And
    Rounds To ``ndigits`` Decimal Places.
    """
    return round(float(v) / 1000.0, ndigits)


def tenthdB(v: ScalarValue, *, ndigits: int = 1) -> float:
    """
    Normalize A Scalar Expressed In Tenths Of A dB.

    Divides ``v`` By ``10.0`` And Rounds To ``ndigits`` Decimal
    Places. Used For MIB fields that are defined as TenthdB.
    """
    return round(float(v) / 10.0, ndigits)
