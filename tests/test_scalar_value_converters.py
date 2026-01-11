# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import pytest

from pypnm.docsis.data_type.enums import MeasStatusType
from pypnm.lib.types import ScalarValue
from pypnm.snmp.casts import (
    as_bool,
    as_float0,
    as_float2,
    as_int,
    as_str,
    measurement_status,
    per_hundred,
    per_thousand,
    scale,
)


@pytest.mark.parametrize("value", [0, 1, "0", "1", 2, "2"])
def test_measurement_status_valid_enum_values(value: ScalarValue) -> None:
    """
    measurement_status should map numeric codes to MeasStatusType string form.
    We use the first enum member as a reference to avoid hard-coding values.
    """
    first_member = list(MeasStatusType)[0]
    # Only run a strict check when the value matches the first_member.value,
    # otherwise we just verify that valid ints do not raise and produce a string.
    if int(value) == int(first_member.value):
        assert measurement_status(value) == str(first_member)
    else:
        out = measurement_status(value)
        assert isinstance(out, str)
        assert out != ""


@pytest.mark.parametrize("value", ["not-an-int", "abc", "", object()])
def test_measurement_status_invalid_returns_other(value: object) -> None:
    assert measurement_status(value) == "other"


@pytest.mark.parametrize(
    "value, expected",
    [
        (0, False),
        (1, True),
        ("0", False),
        ("1", True),
        ("2", True),  # bool(2) is True
        ("", False),  # fallback to bool("") -> False
        ("false", True),  # int() fails, so bool("false") -> True
    ],
)
def test_as_bool_behaviour(value: ScalarValue, expected: bool) -> None:
    assert as_bool(value) is expected


@pytest.mark.parametrize(
    "value, expected",
    [
        (0, 0),
        (1, 1),
        (-5, -5),
        ("10", 10),
        ("-3", -3),
    ],
)
def test_as_int_converts_numeric_strings_and_ints(
    value: ScalarValue, expected: int
) -> None:
    assert as_int(value) == expected


@pytest.mark.parametrize(
    "value, expected",
    [
        (0, "0"),
        (1, "1"),
        (-3, "-3"),
        (1.5, "1.5"),
        ("abc", "abc"),
    ],
)
def test_as_str_round_trips_to_string(value: ScalarValue, expected: str) -> None:
    assert as_str(value) == expected


@pytest.mark.parametrize(
    "value, expected",
    [
        (0, 0.0),
        (1, 1.0),
        (-3, -3.0),
        ("2.5", 2.5),
        ("0", 0.0),
    ],
)
def test_as_float0_basic_conversion(value: ScalarValue, expected: float) -> None:
    assert as_float0(value) == pytest.approx(expected)


@pytest.mark.parametrize(
    "value, expected",
    [
        (0, 0.0),
        (1, 0.01),
        (123, 1.23),
        ("250", 2.50),
        (-100, -1.00),
    ],
)
def test_as_float2_fixed_point_two_decimals(
    value: ScalarValue, expected: float
) -> None:
    assert as_float2(value) == pytest.approx(expected, rel=1e-9, abs=1e-9)


@pytest.mark.parametrize(
    "value, factor, ndigits, expected",
    [
        (100, 0.01, None, 1.0),
        (100, 0.01, 2, 1.00),
        ("250", 0.1, 1, 25.0),
        (5, 2.0, 0, 10.0),
    ],
)
def test_scale_with_and_without_rounding(
    value: ScalarValue,
    factor: float,
    ndigits: int | None,
    expected: float,
) -> None:
    out = scale(value, factor=factor, ndigits=ndigits)
    assert out == pytest.approx(expected, rel=1e-9, abs=1e-9)


@pytest.mark.parametrize(
    "value, ndigits, expected",
    [
        (0, 2, 0.0),
        (100, 2, 1.0),
        ("250", 2, 2.5),
        (123, 1, 1.2),
    ],
)
def test_per_hundred_normalization(
    value: ScalarValue, ndigits: int, expected: float
) -> None:
    assert per_hundred(value, ndigits=ndigits) == pytest.approx(
        expected, rel=1e-9, abs=1e-9
    )


@pytest.mark.parametrize(
    "value, ndigits, expected",
    [
        (0, 3, 0.0),
        (1000, 3, 1.0),
        ("2500", 3, 2.5),
        (1234, 3, 1.234),
        (1234, 2, 1.23),
    ],
)
def test_per_thousand_normalization(
    value: ScalarValue, ndigits: int, expected: float
) -> None:
    assert per_thousand(value, ndigits=ndigits) == pytest.approx(
        expected, rel=1e-9, abs=1e-9
    )
