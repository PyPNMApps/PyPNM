# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from pypnm.lib.csv.manager import (
    CSVManager,
    CSVOrientation,
    CSVValidationError,
)


def test_set_header_once_and_reset() -> None:
    mgr = CSVManager()
    mgr.set_header(["a", "b"])
    with pytest.raises(CSVValidationError):
        mgr.set_header(["x"])
    mgr.clear()
    mgr.set_header(["x"])
    assert mgr.get_headers() == ["x"]


@pytest.mark.parametrize("bad", [[], [""], ["  ", "ok"], [1, 2]])
def test_set_header_validation_errors(bad: list[object]) -> None:
    mgr = CSVManager()
    with pytest.raises(CSVValidationError):
        mgr.set_header(bad)  # type: ignore[arg-type]


def test_insert_row_requires_header() -> None:
    mgr = CSVManager()
    with pytest.raises(CSVValidationError):
        mgr.insert_row([1, 2])


def test_insert_row_length_mismatch() -> None:
    mgr = CSVManager()
    mgr.set_header(["a", "b"])
    with pytest.raises(CSVValidationError):
        mgr.insert_row([1])  # too short
    with pytest.raises(CSVValidationError):
        mgr.insert_row([1, 2, 3])  # too long


def test_insert_and_getters() -> None:
    mgr = CSVManager()
    mgr.set_header(["a", "b", "c"])
    mgr.insert_row([1, None, "z"])
    mgr.insert_multiple_rows([[2, 3, 4]])
    assert mgr.get_column_count() == 3
    assert mgr.get_row_count() == 2
    assert mgr.get_data() == [["1", "", "z"], ["2", "3", "4"]]


def test_validate_data_integrity() -> None:
    mgr = CSVManager()
    mgr.set_header(["h1"])
    mgr.insert_row(["v"])
    assert mgr.validate_data_integrity() is True


def test_validate_data_integrity_failure() -> None:
    mgr = CSVManager()
    mgr.set_header(["h1", "h2"])
    # bypass public API to simulate bad internal state
    mgr.data.append(["only_one"])
    with pytest.raises(CSVValidationError):
        mgr.validate_data_integrity()


def test_to_dataframe_and_back() -> None:
    mgr = CSVManager()
    mgr.set_header(["a", "b"])
    mgr.insert_row([1, 2])
    mgr.insert_row([3, 4])

    df = mgr.to_dataframe()
    assert list(df.columns) == ["a", "b"]
    assert df.shape == (2, 2)
    assert df.iloc[0, 0] == "1" and df.iloc[1, 1] == "4"

    mgr2 = CSVManager()
    mgr2.from_dataframe(df)
    assert mgr2.get_headers() == ["a", "b"]
    assert mgr2.get_data() == [["1", "2"], ["3", "4"]]


def test_preview_contains_key_details() -> None:
    mgr = CSVManager()
    mgr.set_header(["col1", "col2"])
    mgr.insert_row([10, 20])
    txt = mgr.preview()
    assert "CSV Preview" in txt
    assert "Headers (2): col1, col2" in txt
    assert "Data rows: 1" in txt
    assert "10" in txt and "20" in txt


def test_write_requires_path() -> None:
    mgr = CSVManager()
    mgr.set_header(["a"])
    mgr.insert_row([1])
    with pytest.raises(CSVValidationError):
        _ = mgr.get_path_fname()
    with pytest.raises(AttributeError):
        mgr.write()


def test_write_vertical_csv(tmp_path: Path) -> None:
    mgr = CSVManager(CSVOrientation.VERTICAL)
    mgr.set_header(["a", "b"])
    mgr.insert_multiple_rows([[1, 2], [3, 4]])
    out = tmp_path / "v.csv"
    mgr.set_path_fname(out)
    ok = mgr.write(include_index=True, delimiter=",")
    assert ok is True
    rows = list(csv.reader(out.open("r", encoding="utf-8")))
    # header with index
    assert rows[0] == ["Index", "a", "b"]
    # two data rows with index as first column
    assert rows[1] == ["0", "1", "2"]
    assert rows[2] == ["1", "3", "4"]


def test_write_horizontal_csv(tmp_path: Path) -> None:
    mgr = CSVManager(CSVOrientation.HORIZONTAL)
    mgr.set_header(["h1", "h2", "h3"])
    mgr.insert_multiple_rows([[1, 2, 3], [4, 5, 6]])
    out = tmp_path / "h.csv"
    mgr.set_path_fname(out)
    ok = mgr.write()
    assert ok is True
    rows = list(csv.reader(out.open("r", encoding="utf-8")))
    # Each header becomes a row: header, col0, col1
    assert rows[0] == ["h1", "1", "4"]
    assert rows[1] == ["h2", "2", "5"]
    assert rows[2] == ["h3", "3", "6"]


def test_custom_delimiter_vertical(tmp_path: Path) -> None:
    mgr = CSVManager()
    mgr.set_header(["a", "b"])
    mgr.insert_row([10, 20])
    out = tmp_path / "semi.csv"
    mgr.set_path_fname(out)
    mgr.write(delimiter=";")
    content = out.read_text(encoding="utf-8").strip()
    # Header and row separated by semicolons
    assert "a;b" in content
    assert "10;20" in content
