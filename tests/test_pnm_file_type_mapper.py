# tests/test_pnm_file_type_mapper.py
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
import pytest

from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest
from pypnm.pnm.parser.pnm_file_type import PnmFileType
from pypnm.pnm.parser.pnm_type_header_mapper import PnmFileTypeMapper


def test_test_to_file_type_mapping_round_trip() -> None:
    """
    Verify that every DocsPnmCmCtlTest → PnmFileType mapping works in both directions.
    """
    for test_type, file_type in PnmFileTypeMapper._test_to_file_type.items():
        assert PnmFileTypeMapper.get_file_type(test_type) is file_type
        assert PnmFileTypeMapper.get_test_type(file_type) is test_type


def test_all_mapped_tests_are_known_enums() -> None:
    """
    Ensure that all keys in the mapping are valid DocsPnmCmCtlTest members.
    """
    for test_type in PnmFileTypeMapper._test_to_file_type:
        assert isinstance(test_type, DocsPnmCmCtlTest)


def test_all_mapped_file_types_are_known_enums() -> None:
    """
    Ensure that all values in the mapping are valid PnmFileType members.
    """
    for file_type in PnmFileTypeMapper._test_to_file_type.values():
        assert isinstance(file_type, PnmFileType)


def test_unmapped_test_type_returns_none_if_any_exist() -> None:
    """
    If there are DocsPnmCmCtlTest members not present in the mapping,
    verify that get_file_type returns None for at least one of them.
    """
    unmapped_tests = [t for t in DocsPnmCmCtlTest if t not in PnmFileTypeMapper._test_to_file_type]
    if not unmapped_tests:
        pytest.skip("All DocsPnmCmCtlTest values are mapped; no unmapped test type to validate.")
    assert PnmFileTypeMapper.get_file_type(unmapped_tests[0]) is None


def test_unmapped_file_type_returns_none_if_any_exist() -> None:
    """
    If there are PnmFileType members not present in the mapping values,
    verify that get_test_type returns None for at least one of them.
    """
    mapped_file_types = set(PnmFileTypeMapper._test_to_file_type.values())
    unmapped_file_types = [ft for ft in PnmFileType if ft not in mapped_file_types]
    if not unmapped_file_types:
        pytest.skip("All PnmFileType values are mapped; no unmapped file type to validate.")
    assert PnmFileTypeMapper.get_test_type(unmapped_file_types[0]) is None
