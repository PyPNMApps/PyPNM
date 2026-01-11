# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from pypnm.lib.format_string import Format


class TestJoinParen:
    def test_none_or_empty(self) -> None:
        assert Format.join_paren(None) == "(—)"
        assert Format.join_paren([]) == "(—)"
        assert Format.join_paren(()) == "(—)"

    def test_basic_list(self) -> None:
        assert Format.join_paren([1, 2, 3]) == "(1, 2, 3)"

    def test_custom_sep_and_empty_token(self) -> None:
        assert Format.join_paren(["a", "b"], sep=" | ") == "(a | b)"
        assert Format.join_paren([], empty="empty") == "(empty)"

    def test_mixed_types(self) -> None:
        assert Format.join_paren([1, "x", 3.14]) == "(1, x, 3.14)"


class TestHexString:
    def test_strips_prefix_spaces_and_delimiters(self) -> None:
        # removes 0x and spaces; groups by 2 with default ':'
        assert Format.hex_string("0x1a2b 3c4d") == "1a:2b:3c:4d"

    def test_custom_delimiter_and_grouping(self) -> None:
        assert Format.hex_string("deadbeef", delimiter="-", grouping=4) == "dead-beef"

    def test_idempotent_with_same_delimiter(self) -> None:
        # existing delimiter of same char should be normalized back identically
        assert Format.hex_string("aa:bb:cc:dd") == "aa:bb:cc:dd"

    def test_odd_length_keeps_last_short_group(self) -> None:
        # no zero-padding performed; last group may be shorter
        assert Format.hex_string("abc") == "ab:c"


class TestNonAsciiToHex:
    def test_bytes_ascii_printable_round_trip(self) -> None:
        assert Format.non_ascii_to_hex(b"Hello!") == "Hello!"

    def test_bytes_non_ascii_to_hex(self) -> None:
        out = Format.non_ascii_to_hex(b"\xff\xfa")
        assert out == "fffa"

    def test_str_ascii_printable_passthrough(self) -> None:
        assert Format.non_ascii_to_hex("Hello\tWorld") == "Hello\tWorld"

    def test_str_non_ascii_to_utf8_hex(self) -> None:
        # "あ" in UTF-8 is e3 81 82
        assert Format.non_ascii_to_hex("あ") == "e38182"

    def test_other_types_str_coercion(self) -> None:
        # falls back to str(value)
        assert Format.non_ascii_to_hex(12345) == "12345"
