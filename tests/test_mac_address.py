# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import pytest

from pypnm.lib.mac_address import MacAddress, MacAddressFormat


def test_construct_from_str_and_str_repr() -> None:
    mac = MacAddress("00:1A:2B:3C:4D:5E")
    # normalized internal
    assert mac.mac_address == "001a2b3c4d5e"
    # __str__ uses colon form
    assert str(mac) == "00:1a:2b:3c:4d:5e"


def test_construct_from_bytes_and_equality() -> None:
    b = bytes.fromhex("001A2B3C4D5E")
    mac_b = MacAddress(b)
    mac_s = MacAddress("00-1a-2b-3c-4d-5e")
    assert mac_b == mac_s
    assert mac_b.is_equal(mac_s) is True
    # hashes should match for set/dict behavior
    assert hash(mac_b) == hash(mac_s)
    # to_bytes should round-trip to the original bytes
    assert mac_b.to_bytes() == b


def test_to_mac_format_variants() -> None:
    mac = MacAddress("001a.2b3c.4d5e")
    assert mac.to_mac_format(MacAddressFormat.FLAT) == "001a2b3c4d5e"
    assert mac.to_mac_format(MacAddressFormat.COLON) == "00:1a:2b:3c:4d:5e"
    assert mac.to_mac_format(MacAddressFormat.HYPHEN) == "00-1a-2b-3c-4d-5e"
    assert mac.to_mac_format(MacAddressFormat.CISCO) == "001a.2b3c.4d5e"


def test_is_multicast_and_null() -> None:
    # LSB of first octet set -> multicast
    assert MacAddress("01:00:5e:00:00:00").is_multicast() is True
    assert MacAddress("00:00:00:00:00:01").is_multicast() is False

    # null helpers
    assert MacAddress.null() == "00:00:00:00:00:00"
    assert MacAddress("00:00:00:00:00:00").is_null() is True
    assert MacAddress("00:00:00:00:00:01").is_null() is False


def test_is_valid_and_errors() -> None:
    assert MacAddress.is_valid("aa:bb:cc:dd:ee:ff") is True
    assert MacAddress.is_valid("AABBCCDDEEFF") is True
    assert MacAddress.is_valid(b"\xaa\xbb\xcc\xdd\xee\xff") is True

    # bad length / chars
    assert MacAddress.is_valid("zz:bb:cc:dd:ee:ff") is False
    assert MacAddress.is_valid("00:11:22:33:44") is False  # too short
    with pytest.raises(ValueError):
        MacAddress("not-a-mac")
    with pytest.raises(TypeError):
        MacAddress(12345)  # type: ignore[arg-type]


def test_accepts_0x_prefix_and_spaces() -> None:
    mac = MacAddress("0x00 1a 2b 3c 4d 5e")
    assert str(mac) == "00:1a:2b:3c:4d:5e"


def test_to_bytes_and_from_bytes_round_trip() -> None:
    mac_str = "de:ad:be:ef:00:01"
    mac = MacAddress(mac_str)

    b = mac.to_bytes()
    assert isinstance(b, bytes)
    assert len(b) == 6

    mac2 = MacAddress.from_bytes(b)
    assert mac2 == mac
    assert mac2.to_mac_format(MacAddressFormat.COLON) == "de:ad:be:ef:00:01"


def test_from_bytes_rejects_wrong_length() -> None:
    with pytest.raises(ValueError):
        MacAddress.from_bytes(b"\x00\x11")  # too short

    with pytest.raises(ValueError):
        MacAddress.from_bytes(b"\x00" * 7)  # too long


@pytest.mark.skipif(
    __import__("importlib").util.find_spec("pysnmp") is None,
    reason="pysnmp not installed; OctetString path not testable",
)
def test_construct_from_octetstring_when_available() -> None:
    from pysnmp.proto.rfc1902 import OctetString  # type: ignore

    octs = OctetString(b"\x00\x1a\x2b\x3c\x4d\x5e")
    mac = MacAddress(octs)
    assert mac.mac_address == "001a2b3c4d5e"
