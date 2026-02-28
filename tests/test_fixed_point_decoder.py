# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import math

import pytest

from pypnm.pnm.lib.fixed_point_decoder import (
    FixedPointDecoder,
    FractionalBits,
    IntegerBits,
)

# ───────────────────────── helpers ─────────────────────────

def _q(a: int, b: int) -> tuple[IntegerBits, FractionalBits]:
    return (IntegerBits(a), FractionalBits(b))

def _bits_per_component(q: tuple[IntegerBits, FractionalBits]) -> int:
    a, b = int(q[0]), int(q[1])
    return a + b + 1  # +1 sign bit

def _bytes_per_component(q: tuple[IntegerBits, FractionalBits]) -> int:
    tbits = _bits_per_component(q)
    assert tbits % 8 == 0, "Test helper expects byte-aligned Q formats"
    return tbits // 8

def _scale(q: tuple[IntegerBits, FractionalBits]) -> int:
    return 1 << int(q[1])

def _twos_wrap(n: int, total_bits: int) -> int:
    mask = (1 << total_bits) - 1
    return n & mask

def _pack_component(value: float, q: tuple[IntegerBits, FractionalBits], *, signed: bool, byteorder: str) -> bytes:
    """Pack one fixed-point component into bytes, respecting endianness."""
    frac = int(q[1])
    total_bits = _bits_per_component(q)
    byte_len = _bytes_per_component(q)
    scale = 1 << frac

    # Convert float to fixed
    raw = int(round(value * scale))

    if signed:
        raw = _twos_wrap(raw, total_bits)
        return raw.to_bytes(byte_len, byteorder=byteorder, signed=False)

    # unsigned path (clamp)
    max_u = (1 << total_bits) - 1
    raw_u = max(0, min(max_u, raw))
    return raw_u.to_bytes(byte_len, byteorder=byteorder, signed=False)

def _pack_q_pair(re: float, im: float, q: tuple[IntegerBits, FractionalBits], *, signed: bool = True, endian: str = "little") -> bytes:
    """Encode one complex sample for generic Q(a,b), honoring endianness."""
    return (
        _pack_component(re, q, signed=signed, byteorder=endian) +
        _pack_component(im, q, signed=signed, byteorder=endian)
    )

# ───────────────────────── unit tests ─────────────────────────

@pytest.mark.parametrize("q", [_q(1, 14), _q(2, 13)])
def test_decode_fixed_point_signed_basic(q) -> None:
    frac = int(q[1])
    # +1.0
    assert FixedPointDecoder.decode_fixed_point(1 << frac, q, signed=True) == pytest.approx(1.0)
    # +0.25
    assert FixedPointDecoder.decode_fixed_point(1 << (frac - 2), q, signed=True) == pytest.approx(0.25)
    # -1.0 (two's complement of +1.0)
    total_bits = _bits_per_component(q)
    neg_one_tc = _twos_wrap(-(1 << frac), total_bits)
    assert FixedPointDecoder.decode_fixed_point(neg_one_tc, q, signed=True) == pytest.approx(-1.0)

def test_decode_fixed_point_unsigned_q1_14() -> None:
    q = _q(1, 14)
    val = FixedPointDecoder.decode_fixed_point(0x7FFF, q, signed=False)
    assert val == pytest.approx(0x7FFF / (2 ** 14))

def test_decode_fixed_point_non_byte_aligned_allowed_single_value() -> None:
    # Single-value decoder does not enforce byte alignment (only complex decoder does).
    q_bad = _q(1, 15)  # 17 total bits
    val = FixedPointDecoder.decode_fixed_point(0x1, q_bad, signed=True)
    assert val == pytest.approx(1 / (2 ** 15))

def test_decode_complex_rejects_non_byte_aligned() -> None:
    q_bad = _q(1, 15)  # 17 total bits → not byte aligned
    with pytest.raises(ValueError, match="must be a multiple of 8"):
        FixedPointDecoder.decode_complex_data(b"\x00" * 8, q_bad, signed=True)

@pytest.mark.parametrize("q", [_q(1, 14), _q(2, 13)])
@pytest.mark.parametrize("endian", ["little", "big"])
def test_decode_complex_two_samples_signed_roundtrip(q, endian) -> None:
    # Two samples: (1.0, -0.5) and (0.25, 0.0)
    blob = b"".join([
        _pack_q_pair(1.0, -0.5, q, signed=True, endian=endian),
        _pack_q_pair(0.25, 0.0, q, signed=True, endian=endian),
    ])
    out = FixedPointDecoder.decode_complex_data(blob, q, signed=True, endian=endian)
    assert isinstance(out, list)
    assert len(out) == 2
    assert out[0].real == pytest.approx(1.0)
    assert out[0].imag == pytest.approx(-0.5)
    assert out[1].real == pytest.approx(0.25)
    assert out[1].imag == pytest.approx(0.0)

def test_decode_complex_invalid_length() -> None:
    q = _q(1, 14)
    with pytest.raises(ValueError, match="data length must be a multiple of the complex number size"):
        FixedPointDecoder.decode_complex_data(b"\x00\x01\x02", q, signed=True)

def test_decode_complex_unsigned_mode() -> None:
    q = _q(1, 14)
    # Pack using unsigned semantics:
    blob = _pack_q_pair(0x7FFF / (2 ** 14), 0.5, q, signed=False, endian="little")
    vals = FixedPointDecoder.decode_complex_data(blob, q, signed=False, endian="little")
    assert len(vals) == 1
    assert vals[0].real == pytest.approx(0x7FFF / (2 ** 14))
    assert vals[0].imag == pytest.approx(0.5)

def test_decode_complex_empty_ok() -> None:
    q = _q(2, 13)
    out = FixedPointDecoder.decode_complex_data(b"", q, signed=True, endian="big")
    assert isinstance(out, list)
    assert len(out) == 0

@pytest.mark.parametrize("q", [_q(1, 14), _q(2, 13)])
def test_decode_complex_wrong_endian_changes_values(q) -> None:
    # Build little-endian blob but decode as big-endian: values should not match expected
    expected = [(0.5, -0.25), (-0.75, 0.125)]
    blob_le = b"".join(_pack_q_pair(r, i, q, signed=True, endian="little") for (r, i) in expected)

    out_be = FixedPointDecoder.decode_complex_data(blob_le, q, signed=True, endian="big")
    assert len(out_be) == len(expected)

    # At least one component must differ significantly if endian is wrong.
    mismatches = 0
    for got, (er, ei) in zip(out_be, expected, strict=False):
        if not math.isclose(got.real, er, rel_tol=1e-6, abs_tol=1e-6) or \
           not math.isclose(got.imag, ei, rel_tol=1e-6, abs_tol=1e-6):
            mismatches += 1
    assert mismatches >= 1

@pytest.mark.parametrize("q", [_q(1, 14), _q(2, 13)])
def test_decode_complex_data_multiple_samples_roundtrip_like(q) -> None:
    samples = [(0.0, 0.0), (0.5, 0.5), (-0.75, 0.25), (1.0, -1.0)]
    blob = b"".join(_pack_q_pair(r, i, q, signed=True, endian="little") for (r, i) in samples)
    out = FixedPointDecoder.decode_complex_data(blob, q, signed=True, endian="little")
    assert len(out) == len(samples)
    for got, (er, ei) in zip(out, samples, strict=False):
        assert got.real == pytest.approx(er, abs=1e-4)
        assert got.imag == pytest.approx(ei,  abs=1e-4)
