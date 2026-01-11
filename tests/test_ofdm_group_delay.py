# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import json
import math

import pytest
from pydantic import BaseModel, ValidationError

from pypnm.lib.signal_processing.groupdelay.ofdm import (
    GroupDelayOptions,
    OFDMGroupDelay,
    SignConvention,
    SpacedFrequencyAxisHz,
)
from pypnm.lib.types import ComplexSeries, FrequencyHz, IntSeries


def synth_constant_tau_channel(n_bins: int, f0_hz: float, df_hz: float, tau_s: float) -> ComplexSeries:
    H: ComplexSeries = []
    for k in range(n_bins):
        f_k = f0_hz + k * df_hz
        phi = +2.0 * math.pi * f_k * tau_s
        H.append(complex(math.cos(phi), math.sin(phi)))
    return H


# ── Functional correctness ─────────────────────────────────────────────────────

@pytest.mark.parametrize(
    ("n_bins", "f0_hz", "df_hz", "tau_s", "delta_us"),
    [
        pytest.param(256, 300e6, 25_000.0, 8e-6, 0.05, id="constant-delay:+8.00µs@25kHzx256"),
        pytest.param(128, 150e6, 50_000.0, 5e-6, 0.05, id="constant-delay:+5.00µs@50kHzx128"),
        pytest.param(512,  90e6, 25_000.0, 3e-6, 0.05, id="constant-delay:+3.00µs@25kHzx512"),
    ],
)
def test_constant_group_delay_plus_sign__matches_true_delay(
    n_bins: int, f0_hz: float, df_hz: float, tau_s: float, delta_us: float
) -> None:
    H = synth_constant_tau_channel(n_bins, f0_hz, df_hz, tau_s)
    axis = SpacedFrequencyAxisHz(f0_hz=FrequencyHz(int(f0_hz)), df_hz=df_hz)
    opts = GroupDelayOptions(sign=SignConvention.PLUS)
    gd = OFDMGroupDelay(H=H, axis=axis, options=opts, active_mask=None)

    res = gd.result()
    assert math.isfinite(res.mean_group_delay_us)
    assert res.mean_group_delay_us == pytest.approx(tau_s * 1e6, abs=delta_us)


@pytest.mark.parametrize(
    "tau_s",
    [
        pytest.param(2e-6, id="sign-flip:2.00µs"),
        pytest.param(7e-6, id="sign-flip:7.00µs"),
        pytest.param(11e-6, id="sign-flip:11.00µs"),
    ],
)
def test_sign_convention_minus__negates_mean_delay(tau_s: float) -> None:
    n_bins, f0_hz, df_hz = 128, 200e6, 25_000.0
    H = synth_constant_tau_channel(n_bins, f0_hz, df_hz, tau_s)
    axis = SpacedFrequencyAxisHz(f0_hz=FrequencyHz(int(f0_hz)), df_hz=df_hz)
    gd = OFDMGroupDelay(H=H, axis=axis, options=GroupDelayOptions(sign=SignConvention.MINUS), active_mask=None)

    res = gd.result()
    assert math.isfinite(res.mean_group_delay_us)
    assert res.mean_group_delay_us == pytest.approx(-tau_s * 1e6, abs=0.05)


def test_enforce_nonnegative_clamps__with_minus_convention() -> None:
    n_bins, f0_hz, df_hz, tau_s = 64, 220e6, 25_000.0, 6e-6
    H = synth_constant_tau_channel(n_bins, f0_hz, df_hz, tau_s)
    axis = SpacedFrequencyAxisHz(f0_hz=FrequencyHz(int(f0_hz)), df_hz=df_hz)
    gd = OFDMGroupDelay(
        H=H,
        axis=axis,
        options=GroupDelayOptions(sign=SignConvention.MINUS, enforce_nonnegative=True),
        active_mask=None,
    )
    res = gd.result()
    assert math.isfinite(res.mean_group_delay_us)
    assert res.mean_group_delay_us == pytest.approx(0.0, abs=0.01)
    assert any(math.isfinite(v) and v == pytest.approx(0.0, abs=1e-3) for v in res.tau_us if math.isfinite(v))


def test_active_mask_gaps__unwrap_is_segmented_and_gaps_nan() -> None:
    n_bins, f0_hz, df_hz, tau_s = 200, 100e6, 25_000.0, 3e-6
    H = synth_constant_tau_channel(n_bins, f0_hz, df_hz, tau_s)

    mask: IntSeries = [1]*50 + [0]*20 + [1]*80 + [0]*50
    axis = SpacedFrequencyAxisHz(f0_hz=FrequencyHz(int(f0_hz)), df_hz=df_hz)
    gd = OFDMGroupDelay(H=H, axis=axis, options=GroupDelayOptions(sign=SignConvention.PLUS), active_mask=mask)
    res = gd.result()

    assert res.mean_group_delay_us == pytest.approx(tau_s * 1e6, abs=0.05)
    assert any(mask[i] == 0 and (not math.isfinite(res.tau_s[i]) or not math.isfinite(res.tau_us[i])) for i in range(n_bins))


def test_smoothing_window__reduces_local_variation_without_biasing_mean() -> None:
    n_bins, f0_hz, df_hz, tau_s = 256, 50e6, 25_000.0, 12e-6
    base = synth_constant_tau_channel(n_bins, f0_hz, df_hz, tau_s)

    eps, period = 0.1, 17
    H: ComplexSeries = []
    for k, h in enumerate(base):
        phi = math.atan2(h.imag, h.real) + eps * math.sin(2.0 * math.pi * (k / period))
        H.append(complex(math.cos(phi), math.sin(phi)))

    axis = SpacedFrequencyAxisHz(f0_hz=FrequencyHz(int(f0_hz)), df_hz=df_hz)

    r_raw = OFDMGroupDelay(H=H, axis=axis, options=GroupDelayOptions(sign=SignConvention.PLUS)).result()
    r_sm  = OFDMGroupDelay(H=H, axis=axis, options=GroupDelayOptions(sign=SignConvention.PLUS, smooth_win=9)).result()

    assert r_raw.mean_group_delay_us == pytest.approx(tau_s * 1e6, abs=0.15)
    assert r_sm.mean_group_delay_us  == pytest.approx(tau_s * 1e6, abs=0.15)

    def mean_abs_delta(series: list[float]) -> float:
        acc = 0.0
        cnt = 0
        for i in range(1, len(series)):
            a, b = series[i-1], series[i]
            if math.isfinite(a) and math.isfinite(b):
                acc += abs(b - a)
                cnt += 1
        return acc / cnt if cnt > 0 else float("nan")

    mad_raw = mean_abs_delta(r_raw.tau_s)
    mad_sm  = mean_abs_delta(r_sm.tau_s)
    assert mad_sm <= mad_raw or math.isclose(mad_sm, mad_raw, rel_tol=1e-6)


# ── Validation & BaseModel compliance ─────────────────────────────────────────

def test_axis_validation__rejects_nonpositive_df() -> None:
    with pytest.raises(ValueError):
        SpacedFrequencyAxisHz(f0_hz=FrequencyHz(int(100e6)), df_hz=0.0)
    with pytest.raises(ValueError):
        SpacedFrequencyAxisHz(f0_hz=FrequencyHz(int(100e6)), df_hz=-25_000.0)


def test_active_mask_length_mismatch__raises_value_error() -> None:
    n_bins, f0_hz, df_hz, tau_s = 16, 80e6, 25_000.0, 2e-6
    H = synth_constant_tau_channel(n_bins, f0_hz, df_hz, tau_s)
    axis = SpacedFrequencyAxisHz(f0_hz=FrequencyHz(int(f0_hz)), df_hz=df_hz)
    bad_mask: IntSeries = [1] * (n_bins - 1)
    with pytest.raises(ValueError):
        OFDMGroupDelay(H=H, axis=axis, active_mask=bad_mask)


def test_models_are_pydantic_basemodels__axis_and_options() -> None:
    axis = SpacedFrequencyAxisHz(f0_hz=FrequencyHz(300_000_000), df_hz=25_000.0)
    opts = GroupDelayOptions()
    assert isinstance(axis, BaseModel)
    assert isinstance(opts, BaseModel)


def test_groupdelayoptions_validation__smooth_win_rules() -> None:
    with pytest.raises(ValidationError):
        GroupDelayOptions(smooth_win=2)
    with pytest.raises(ValidationError):
        GroupDelayOptions(smooth_win=0)
    with pytest.raises(ValidationError):
        GroupDelayOptions(smooth_win=-3)
    assert GroupDelayOptions(smooth_win=3).smooth_win == 3
    assert GroupDelayOptions(smooth_win=9).smooth_win == 9


def test_axis_json_roundtrip__model_dump_and_validate_json() -> None:
    axis = SpacedFrequencyAxisHz(f0_hz=FrequencyHz(450_000_000), df_hz=50_000.0)
    s = axis.model_dump_json()
    axis2 = SpacedFrequencyAxisHz.model_validate_json(s)
    assert axis2.f0_hz == axis.f0_hz
    assert axis2.df_hz == axis.df_hz


def test_compact_model_dump_schema__keys_and_lengths() -> None:
    n_bins, f0_hz, df_hz, tau_s = 64, 300e6, 25_000.0, 4e-6
    H = synth_constant_tau_channel(n_bins, f0_hz, df_hz, tau_s)
    gd = OFDMGroupDelay(
        H=H,
        axis=SpacedFrequencyAxisHz(f0_hz=FrequencyHz(int(f0_hz)), df_hz=df_hz),
        options=GroupDelayOptions(sign=SignConvention.PLUS),
    )
    compact = gd.series()
    payload = compact.model_dump()
    assert set(payload.keys()) == {"freq_hz", "tau_s"}
    assert isinstance(payload["freq_hz"], list) and len(payload["freq_hz"]) == n_bins
    assert isinstance(payload["tau_s"], list) and len(payload["tau_s"]) == n_bins
    assert all(isinstance(x, int) for x in payload["freq_hz"])


def test_full_model_dump_and_types__required_keys_and_json_safe() -> None:
    n_bins, f0_hz, df_hz, tau_s = 128, 200e6, 25_000.0, 9e-6
    H = synth_constant_tau_channel(n_bins, f0_hz, df_hz, tau_s)
    gd = OFDMGroupDelay(
        H=H,
        axis=SpacedFrequencyAxisHz(f0_hz=FrequencyHz(int(f0_hz)), df_hz=df_hz),
        options=GroupDelayOptions(sign=SignConvention.PLUS, smooth_win=7),
    )
    full = gd.result()
    dump = full.model_dump()

    assert {
        "freq_hz", "wrapped_phase", "unwrapped_phase", "dphi_df",
        "tau_s", "tau_us", "valid_mask", "mean_group_delay_us"
    }.issubset(dump.keys())

    for key in ["freq_hz", "wrapped_phase", "unwrapped_phase", "dphi_df", "tau_s", "tau_us", "valid_mask"]:
        assert isinstance(dump[key], list) and len(dump[key]) == n_bins

    assert all(v in (0, 1) for v in dump["valid_mask"])
    assert all(isinstance(x, int) for x in dump["freq_hz"])
    assert all(isinstance(x, float) for x in dump["tau_s"])
    assert all(isinstance(x, float) for x in dump["tau_us"])
    assert isinstance(dump["mean_group_delay_us"], float)

    json.dumps(dump)


def test_schema_contains_descriptions__spot_check_required_fields() -> None:
    schema = OFDMGroupDelay.model_json_schema()
    props = schema.get("properties", {})
    assert "H" in props and "description" in props["H"]
    assert "axis" in props and "description" in props["axis"]
    assert "options" in props and "description" in props["options"]


def test_invalid_active_mask_type_rejected__length_check() -> None:
    n_bins, f0_hz, df_hz, tau_s = 8, 100e6, 25_000.0, 1e-6
    H = synth_constant_tau_channel(n_bins, f0_hz, df_hz, tau_s)
    axis = SpacedFrequencyAxisHz(f0_hz=FrequencyHz(int(f0_hz)), df_hz=df_hz)
    with pytest.raises(ValueError):
        OFDMGroupDelay(H=H, axis=axis, active_mask=[1, 0, 1])  # wrong length
