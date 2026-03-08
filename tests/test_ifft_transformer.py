# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import numpy as np
import pytest

from pypnm.lib.signal_processing.ifft_transformer import FrequencyDomainIfftTransformer


def test_transform_single_series_hann_no_padding_matches_numpy_pipeline() -> None:
    x = np.array([1.0, 2.0, 3.0, 4.0], dtype=float)
    tr = FrequencyDomainIfftTransformer(window="hann", pad_to_power_of_two=False)

    y = tr.transform(x)
    expected = np.fft.ifft(x * np.hanning(x.size), n=x.size)

    assert y.shape == (x.size,)
    assert np.allclose(y, expected, atol=1e-12)


def test_transform_multi_series_averages_then_transforms() -> None:
    a = np.array([1.0, 2.0, 3.0, 4.0], dtype=float)
    b = np.array([2.0, 3.0, 4.0, 5.0], dtype=float)
    samples = np.vstack([a, b])
    tr = FrequencyDomainIfftTransformer(window="hann", pad_to_power_of_two=False)

    y = tr.transform(samples)

    avg = np.mean(samples, axis=0)
    expected = np.fft.ifft(avg * np.hanning(avg.size), n=avg.size)
    assert np.allclose(y, expected, atol=1e-12)


def test_transform_zero_pads_to_next_power_of_two() -> None:
    x = np.array([1.0, 2.0, 3.0, 4.0, 5.0], dtype=float)  # len=5 -> 8
    tr = FrequencyDomainIfftTransformer(window="none", pad_to_power_of_two=True)

    y = tr.transform(x)

    assert y.shape == (8,)
    assert np.allclose(y, np.fft.ifft(x, n=8), atol=1e-12)


def test_transform_rejects_non_finite_values() -> None:
    tr = FrequencyDomainIfftTransformer()
    with pytest.raises(ValueError, match="finite"):
        tr.transform([1.0, float("nan"), 2.0])


def test_transform_rejects_ragged_2d_input() -> None:
    tr = FrequencyDomainIfftTransformer()
    with pytest.raises(ValueError, match="rectangular 2-D"):
        tr.transform([[1.0, 2.0], [3.0]])


def test_transform_rejects_unsupported_window() -> None:
    with pytest.raises(ValueError, match="Unsupported window"):
        FrequencyDomainIfftTransformer(window="blackman")
