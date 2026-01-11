# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import numpy as np
import pytest

from pypnm.api.routes.advance.analysis.signal_analysis.detection.anolamaly.heatmap_anomaly_detection import (
    HeatmapAnomalyDetector,
)


@pytest.mark.pnm
def test_compute_zmap_basic_stats() -> None:
    # simple 2D ramp
    a = np.arange(20, dtype=float).reshape(4, 5)
    det = HeatmapAnomalyDetector(a, threshold=2.0)
    z = det.compute_zmap()

    assert z.shape == a.shape
    # zmap should be zero-mean, unit-variance (up to numerical tolerance)
    assert abs(z.mean()) < 1e-12
    assert abs(z.std() - 1.0) < 1e-12


@pytest.mark.pnm
def test_compute_zmap_zero_sigma() -> None:
    # constant matrix -> std == 0 -> zmap should be all zeros
    a = np.full((3, 4), 7.0)
    det = HeatmapAnomalyDetector(a, threshold=3.0)
    z = det.compute_zmap()
    assert np.all(z == 0.0)

    mask = det.detect()
    assert mask.shape == a.shape
    # no anomalies because z == 0 everywhere
    assert not mask.any()


@pytest.mark.pnm
def test_detect_thresholding_and_boxes_single_blob() -> None:
    # Create a small grid with one obvious high anomaly block
    a = np.zeros((6, 6), dtype=float)
    a[2:4, 3:5] = 100.0  # 2x2 bright blob

    det = HeatmapAnomalyDetector(a, threshold=2.0)
    mask = det.detect()

    # Blob region should be True; outside False
    assert mask[2:4, 3:5].all()
    assert not mask[:2, :].any()
    assert not mask[4:, :].any()

    boxes = det.find_boxes()
    # exactly one box, spanning the 2x2 region
    assert len(boxes) == 1
    r0, c0, r1, c1 = boxes[0]
    assert (r0, c0, r1, c1) == (2, 3, 3, 4)


@pytest.mark.pnm
def test_find_boxes_multiple_disjoint_blobs() -> None:
    a = np.zeros((8, 8), dtype=float)
    a[1:3, 1:3] = 10.0  # blob A
    a[5:7, 5:7] = -10.0  # blob B (negative should also be flagged via |z|)

    det = HeatmapAnomalyDetector(a, threshold=1.0)
    det.detect()
    boxes = det.find_boxes()

    # We expect two disjoint boxes
    assert len(boxes) == 2
    assert (1, 1, 2, 2) in boxes
    assert (5, 5, 6, 6) in boxes


@pytest.mark.pnm
def test_four_connectivity_not_diagonal_connected() -> None:
    # Two pixels touching diagonally should be separate components.
    a = np.zeros((3, 3), dtype=float)
    a[0, 0] = 100.0
    a[1, 1] = 100.0

    det = HeatmapAnomalyDetector(a, threshold=1.0)
    det.detect()
    boxes = det.find_boxes()

    assert len(boxes) == 2
    assert (0, 0, 0, 0) in boxes
    assert (1, 1, 1, 1) in boxes


@pytest.mark.pnm
def test_to_json_structure_after_detection() -> None:
    a = np.zeros((5, 5), dtype=float)
    a[2, 2] = 50.0

    det = HeatmapAnomalyDetector(a, threshold=1.5)
    det.detect()
    det.find_boxes()
    payload = det.to_json()

    assert "threshold" in payload and payload["threshold"] == 1.5
    assert "boxes" in payload and isinstance(payload["boxes"], list)
    # one 1x1 box expected
    assert payload["boxes"] == [
        {"row_min": 2, "col_min": 2, "row_max": 2, "col_max": 2}
    ]
