## Agent Review Bundle Summary
- Goal: Update US OFDMA pre-eq docs and add tests for OFDMA analysis types.
- Changes: Removed unsupported OFDMA analysis type from docs; added analysis type validation tests.
- Files: docs/api/fast-api/multi/multi-capture-us-ofdma-pre-eq.md; tests/test_multi_us_ofdma_pre_eq_analysis_types.py.
- Tests: python3 -m compileall src; ruff check src; ruff format --check . (fails: repo drift); pytest -q; mkdocs build -s.
- Notes: pytest skips due to PNM_CM_IT not set; ruff format check failed because of pre-existing formatting drift; mkdocs build reports pages not in nav.

# FILE: docs/api/fast-api/multi/multi-capture-us-ofdma-pre-eq.md
# Multi-Capture US OFDMA Pre-Equalization

This API runs periodic upstream OFDMA pre-equalization captures and stores each capture as PNM files. After the
capture window completes, you can download a ZIP of the PNM files or run post-capture signal analysis.

## Endpoints

| # | Method | Path | Description |
| - | ------ | ---- | ----------- |
| 1 | POST | `/advance/multiUsOfdmaPreEqualization/start` | Begin a multi-sample US OFDMA pre-equalization capture |
| 2 | GET | `/advance/multiUsOfdmaPreEqualization/status/{operation_id}` | Poll capture progress |
| 3 | GET | `/advance/multiUsOfdmaPreEqualization/results/{operation_id}` | Download a ZIP of captured PNM files |
| 4 | DELETE | `/advance/multiUsOfdmaPreEqualization/stop/{operation_id}` | Stop the capture after the current iteration |
| 5 | POST | `/advance/multiUsOfdmaPreEqualization/analysis` | Run post-capture signal analysis |

## Start capture

**Request** `POST /advance/multiUsOfdmaPreEqualization/start`

```json
{
  "cable_modem": {
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "ip_address": "192.168.0.100"
  },
  "capture": {
    "parameters": {
      "measurement_duration": 60,
      "sample_interval": 5
    }
  },
  "measure": {
    "mode": 0
  }
}
```

**Response**

```json
{
  "status": 0,
  "message": "Multi capture started",
  "group_id": "group-1",
  "operation_id": "op-1"
}
```

## Status

**Request** `GET /advance/multiUsOfdmaPreEqualization/status/{operation_id}`

**Response**

```json
{
  "status": 0,
  "message": "OK",
  "operation": {
    "operation_id": "op-1",
    "state": "running",
    "collected": 3,
    "time_remaining": 45,
    "message": null
  }
}
```

## Results

**Request** `GET /advance/multiUsOfdmaPreEqualization/results/{operation_id}`

Returns a ZIP file containing the captured PNM files for each iteration.

- ZIP name: `multiUsOfdmaPreEqualization_<mac>_<operation_id>.zip`

## Stop

**Request** `DELETE /advance/multiUsOfdmaPreEqualization/stop/{operation_id}`

Stops the capture after the current iteration finishes. The `status` endpoint will reflect final state once complete.

## Analysis

**Request** `POST /advance/multiUsOfdmaPreEqualization/analysis`

```json
{
  "operation_id": "op-1",
  "analysis": {
    "type": "MIN_AVG_MAX",
    "output": {
      "type": "JSON"
    },
    "plot": {
      "enable": false
    }
  }
}
```

Supported analysis types:

- MIN_AVG_MAX
- GROUP_DELAY
- ECHO_DETECTION_IFFT

**Response**

```json
{
  "status": 0,
  "message": "OK",
  "data": {
    "analysis_type": "MIN_AVG_MAX",
    "results": []
  }
}
```


# FILE: tests/test_multi_us_ofdma_pre_eq_analysis_types.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import pytest
from pydantic import ValidationError

from pypnm.api.routes.advance.analysis.signal_analysis.multi_ofdma_pre_eq_signal_analysis import (
    MultiOfdmaPreEqAnalysisType,
)
from pypnm.api.routes.advance.multi_us_ofdma_pre_eq.schemas import (
    MultiUsOfdmaPreEqAnalysisContainerModel,
)


def test_ofdma_pre_eq_analysis_type_values() -> None:
    values = {item.value for item in MultiOfdmaPreEqAnalysisType}
    assert values == {"min-avg-max", "group-delay", "echo-detection-ifft"}
    assert "lte-detection-phase-slope" not in values


def test_ofdma_pre_eq_analysis_schema_rejects_lte() -> None:
    with pytest.raises(ValidationError):
        MultiUsOfdmaPreEqAnalysisContainerModel(type="lte-detection-phase-slope")
