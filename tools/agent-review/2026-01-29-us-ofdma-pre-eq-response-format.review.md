## Agent Review Bundle Summary
- Goal: Align US OFDMA Pre-Equalization multi-capture response examples with the common response format.
- Changes: Updated start/status/analysis response examples to include mac_address, correct status values, and realistic IDs.
- Files: docs/api/fast-api/multi/multi-capture-us-ofdma-pre-eq.md
- Tests: mkdocs build -s
- Notes: mkdocs reports many pages not included in nav (pre-existing).

# FILE: /home/dev01/Projects/PyPNM/docs/api/fast-api/multi/multi-capture-us-ofdma-pre-eq.md
# Multi-Capture US OFDMA Pre-Equalization

This API runs periodic upstream OFDMA pre-equalization captures and stores each capture as PNM files. After the
capture window completes, you can download a ZIP of the PNM files or run post-capture signal analysis.

## Endpoints

| # | Method | Path | Description |
| - | ------ | ---- | ----------- |
| 1 | POST | `/advance/multi/us/ofdmaPreEqualization/start` | Begin a multi-sample US OFDMA pre-equalization capture |
| 2 | GET | `/advance/multi/us/ofdmaPreEqualization/status/{operation_id}` | Poll capture progress |
| 3 | GET | `/advance/multi/us/ofdmaPreEqualization/results/{operation_id}` | Download a ZIP of captured PNM files |
| 4 | DELETE | `/advance/multi/us/ofdmaPreEqualization/stop/{operation_id}` | Stop the capture after the current iteration |
| 5 | POST | `/advance/multi/us/ofdmaPreEqualization/analysis` | Run post-capture signal analysis |

## Start capture

**Request** `POST /advance/multi/us/ofdmaPreEqualization/start`

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
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": "running",
  "message": null,
  "group_id": "3bd6f7c107ad465b",
  "operation_id": "4aca137c1e9d4eb6"
}
```

## Status

**Request** `GET /advance/multi/us/ofdmaPreEqualization/status/{operation_id}`

**Response**

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": "success",
  "message": null,
  "operation": {
    "operation_id": "4aca137c1e9d4eb6",
    "state": "running",
    "collected": 3,
    "time_remaining": 45,
    "message": null
  }
}
```

## Results

**Request** `GET /advance/multi/us/ofdmaPreEqualization/results/{operation_id}`

Returns a ZIP file containing the captured PNM files for each iteration.

- ZIP name: `multiOfdmaPreEqualization_<mac>_<operation_id>.zip`

## Stop

**Request** `DELETE /advance/multi/us/ofdmaPreEqualization/stop/{operation_id}`

Stops the capture after the current iteration finishes. The `status` endpoint will reflect final state once complete.

## Analysis

**Request** `POST /advance/multi/us/ofdmaPreEqualization/analysis`

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
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": 0,
  "message": "Analysis MIN_AVG_MAX completed for group 3bd6f7c107ad465b",
  "data": {
    "analysis_type": "MIN_AVG_MAX",
    "results": []
  }
}
```
