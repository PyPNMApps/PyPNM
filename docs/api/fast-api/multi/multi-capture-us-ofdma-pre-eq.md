# Multi-Capture US OFDMA Pre-Equalization

This API runs periodic upstream OFDMA pre-equalization captures and stores each capture as PNM files. After the
capture window completes, you can download a ZIP of the PNM files or run post-capture signal analysis.

## Endpoints

| # | Method | Path | Description |
| - | ------ | ---- | ----------- |
| 1 | POST | `/advance/multi/usOfdmaPreEqualization/start` | Begin a multi-sample US OFDMA pre-equalization capture |
| 2 | GET | `/advance/multi/usOfdmaPreEqualization/status/{operation_id}` | Poll capture progress |
| 3 | GET | `/advance/multi/usOfdmaPreEqualization/results/{operation_id}` | Download a ZIP of captured PNM files |
| 4 | DELETE | `/advance/multi/usOfdmaPreEqualization/stop/{operation_id}` | Stop the capture after the current iteration |
| 5 | POST | `/advance/multi/usOfdmaPreEqualization/analysis` | Run post-capture signal analysis |

## Start capture

**Request** `POST /advance/multi/usOfdmaPreEqualization/start`

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

**Request** `GET /advance/multi/usOfdmaPreEqualization/status/{operation_id}`

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

**Request** `GET /advance/multi/usOfdmaPreEqualization/results/{operation_id}`

Returns a ZIP file containing the captured PNM files for each iteration.

- ZIP name: `multiUsOfdmaPreEqualization_<mac>_<operation_id>.zip`

## Stop

**Request** `DELETE /advance/multi/usOfdmaPreEqualization/stop/{operation_id}`

Stops the capture after the current iteration finishes. The `status` endpoint will reflect final state once complete.

## Analysis

**Request** `POST /advance/multi/usOfdmaPreEqualization/analysis`

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
