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
  "system_description": {
    "HW_REV": "1.0",
    "VENDOR": "LANCity",
    "BOOTR": "NONE",
    "SW_REV": "1.0.0",
    "MODEL": "LCPET-3",
    "is_empty": false
  },
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
  "system_description": {
    "HW_REV": "1.0",
    "VENDOR": "LANCity",
    "BOOTR": "NONE",
    "SW_REV": "1.0.0",
    "MODEL": "LCPET-3",
    "is_empty": false
  },
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

Typical stop response:

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "system_description": {
    "HW_REV": "1.0",
    "VENDOR": "LANCity",
    "BOOTR": "NONE",
    "SW_REV": "1.0.0",
    "MODEL": "LCPET-3",
    "is_empty": false
  },
  "status": "stopped",
  "message": null,
  "operation": {
    "operation_id": "4aca137c1e9d4eb6",
    "state": "stopped",
    "collected": 8,
    "time_remaining": 0,
    "message": null
  }
}
```

## Analysis

**Request** `POST /advance/multi/us/ofdmaPreEqualization/analysis`
**Body** (`MultiUsOfdmaPreEqAnalysisRequest` - preferred string enums):

```json
{
  "analysis": {
    "type": "group-delay",
    "output": { "type": "json" }
  },
  "operation_id": "4aca137c1e9d4eb6"
}
```

## Analysis Types

**Analysis Types** (`analysis.type`)

| Type                  | Description                                                |
| --------------------- | ---------------------------------------------------------- |
| `min-avg-max`         | Min/avg/max magnitude across captures per subcarrier       |
| `group-delay`         | Per-subcarrier group delay from averaged phase response    |
| `echo-detection-ifft` | Echo/impulse response estimation via IFFT                  |

**Output Types** (`analysis.output.type`)

| Value       | Name      | Description                            | Media Type         |
| :---------- | :-------- | :------------------------------------- | :----------------- |
| `"json"`    | `JSON`    | Structured JSON body                   | `application/json` |
| `"archive"` | `ARCHIVE` | ZIP containing CSV + PNG report bundle | `application/zip`  |

## Response Fields By Analysis Type

For **Min-Avg-Max**:

| Field/Path           | Type/Example | Meaning                                   |
| -------------------- | ----------- | ----------------------------------------- |
| `results[].channel_id` | int       | Channel identifier.                        |
| `results[].frequency`  | array[int] (Hz) | Subcarrier center frequencies.        |
| `results[].min`        | array[float] | Minimum magnitude per subcarrier.        |
| `results[].avg`        | array[float] | Average magnitude per subcarrier.        |
| `results[].max`        | array[float] | Maximum magnitude per subcarrier.        |

For **Group Delay**:

| Field/Path              | Type/Example     | Meaning                                  |
| ----------------------- | --------------- | ---------------------------------------- |
| `results[].channel_id`  | int             | Channel identifier.                       |
| `results[].frequency`   | array[int] (Hz) | Subcarrier center frequencies.            |
| `results[].group_delay_us` | array[float] | Group delay values (microseconds).     |

For **Echo-Detection (IFFT)**:

| Field/Path                 | Type/Example | Meaning                                      |
| -------------------------- | ----------- | -------------------------------------------- |
| `results[].channel_id`     | int         | Channel identifier.                           |
| `results[].impulse_response` | array[float] | Impulse-response magnitude vs sample index. |
| `results[].sample_rate`    | float (Hz)  | Sample rate used for IFFT.                   |

**Response**

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": 0,
  "message": "Analysis group-delay completed for group 3bd6f7c107ad465b",
  "data": {
    "analysis_type": "group-delay",
    "results": []
  }
}
```

## Session Metadata

`system_description` behavior for multi-capture:
1. Captured once during start precheck.
2. Cached for the operation session.
3. Returned in start/status/stop responses.
4. Reused for transaction metadata insertion to avoid repeated per-sample SNMP sysDescr calls.
