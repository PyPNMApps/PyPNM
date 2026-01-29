## Agent Review Bundle Summary
- Goal: Correct US OFDMA Pre-Equalization analysis request/response docs and list per-analysis response fields.
- Changes: Updated analysis request schema, added analysis/output tables and per-type response fields, refreshed example response, added FAQ entry.
- Files: docs/api/fast-api/multi/multi-capture-us-ofdma-pre-eq.md; docs/issues/index.md
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

# FILE: /home/dev01/Projects/PyPNM/docs/issues/index.md
# Reporting Issues

If you encounter a bug or unexpected behavior while using PyPNM, please report it
so we can investigate and resolve the issue. This document outlines the steps to
create a support bundle that captures the necessary data for debugging.

[REPORTING ISSUES](reporting-issues.md)

## Support Bundle Script

PyPNM includes a support bundle script that collects relevant logs, database
entries, and configuration files related to your issue. This script helps
sanitize sensitive information before sharing it with the PyPNM support team.

[Support Bundle Builder](support-bundle.md)

## FAQ

Q: Why is extension data missing after processing a PNM transaction record?  
A: Ensure the transaction record includes an `extension` mapping and that the update helper merges the extension into the PNM data before returning the result.

Q: Why does US PreEq SNMP retrieval log validation errors about missing fields?  
A: Some modems return sparse or empty entries for certain indices. Ensure the device supports the table and that the entry is populated; missing required fields will cause the entry to be skipped.

Q: Why do multi US OFDMA Pre-Equalization plots show a Channel Estimation title?  
A: Update to a build that includes the plot title fix; the title now reflects the PNM file type as US PreEqualization (PNN6) or US Last PreEqualization (PNN7).

Q: Why do US OFDMA Pre-Equalization analysis examples reject uppercase analysis types?  
A: The multi-capture analysis endpoints accept the string enum values (`min-avg-max`, `group-delay`, `echo-detection-ifft`) along with the standard analysis output structure.

## TODO

- Add or update a FAQ entry whenever an error is fixed so the resolution is documented.
- Add FAQ entries when SNMP validation errors are addressed to capture the resolution.
- Track FAQ updates for the US OFDMA Pre-Equalization plot title fix.
- Track FAQ updates for the US OFDMA Pre-Equalization analysis request format.
