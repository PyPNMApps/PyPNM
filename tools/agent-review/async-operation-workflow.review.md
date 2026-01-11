### Summary
Added a filesystem-backed operation registry with status/cancel/result endpoints for multi-RxMER and multi-ChannelEstimation, plus operation workflow tests and documentation updates for the new async flow.

### Modified Files
- docs/api/fast-api/multi/capture-operation.md
- docs/api/fast-api/multi/multi-capture-chan-est.md
- docs/api/fast-api/multi/multi-capture-rxmer.md
- src/pypnm/api/routes/advance/common/capture_service.py
- src/pypnm/api/routes/advance/common/operation_workflow_service.py
- src/pypnm/api/routes/advance/common/schema/operation_schema.py
- src/pypnm/api/routes/advance/multi_ds_chan_est/router.py
- src/pypnm/api/routes/advance/multi_rxmer/router.py
- src/pypnm/lib/constants.py
- src/pypnm/lib/operations/__init__.py
- src/pypnm/lib/operations/operation_models.py
- src/pypnm/lib/operations/operation_store.py
- tests/test_operation_workflow.py

### Commands Executed And Results
- `python3 -m compileall src` → pass
- `ruff check .` → pass
- `ruff format --check .` → pass
- `pytest` → pass (535 passed, 4 skipped)
- `pypnm-software-qa-checker` → pass

### Tests
- `pytest` → pass (535 passed, 4 skipped)
- `ruff` → pass (`ruff check .`)
- `pypnm-software-qa-checker` → pass

### Notes / Warnings
- Loop nesting checker emitted warnings for existing max_depth=2 locations; check passed.

### Remaining TODOs / Follow-Ups
- None

# FILE: docs/api/fast-api/multi/capture-operation.md
# Multi‑Capture Operation Overview

When you initiate a **multi-capture** session (e.g., Multi‑RxMER or Multi‑DS‑Channel‑Estimation), PyPNM maintains a lightweight file‑based tracking system and stages resulting PNM binaries for downstream workflows.

**Directory Layout**:

```text
.data/
├── db/
│   ├── operation_capture.json      # Maps operations to capture groups
│   ├── capture_group.json          # Records capture groups
│   └── transactions.json           # Lists each staged file transaction
├── operations/
│   └── <operation_id>.json         # Status + progress for async operations
└── pnm/
    └── <.bin files>                # Raw PNM captures retrieved via TFTP
```

## 1. Operation Status Registry (`operations/<operation_id>.json`)

Each operation has its own status file to support `status`, `result`, and `cancel` endpoints.

**Example**:

```json
{
  "operation_id": "f6afb2d7df2c4a5c",
  "state": "running",
  "created_ts": 1730000000,
  "updated_ts": 1730000010,
  "progress_current": 1,
  "progress_total": 6,
  "message": "Operation running",
  "error": null,
  "artifact_paths": [
    "ds_ofdm_rxmer_per_subcar_aa:bb:cc:dd:ee:ff_160_1730000000.bin"
  ]
}
```

## 2. Operation Database (`operation_capture.json`)

Records each background **operation** and its connection to a capture group.

**Example**:

```json
{
  "f6afb2d7df2c4a5c": {
    "capture_group": "10b6ea239641487c",
    "created": 1748280293
  }
}
```

* **Key**: `operation_id` (e.g., `f6afb2d7df2c4a5c`).
* **capture\_group**: Associated `capture_group_id`.
* **created**: Unix timestamp when the operation started.

## 3. Capture Group Database (`capture_group.json`)

Tracks each high‑level invocation as a distinct **capture group**.

**Example**:

```json
{
  "10b6ea239641487c": {
    "created": 1748280293,
    "transactions": [
      "2ee6138bbc1b3c3d",
      "65c04a28d0add931",
      "df4d2b3e3146ef30",
      "6773c9ebc097a579"
    ]
  }
}
```

* **Key**: `capture_group_id` (e.g., `10b6ea239641487c`).
* **created**: Unix timestamp when the group was created.
* **transactions**: List of associated `transaction_id`s (one per file).

## 4. Transactions Manifest (`transactions.json`)

A detailed manifest of every PNM file moved into `.data/pnm/` during the capture.

**Example**:

```json
{
  "2ee6138bbc1b3c3d": {
      "timestamp": 1748280294,
      "mac_address": "aa:bb:cc:dd:ee:ff",
      "pnm_test_type": "DS_OFDM_RXMER_PER_SUBCAR",
      "filename": "ds_ofdm_rxmer_per_subcar_aa:bb:cc:dd:ee:ff_34_1748280294.bin",
      "device_details": {
          "sys_descr": {
              "HW_REV": "1.0",
              "VENDOR": "LANCity",
              "BOOTR": "NONE",
              "SW_REV": "1.0.0",
              "MODEL": "LCPET-3"
          }
      }
  }
}
```

* **Key**: `transaction_id` (e.g., `2ee6138bbc1b3c3d`).
* **timestamp**: Unix epoch when the file was staged.
* **mac\_address**: Sanitized MAC of the target modem.
* **pnm\_test\_type**: Identifier of the PNM capture type.
* **filename**: Name of the `.bin` file in `.data/pnm/`.
* **device\_details.sys\_descr**: Snapshot of modem metadata at capture time.

## Workflow Summary

1. **Start Multi‑Capture**: System generates a new `operation_id` linked to a new `capture_group_id`.
2. **Periodic Triggers**: SNMP instructs the modem to TFTP-upload the PNM blob.
3. **File Staging**: PyPNM copies each `.bin` into `.data/pnm/` and appends a JSON entry.
4. **Database Updates**: Timestamps and transaction lists are updated in both `operation_capture.json` and `capture_group.json`.
5. **Completion**: After the capture ends, the three JSON tables fully describe what was captured, when, and for which operation/group.

> Downstream tools can monitor `transactions.json` as a manifest to automatically discover and process new PNM files—no manual polling required.

1. **Start Multi‑Capture**: System generates a new `operation_id` linked to a new `capture_group_id`.
2. **Periodic Triggers**: SNMP instructs the modem to TFTP-upload the PNM blob.
3. **File Staging**: PyPNM copies each `.bin` into `.data/pnm/` and appends a JSON entry.
4. **Database Updates**: Timestamps and transaction lists are updated in both `operation_capture.json` and `capture_group.json`.
5. **Completion**: After the capture ends, the three JSON tables fully describe what was captured, when, and for which operation/group.

> Downstream tools can monitor `transactions.json` as a manifest to automatically discover and process new PNM files—no manual polling required.

# FILE: docs/api/fast-api/multi/multi-capture-chan-est.md
# Multi-DS Channel Estimation Capture & Analysis API

A concise, implementation-ready reference for orchestrating downstream OFDM channel-estimation captures, status polling, result retrieval, early termination, and post-capture analysis.

## Contents

* [At a Glance](#at-a-glance)
* [Workflow](#workflow)
* [Endpoints](#endpoints)
  * [1) Start Capture](#1-start-capture)
  * [2) Status (Operation Registry)](#2-status-operation-registry)
  * [3) Result (Operation Registry)](#3-result-operation-registry)
  * [4) Cancel (Operation Registry)](#4-cancel-operation-registry)
  * [5) Download Results (Legacy ZIP)](#5-download-results-legacy-zip)
  * [6) Stop Capture Early (Legacy)](#6-stop-capture-early-legacy)
  * [7) Analysis](#7-analysis)
* [Timing & Polling](#timing--polling)
* [Plot Examples](#plot-examples)
  * [Min-Avg-Max Magnitude Plot](#min-avg-max-magnitude-plot)
  * [Group Delay Plot](#group-delay-plot)
  * [Echo Detection - IFFT Impulse Response](#echo-detection--ifft-impulse-response)
* [Response Field Reference](#response-field-reference)
  * [Start / Status / Stop](#start--status--stop)
  * [Download ZIP](#download-zip)
  * [Analysis (JSON)](#analysis-json)
* [Analysis Types](#analysis-types)

## At a Glance

| Step | HTTP | Path                                       | Purpose                                        |
| ---: | :--- | :----------------------------------------- | :--------------------------------------------- |
|    1 | POST | `/advance/multiChannelEstimation/start`    | Begin a multi-sample ChannelEstimation capture |
|    2 | POST | `/advance/multiChannelEstimation/status`   | Poll capture progress                          |
|    3 | POST | `/advance/multiChannelEstimation/result`   | Retrieve final results once completed          |
|    4 | POST | `/advance/multiChannelEstimation/cancel`   | Cancel the capture after current work          |
|    5 | POST | `/advance/multiChannelEstimation/analysis` | Run post-capture signal analysis               |

Legacy endpoints remain available:
* `GET /advance/multiChannelEstimation/status/{operation_id}`
* `GET /advance/multiChannelEstimation/results/{operation_id}`
* `DELETE /advance/multiChannelEstimation/stop/{operation_id}`

### Identifiers

* `group_id`: Logical grouping for related operations.
* `operation_id`: Unique handle for one capture session. Use it for status, stop, results, and analysis.

## Workflow

1. **Start Capture** → receive `group_id` and `operation_id`.
2. **Poll Status** until `state == "completed"`.
3. **Retrieve Results** once finished.
4. **(Optional)** **Cancel** to end after the current iteration.
5. **Run Analysis** on the finished capture using `operation_id` + analysis type.

## Endpoints

### 1) Start Capture

Starts a background multi-sample ChannelEstimation capture with a fixed duration and sample interval.

**Request** `POST /advance/multiChannelEstimation/start`  
**Body** (`MultiChanEstRequest`):

```json
{
  "cable_modem": {
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "ip_address": "192.168.0.100"
  },
  "snmp": {
    "snmpV2C": { "community": "public" }
  },
  "capture": {
    "parameters": {
      "measurement_duration": 120,
      "sample_interval": 15
    }
  }
}
```

#### Response (MultiChanEstimationStartResponse)

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": "running",
  "message": null,
  "group_id": "3bd6f7c107ad465b",
  "operation_id": "3df9f479d7a549b7"
}
```

### 2) Status (Operation Registry)

**Request** `POST /advance/multiChannelEstimation/status`  
**Body**:

```json
{
  "operation_id": "3df9f479d7a549b7"
}
```

#### Response

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": "success",
  "message": null,
  "operation": {
    "operation_id": "3df9f479d7a549b7",
    "state": "running",
    "created_ts": 1730000000,
    "updated_ts": 1730000015,
    "progress_current": 1,
    "progress_total": 8,
    "message": "Operation running",
    "error": null,
    "artifact_paths": [
      "ds_ofdm_chan_estimate_coef_aa:bb:cc:dd:ee:ff_160_1730000000.bin"
    ]
  }
}
```

### 3) Result (Operation Registry)

**Request** `POST /advance/multiChannelEstimation/result`  
**Body**:

```json
{
  "operation_id": "3df9f479d7a549b7"
}
```

#### Response

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": "success",
  "message": null,
  "operation": {
    "operation_id": "3df9f479d7a549b7",
    "state": "completed",
    "created_ts": 1730000000,
    "updated_ts": 1730000120,
    "progress_current": 8,
    "progress_total": 8,
    "message": "Operation completed",
    "error": null,
    "artifact_paths": [
      "ds_ofdm_chan_estimate_coef_aa:bb:cc:dd:ee:ff_160_1730000000.bin"
    ]
  }
}
```

If the operation is not completed, the endpoint returns HTTP 409.

### 4) Cancel (Operation Registry)

**Request** `POST /advance/multiChannelEstimation/cancel`  
**Body**:

```json
{
  "operation_id": "3df9f479d7a549b7"
}
```

#### Response

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": "success",
  "message": null,
  "operation": {
    "operation_id": "3df9f479d7a549b7",
    "state": "canceled",
    "created_ts": 1730000000,
    "updated_ts": 1730000040,
    "progress_current": 2,
    "progress_total": 8,
    "message": "Operation canceled",
    "error": null,
    "artifact_paths": []
  }
}
```

### 5) Download Results (Legacy ZIP)

**Request** `GET /advance/multiChannelEstimation/results/{operation_id}`

#### Response

* `Content-Type: application/zip`
* ZIP name: `multiChannelEstimation_<mac>_<operation_id>.zip`
* Contains ChannelEstimation coefficient files, for example:

```text
ds_ofdm_chan_estimate_coef_aabbccddeeff_160_1751762613.bin
ds_ofdm_chan_estimate_coef_aabbccddeeff_160_1751762629.bin
ds_ofdm_chan_estimate_coef_aabbccddeeff_160_1751762645.bin
```

### 6) Stop Capture Early (Legacy)

**Request** `DELETE /advance/multiChannelEstimation/stop/{operation_id}`

#### Response (MultiChanEstStatusResponse)

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": "stopped",
  "message": null,
  "operation": {
    "operation_id": "3df9f479d7a549b7",
    "state": "stopped",
    "collected": 5,
    "time_remaining": 0,
    "message": null
  }
}
```

### 7) Analysis

**Request** `POST /advance/multiChannelEstimation/analysis`  
**Body** (`MultiChanEstAnalysisRequest` - preferred string enums):

```json
{
  "analysis": {
    "type": "group-delay",
    "output": { "type": "json" }
  },
  "operation_id": "3df9f479d7a549b7"
}
```

## Analysis Types

**Analysis Types** (`analysis.type`)

| Type                        | Description                                                |
| --------------------------- | ---------------------------------------------------------- |
| `min-avg-max`               | Min/avg/max magnitude across captures per subcarrier       |
| `group-delay`               | Per-subcarrier group delay from averaged phase response    |
| `lte-detection-phase-slope` | LTE-like interference from group-delay ripple anomalies    |
| `echo-detection-ifft`       | Echo/impulse response estimation via IFFT                  |

**Output Types** (`analysis.output.type`)

| Value       | Name      | Description                              | Media Type         |
| :---------- | :-------- | :--------------------------------------- | :----------------- |
| `"json"`    | `JSON`    | Structured JSON body                     | `application/json` |
| `"archive"` | `ARCHIVE` | ZIP containing CSV + PNG report bundle   | `application/zip`  |

## Timing & Polling {#timing--polling}

### Capture Timing

* `measurement_duration` *(s)* → total run length. Example: `120` means two minutes.
* `sample_interval` *(s)* → period between samples. Example: `15` over `120` seconds → **8** samples.

### Polling Strategy

* Poll **no more than once per** `sample_interval`.
* Stop polling when `time_remaining == 0` **and** `state == "completed"` or `state == "stopped"`.

### Results Availability

* When `state ∈ ["completed","stopped"]`, the ZIP is immediately available.
* Files are produced at sampling time; the archive is just a bundle step.

### Stop Semantics

1. Current iteration finishes.  
2. Final PNM for that iteration is written.  
3. `state → "stopped"` (remaining time may be > 0 if mid-interval).

## Plot Examples

### Min-Avg-Max Magnitude Plot

| Channel | Plot | Description                                      | Note                                      |
| ------- | ---- | ------------------------------------------------ | ----------------------------------------- |
| 193     | [Min-Avg-Max ](./images/multi-chan-est/193_chan_est_min_avg_max.png)  | Min/Avg/Max channel-estimation magnitude vs f.   | Flat regions may indicate stable response |
| 194     | [Min-Avg-Max](./images/multi-chan-est/194_chan_est_min_avg_max.png)  | Min/Avg/Max channel-estimation magnitude vs f.   | Flat regions may indicate stable response |
| 195     | [Min-Avg-Max](./images/multi-chan-est/195_chan_est_min_avg_max.png)  | Min/Avg/Max channel-estimation magnitude vs f.   | Flat regions may indicate stable response |
| 196     | [Min-Avg-Max](./images/multi-chan-est/196_chan_est_min_avg_max.png)  | Min/Avg/Max channel-estimation magnitude vs f.   | Flat regions may indicate stable response |
| 197     | [Min-Avg-Max](./images/multi-chan-est/197_chan_est_min_avg_max.png)  | Min/Avg/Max channel-estimation magnitude vs f.   | Flat regions may indicate stable response |

### Group Delay Plot

| Channel | Plot | Description                                      | Note                                      |
| ------- | ---- | ------------------------------------------------ | ----------------------------------------- |
| 193     | [Group Delay](./images/multi-chan-est/193_chan_est_group_delay.png) | Per-subcarrier group delay vs frequency. | Spikes can indicate echoes or filter issues. |
| 194     | [Group Delay](./images/multi-chan-est/194_chan_est_group_delay.png) | Per-subcarrier group delay vs frequency. | Spikes can indicate echoes or filter issues. |
| 195     | [Group Delay](./images/multi-chan-est/195_chan_est_group_delay.png) | Per-subcarrier group delay vs frequency. | Spikes can indicate echoes or filter issues. |
| 196     | [Group Delay](./images/multi-chan-est/196_chan_est_group_delay.png) | Per-subcarrier group delay vs frequency. | Spikes can indicate echoes or filter issues. |
| 197     | [Group Delay](./images/multi-chan-est/197_chan_est_group_delay.png) | Per-subcarrier group delay vs frequency. | Spikes can indicate echoes or filter issues. |


### Echo Detection - IFFT Impulse Response {#echo-detection--ifft-impulse-response}

| Channel | Plot | Description                                      | Note                                      |
| ------- | ---- | ------------------------------------------------ | ----------------------------------------- |
| 193     | [Echo IFFT](./images/multi-chan-est/193_chan_est_echo_ifft.png) | Impulse-response magnitude vs time (IFFT).    | Secondary peaks map to echo paths in the HFC. |
| 194     | [Echo IFFT](./images/multi-chan-est/194_chan_est_echo_ifft.png) | Impulse-response magnitude vs time (IFFT).    | Secondary peaks map to echo paths in the HFC. |
| 195     | [Echo IFFT](./images/multi-chan-est/195_chan_est_echo_ifft.png) | Impulse-response magnitude vs time (IFFT).    | Secondary peaks map to echo paths in the HFC. |
| 196     | [Echo IFFT](./images/multi-chan-est/196_chan_est_echo_ifft.png) | Impulse-response magnitude vs time (IFFT).    | Secondary peaks map to echo paths in the HFC. |
| 197     | [Echo IFFT](./images/multi-chan-est/197_chan_est_echo_ifft.png) | Impulse-response magnitude vs time (IFFT).    | Secondary peaks map to echo paths in the HFC. |


## Response Field Reference

### Operation Registry Responses

`POST /status`, `POST /result`, and `POST /cancel` return the same `operation` shape:

* `state`: `created`, `running`, `completed`, `failed`, `canceled`
* `created_ts` / `updated_ts`: epoch seconds
* `progress_current` / `progress_total`: capture progress counters
* `artifact_paths`: relative artifact paths (when available)

### Start / Status / Stop {#start--status--stop}

| Field                       | Type    | Description                                                                 |
| --------------------------- | ------- | --------------------------------------------------------------------------- |
| `mac_address`               | string  | Cable modem MAC address.                                                    |
| `status`                    | string  | Start: `"running"`; Status/Stop: high-level status string.                 |
| `message`                   | string  | Optional detail text.                                                       |
| `group_id`                  | string  | Logical grouping for related operations (Start only).                       |
| `operation_id`              | string  | Unique capture handle used with status/results/stop/analysis.              |
| `operation.state`           | string  | Current state: `running`, `completed`, or `stopped`.                        |
| `operation.collected`       | integer | Number of captured samples.                                                 |
| `operation.time_remaining`  | integer | Estimated seconds left.                                                     |

### Download ZIP

| Aspect               | Value / Format                                                   |
| -------------------- | ---------------------------------------------------------------- |
| `Content-Type`       | `application/zip`                                               |
| ZIP name             | `multiChannelEstimation_<mac>_<operation_id>.zip`               |
| PNM file name format | `ds_ofdm_chan_estimate_coef_<mac>_<channel_id>_<epoch>.bin`     |

### Analysis (JSON)

These keys appear under the `data` object of `MultiChanEstimationAnalysisResponse`. Per-type models differ, but common fields include:

For **Min-Avg-Max**:

[Min-Avg-Max - Theory of Operation](analysis/multi-chanest-min-avg-max.md)

| Field/Path             | Type/Example        | Meaning                                          |
| ---------------------- | ------------------- | ------------------------------------------------ |
| `results[].channel_id` | int                 | Channel identifier.                              |
| `results[].frequency`  | array[int] (Hz)     | Per-subcarrier center frequency.                 |
| `results[].min`        | array[float] (dB)   | Minimum magnitude per subcarrier.                |
| `results[].avg`        | array[float] (dB)   | Average magnitude per subcarrier.                |
| `results[].max`        | array[float] (dB)   | Maximum magnitude per subcarrier.                |

For **Group-Delay**:

[Group-Delay - Theory of Operation](analysis/group-delay-calculator.md)

| Field/Path                 | Type/Example        | Meaning                                        |
| -------------------------- | ------------------- | ---------------------------------------------- |
| `results[].channel_id`     | int                 | Channel identifier.                            |
| `results[].frequency`      | array[int] (Hz)     | Per-subcarrier center frequency.               |
| `results[].group_delay_us` | array[float] (µs)   | Group delay per subcarrier.                    |

For **LTE-Detection (Phase-Slope)**:

| Field/Path                 | Type/Example        | Meaning                                        |
| -------------------------- | ------------------- | ---------------------------------------------- |
| `results[].channel_id`     | int                 | Channel identifier.                            |
| `results[].anomalies`      | array[float]        | LTE-like anomaly metric per segment/bin.       |
| `results[].threshold`      | float               | Threshold used to flag anomalies.              |
| `results[].bin_widths`     | array[float] (Hz)   | Bin widths used for segmentation.              |

For **Echo-Detection (IFFT)**:

[Echo-Detection (IFFT) - Theory of Operation](analysis/ofdm-echo-detection.md)

| Field/Path                    | Type/Example      | Meaning                                        |
| ----------------------------- | ----------------- | ---------------------------------------------- |
| `results[].channel_id`        | int               | Channel identifier.                            |
| `results[].impulse_response`  | array[float]      | Magnitude of impulse response vs sample index. |
| `results[].sample_rate`       | float (Hz)        | Sample rate used for IFFT.                     |

A typical JSON response:

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": 0,
  "message": "Analysis group-delay completed for group 3bd6f7c107ad465b",
  "data": {
    "analysis_type": "group-delay",
    "results": [
      {
        "channel_id": 194,
        "frequency": [90000000, 90001562, 90003125],
        "group_delay_us": [0.08, 0.07, 0.09]
      }
    ]
  }
}
```

# FILE: docs/api/fast-api/multi/multi-capture-rxmer.md
# Multi‑RxMER Capture & Analysis API

A concise, implementation‑ready reference for orchestrating downstream OFDM RxMER captures, status polling, result retrieval,
early termination, and post‑capture analysis.

## Contents

* [At a Glance](#at-a-glance)
* [Workflow](#workflow)
* [Endpoints](#endpoints)
  * [1) Start Capture](#1-start-capture)
  * [2) Status (Operation Registry)](#2-status-operation-registry)
  * [3) Result (Operation Registry)](#3-result-operation-registry)
  * [4) Cancel (Operation Registry)](#4-cancel-operation-registry)
  * [5) Download Results (Legacy ZIP)](#5-download-results-legacy-zip)
  * [6) Stop Capture Early (Legacy)](#6-stop-capture-early-legacy)
  * [7) Analysis](#7-analysis)
* [Timing & Polling](#timing--polling)
* [Plot Examples](#plot-examples)
  * [Min‑Avg‑Max Line Plot](#min-avg-max-line-plot)
  * [RxMER Heat Map](#rxmer-heat-map)
  * [OFDM Profile Performance 1 Overlay](#ofdm-profile-performance-1-overlay)
* [Response Field Reference](#response-field-reference)
  * [Start / Status / Stop](#start--status--stop)
  * [Download ZIP](#download-zip)
  * [Analysis (JSON)](#analysis-json)
* [Compatibility Matrix](#compatibility-matrix)

## At a Glance

| Step | HTTP | Path                          | Purpose                                |
| ---: | :--- | :---------------------------- | :------------------------------------- |
|    1 | POST | `/advance/multiRxMer/start`   | Begin a background capture             |
|    2 | POST | `/advance/multiRxMer/status`  | Poll capture progress                  |
|    3 | POST | `/advance/multiRxMer/result`  | Retrieve final results once completed  |
|    4 | POST | `/advance/multiRxMer/cancel`  | Cancel the capture after current work  |
|    5 | POST | `/advance/multiRxMer/analysis`| Run post‑capture analytics             |

Legacy endpoints remain available:
* `GET /advance/multiRxMer/status/{operation_id}`
* `GET /advance/multiRxMer/results/{operation_id}`
* `DELETE /advance/multiRxMer/stop/{operation_id}`

### Identifiers

* `group_id`: Logical grouping for related operations.
* `operation_id`: Unique handle for one capture session. Use it for status, stop, results, and analysis.

## Workflow

1. **Start Capture** → receive `group_id` and `operation_id`.
2. **Poll Status** until `state == "completed"`.
3. **Retrieve Results** once finished.
4. **(Optional)** **Cancel** to end after the current iteration.
5. **Run Analysis** on the finished capture using `operation_id` + analysis type.

## Endpoints

### 1) Start Capture

Starts a background RxMER capture with a fixed duration and sample interval.

**Request** `POST /advance/multiRxMer/start`  
**Body** (`MultiRxMerRequest`):

```json
{
  "cable_modem": {
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "ip_address": "192.168.0.100"
  },
  "snmp": {
    "snmpV2C": { "community": "public" }
  },
  "capture": {
    "parameters": {
      "measurement_duration": 60,
      "sample_interval": 10
    }
  },
  "measure": { "mode": 1 }
}
```

#### Compatibility Matrix

| Measure Mode        | Suited Analyses                                                | Processes                                |
| ------------------- | -------------------------------------------------------------- | ---------------------------------------- |
|      `0`            | `min-avg-max`, `rxmer-heat-map`                                | RxMER                                    |
|      `1`            | `ofdm-profile-performance-1`, `min-avg-max`, `rxmer-heat-map`  | RxMER + Modulation Profile + FEC Summary |

> Use `mode=1` when you specifically want OFDM performance context; otherwise `mode=0` is recommended for continuous monitoring.

#### Response (MultiRxMerStartResponse)

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": "running",
  "message": "Starting Multi-RxMER capture for MAC=aa:bb:cc:dd:ee:ff",
  "group_id": "3bd6f7c107ad465b",
  "operation_id": "4aca137c1e9d4eb6"
}
```

### 2) Status (Operation Registry)

**Request** `POST /advance/multiRxMer/status`  
**Body**:

```json
{
  "operation_id": "4aca137c1e9d4eb6"
}
```

#### Response

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": "success",
  "message": null,
  "operation": {
    "operation_id": "4aca137c1e9d4eb6",
    "state": "running",
    "created_ts": 1730000000,
    "updated_ts": 1730000010,
    "progress_current": 1,
    "progress_total": 6,
    "message": "Operation running",
    "error": null,
    "artifact_paths": [
      "ds_ofdm_rxmer_per_subcar_aa:bb:cc:dd:ee:ff_160_1730000000.bin"
    ]
  }
}
```

### 3) Result (Operation Registry)

**Request** `POST /advance/multiRxMer/result`  
**Body**:

```json
{
  "operation_id": "4aca137c1e9d4eb6"
}
```

#### Response

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": "success",
  "message": null,
  "operation": {
    "operation_id": "4aca137c1e9d4eb6",
    "state": "completed",
    "created_ts": 1730000000,
    "updated_ts": 1730000060,
    "progress_current": 6,
    "progress_total": 6,
    "message": "Operation completed",
    "error": null,
    "artifact_paths": [
      "ds_ofdm_rxmer_per_subcar_aa:bb:cc:dd:ee:ff_160_1730000000.bin"
    ]
  }
}
```

If the operation is not completed, the endpoint returns HTTP 409.

### 4) Cancel (Operation Registry)

**Request** `POST /advance/multiRxMer/cancel`  
**Body**:

```json
{
  "operation_id": "4aca137c1e9d4eb6"
}
```

#### Response

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": "success",
  "message": null,
  "operation": {
    "operation_id": "4aca137c1e9d4eb6",
    "state": "canceled",
    "created_ts": 1730000000,
    "updated_ts": 1730000030,
    "progress_current": 2,
    "progress_total": 6,
    "message": "Operation canceled",
    "error": null,
    "artifact_paths": []
  }
}
```

### 5) Download Results (Legacy ZIP)

**Request** `GET /advance/multiRxMer/results/{operation_id}`

#### Response

* `Content-Type: application/zip`
* ZIP name: `<mac>_<model>_<ephoc>.zip`
* Contains files like:

```text
ds_ofdm_rxmer_per_subcar_aabbccddeeff_160_1751762613.bin
ds_ofdm_modulation_profile_aabbccddeeff_160_1762980708
ds_ofdm_codeword_error_rate_aabbccddeeff_160_1762980674.bin
aabbccddeeff_lpet3_1762980743_rxmer_min_avg_max_160.csv
aabbccddeeff_lpet3_1762981896_ofdm_profile_perf_1_ch160_pid0.csv
aabbccddeeff_lpet3_1762981556_rxmer_ofdm_heat_map_160.csv
aabbccddeeff_lpet3_1763007607_160_profile_0_ofdm_profile_perf_1.png
aabbccddeeff_lpet3_1763007680_160_rxmer_min_avg_max.png
aabbccddeeff_lpet3_1763007737_160_rxmer_heat_map.png 
```

### 6) Stop Capture Early (Legacy)

**Request** `DELETE /advance/multiRxMer/stop/{operation_id}`

#### Stop Response (MultiRxMerStatusResponse)

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": "stopped",
  "message": null,
  "operation": {
    "operation_id": "4aca137c1e9d4eb6",
    "state": "stopped",
    "collected": 4,
    "time_remaining": 42,
    "message": null
  }
}
```

### 7) Analysis

**Request** `POST /advance/multiRxMer/analysis`  
**Body** (`MultiRxMerAnalysisRequest` - preferred string enums):

```json
{
  "analysis": {
    "type": "min-avg-max",
    "output": { "type": "json" }
  },
  "operation_id": "4aca137c1e9d4eb6"
}
```

**Analysis Types** (`analysis.type`)

| Type                         | Description                          | `measure.mode`|
| ---------------------------- | ------------------------------------ | ------------- |
| `min-avg-max`                | Min/Avg/Max RxMER across samples     | `0` or `1`    |
| `rxmer-heat-map`             | Time × Frequency heatmap grid        | `0` or `1`    |
| `ofdm-profile-performance-1` | Per‑subcarrier performance metrics   | `1`           |

**Output Types** (`analysis.output.type`)

| Value      | Name      | Description                              | Media Type         |
| :--------- | :-------- | :--------------------------------------- | :----------------- |
| `"json"`   | `JSON`    | Structured JSON body                     | `application/json` |
| `"archive"`| `ARCHIVE` | ZIP containing multiple artifacts        | `application/zip`  |

## Timing & Polling {#timing--polling}

### Capture Timing

* `measurement_duration` *(s)* → total run length. Example: `60` means one minute.
* `sample_interval` *(s)* → period between samples. Example: `10` over `60` seconds → **6** samples.

### Polling Strategy

* Poll **no more than once per** `sample_interval`.
* Stop polling when `time_remaining == 0` **and** `state == "completed"`.

### Results Availability

* When `state ∈ ["completed","stopped"]`, the ZIP is immediately available.
* Files are produced at sampling time; the archive is just a bundle step.

### Stop Semantics

1. Current iteration finishes.  
2. Final PNM for that iteration is written.  
3. `state → "stopped"` (remaining time may be > 0 if mid‑interval).

## Plot Examples

### Min-Avg-Max Line Plot

| Plot | Description | Note |
| ---- | ----------- | ---- |
| [Min‑Avg‑Max](./images/multi-rxmer/160_rxmer_min_avg_max.png) | Min/Avg/Max RxMER across samples. | Constant line indicates low RxMER @ 750MHz |

### RxMER Heat Map

| Plot | Description | Note |
| ---- | ----------- | ---- |
| [Heat-Map](./images/multi-rxmer/160_rxmer_heat_map.png) | Time × Frequency heatmap grid. | Constant dark Line indicating low RxMER |

### OFDM Profile Performance 1 Overlay

| Plot | Profile | Description |
| ---- | :-----: | ----------- |
| [256‑QAM](./images/multi-rxmer/160_profile_0_ofdm_profile_perf_1.png) | `0` | Avg‑RxMER with modulation profile overlay and FEC summary across sample time. |
| [1K‑QAM](./images/multi-rxmer/160_profile_1_ofdm_profile_perf_1.png)  | `1` | Avg‑RxMER with modulation profile overlay and FEC summary across sample time. |
| [2K‑QAM](./images/multi-rxmer/160_profile_2_ofdm_profile_perf_1.png)  | `2` | Avg‑RxMER with modulation profile overlay and FEC summary across sample time. |
| [4K‑QAM](./images/multi-rxmer/160_profile_3_ofdm_profile_perf_1.png)  | `3` | Avg‑RxMER with modulation profile overlay and FEC summary across sample time. |

## Response Field Reference

### Operation Registry Responses

`POST /status`, `POST /result`, and `POST /cancel` return the same `operation` shape:

* `state`: `created`, `running`, `completed`, `failed`, `canceled`
* `created_ts` / `updated_ts`: epoch seconds
* `progress_current` / `progress_total`: capture progress counters
* `artifact_paths`: relative artifact paths (when available)

### Start / Status / Stop {#start--status--stop}

| Field                       | Type    | Description                                                                 |
| -------------------------- | ------- | --------------------------------------------------------------------------- |
| `mac_address`              | string  | Cable modem MAC address.                                                    |
| `status`                   | string  | Start: `"running"`; Status/Stop: high‑level status string.                |
| `message`                  | string  | Optional detail text.                                                       |
| `group_id`                 | string  | Logical grouping for related operations (Start only).                       |
| `operation_id`             | string  | Unique capture handle used with status/results/stop/analysis.               |
| `operation.state`          | string  | Current state: `running`, `completed`, or `stopped`.                        |
| `operation.collected`      | integer | Number of captured samples.                                                 |
| `operation.time_remaining` | integer | Estimated seconds left.                                                     |

### Download ZIP

| Aspect                | Value / Format                                           |
| -------------------- | --------------------------------------------------------- |
| `Content-Type`       | `application/zip`                                         |
| ZIP name             | `multiRxMer_<mac>_<operation_id>.zip`                     |
| PNM file name format | `ds_ofdm_rxmer_per_subcar_<mac>_<channel_id>_<epoch>.bin` |

### Analysis (JSON)

These keys appear under the `data` object of `MultiRxMerAnalysisResponse`. Per‑type models differ, but common fields include:

| Field/Path                                       | Type/Example             | Meaning                                                                              |
| ------------------------------------------------ | ------------------------ | ------------------------------------------------------------------------------------ |
| `<channel_id>`                                   | string/int key           | Map key representing a single OFDM channel’s results.                                |
| `channel_id`                                     | int                      | Channel identifier repeated in the model.                                            |
| `frequency`                                      | array[int] (Hz)          | Per‑subcarrier center frequency.                                                     |
| `min` / `avg` / `max`                            | array[float] (dB)        | Min/avg/max RxMER per subcarrier (MIN_AVG_MAX).                                      |
| `timestamps`                                     | array[int] (epoch sec)   | Capture timestamps for heat map rows (RXMER_HEAT_MAP).                               |
| `values`                                         | array[array[float]] (dB) | Heat map matrix rows aligned to `timestamps` (RXMER_HEAT_MAP).                       |
| `avg_mer`                                        | array[float] (dB)        | Average MER across captures per subcarrier (OFDM_PROFILE_PERFORMANCE_1).             |
| `mer_shannon_limits`                             | array[float] (dB)        | Derived MER (min SNR) per subcarrier (OFDM_PROFILE_PERFORMANCE_1).                   |
| `profiles[].profile_id`                          | int                      | Modulation profile index.                                                            |
| `profiles[].profile_min_mer`                     | array[float] (dB)        | Minimum MER allowed by the profile per subcarrier.                                   |
| `profiles[].capacity_delta`                      | array[float] (dB)        | `avg_mer - profile_min_mer` per subcarrier.                                          |
| `profiles[].fec_summary.start/end`               | int (epoch sec)          | FEC observation window boundaries.                                                   |
| `profiles[].fec_summary.summary[].summary.total_codewords` | int            | Total FEC codewords counted.                                                         |
| `profiles[].fec_summary.summary[].summary.corrected`       | int            | FEC corrected codewords.                                                             |
| `profiles[].fec_summary.summary[].summary.uncorrectable`   | int            | Uncorrectable codewords.                                                             |

# FILE: src/pypnm/api/routes/advance/common/capture_service.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from typing import Any, cast

from pypnm.api.routes.advance.common.operation_manager import OperationManager
from pypnm.api.routes.advance.common.operation_state import OperationState
from pypnm.api.routes.common.classes.file_capture.capture_group import CaptureGroup
from pypnm.api.routes.common.classes.file_capture.capture_sample import CaptureSample
from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.api.routes.common.extended.common_messaging_service import (
    MessageResponse,
    MessageResponseType,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.lib.constants import OperationExecutionState
from pypnm.lib.operations.operation_store import OperationStore
from pypnm.lib.types import GroupId, OperationId, TimeStamp
from pypnm.lib.utils import Generate


class AbstractCaptureService(ABC):
    """
    Abstract base for periodic background capture services with capture-group support.

    Responsibilities:
        - Create a new capture session (group + operation ID)
        - Periodically fetch raw MessageResponse objects (_capture_message_response)
        - Parse responses into CaptureSample objects (_process_captures)
        - Store samples in memory and persist transaction IDs via CaptureGroup
        - Provide status, results, and stop functionality

    Attributes:
        duration (float): Total runtime for captures, in seconds.
        interval (float): Delay between successive capture iterations, in seconds.
        _ops (Dict[str, Dict[str, Any]]): In-memory state for active operations.
        _cap_group (CaptureGroup): Persistence for transaction IDs across restarts.
        logger (logging.Logger): Logger for operational messages.
    """

    def __init__(self, duration: float, interval: float) -> None:
        """
        Initialize the capture service framework.

        Args:
            duration: Total duration (seconds) for which to run captures.
            interval: Interval (seconds) between capture iterations.

        Raises:
            OSError: If the capture-group database cannot be initialized.
        """
        self.duration = duration
        self.interval = interval
        self.time_remaining: int = 0
        self._ops: dict[str, dict[str, Any]] = {}
        self.logger = logging.getLogger(self.__class__.__name__)
        try:
            self._cap_group = CaptureGroup()
        except Exception as exc:
            self.logger.error(
                f"Failed to initialize CaptureGroup, reason={exc}", exc_info=True
            )
            raise

        self._capture_group_id: GroupId = GroupId("")
        self._operation_id: OperationId = OperationId("")
        self._operation_store = OperationStore()

    async def start(self) -> tuple[GroupId, OperationId]:
        """
        Create a new capture group and operation, then schedule the background runner.

        Returns:
            A tuple of (group_id, operation_id):
            - group_id: 16-character ID for grouping transactions.
            - operation_id: 16-character unique ID for this capture run.

        Side Effects:
            - Registers a new entry in the CaptureGroup database.
            - Launches an asyncio background task that performs captures.

        Raises:
            Exception: Propagates errors from CaptureGroup creation or task scheduling.
        """
        try:
            group_id = self._cap_group.create_group()
        except Exception as exc:
            self.logger.error(
                f"Failed to create capture group, reason={exc}", exc_info=True
            )
            raise

        try:
            om = OperationManager(capture_group_id=group_id)
            operation_id: OperationId = om.register()
        except Exception as exc:
            self.logger.error(
                f"Failed to create operation manager, reason={exc}", exc_info=True
            )
            raise

        start_time = time.time()
        progress_total = OperationStore.estimate_progress_total(
            self.duration, self.interval
        )
        self._ops[operation_id] = {
            "group_id": group_id,
            "state": OperationState.RUNNING,
            "start_time": start_time,
            "duration": self.duration,
            "interval": self.interval,
            "time_remaining": self.time_remaining,
            "samples": [],
            "progress_total": progress_total,
        }

        self.setOperationFinalInvocation(operation_id, False)
        self._operation_store.create_operation(
            operation_id=operation_id,
            progress_total=progress_total,
            message="Operation created",
        )
        self._operation_store.update_operation(
            operation_id=operation_id,
            state=OperationExecutionState.RUNNING,
            progress_current=0,
            progress_total=progress_total,
            message="Operation running",
            error=None,
            artifact_paths=None,
        )

        self.logger.info(
            f"CaptureGroup={group_id} / Operation={operation_id} started "
            f"({self.duration}s @ {self.interval}s interval)"
        )

        async def _runner() -> None:
            end_time = start_time + self.duration
            progress_current = 0

            while (time.time() < end_time) and self._ops[operation_id][
                "state"
            ] == OperationState.RUNNING:
                if self._operation_store.is_canceled(operation_id):
                    self._ops[operation_id]["state"] = OperationState.STOPPED
                    self._operation_store.update_operation(
                        operation_id=operation_id,
                        state=OperationExecutionState.CANCELED,
                        progress_current=progress_current,
                        progress_total=progress_total,
                        message="Operation canceled",
                        error=None,
                        artifact_paths=self._artifact_paths(operation_id),
                    )
                    return
                now = time.time()
                remaining = max(0, int(end_time - now))
                self._ops[operation_id]["time_remaining"] = remaining
                iteration_ts = Generate.time_stamp()

                # Add a waitup front so that it can goto the next function
                await asyncio.sleep(self.interval)

                try:
                    msg_rsp = await self._capture_message_response()
                    samples = self._process_captures(msg_rsp)
                    for sample in samples:
                        self._ops[operation_id]["samples"].append(sample)
                        self._cap_group.add_transaction(sample.transaction_id)
                        self.logger.debug(
                            f"[{operation_id}] Captured sample txn={sample.transaction_id}"
                        )
                    progress_current += 1
                    self._operation_store.update_operation(
                        operation_id=operation_id,
                        state=OperationExecutionState.RUNNING,
                        progress_current=progress_current,
                        progress_total=progress_total,
                        message="Operation running",
                        error=None,
                        artifact_paths=self._artifact_paths(operation_id),
                    )

                except Exception as exc:
                    error_msg = str(exc)
                    self.logger.error(
                        f"[{operation_id}] Capture error: {error_msg}", exc_info=True
                    )
                    self._ops[operation_id]["samples"].append(
                        CaptureSample(
                            timestamp=cast(TimeStamp, iteration_ts),
                            transaction_id="",
                            filename="",
                            error=error_msg,
                        )
                    )
                    progress_current += 1
                    self._operation_store.update_operation(
                        operation_id=operation_id,
                        state=OperationExecutionState.RUNNING,
                        progress_current=progress_current,
                        progress_total=progress_total,
                        message="Operation running with errors",
                        error=error_msg,
                        artifact_paths=self._artifact_paths(operation_id),
                    )

            # Complete if still running
            if self._ops[operation_id]["state"] == OperationState.RUNNING:
                self._ops[operation_id]["state"] = OperationState.COMPLETED
                iteration_ts = time.time()

                try:
                    self.logger.info(
                        f"Runner ended, Final Invocation , One Last Cycle before ending"
                        f"state={self._ops[operation_id]['state']}"
                        f"time-remaining={self._ops[operation_id]['time_remaining']}"
                    )

                    self.setOperationFinalInvocation(operation_id, True)
                    msg_rsp: MessageResponse = await self._capture_message_response()

                    # This is here to before any last operation at the time of the completion of the task
                    if msg_rsp.status == ServiceStatusCode.SKIP_MESSAGE_RESPONSE:
                        self.logger.info("Skipping last _capture_message_response()")
                    else:
                        samples = self._process_captures(msg_rsp)
                        for sample in samples:
                            self._ops[operation_id]["samples"].append(sample)
                            self._cap_group.add_transaction(sample.transaction_id)
                            self.logger.info(
                                f"[{operation_id}] Captured sample txn={sample.transaction_id}"
                            )
                        progress_current += 1

                except Exception as exc:
                    error_msg = str(exc)
                    self.logger.error(
                        f"[{operation_id}] Capture error: {error_msg}", exc_info=True
                    )
                    self._ops[operation_id]["samples"].append(
                        CaptureSample(
                            timestamp=cast(TimeStamp, iteration_ts),
                            transaction_id="",
                            filename="",
                            error=error_msg,
                        )
                    )
                    progress_current += 1
                    self._operation_store.update_operation(
                        operation_id=operation_id,
                        state=OperationExecutionState.RUNNING,
                        progress_current=progress_current,
                        progress_total=progress_total,
                        message="Operation running with errors",
                        error=error_msg,
                        artifact_paths=self._artifact_paths(operation_id),
                    )

            self.logger.info(
                f"[{operation_id}] Capture session ended with state={self._ops[operation_id]['state']}"
            )
            final_state = (
                OperationExecutionState.CANCELED
                if self._ops[operation_id]["state"] == OperationState.STOPPED
                else OperationExecutionState.COMPLETED
            )
            self._operation_store.update_operation(
                operation_id=operation_id,
                state=final_state,
                progress_current=max(progress_current, progress_total),
                progress_total=progress_total,
                message=f"Operation {final_state.value}",
                error=None,
                artifact_paths=self._artifact_paths(operation_id),
            )

            ###############
            # Main RUNNER #
            ###############

        try:
            asyncio.create_task(_runner())
        except Exception as exc:
            self.logger.error(
                f"Failed to schedule capture runner task, reason={exc}", exc_info=True
            )
            raise

        self._capture_group_id = group_id
        self._operation_id = operation_id

        return group_id, operation_id

    def getCaptureGroupID(self) -> GroupId:
        return self._capture_group_id

    def getOperationID(self) -> OperationId:
        return self._operation_id

    def getOperation(self, operation_id: OperationId) -> dict[str, dict[str, Any]]:
        return self._ops[operation_id]

    def getOperationState(self, operation_id: OperationId) -> OperationState:
        return self._ops[operation_id]["state"]

    def setOperationFinalInvocation(
        self, operation_id: OperationId, state: bool
    ) -> None:
        "Indicate that Runner is done, and invocate any final operations"
        self._ops[operation_id]["final_invocation"] = state

    def getOperationFinalInvocation(self, operation_id: OperationId) -> bool:
        return self._ops[operation_id]["final_invocation"]

    def status(self, operation_id: OperationId) -> dict[str, Any]:
        """
        Get the current state and sample count for a capture operation.

        Args:
            operation_id: The ID of the capture operation.

        Returns:
            A dict containing:
                - state (OperationState): Current operation state.
                - collected (int): Number of samples collected.
        """
        op = self._ops.get(operation_id)
        if not op:
            return {"state": OperationState.UNKNOWN, "collected": 0}

        return {
            "state": op["state"],
            "collected": len(op["samples"]),
            "time_remaining": op.get("time_remaining", 0),
        }

    def results(self, operation_id: OperationId) -> list[CaptureSample]:
        """
        Retrieve all CaptureSample objects collected for the operation.

        Args:
            operation_id: The ID of the capture operation.

        Returns:
            A list of CaptureSample. Empty if operation not found.
        """
        op = self._ops.get(operation_id)
        return op["samples"] if op else []

    def stop(self, operation_id: OperationId) -> None:
        """
        Signal the background runner to stop after the current iteration.

        Args:
            operation_id: The ID of the capture operation.

        Effects:
            Sets the operation state to STOPPED if it was RUNNING.
            Idempotent if called multiple times.
        """
        op = self._ops.get(operation_id)
        if op and op["state"] == OperationState.RUNNING:
            op["state"] = OperationState.STOPPED
            self._operation_store.mark_canceled(operation_id, "Operation canceled")
            self.logger.info(f"[{operation_id}] Stopped by user")

    def _process_captures(self, msg_rsp: MessageResponse) -> list[CaptureSample]:
        """
        Parse a raw MessageResponse into a list of CaptureSample objects.

        Args:
            msg_rsp: MessageResponse from _capture_message_response.

        Returns:
            A list of CaptureSample. On payload/type/parsing errors, returns
            a list with a single CaptureSample indicating the error.
        """
        ts = cast(TimeStamp, Generate.time_stamp())
        payload = msg_rsp.payload
        if not isinstance(payload, list):
            err = f"Unexpected payload type: {type(payload).__name__}"
            self.logger.error(err)
            return [
                CaptureSample(timestamp=ts, transaction_id="", filename="", error=err)
            ]

        samples: list[CaptureSample] = []
        for idx, entry in enumerate(payload):
            try:
                status_str, msg_type, body = MessageResponse.get_payload_msg(entry)  # type: ignore

            except Exception as exc:
                err = f"Failed to parse payload entry {idx}: {exc}"
                self.logger.error(err, exc_info=True)
                samples.append(
                    CaptureSample(
                        timestamp=ts, transaction_id="", filename="", error=err
                    )
                )
                continue

            if status_str != ServiceStatusCode.SUCCESS.name:
                err = f"Payload entry {idx} returned status {status_str}"
                self.logger.error(err)
                samples.append(
                    CaptureSample(
                        timestamp=ts, transaction_id="", filename="", error=err
                    )
                )
                continue

            if msg_type != MessageResponseType.PNM_FILE_TRANSACTION.name:
                # skip non-transaction messages
                continue

            txn_id = body.get("transaction_id", "")
            filename = body.get("filename", "")
            if not txn_id or not filename:
                err = f"Missing txn_id or filename in entry {idx}"
                self.logger.warning(f"{err}: {body}")
                samples.append(
                    CaptureSample(
                        timestamp=ts,
                        transaction_id=txn_id,
                        filename=filename,
                        error="missing-txn-or-filename",
                    )
                )
                continue

            try:
                rec = PnmFileTransaction().get_record(txn_id)
            except Exception as exc:
                err = f"DB fetch error for txn {txn_id}: {exc}"
                self.logger.error(err, exc_info=True)
                samples.append(
                    CaptureSample(
                        timestamp=ts,
                        transaction_id=txn_id,
                        filename=filename,
                        error="db-fetch-error",
                    )
                )
                continue

            if rec is None:
                err = f"No DB record found for txn {txn_id}"
                self.logger.warning(err)
                samples.append(
                    CaptureSample(
                        timestamp=ts,
                        transaction_id=txn_id,
                        filename=filename,
                        error="no-db-record",
                    )
                )
            else:
                samples.append(
                    CaptureSample(
                        timestamp=ts,
                        transaction_id=txn_id,
                        filename=filename,
                        error=None,
                    )
                )

        if not samples:
            err = "No valid transactions found in payload"
            self.logger.warning(err)
            return [
                CaptureSample(
                    timestamp=ts,
                    transaction_id="",
                    filename="",
                    error="no-transactions",
                )
            ]

        return samples

    def _artifact_paths(self, operation_id: OperationId) -> list[str]:
        samples = self._ops.get(operation_id, {}).get("samples", [])
        return [sample.filename for sample in samples if sample.filename]

    @abstractmethod
    async def _capture_message_response(self) -> MessageResponse:
        """
        Perform one capture iteration and return its raw response.

        This method is called by the runner each cycle. Subclasses must
        implement the actual SNMP/TFTP logic and always return a
        `MessageResponse`, even on errors.

        Returns
        -------
        MessageResponse
            The raw capture response. Its `.status` field indicates success,
            failure, or a special skip code.

        Notes
        -----
        - On internal exception, catch it and return a failure response, e.g.:
          `MessageResponse(ServiceStatusCode.YOUR_ERROR_CODE)`.
        - To indicate “no PNM file needed right now” (e.g. final cleanup),
          return a `MessageResponse` with
          ``status == ServiceStatusCode.SKIP_MESSAGE_RESPONSE``.
        """
        ...

# FILE: src/pypnm/api/routes/advance/common/operation_workflow_service.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pypnm.lib.operations.operation_models import OperationStatusModel

from pypnm.api.routes.advance.common.capture_service import AbstractCaptureService
from pypnm.lib.constants import OperationExecutionState
from pypnm.lib.operations.operation_store import OperationStore
from pypnm.lib.types import OperationId


class OperationWorkflowService:
    """
    Shared workflow helpers for status, cancel, and result endpoints.
    """

    @staticmethod
    def get_status(operation_id: OperationId) -> OperationStatusModel:
        store = OperationStore()
        status = store.get_operation(operation_id)
        if status is None:
            raise KeyError(f"Operation not found: {operation_id}")
        return status

    @staticmethod
    def cancel(
        operation_id: OperationId, service: AbstractCaptureService | None = None
    ) -> OperationStatusModel:
        store = OperationStore()
        status = store.mark_canceled(operation_id, "Operation canceled")
        if status is None:
            raise KeyError(f"Operation not found: {operation_id}")
        if service is not None:
            service.stop(operation_id)
        return status

    @staticmethod
    def get_result(operation_id: OperationId) -> OperationStatusModel:
        store = OperationStore()
        status = store.get_operation(operation_id)
        if status is None:
            raise KeyError(f"Operation not found: {operation_id}")
        if status.state != OperationExecutionState.COMPLETED:
            raise ValueError("Operation not completed")
        return status


__all__ = ["OperationWorkflowService"]

# FILE: src/pypnm/api/routes/advance/common/schema/operation_schema.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pydantic import BaseModel, Field
from pypnm.lib.operations.operation_models import OperationStatusModel

from pypnm.api.routes.common.classes.common_endpoint_classes.common_req_resp import (
    CommonResponse,
)
from pypnm.lib.types import OperationId


class OperationRequest(BaseModel):
    """
    Request body carrying a PyPNM operation identifier.
    """

    operation_id: OperationId = Field(
        ..., description="Operation ID for status/cancel/result calls."
    )


class OperationStatusResponse(CommonResponse):
    """
    Response containing the latest operation status record.
    """

    operation: OperationStatusModel = Field(
        ..., description="Filesystem-backed operation status."
    )


class OperationCancelResponse(CommonResponse):
    """
    Response returned after a cancel request.
    """

    operation: OperationStatusModel = Field(
        ..., description="Filesystem-backed operation status."
    )


class OperationResultResponse(CommonResponse):
    """
    Response returned for result requests.
    """

    operation: OperationStatusModel = Field(
        ..., description="Filesystem-backed operation status."
    )


__all__ = [
    "OperationRequest",
    "OperationStatusResponse",
    "OperationCancelResponse",
    "OperationResultResponse",
]

# FILE: src/pypnm/api/routes/advance/multi_ds_chan_est/router.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import io
import logging
import os
import zipfile
from collections.abc import Callable
from typing import cast

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, StreamingResponse

from pypnm.api.routes.advance.analysis.signal_analysis.multi_chan_est_singnal_analysis import (
    MultiChanEstAnalysisType,
    MultiChanEstimationSignalAnalysis,
)
from pypnm.api.routes.advance.common.abstract.service import AbstractService
from pypnm.api.routes.advance.common.capture_data_aggregator import (
    CaptureDataAggregator,
)
from pypnm.api.routes.advance.common.capture_service import AbstractCaptureService
from pypnm.api.routes.advance.common.operation_manager import OperationManager
from pypnm.api.routes.advance.common.operation_state import OperationState
from pypnm.api.routes.advance.common.operation_workflow_service import (
    OperationWorkflowService,
)
from pypnm.api.routes.advance.common.schema.operation_schema import (
    OperationCancelResponse,
    OperationRequest,
    OperationResultResponse,
    OperationStatusResponse,
)
from pypnm.api.routes.advance.multi_ds_chan_est.schemas import (
    AnalysisDataModel,
    MultiChanEstAnalysisRequest,
    MultiChanEstimationAnalysisResponse,
    MultiChanEstimationResponseStatus,
    MultiChanEstimationStartResponse,
    MultiChanEstRequest,
    MultiChanEstStatusResponse,
)
from pypnm.api.routes.advance.multi_ds_chan_est.service import (
    MultiChannelEstimationService,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.common.enum import (
    OutputType,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.request_defaults import (
    RequestDefaultsResolver,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.snmp.schemas import (
    SnmpResponse,
)
from pypnm.api.routes.common.classes.file_capture.file_type import FileType
from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.files.service import PnmFileService
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cable_modem import CableModem
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE
from pypnm.lib.inet import Inet, InetAddressStr
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import GroupId, MacAddressStr, OperationId


class MultiDsChanEstRouter(AbstractService):
    """Router for handling Multi-DS-Channel-Estimation operations."""

    def __init__(self) -> None:
        super().__init__()
        self.router = APIRouter(
            prefix="/advance/multiChannelEstimation",
            tags=["PNM Operations - Multi-DS-Channel-Estimation"],
        )
        self.logger = logging.getLogger(self.__class__.__name__)
        self._add_routes()

    # ──────────────────────────────────────────────────────────
    # Routes
    # ──────────────────────────────────────────────────────────
    def _add_routes(self) -> None:
        @self.router.post(
            "/start",
            response_model=MultiChanEstimationStartResponse | SnmpResponse,
            summary="Start a multi-sample ChannelEstimation capture",
        )
        async def start_multi_chan_estimation(
            request: MultiChanEstRequest,
        ) -> MultiChanEstimationStartResponse | SnmpResponse:
            duration, interval = (
                request.capture.parameters.measurement_duration,
                request.capture.parameters.sample_interval,
            )
            mac_address: MacAddressStr = request.cable_modem.mac_address
            ip_address: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(
                request.cable_modem.snmp
            )
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(
                request.cable_modem.pnm_parameters.tftp
            )

            self.logger.info(
                f"[start] Multi-ChanEst for MAC={mac_address}, duration={duration}s interval={interval}s"
            )

            cm = CableModem(
                mac_address=MacAddress(mac_address),
                inet=Inet(ip_address),
                write_community=community,
            )

            # Pre-checks
            status, msg = await CableModemServicePreCheck(
                cable_modem=cm, validate_ofdm_exist=True
            ).run_precheck()
            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(
                    f"[start] Precheck failed for MAC={mac_address}: {msg}"
                )
                return SnmpResponse(mac_address=mac_address, status=status, message=msg)

            group_id, operation_id = await self.loadService(
                MultiChannelEstimationService,
                cm,
                tftp_servers,
                duration=duration,
                interval=interval,
            )
            return MultiChanEstimationStartResponse(
                mac_address=mac_address,
                status=OperationState.RUNNING,
                message=None,
                group_id=group_id,
                operation_id=operation_id,
            )

        @self.router.get(
            "/status/{operation_id}",
            response_model=MultiChanEstStatusResponse,
            summary="Get status of a multi-sample ChannelEstimation capture",
        )
        def get_status(operation_id: OperationId) -> MultiChanEstStatusResponse:
            try:
                service: MultiChannelEstimationService = cast(
                    MultiChannelEstimationService, self.getService(operation_id)
                )

            except KeyError as err:
                raise HTTPException(
                    status_code=404, detail="Operation not found"
                ) from err

            status = service.status(operation_id)
            return MultiChanEstStatusResponse(
                mac_address=service.cm.get_mac_address.mac_address,
                status="success",
                message=None,
                operation=MultiChanEstimationResponseStatus(
                    operation_id=operation_id,
                    state=status["state"],
                    collected=status["collected"],
                    time_remaining=status["time_remaining"],
                    message=None,
                ),
            )

        @self.router.post(
            "/status",
            response_model=OperationStatusResponse,
            summary="Get status of a multi-sample ChannelEstimation capture (operation registry)",
            responses=FAST_API_RESPONSE,
        )
        def get_status_post(request: OperationRequest) -> OperationStatusResponse:
            try:
                status = OperationWorkflowService.get_status(request.operation_id)
            except KeyError as err:
                raise HTTPException(
                    status_code=404, detail="Operation not found"
                ) from err
            return OperationStatusResponse(
                status="success",
                message=None,
                operation=status,
            )

        @self.router.get(
            "/results/{operation_id}",
            summary="Download a ZIP archive of all ChannelEstimation capture files",
            responses={
                200: {
                    "content": {"application/zip": {}},
                    "description": "ZIP archive of capture files",
                }
            },
        )
        def download_results_zip(operation_id: OperationId) -> StreamingResponse:
            svc: MultiChannelEstimationService = cast(
                MultiChannelEstimationService, self.getService(operation_id)
            )
            samples = svc.results(operation_id)
            pnm_dir, mac = (
                str(SystemConfigSettings.pnm_dir()),
                svc.cm.get_mac_address.mac_address,
            )
            buf = io.BytesIO()

            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                for s in samples:
                    path = os.path.join(pnm_dir, s.filename)

                    try:
                        zf.write(path, arcname=os.path.basename(s.filename))

                    except FileNotFoundError:
                        self.logger.warning(f"[zip] Missing: {path}")

                    except Exception as e:
                        self.logger.warning(f"[zip] Skip {path}: {e}")

            buf.seek(0)
            headers = {
                "Content-Disposition": f"attachment; filename=multiChannelEstimation_{mac}_{operation_id}.zip"
            }
            return StreamingResponse(buf, media_type="application/zip", headers=headers)

        @self.router.delete(
            "/stop/{operation_id}",
            response_model=MultiChanEstStatusResponse,
            summary="Stop a running multi-sample ChannelEstimation capture early",
        )
        def stop_capture(operation_id: OperationId) -> MultiChanEstStatusResponse:
            """ """
            try:
                service: MultiChannelEstimationService = cast(
                    MultiChannelEstimationService, self.getService(operation_id)
                )

            except KeyError as err:
                raise HTTPException(
                    status_code=404, detail="Operation not found"
                ) from err

            service.stop(operation_id)
            status = service.status(operation_id)
            return MultiChanEstStatusResponse(
                mac_address=service.cm.get_mac_address.mac_address,
                status=OperationState.STOPPED,
                message=None,
                operation=MultiChanEstimationResponseStatus(
                    operation_id=operation_id,
                    state=status["state"],
                    collected=status["collected"],
                    time_remaining=status["time_remaining"],
                    message=None,
                ),
            )

        @self.router.post(
            "/cancel",
            response_model=OperationCancelResponse,
            summary="Cancel a running multi-sample ChannelEstimation capture",
            responses=FAST_API_RESPONSE,
        )
        def cancel_capture(request: OperationRequest) -> OperationCancelResponse:
            try:
                service: AbstractCaptureService = self.getService(request.operation_id)
            except KeyError:
                service = None
            try:
                status = OperationWorkflowService.cancel(request.operation_id, service)
            except KeyError as err:
                raise HTTPException(
                    status_code=404, detail="Operation not found"
                ) from err
            return OperationCancelResponse(
                status="success",
                message=None,
                operation=status,
            )

        @self.router.post(
            "/result",
            response_model=OperationResultResponse,
            summary="Get ChannelEstimation results once the operation completes",
            responses=FAST_API_RESPONSE,
        )
        def get_result(request: OperationRequest) -> OperationResultResponse:
            try:
                status = OperationWorkflowService.get_result(request.operation_id)
            except KeyError as err:
                raise HTTPException(
                    status_code=404, detail="Operation not found"
                ) from err
            except ValueError as err:
                raise HTTPException(status_code=409, detail=str(err)) from err
            return OperationResultResponse(
                status="success",
                message=None,
                operation=status,
            )

        @self.router.post(
            "/analysis",
            response_model=MultiChanEstimationAnalysisResponse,
            summary="Perform signal analysis on a previously executed Multi-ChannelEstimation",
        )
        def analysis(
            request: MultiChanEstAnalysisRequest,
        ) -> MultiChanEstimationAnalysisResponse | FileResponse:
            """
            Perform post-capture analysis on Multi-ChannelEstimation measurement data.

            Supports:
            - MIN_AVG_MAX
            - GROUP_DELAY
            - LTE_DETECTION_PHASE_SLOPE
            - ECHO_DETECTION_PHASE_SLOPE
            - ECHO_DETECTION_IFFT
            """
            try:
                capture_group_id: GroupId = OperationManager.get_capture_group(
                    request.operation_id
                )
                self.logger.info(
                    f"[analysis] operation_id={request.operation_id} capture_group={capture_group_id}"
                )
            except KeyError:
                msg = f"No capture group found for operation {request.operation_id}"
                self.logger.error(msg)
                return MultiChanEstimationAnalysisResponse(
                    mac_address=MacAddress.null(),
                    status=ServiceStatusCode.CAPTURE_GROUP_NOT_FOUND,
                    message=msg,
                    data=AnalysisDataModel(analysis_type="UNKNOWN", results=[]),
                )

            # Prepare data aggregator
            cda = CaptureDataAggregator(capture_group_id)

            # Parse analysis type
            try:
                atype = MultiChanEstAnalysisType(request.analysis.type)

            except ValueError:
                msg = f"Invalid analysis type: {request.analysis.type}"
                self.logger.error(msg)
                return MultiChanEstimationAnalysisResponse(
                    mac_address=MacAddress.null(),
                    status=ServiceStatusCode.DS_OFDM_CHAN_EST_INVALID_ANALYSIS_TYPE,
                    message=msg,
                    data=AnalysisDataModel(analysis_type="UNKNOWN", results=[]),
                )

            # Dispatch map for type → analysis engine
            analysis_map: dict[
                MultiChanEstAnalysisType,
                Callable[[CaptureDataAggregator], MultiChanEstimationSignalAnalysis],
            ] = {
                MultiChanEstAnalysisType.MIN_AVG_MAX: lambda agg: MultiChanEstimationSignalAnalysis(
                    agg, MultiChanEstAnalysisType.MIN_AVG_MAX
                ),
                MultiChanEstAnalysisType.GROUP_DELAY: lambda agg: MultiChanEstimationSignalAnalysis(
                    agg, MultiChanEstAnalysisType.GROUP_DELAY
                ),
                MultiChanEstAnalysisType.LTE_DETECTION_PHASE_SLOPE: lambda agg: MultiChanEstimationSignalAnalysis(
                    agg, MultiChanEstAnalysisType.LTE_DETECTION_PHASE_SLOPE
                ),
                MultiChanEstAnalysisType.ECHO_DETECTION_IFFT: lambda agg: MultiChanEstimationSignalAnalysis(
                    agg, MultiChanEstAnalysisType.ECHO_DETECTION_IFFT
                ),
            }

            if atype not in analysis_map:
                msg = f"Unsupported analysis type: {atype}"
                self.logger.error(msg)
                return MultiChanEstimationAnalysisResponse(
                    mac_address=MacAddress.null(),
                    status=ServiceStatusCode.DS_OFDM_CHAN_EST_INVALID_ANALYSIS_TYPE,
                    message=msg,
                    data=AnalysisDataModel(analysis_type="UNKNOWN", results=[]),
                )

            # Determine output type
            output_type: OutputType = request.analysis.output.type
            engine = analysis_map[atype](cda)
            analysis_result = engine.to_model()

            # Handle output formats
            if output_type == OutputType.JSON:
                err = analysis_result.error
                status = (
                    ServiceStatusCode.SUCCESS if not err else ServiceStatusCode.FAILURE
                )
                message = (
                    err
                    or f"Analysis {analysis_result.analysis_type} completed for group {capture_group_id}"
                )

                data_model = AnalysisDataModel(
                    analysis_type=analysis_result.analysis_type,
                    results=[r.model_dump() for r in analysis_result.results],
                )

                mac = engine.getMacAddresses()[0].mac_address
                self.logger.info(
                    f"[analysis] type={atype.name} mac={mac} status={status.name} group={capture_group_id}"
                )

                return MultiChanEstimationAnalysisResponse(
                    mac_address=mac, status=status, message=message, data=data_model
                )

            elif output_type == OutputType.ARCHIVE:
                try:
                    rpt = engine.build_report()
                    self.logger.info(
                        f"[analysis] Built archive report for group {capture_group_id}"
                    )
                    return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

                except Exception as e:
                    msg = f"Archive build failed: {e}"
                    self.logger.error(msg)
                    return MultiChanEstimationAnalysisResponse(
                        mac_address=MacAddress.null(),
                        status=ServiceStatusCode.FAILURE,
                        message=msg,
                        data=AnalysisDataModel(analysis_type=atype.name, results=[]),
                    )

            # Unsupported output type
            msg = f"Unsupported output type: {output_type}"
            self.logger.error(msg)
            return MultiChanEstimationAnalysisResponse(
                mac_address=MacAddress.null(),
                status=ServiceStatusCode.INVALID_OUTPUT_TYPE,
                message=msg,
                data=AnalysisDataModel(analysis_type=atype.name, results=[]),
            )


# Auto-register
router = MultiDsChanEstRouter().router

# FILE: src/pypnm/api/routes/advance/multi_rxmer/router.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import io
import logging
import os
import zipfile
from typing import cast

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, StreamingResponse

from pypnm.api.routes.advance.analysis.signal_analysis.multi_rxmer_signal_analysis import (
    MultiRxMerAnalysisResult,
    MultiRxMerAnalysisType,
    MultiRxMerSignalAnalysis,
)
from pypnm.api.routes.advance.common.abstract.service import AbstractService
from pypnm.api.routes.advance.common.capture_data_aggregator import (
    CaptureDataAggregator,
)
from pypnm.api.routes.advance.common.capture_service import AbstractCaptureService
from pypnm.api.routes.advance.common.operation_manager import OperationManager
from pypnm.api.routes.advance.common.operation_state import OperationState
from pypnm.api.routes.advance.common.operation_workflow_service import (
    OperationWorkflowService,
)
from pypnm.api.routes.advance.common.schema.operation_schema import (
    OperationCancelResponse,
    OperationRequest,
    OperationResultResponse,
    OperationStatusResponse,
)
from pypnm.api.routes.advance.multi_rxmer.schemas import (
    MultiRxMerAnalysisRequest,
    MultiRxMerAnalysisResponse,
    MultiRxMerMeasureModes,
    MultiRxMerRequest,
    MultiRxMerResponseStatus,
    MultiRxMerStartResponse,
    MultiRxMerStatusResponse,
)
from pypnm.api.routes.advance.multi_rxmer.service import (
    MultiRxMer_Ofdm_Performance_1_Service,
    MultiRxMerService,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.common.enum import (
    OutputType,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.request_defaults import (
    RequestDefaultsResolver,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.snmp.schemas import (
    SnmpResponse,
)
from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.files.service import FileType, PnmFileService
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cable_modem import CableModem
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE
from pypnm.lib.inet import Inet, InetAddressStr
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import GroupId, MacAddressStr, OperationId


class MultiRxMerRouter(AbstractService):
    """
    Router For Multi-RxMER Capture And Analysis

    Overview
    --------
    Exposes endpoints to:
      • Start a background, periodic RxMER capture on a DOCSIS cable modem
      • Poll capture status (state, collected sample count, time remaining)
      • Download all collected raw RxMER files as a ZIP archive
      • Stop an active capture early
      • Run post-capture analysis on the collected dataset

    Execution Model
    ---------------
    Each capture runs asynchronously under a managed operation. The returned `operation_id`
    is used to query status, fetch results, or trigger analysis. Pre-checks verify PNM-ready
    state and the presence of downstream OFDM.

    Inherits
    --------
    AbstractService
        Provides `loadService(...)` and `getService(...)` for service lifecycle and operation lookup.
    """

    def __init__(self) -> None:
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.router = APIRouter(
            prefix="/advance/multiRxMer",
            tags=["PNM Operations - Multi-Downstream OFDM RxMER"],
        )
        self._add_routes()

    def _add_routes(self) -> None:
        @self.router.post(
            "/start",
            response_model=MultiRxMerStartResponse | SnmpResponse,
            summary="Start a Multi-RxMER capture",
            responses=FAST_API_RESPONSE,
        )
        async def start_multi_rxmer(
            request: MultiRxMerRequest,
        ) -> SnmpResponse | MultiRxMerStartResponse:
            """
            Start Multi-RxMER Capture

            Description
            -----------
            Starts an asynchronous RxMER capture on the target cable modem. Sampling cadence is
            controlled by `capture.parameters.measurement_duration` and `capture.parameters.sample_interval`.

            Modes
            -----
            • `MeasureModes.CONTINUOUS` - Continuous sampling for min/avg/max and heat-map workflows
            • `MeasureModes.OFDM_PERFORMANCE_1` - Performance study pairing RxMER with modulation-profile
              and FEC summary collection

            Returns
            -------
            • `MultiRxMerStartResponse` with `group_id` and `operation_id` on success
            • `SnmpResponse` when modem pre-checks fail (e.g., not PNM-ready or OFDM missing)

            [API Guide - Results](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/multi/multi-capture-rxmer.md#3-download-measurements)
            """

            mac_address: MacAddressStr = request.cable_modem.mac_address
            ip_address: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(
                request.cable_modem.snmp
            )
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(
                request.cable_modem.pnm_parameters.tftp
            )
            duration = request.capture.parameters.measurement_duration
            interval = request.capture.parameters.sample_interval

            measure_modes = request.measure.mode
            msg: str = ""

            self.logger.info(
                f"Starting Multi-RxMER capture for MAC={mac_address} "
                f"(duration={duration}s, interval={interval}s)"
            )

            cable_modem = CableModem(
                mac_address=MacAddress(mac_address),
                inet=Inet(ip_address),
                write_community=community,
            )

            status, msg = await CableModemServicePreCheck(
                cable_modem=cable_modem,
                validate_ofdm_exist=True,
                validate_pnm_ready_status=True,
            ).run_precheck()
            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse(mac_address=mac_address, status=status, message=msg)

            if measure_modes == MultiRxMerMeasureModes.CONTINUOUS:
                msg = f"Starting Multi-RxMER capture for MAC={mac_address}"
                self.logger.info(f"{msg}")
                group_id, operation_id = await self.loadService(
                    MultiRxMerService,
                    cable_modem,
                    tftp_servers,
                    duration=duration,
                    interval=interval,
                )

            elif measure_modes == MultiRxMerMeasureModes.OFDM_PERFORMANCE_1:
                msg = f"Starting Multi-RxMER-OFDM-Performance-1 capture for MAC={mac_address}"
                self.logger.info(f"{msg}")
                group_id, operation_id = await self.loadService(
                    MultiRxMer_Ofdm_Performance_1_Service,
                    cable_modem,
                    tftp_servers,
                    duration=duration,
                    interval=interval,
                )

            else:
                self.logger.error(f"Invalid Measure Mode Selected: ({measure_modes})")
                return MultiRxMerStartResponse(
                    mac_address=mac_address,
                    status=ServiceStatusCode.MEASURE_MODE_INVALID,
                    message=f"{ServiceStatusCode.MEASURE_MODE_INVALID.name}",
                    group_id="",
                    operation_id="",
                )

            return MultiRxMerStartResponse(
                mac_address=mac_address,
                status=OperationState.RUNNING,
                message=msg,
                group_id=group_id,
                operation_id=operation_id,
            )

        @self.router.get(
            "/status/{operation_id}",
            response_model=MultiRxMerStatusResponse,
            summary="Get status of a Multi-RxMER capture",
            responses=FAST_API_RESPONSE,
        )
        def get_status(operation_id: OperationId) -> MultiRxMerStatusResponse:
            """
            Check Multi-RxMER Capture Status

            Description
            -----------
            Returns the current state of the capture, number of samples collected, and estimated
            time remaining for the given `operation_id`.

            Path Parameters
            ---------------
            operation_id : OperationId
                Identifier returned by `/start`.

            Returns
            -------
            `MultiRxMerStatusResponse` populated with `operation.state`, `operation.collected`,
            and `operation.time_remaining`.

            Errors
            ------
            404 — Operation not found.

            [API Guide - Results](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/multi/multi-capture-rxmer.md#3-download-measurements)
            """
            try:
                service: MultiRxMerService = cast(
                    MultiRxMerService, self.getService(operation_id)
                )

            except KeyError as err:
                raise HTTPException(
                    status_code=404, detail="Operation not found"
                ) from err

            status = service.status(operation_id)

            self.logger.debug(f"OpId: {operation_id} - Status: {status}")

            return MultiRxMerStatusResponse(
                mac_address=service.cm.get_mac_address.mac_address,
                status="success",
                message=None,
                operation=MultiRxMerResponseStatus(
                    operation_id=operation_id,
                    state=status["state"],
                    collected=status["collected"],
                    time_remaining=status["time_remaining"],
                    message=None,
                ),
            )

        @self.router.post(
            "/status",
            response_model=OperationStatusResponse,
            summary="Get status of a Multi-RxMER capture (operation registry)",
            responses=FAST_API_RESPONSE,
        )
        def get_status_post(request: OperationRequest) -> OperationStatusResponse:
            try:
                status = OperationWorkflowService.get_status(request.operation_id)
            except KeyError as err:
                raise HTTPException(
                    status_code=404, detail="Operation not found"
                ) from err
            return OperationStatusResponse(
                status="success",
                message=None,
                operation=status,
            )

        @self.router.get(
            "/results/{operation_id}",
            summary="Download a ZIP archive of all RxMER capture files",
            responses=FAST_API_RESPONSE,
        )
        def download_measurements_zip(operation_id: OperationId) -> StreamingResponse:
            """
            Download Captured RxMER Measurements (ZIP)

            Description
            -----------
            Streams a ZIP archive containing all RxMER `.bin` files associated with the specified
            `operation_id`. Useful for offline analysis or archival.

            Content
            -------
            • Media Type: `application/zip`
            • Disposition: `attachment; filename=multiRxMer_<mac>_<operation_id>.zip`

            Path Parameters
            ---------------
            operation_id : OperationId
                Identifier returned by `/start`.

            Returns
            -------
            `StreamingResponse` — Streamed ZIP of all capture files found. Missing files are logged and skipped.

            [API Guide - Results](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/multi/multi-capture-rxmer.md#3-download-measurements)
            """
            svc: MultiRxMerService = cast(
                MultiRxMerService, self.getService(operation_id)
            )
            samples = svc.results(operation_id)

            pnm_dir = str(SystemConfigSettings.pnm_dir())
            mac = svc.cm.get_mac_address.mac_address

            buf = io.BytesIO()
            with zipfile.ZipFile(
                buf, mode="w", compression=zipfile.ZIP_DEFLATED
            ) as zipf:
                for sample in samples:
                    file_path = os.path.join(pnm_dir, sample.filename)
                    arcname = os.path.basename(sample.filename)
                    try:
                        zipf.write(file_path, arcname=arcname)
                    except FileNotFoundError:
                        self.logger.warning(f"File not found, skipping: {file_path}")
                    except Exception as e:
                        self.logger.warning(f"Skipping {file_path}: {e}")

            buf.seek(0)

            headers = {
                "Content-Disposition": f"attachment; filename=multiRxMer_{mac}_{operation_id}.zip"
            }
            return StreamingResponse(buf, media_type="application/zip", headers=headers)

        @self.router.delete(
            "/stop/{operation_id}",
            response_model=MultiRxMerStatusResponse,
            summary="Stop a running Multi-RxMER capture early",
            responses=FAST_API_RESPONSE,
        )
        def stop_capture(operation_id: OperationId) -> MultiRxMerStatusResponse:
            """
            Stop Multi-RxMER Capture

            Description
            -----------
            Signals the background worker to stop sampling after the current iteration for the
            specified `operation_id`.

            Path Parameters
            ---------------
            operation_id : OperationId
                Identifier returned by `/start`.

            Returns
            -------
            `MultiRxMerStatusResponse` — Finalized state and counters at stop time.

            Errors
            ------
            404 — Operation not found.

            [API Guide - Results](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/multi/multi-capture-rxmer.md#3-download-measurements)
            """
            try:
                service: MultiRxMerService = cast(
                    MultiRxMerService, self.getService(operation_id)
                )
            except KeyError as err:
                raise HTTPException(
                    status_code=404, detail="Operation not found"
                ) from err

            service.stop(operation_id)
            status = service.status(operation_id)

            return MultiRxMerStatusResponse(
                mac_address=service.cm.get_mac_address.mac_address,
                status=OperationState.STOPPED,
                message=None,
                operation=MultiRxMerResponseStatus(
                    operation_id=operation_id,
                    state=status["state"],
                    collected=status["collected"],
                    time_remaining=status["time_remaining"],
                    message=None,
                ),
            )

        @self.router.post(
            "/cancel",
            response_model=OperationCancelResponse,
            summary="Cancel a running Multi-RxMER capture",
            responses=FAST_API_RESPONSE,
        )
        def cancel_capture(request: OperationRequest) -> OperationCancelResponse:
            try:
                service: AbstractCaptureService = self.getService(request.operation_id)
            except KeyError:
                service = None
            try:
                status = OperationWorkflowService.cancel(request.operation_id, service)
            except KeyError as err:
                raise HTTPException(
                    status_code=404, detail="Operation not found"
                ) from err
            return OperationCancelResponse(
                status="success",
                message=None,
                operation=status,
            )

        @self.router.post(
            "/result",
            response_model=OperationResultResponse,
            summary="Get Multi-RxMER results once the operation completes",
            responses=FAST_API_RESPONSE,
        )
        def get_result(request: OperationRequest) -> OperationResultResponse:
            try:
                status = OperationWorkflowService.get_result(request.operation_id)
            except KeyError as err:
                raise HTTPException(
                    status_code=404, detail="Operation not found"
                ) from err
            except ValueError as err:
                raise HTTPException(status_code=409, detail=str(err)) from err
            return OperationResultResponse(
                status="success",
                message=None,
                operation=status,
            )

        @self.router.post(
            "/analysis",
            response_model=MultiRxMerAnalysisResponse,
            summary="Perform signal analysis on a previously executed Multi-RxMER captures",
            responses=FAST_API_RESPONSE,
        )
        def analysis(
            request: MultiRxMerAnalysisRequest,
        ) -> MultiRxMerAnalysisResponse | FileResponse:
            """
            Multi-RxMER Analysis

            Description
            -----------
            Runs post-capture analysis for the dataset associated with `request.operation_id`.
            The capture group is derived internally from the operation.

            Analysis Types
            --------------
            • `MIN_AVG_MAX` — Per-subcarrier min/avg/max over the series
            • `RXMER_HEAT_MAP` — Heat-map oriented dataset for visualization
            • `OFDM_PROFILE_PERFORMANCE_1` — Averages RxMER, compares to modulation profiles,
              and aggregates FEC statistics over time

            Output
            ------
            Controlled by `request.analysis.output.type`:
            • `OutputType.JSON` — Typed JSON payload for UI consumption
            • `OutputType.ARCHIVE` — Generated ZIP report via `PnmFileService`

            Returns
            -------
            • `MultiRxMerAnalysisResponse` (JSON output)
            • `FileResponse` (archive report)

            Errors
            ------
            • Capture group not found for the supplied operation
            • Invalid analysis type or invalid output type

            [API Guide - Results](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/multi/multi-capture-rxmer.md#3-download-measurements)
            """
            try:
                capture_group_id: GroupId = OperationManager.get_capture_group(
                    request.operation_id
                )
                self.logger.info(
                    f"[analysis] - OperationID: {request.operation_id} -> CaptureGroup: {capture_group_id}"
                )

            except KeyError:
                return MultiRxMerAnalysisResponse(
                    mac_address=MacAddress.null(),
                    status=ServiceStatusCode.CAPTURE_GROUP_NOT_FOUND,
                    message=f"No capture group found for operation {request.operation_id}",
                    data={},
                )

            cda = CaptureDataAggregator(capture_group_id)

            try:
                atype = MultiRxMerAnalysisType(request.analysis.type)
            except ValueError:
                msg = f"Invalid Analysis Type, reason: {request.analysis.type}"
                return MultiRxMerAnalysisResponse(
                    mac_address=MacAddress.null(),
                    status=ServiceStatusCode.DS_OFDM_MULIT_RXMER_ANALYSIS_TYPE,
                    message=msg,
                    data={},
                )
            self.logger.info(
                f"Performing Multi-RxMER Min/Avg/Max Analysis for group: {capture_group_id}"
            )

            if atype == MultiRxMerAnalysisType.MIN_AVG_MAX:
                engine = MultiRxMerSignalAnalysis(cda, atype)
                multi_analysis: MultiRxMerAnalysisResult = engine.to_model()

            elif atype == MultiRxMerAnalysisType.RXMER_HEAT_MAP:
                engine = MultiRxMerSignalAnalysis(
                    cda, MultiRxMerAnalysisType.RXMER_HEAT_MAP
                )
                multi_analysis = engine.to_model()

            elif atype == MultiRxMerAnalysisType.OFDM_PROFILE_PERFORMANCE_1:
                """
                    Operation of this test:
                    -----------------------
                    * Collect a seriers of RxMER
                    * Collect at least 1 Modualtion Profile=
                    * Collect a Fec Summary at:
                        - 1 FecSummary every 10 Min
                        - At end of the test

                    OFDM_PROFILE_MEASUREMENT_1
                    --------------------------
                    * Calculate the Avg RxMER of the series
                    * Calculate Shannon for each subcarrier
                    * Compare each modualtion profile against the RxMER Average
                    * Calculate the percentage of subcarries that are outside a given profile
                    * Provide total FEC Stats for each profile over the time of the capture.
                """
                engine = MultiRxMerSignalAnalysis(
                    cda, MultiRxMerAnalysisType.OFDM_PROFILE_PERFORMANCE_1
                )
                multi_analysis = engine.to_model()

            else:
                msg = f"Invalid Analysis Type {atype}"
                return MultiRxMerAnalysisResponse(
                    mac_address=MacAddress.null(),
                    status=ServiceStatusCode.DS_OFDM_MULIT_RXMER_ANALYSIS_TYPE,
                    message=msg,
                    data={},
                )

            # 4) Map analysis output to response fields
            analysis_name = MultiRxMerAnalysisType(atype).name
            message = f"Analysis {analysis_name} completed for group {capture_group_id}"

            try:
                output_type = request.analysis.output.type
            except ValueError:
                msg = f"Invalid Output Type Selected: ({request.analysis.output.type})"
                return MultiRxMerAnalysisResponse(
                    mac_address=MacAddress.null(),
                    status=ServiceStatusCode.INVALID_OUTPUT_TYPE,
                    message=msg,
                    data={},
                )

            mac_address = multi_analysis.mac_address

            if output_type == OutputType.JSON:
                data = multi_analysis.model_dump().get("data", {})
                return MultiRxMerAnalysisResponse(
                    mac_address=mac_address,
                    status=ServiceStatusCode.SUCCESS,
                    message=message,
                    data=data,
                )

            elif output_type == OutputType.ARCHIVE:
                rpt = engine.build_report()
                return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

            else:
                # Fallback for unsupported output types
                return MultiRxMerAnalysisResponse(
                    mac_address=mac_address,
                    status=ServiceStatusCode.INVALID_OUTPUT_TYPE,
                    message=f"Unsupported output type: {output_type}",
                    data={},
                )


# For dynamic auto-registration
router = MultiRxMerRouter().router

# FILE: src/pypnm/lib/constants.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from typing import Final, Literal, TypeAlias, TypeVar, cast

from pypnm.lib.types import (
    CaptureTime,
    ChannelId,
    FloatEnum,
    FrequencyHz,
    Number,
    ProfileId,
    StringEnum,
)

DEFAULT_SSH_PORT: int = 22

HZ: Final[int] = 1
KHZ: Final[int] = 1_000
MHZ: Final[int] = 1_000_000
GHZ: Final[int] = 1_000_000_000

FEET_PER_METER: Final[float] = 3.280839895013123
SPEED_OF_LIGHT: Final[float] = 299_792_458.0  # m/s

NULL_ARRAY_NUMBER: Final[list[Number]] = [0]

ZERO_FREQUENCY: Final[FrequencyHz] = cast(FrequencyHz, 0)

INVALID_CHANNEL_ID: Final[ChannelId] = cast(ChannelId, -1)
INVALID_PROFILE_ID: Final[ProfileId] = cast(ProfileId, -1)
INVALID_SUB_CARRIER_ZERO_FREQ: Final[FrequencyHz] = cast(FrequencyHz, 0)
INVALID_START_VALUE: Final[int] = -1
INVALID_SCHEMA_TYPE: Final[int] = -1
INVALID_CAPTURE_TIME: Final[CaptureTime] = cast(CaptureTime, -1)

DEFAULT_CAPTURE_TIME: Final[CaptureTime] = cast(CaptureTime, 19700101)  # epoch start

CableTypes: TypeAlias = Literal["RG6", "RG59", "RG11"]

# Velocity Factor (VF) by cable type (fraction of c0)
CABLE_VF: Final[dict[CableTypes, float]] = {
    "RG6": 0.87,
    "RG59": 0.82,
    "RG11": 0.87,
}


class CableType(FloatEnum):
    RG6 = 0.87
    RG59 = 0.82
    RG11 = 0.87


class MediaType(StringEnum):
    """
    Canonical Media Type Enumeration Used For File And HTTP Responses.

    Values
    ------
    APPLICATION_JSON
        JSON payloads (FastAPI JSONResponse, .json files).
    APPLICATION_ZIP
        ZIP archives (analysis bundles, multi-file exports).
    APPLICATION_OCTET_STREAM
        Raw binary streams (PNM files, generic downloads).
    TEXT_CSV
        Comma-separated values (tabular exports).
    """

    APPLICATION_JSON = "application/json"
    APPLICATION_ZIP = "application/zip"
    APPLICATION_OCTET_STREAM = "application/octet-stream"
    TEXT_CSV = "text/csv"


class OperationExecutionState(StringEnum):
    """
    Canonical operation lifecycle state for async workflows.
    """

    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"


T = TypeVar("T")

DEFAULT_SPECTRUM_ANALYZER_INDICES: Final[list[int]] = [0]


FEC_SUMMARY_TYPE_STEP_SECONDS: dict[int, int] = {
    2: 1,  # interval10min(2): 600 samples, 1 sec apart
    3: 60,  # interval24hr(3): 1440 samples, 60 sec apart
    # other(1): unknown / device-specific, do not enforce
}

FEC_SUMMARY_TYPE_LABEL: dict[int, str] = {
    1: "other",
    2: "10-minute interval (1s cadence)",
    3: "24-hour interval (60s cadence)",
}

__all__ = [
    "DEFAULT_SSH_PORT",
    "HZ",
    "KHZ",
    "MHZ",
    "GHZ",
    "ZERO_FREQUENCY",
    "FEET_PER_METER",
    "SPEED_OF_LIGHT",
    "NULL_ARRAY_NUMBER",
    "INVALID_CHANNEL_ID",
    "INVALID_PROFILE_ID",
    "INVALID_SUB_CARRIER_ZERO_FREQ",
    "INVALID_START_VALUE",
    "INVALID_SCHEMA_TYPE",
    "INVALID_CAPTURE_TIME",
    "DEFAULT_CAPTURE_TIME",
    "CableTypes",
    "CABLE_VF",
    "DEFAULT_SPECTRUM_ANALYZER_INDICES",
    "FEC_SUMMARY_TYPE_STEP_SECONDS",
    "FEC_SUMMARY_TYPE_LABEL",
    "OperationExecutionState",
]

# FILE: src/pypnm/lib/operations/__init__.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pypnm.lib.operations.operation_models import OperationStatusModel
from pypnm.lib.operations.operation_store import OperationStore

__all__ = [
    "OperationStatusModel",
    "OperationStore",
]

# FILE: src/pypnm/lib/operations/operation_models.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pydantic import BaseModel, Field

from pypnm.lib.constants import OperationExecutionState
from pypnm.lib.types import OperationId, PathArray, TimeStamp


class OperationStatusModel(BaseModel):
    """
    Filesystem-backed operation status record.
    """

    operation_id: OperationId = Field(
        ..., description="Operation identifier used for status/cancel/result calls."
    )
    state: OperationExecutionState = Field(
        ..., description="Execution state for the operation lifecycle."
    )
    created_ts: TimeStamp = Field(
        ..., description="Creation timestamp (epoch seconds)."
    )
    updated_ts: TimeStamp = Field(
        ..., description="Last update timestamp (epoch seconds)."
    )
    progress_current: int = Field(
        ..., description="Current completed units for the operation."
    )
    progress_total: int = Field(
        ..., description="Total expected units for the operation."
    )
    message: str = Field(..., description="Human-readable operation status message.")
    error: str | None = Field(
        None, description="Optional error details when failures occur."
    )
    artifact_paths: PathArray | None = Field(
        None, description="Optional list of generated artifact paths."
    )


__all__ = ["OperationStatusModel"]

# FILE: src/pypnm/lib/operations/operation_store.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
import logging
import math
from pathlib import Path

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.constants import OperationExecutionState
from pypnm.lib.operations.operation_models import OperationStatusModel
from pypnm.lib.types import OperationId, PathLike
from pypnm.lib.utils import Generate


class OperationStore:
    """
    Filesystem-backed operation registry with one JSON file per operation ID.
    """

    _DEFAULT_DIR_NAME: str = "operations"
    _FILE_SUFFIX: str = ".json"
    _MIN_INTERVAL_SECONDS: float = 1.0
    _MIN_PROGRESS_TOTAL: int = 1

    def __init__(self, base_dir: Path | None = None) -> None:
        """
        Initialize the store under the configured .data root.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        if base_dir is None:
            pnm_dir = Path(SystemConfigSettings.pnm_dir())
            base_dir = pnm_dir.parent / self._DEFAULT_DIR_NAME
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def estimate_progress_total(duration: float, interval: float) -> int:
        """
        Estimate total work units for a periodic capture workflow.
        """
        effective_interval = (
            interval if interval > 0 else OperationStore._MIN_INTERVAL_SECONDS
        )
        total = int(math.ceil(duration / effective_interval))
        return max(OperationStore._MIN_PROGRESS_TOTAL, total)

    def _operation_path(self, operation_id: OperationId) -> Path:
        filename = f"{operation_id}{self._FILE_SUFFIX}"
        return self.base_dir / filename

    def _atomic_write(self, path: Path, status: OperationStatusModel) -> None:
        temp_path = path.with_suffix(".tmp")
        with temp_path.open("w", encoding="utf-8") as handle:
            json.dump(status.model_dump(), handle, indent=2)
        temp_path.replace(path)

    def create_operation(
        self,
        operation_id: OperationId,
        progress_total: int,
        message: str,
    ) -> OperationStatusModel:
        """
        Create a new operation status record in CREATED state.
        """
        now = Generate.time_stamp()
        status = OperationStatusModel(
            operation_id=operation_id,
            state=OperationExecutionState.CREATED,
            created_ts=now,
            updated_ts=now,
            progress_current=0,
            progress_total=progress_total,
            message=message,
            error=None,
            artifact_paths=None,
        )
        path = self._operation_path(operation_id)
        self._atomic_write(path, status)
        return status

    def update_operation(
        self,
        operation_id: OperationId,
        state: OperationExecutionState,
        progress_current: int,
        progress_total: int,
        message: str,
        error: str | None = None,
        artifact_paths: list[PathLike] | None = None,
    ) -> OperationStatusModel:
        """
        Update and persist operation status.
        """
        now = Generate.time_stamp()
        status = OperationStatusModel(
            operation_id=operation_id,
            state=state,
            created_ts=self._get_created_ts(operation_id, now),
            updated_ts=now,
            progress_current=progress_current,
            progress_total=progress_total,
            message=message,
            error=error,
            artifact_paths=artifact_paths,
        )
        path = self._operation_path(operation_id)
        self._atomic_write(path, status)
        return status

    def _get_created_ts(self, operation_id: OperationId, fallback: int) -> int:
        existing = self.get_operation(operation_id)
        return int(existing.created_ts) if existing else fallback

    def get_operation(self, operation_id: OperationId) -> OperationStatusModel | None:
        """
        Retrieve an operation status record from disk.
        """
        path = self._operation_path(operation_id)
        if not path.exists():
            return None
        try:
            with path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            return OperationStatusModel.model_validate(data)
        except Exception as exc:
            self.logger.error(
                f"Failed to read operation status {operation_id}: {exc}", exc_info=True
            )
            return None

    def mark_canceled(
        self, operation_id: OperationId, message: str
    ) -> OperationStatusModel | None:
        """
        Mark an operation as canceled.
        """
        existing = self.get_operation(operation_id)
        if not existing:
            return None
        return self.update_operation(
            operation_id=operation_id,
            state=OperationExecutionState.CANCELED,
            progress_current=int(existing.progress_current),
            progress_total=int(existing.progress_total),
            message=message,
            error=existing.error,
            artifact_paths=existing.artifact_paths,
        )

    def is_canceled(self, operation_id: OperationId) -> bool:
        """
        Check whether an operation has been canceled.
        """
        status = self.get_operation(operation_id)
        return bool(status and status.state == OperationExecutionState.CANCELED)


__all__ = ["OperationStore"]

# FILE: tests/test_operation_workflow.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from pypnm.api.routes.advance.common.capture_service import AbstractCaptureService
from pypnm.api.routes.advance.common.operation_workflow_service import (
    OperationWorkflowService,
)
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.constants import OperationExecutionState
from pypnm.lib.operations.operation_store import OperationStore
from pypnm.lib.types import OperationId


class _FakeCaptureService(AbstractCaptureService):
    async def _capture_message_response(self) -> MessageResponse:
        return MessageResponse(ServiceStatusCode.SUCCESS, payload=[])


def _configure_operation_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base_dir = tmp_path / ".data"
    pnm_dir = base_dir / "pnm"
    db_dir = base_dir / "db"
    pnm_dir.mkdir(parents=True, exist_ok=True)
    db_dir.mkdir(parents=True, exist_ok=True)

    capture_group_db = db_dir / "capture_group.json"
    operation_db = db_dir / "operation_capture.json"

    monkeypatch.setattr(
        SystemConfigSettings,
        "pnm_dir",
        classmethod(lambda cls: str(pnm_dir)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "capture_group_db",
        classmethod(lambda cls: str(capture_group_db)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "operation_db",
        classmethod(lambda cls: str(operation_db)),
    )


@pytest.mark.asyncio
async def test_start_creates_running_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_paths(tmp_path, monkeypatch)
    service = _FakeCaptureService(duration=0, interval=1)
    _, operation_id = await service.start()

    store = OperationStore()
    status = store.get_operation(operation_id)
    assert status is not None
    assert status.state == OperationExecutionState.RUNNING

    await asyncio.sleep(0)
    completed = store.get_operation(operation_id)
    assert completed is not None
    assert completed.state == OperationExecutionState.COMPLETED
    assert completed.progress_current >= 1


@pytest.mark.asyncio
async def test_cancel_marks_canceled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_paths(tmp_path, monkeypatch)
    service = _FakeCaptureService(duration=1, interval=0)
    _, operation_id = await service.start()

    canceled = OperationWorkflowService.cancel(operation_id, service)
    assert canceled.state == OperationExecutionState.CANCELED

    await asyncio.sleep(0)
    store = OperationStore()
    status = store.get_operation(operation_id)
    assert status is not None
    assert status.state == OperationExecutionState.CANCELED


def test_result_requires_completed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_paths(tmp_path, monkeypatch)
    store = OperationStore()
    operation_id = OperationId("op-test-1")
    store.create_operation(operation_id, progress_total=1, message="Operation created")
    store.update_operation(
        operation_id=operation_id,
        state=OperationExecutionState.RUNNING,
        progress_current=0,
        progress_total=1,
        message="Operation running",
        error=None,
        artifact_paths=None,
    )

    with pytest.raises(ValueError):
        OperationWorkflowService.get_result(operation_id)

    store.update_operation(
        operation_id=operation_id,
        state=OperationExecutionState.COMPLETED,
        progress_current=1,
        progress_total=1,
        message="Operation completed",
        error=None,
        artifact_paths=None,
    )
    status = OperationWorkflowService.get_result(operation_id)
    assert status.state == OperationExecutionState.COMPLETED
