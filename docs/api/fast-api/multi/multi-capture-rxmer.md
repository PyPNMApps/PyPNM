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
