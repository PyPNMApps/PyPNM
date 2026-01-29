# Multi-DS Channel Estimation Capture & Analysis API

A concise, implementation-ready reference for orchestrating downstream OFDM channel-estimation captures, status polling, result retrieval, early termination, and post-capture analysis.

## Contents

* [At a Glance](#at-a-glance)
* [Workflow](#workflow)
* [Endpoints](#endpoints)
  * [1) Start Capture](#1-start-capture)
  * [2) Status Check](#2-status-check)
  * [3) Download Results](#3-download-results)
  * [4) Stop Capture Early](#4-stop-capture-early)
  * [5) Analysis](#5-analysis)
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

| Step | HTTP   | Path                                                       | Purpose                                        |
| ---: | :----- | :--------------------------------------------------------- | :--------------------------------------------- |
|    1 | POST   | `/advance/multi/ds/channelEstimation/start`                    | Begin a multi-sample ChannelEstimation capture |
|    2 | GET    | `/advance/multi/ds/channelEstimation/status/{operation_id}`    | Poll capture progress                          |
|    3 | GET    | `/advance/multi/ds/channelEstimation/results/{operation_id}`   | Download a ZIP of captured PNM files           |
|    4 | DELETE | `/advance/multi/ds/channelEstimation/stop/{operation_id}`      | Stop the capture after current iteration       |
|    5 | POST   | `/advance/multi/ds/channelEstimation/analysis`                 | Run post-capture signal analysis               |

### Identifiers

* `group_id`: Logical grouping for related operations.
* `operation_id`: Unique handle for one capture session. Use it for status, stop, results, and analysis.

## Workflow

1. **Start Capture** → receive `group_id` and `operation_id`.
2. **Poll Status** until `state ∈ ["completed","stopped"]`.
3. **Download Results** once finished or stopped.
4. **(Optional)** **Stop Early** to end after the current iteration.
5. **Run Analysis** on the finished capture using `operation_id` + analysis type.

## Endpoints

### 1) Start Capture

Starts a background multi-sample ChannelEstimation capture with a fixed duration and sample interval.

**Request** `POST /advance/multi/ds/channelEstimation/start`  
**Body** (`MultiChanEstRequest`):

```json
{
  "cable_modem": {
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "ip_address": "192.168.0.100",
    "pnm_parameters": {
      "tftp": {
        "ipv4": "192.168.0.10",
        "ipv6": "2001:db8::10"
      },
      "capture": {
        "channel_ids": [193, 194]
      }
    },
    "snmp": {
      "snmpV2C": { "community": "public" }
    }
  },
  "capture": {
    "parameters": {
      "measurement_duration": 120,
      "sample_interval": 15
    }
  }
}
```

When `pnm_parameters.capture.channel_ids` is omitted or empty, the capture includes all downstream OFDM channels.

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

### 2) Status Check

**Request** `GET /advance/multi/ds/channelEstimation/status/{operation_id}`

#### Response (MultiChanEstStatusResponse)

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": "success",
  "message": null,
  "operation": {
    "operation_id": "3df9f479d7a549b7",
    "state": "running",
    "collected": 3,
    "time_remaining": 105,
    "message": null
  }
}
```

### 3) Download Results

**Request** `GET /advance/multi/ds/channelEstimation/results/{operation_id}`

#### Response

* `Content-Type: application/zip`
* ZIP name: `multiChannelEstimation_<mac>_<operation_id>.zip`
* Contains ChannelEstimation coefficient files, for example:

```text
ds_ofdm_chan_estimate_coef_aabbccddeeff_160_1751762613.bin
ds_ofdm_chan_estimate_coef_aabbccddeeff_160_1751762629.bin
ds_ofdm_chan_estimate_coef_aabbccddeeff_160_1751762645.bin
```

### 4) Stop Capture Early

**Request** `DELETE /advance/multi/ds/channelEstimation/stop/{operation_id}`

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

### 5) Analysis

**Request** `POST /advance/multi/ds/channelEstimation/analysis`  
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
