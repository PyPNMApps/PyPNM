# DOCSIS 3.0 Upstream ATDMA Channel Statistics

Provides Access To DOCSIS 3.0 Upstream SC-QAM (ATDMA) Channel Statistics.

## Endpoint

**POST** `/docs/if30/us/atdma/chan/stats`

## Request

Use the SNMP-only format: [Common → Request](../../../../common/request.md)  
TFTP parameters are not required.

## Response

This endpoint returns the standard envelope described in [Common → Response](../../../../common/response.md) (`status`, `message`, `device`, `data`).

`device` is the top-level device identity block and contains `device.mac_address` and `device.system_description` (empty model when unavailable).

`data` is an **object** with the upstream channel entries plus an optional DWR window evaluation summary. Each entry contains the SNMP table `index`, the upstream `channel_id`, and an `entry` with configuration, status, and (where available) raw pre-EQ data (`docsIf3CmStatusUsEqData`).

### Abbreviated Example

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": 0,
  "message": null,
  "data": {
    "entries": [
      {
        "index": 80,
        "channel_id": 1,
        "entry": {
          "docsIfUpChannelId": 1,
          "docsIfUpChannelFrequency": 14600000,
          "docsIfUpChannelWidth": 6400000,
          "docsIfUpChannelModulationProfile": 0,
          "docsIfUpChannelSlotSize": 2,
          "docsIfUpChannelTxTimingOffset": 6436,
          "docsIfUpChannelRangingBackoffStart": 3,
          "docsIfUpChannelRangingBackoffEnd": 8,
          "docsIfUpChannelTxBackoffStart": 2,
          "docsIfUpChannelTxBackoffEnd": 6,
          "docsIfUpChannelType": 2,
          "docsIfUpChannelCloneFrom": 0,
          "docsIfUpChannelUpdate": false,
          "docsIfUpChannelStatus": 1,
          "docsIfUpChannelPreEqEnable": true,
          "docsIf3CmStatusUsTxPower": 49.0,
          "docsIf3CmStatusUsT3Timeouts": 0,
          "docsIf3CmStatusUsT4Timeouts": 0,
          "docsIf3CmStatusUsRangingAborteds": 0,
          "docsIf3CmStatusUsModulationType": 2,
          "docsIf3CmStatusUsEqData": "0x08011800ffff0003...00020001",
          "docsIf3CmStatusUsT3Exceededs": 0,
          "docsIf3CmStatusUsIsMuted": false,
          "docsIf3CmStatusUsRangingStatus": "success"
        }
      },
      {
        "index": 81,
        "channel_id": 2,
        "entry": {
          "docsIfUpChannelId": 2,
          "docsIfUpChannelFrequency": 21000000,
          "docsIfUpChannelWidth": 6400000,
          "docsIfUpChannelModulationProfile": 0,
          "docsIfUpChannelSlotSize": 2,
          "docsIfUpChannelTxTimingOffset": 6436,
          "docsIfUpChannelRangingBackoffStart": 3,
          "docsIfUpChannelRangingBackoffEnd": 8,
          "docsIfUpChannelTxBackoffStart": 2,
          "docsIfUpChannelTxBackoffEnd": 6,
          "docsIfUpChannelType": 2,
          "docsIfUpChannelCloneFrom": 0,
          "docsIfUpChannelUpdate": false,
          "docsIfUpChannelStatus": 1,
          "docsIfUpChannelPreEqEnable": true,
          "docsIf3CmStatusUsTxPower": 48.5,
          "docsIf3CmStatusUsT3Timeouts": 0,
          "docsIf3CmStatusUsT4Timeouts": 0,
          "docsIf3CmStatusUsRangingAborteds": 0,
          "docsIf3CmStatusUsModulationType": 2,
          "docsIf3CmStatusUsEqData": "0x08011800ffff0001...0002",
          "docsIf3CmStatusUsT3Exceededs": 0,
          "docsIf3CmStatusUsIsMuted": false,
          "docsIf3CmStatusUsRangingStatus": "success"
        }
      }
    ],
    "dwr_window_check": {
      "dwr_warning_db": 6.0,
      "dwr_violation_db": 12.0,
      "channel_count": 2,
      "min_power_dbmv": 48.5,
      "max_power_dbmv": 49.0,
      "spread_db": 0.5,
      "is_warning": false,
      "is_violation": false,
      "extreme_channel_ids": [1, 2]
    }
  }
}
```

## Data Fields

| Field              | Type   | Description                                      |
| ------------------ | ------ | ------------------------------------------------ |
| `entries`          | array  | Upstream channel entries (same as prior format). |
| `dwr_window_check` | object | DWR evaluation summary, or null when unavailable. |

## DWR Window Check Fields

| Field              | Type  | Units | Description |
| ------------------ | ----- | ----- | ----------- |
| `dwr_warning_db`   | float | dB    | Warning threshold for the DWR spread. |
| `dwr_violation_db` | float | dB    | Violation threshold for the DWR spread. |
| `channel_count`    | int   | —     | Number of channels included in the evaluation. |
| `min_power_dbmv`   | float | dBmV  | Minimum transmit power across channels. |
| `max_power_dbmv`   | float | dBmV  | Maximum transmit power across channels. |
| `spread_db`        | float | dB    | Power spread across channels (max-min). |
| `is_warning`       | bool  | —     | True when warning_db < spread_db <= violation_db. |
| `is_violation`     | bool  | —     | True when spread_db > violation_db. |
| `extreme_channel_ids` | array | —  | Channel IDs that define the min/max spread. |

## Channel Fields

| Field        | Type | Description                                                                 |
| ------------ | ---- | --------------------------------------------------------------------------- |
| `index`      | int  | **SNMP table index** (OID instance) for this channel’s row in the CM table. |
| `channel_id` | int  | DOCSIS upstream SC-QAM (ATDMA) logical channel ID.                          |

## Entry Fields

| Field                                | Type   | Units | Description                                             |
| ------------------------------------ | ------ | ----- | ------------------------------------------------------- |
| `docsIfUpChannelId`                  | int    | —     | Upstream channel ID (mirrors logical ID).               |
| `docsIfUpChannelFrequency`           | int    | Hz    | Center frequency.                                       |
| `docsIfUpChannelWidth`               | int    | Hz    | Channel width.                                          |
| `docsIfUpChannelModulationProfile`   | int    | —     | Modulation profile index.                               |
| `docsIfUpChannelSlotSize`            | int    | —     | Slot size (minislot units).                             |
| `docsIfUpChannelTxTimingOffset`      | int    | —     | Transmit timing offset (implementation-specific units). |
| `docsIfUpChannelRangingBackoffStart` | int    | —     | Initial ranging backoff window start.                   |
| `docsIfUpChannelRangingBackoffEnd`   | int    | —     | Initial ranging backoff window end.                     |
| `docsIfUpChannelTxBackoffStart`      | int    | —     | Data/backoff start window.                              |
| `docsIfUpChannelTxBackoffEnd`        | int    | —     | Data/backoff end window.                                |
| `docsIfUpChannelType`                | int    | —     | Channel type enum (e.g., `2` = ATDMA).                  |
| `docsIfUpChannelCloneFrom`           | int    | —     | Clone source channel (if used).                         |
| `docsIfUpChannelUpdate`              | bool   | —     | Indicates a pending/active update.                      |
| `docsIfUpChannelStatus`              | int    | —     | Operational status enum.                                |
| `docsIfUpChannelPreEqEnable`         | bool   | —     | Whether pre-equalization is enabled.                    |
| `docsIf3CmStatusUsTxPower`           | float  | dBmV  | Upstream transmit power.                                |
| `docsIf3CmStatusUsT3Timeouts`        | int    | —     | T3 timeouts counter.                                    |
| `docsIf3CmStatusUsT4Timeouts`        | int    | —     | T4 timeouts counter.                                    |
| `docsIf3CmStatusUsRangingAborteds`   | int    | —     | Aborted ranging attempts.                               |
| `docsIf3CmStatusUsModulationType`    | int    | —     | Modulation type enum.                                   |
| `docsIf3CmStatusUsEqData`            | string | hex   | Raw pre-EQ coefficient payload (hex string; raw octets). |
| `docsIf3CmStatusUsT3Exceededs`       | int    | —     | Exceeded T3 attempts.                                   |
| `docsIf3CmStatusUsIsMuted`           | bool   | —     | Whether the upstream transmitter is muted.              |
| `docsIf3CmStatusUsRangingStatus`     | string | —     | Ranging state name (e.g., `success`).                   |

## Notes

* `docsIf3CmStatusUsEqData` contains the raw equalizer payload; decode to taps (location, magnitude, phase) in analysis workflows.
* The hex string preserves original SNMP octets (for example `FF` stays `FF`, not UTF-8 encoded).
* Use the combination of `TxPower`, timeout counters, and ranging status to corroborate upstream health with pre-EQ shape.
* Channels are discovered automatically; no channel list is required in the request.
* DWR warning and violation thresholds are evaluated against the min/max power spread for all channels returned.
# DOCSIS 3.0 Upstream ATDMA Pre-Equalization

Provides Access To DOCSIS 3.0 Upstream SC-QAM (ATDMA) Pre-Equalization Tap Data For Plant Analysis (Reflections, Group Delay, Pre-Echo).

## Endpoint

**POST** `/docs/if30/us/scqam/chan/preEqualization`

## Request

Use the SNMP-only format: [Common → Request](../../../../common/request.md)  
TFTP parameters are not required.

## Response

This endpoint returns the standard envelope described in [Common → Response](../../../../common/response.md) (`status`, `message`, `device`, `data`).

`device` is the top-level device identity block and contains `device.mac_address` and `device.system_description` (empty model when unavailable).

`data` is an **object** keyed by the **SNMP table index** of each upstream channel.  
Each value contains decoded tap configuration and coefficient arrays.

### Abbreviated Example

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": 0,
  "message": null,
  "data": {
    "80": {
      "main_tap_location": 8,
      "forward_taps_per_symbol": 1,
      "num_forward_taps": 24,
      "num_reverse_taps": 0,
      "forward_coefficients": [
        { "real": 0, "imag": 4, "magnitude": 4.0, "magnitude_power_dB": 12.04 },
        { "real": 2, "imag": -15425, "magnitude": 15425.0, "magnitude_power_dB": 83.76 },
        { "real": -15426, "imag": 1, "magnitude": 15426.0, "magnitude_power_dB": 83.77 }
        /* ... taps elided ... */
      ],
      "reverse_coefficients": []
    },
    "81": {
      "main_tap_location": 8,
      "forward_taps_per_symbol": 1,
      "num_forward_taps": 24,
      "num_reverse_taps": 0,
      "forward_coefficients": [
        { "real": -15425, "imag": -15425, "magnitude": 21814.24, "magnitude_power_dB": 86.77 },
        { "real": 1, "imag": 3, "magnitude": 3.16, "magnitude_power_dB": 10.0 },
        { "real": 1, "imag": -15425, "magnitude": 15425.0, "magnitude_power_dB": 83.76 }
        /* ... taps elided ... */
      ],
      "reverse_coefficients": []
    }
    /* ... other upstream channel indices elided ... */
  }
}
```

## Container Keys

| Key (top-level under `data`) | Type   | Description                                                       |
| ---------------------------- | ------ | ----------------------------------------------------------------- |
| `"80"`, `"81"`, …            | string | **SNMP table index** for the upstream channel row (OID instance). |

## Channel-Level Fields

| Field                     | Type    | Description                                                 |
| ------------------------- | ------- | ----------------------------------------------------------- |
| `main_tap_location`       | integer | Location of the main tap (typically near the filter center) |
| `forward_taps_per_symbol` | integer | Number of forward taps per symbol                           |
| `num_forward_taps`        | integer | Total forward equalizer taps                                |
| `num_reverse_taps`        | integer | Total reverse equalizer taps (often `0` for ATDMA)          |
| `forward_coefficients`    | array   | Complex tap coefficients applied in forward direction       |
| `reverse_coefficients`    | array   | Complex tap coefficients applied in reverse direction       |
| `metrics`                 | object  | Derived equalizer metrics and frequency response            |

## Coefficient Object Fields

| Field                | Type  | Units | Description                          |
| -------------------- | ----- | ----- | ------------------------------------ |
| `real`               | int   | —     | Real part of the complex coefficient |
| `imag`               | int   | —     | Imaginary part of the coefficient    |
| `magnitude`          | float | —     | Magnitude of the complex tap         |
| `magnitude_power_dB` | float | dB    | Power of the tap in dB               |

## Equalizer Metrics Fields

| Field                           | Type  | Units | Description                                   |
| ------------------------------- | ----- | ----- | --------------------------------------------- |
| `main_tap_energy`               | float | —     | Main tap energy (MTE)                         |
| `main_tap_nominal_energy`       | float | —     | Main tap nominal energy (MTNE)                |
| `pre_main_tap_energy`           | float | —     | Pre-main tap energy (PreMTE)                  |
| `post_main_tap_energy`          | float | —     | Post-main tap energy (PostMTE)                |
| `total_tap_energy`              | float | —     | Total tap energy (TTE)                        |
| `main_tap_compression`          | float | dB    | Main tap compression (MTC)                    |
| `main_tap_ratio`                | float | dB    | Main tap ratio (MTR)                          |
| `non_main_tap_energy_ratio`     | float | dB    | Non-main tap to total energy ratio (NMTER)    |
| `pre_main_tap_total_energy_ratio` | float | dB  | Pre-main tap to total energy ratio (PreMTTER) |
| `post_main_tap_total_energy_ratio` | float | dB | Post-main tap to total energy ratio (PostMTTER) |
| `pre_post_energy_symmetry_ratio`  | float | dB | Pre-post energy symmetry ratio (PPESR)        |
| `pre_post_tap_symmetry_ratio`     | float | dB | Pre-post tap symmetry ratio (PPTSR)           |
| `frequency_response`              | object | —  | Frequency response derived from tap coefficients |

## Frequency Response Fields

| Field                         | Type          | Units | Description                                         |
| ----------------------------- | ------------- | ----- | --------------------------------------------------- |
| `fft_size`                    | integer       | —     | FFT size used to compute the response               |
| `frequency_bins`              | array[float]  | —     | Normalized bins from 0 to 1                         |
| `magnitude`                   | array[float]  | —     | Magnitude response per bin                          |
| `magnitude_power_db`          | array[float]  | dB    | Magnitude power per bin                             |
| `magnitude_power_db_normalized` | array[float] | dB    | Magnitude power normalized to the DC bin (bin 0)    |
| `phase_radians`               | array[float]  | rad   | Phase response per bin                              |

## Notes

* Each top-level key under `data` is the DOCSIS **SNMP index** for an upstream SC-QAM (ATDMA) channel.
* Forward taps pre-compensate the channel (handling pre-echo/echo paths); reverse taps are uncommon in ATDMA.
* Use tap shapes and main-tap offset to infer echo path delay and alignment health.
* Tap coefficients are signed integers; convert to floating-point as needed for analysis.
* `magnitude_power_db_normalized` references the DC bin (bin 0) as 0 dB when non-zero.
