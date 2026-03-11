# PNM Operations - Downstream OFDM Constellation Display

Visual Inspection Of Downstream OFDM I/Q Symbols For Rapid RF Diagnostics.

## Overview

[`CmDsConstDispMeas`](http://github.com/PyPNMApps/PyPNM/blob/main/src/pypnm/pnm/parser/CmDsConstDispMeas.py)
validates constellation capture payloads, unpacks per-symbol I/Q samples, normalizes frequency metadata, and exposes a
typed model for downstream plotting and analysis (scatter, cluster metrics, and profile-aligned modulation overlays).

## Endpoint

`POST /docs/pnm/ds/ofdm/constellationDisplay/getCapture`

## Request

Refer to [Common → Request](../../../common/request.md).  
**Deltas (Analysis-Only Additions):** optional `analysis`, `analysis.output`, and `analysis.plot.ui` /
`analysis.plot.options` controls.

## Example Request

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
        "channel_ids": []
      }
    },
    "snmp": {
      "snmpV2C": {
        "community": "private"
      }
    }
  },
  "analysis": {
    "type": "basic",
    "output": {
      "type": "json"
    },
    "plot": {
      "ui": {
        "theme": "dark"
      },
      "options": {
        "display_cross_hair": true
      }
    }
  },
  "capture_settings": {
    "modulation_order_offset": 0,
    "number_sample_symbol": 8192
  }
}
```

### Delta Table

| JSON path                                   | Type    | Allowed values / format           | Default | Description                                                                                               |
|---------------------------------------------|---------|-----------------------------------|---------|-----------------------------------------------------------------------------------------------------------|
| `analysis.type`                             | string  | "basic"                           | "basic" | Selects the analysis mode used during capture processing.                                                 |
| `analysis.output.type`                      | string  | "json" , "archive"                | "json"  | Output format: `json` returns inline `data`; `archive` returns a ZIP (CSV exports and PNG plots).         |
| `analysis.plot.ui.theme`                    | string  | "light" , "dark"                  | "dark"  | Theme hint for plot generation (colors, grid, ticks). Does not affect raw metrics or CSV output.         |
| `analysis.plot.options.display_cross_hair`  | boolean | `true` , `false`                  | true    | When true, draws a cross-hair overlay at the constellation origin to aid symbol centering and alignment. |

### Capture Settings

| JSON path                                  | Type | Default | Description                                                              |
|--------------------------------------------|------|---------|--------------------------------------------------------------------------|
| `capture_settings.modulation_order_offset` | int  | 0       | Modulation-order offset to capture (0 = base profile).                   |
| `capture_settings.number_sample_symbol`    | int  | 8192    | Number of I/Q symbols to capture.                                        |

### Usage Notes

* `modulation_order_offset` corresponds to the lowest modulation order in the selected stream. If you know the modulation
  profile composition, start at 0 and increment the offset to step through each modulation order present.
* Operators often use one modulation order per profile (Example 1), but mixed-order profiles (Example 2) also exist.
* `analysis.plot.options.display_cross_hair` only affects the visualization layer. Metrics, CSV exports, and archive
  contents are unchanged; the cross-hair is a visual reference to quickly gauge symbol centering, bias, and rotation.

### Example 1: Single Modulation Order Per Profile

| Profile | Modulation | Offset |
|---------|------------|--------|
| 0       | 256QAM     | 0      |
| 1       | 1024QAM    | 1      |
| 2       | 2048QAM    | 2      |
| 3       | 4096QAM    | 3      |

### Example 2: Mixed Modulation Orders Per Profile

| Profile | Modulations          |
|---------|----------------------|
| 0       | 16QAM + 256QAM       |
| 1       | 256QAM + 512QAM      |
| 2       | 1024QAM + 2048QAM    |
| 3       | 4096QAM              |

Offsets derived from the mixed orders:

| Order Index | Modulation | Notes |
|------------:|------------|-------|
| 0           | [16QAM](./images/constellation/16qam-constellation.png)   | Appears in Profile 0        |
| 1           | [256QAM](./images/constellation/256qam-constellation.png) | Appears in Profiles 0 and 1 |
| 2           | 512QAM                                                   | Appears in Profile 1        |
| 3           | [1024QAM](./images/constellation/1kqam-constellation.png) | Appears in Profile 2        |
| 4           | [2048QAM](./images/constellation/2kqam-constellation.png) | Appears in Profile 2        |
| 5           | [4096QAM](./images/constellation/4kqam-constellation.png) | Appears in Profile 3        |

### Notes

* When `analysis.output.type = "archive"`, the HTTP response body is the file (no `data` JSON payload).
* Constellation points are reported as `[Real, Imaginary]` with `complex_unit = "[Real, Imaginary]"` in models.
* If the selected `modulation_order_offset` corresponds to a stream for which the CMTS is not receiving
  traffic (user data or MAC messages), the CM may take a long time to reach the requested `number_sample_symbol`.
* To capture specific channels, set `cable_modem.pnm_parameters.capture.channel_ids`. Empty or missing means all channels.

## Response

Standard envelope with payload under `data`.

### Abbreviated Example

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": 0,
  "message": null,
  "data": {
    "analysis": [
      {
        "device_details": {
          "system_description": {
            "HW_REV": "1.0",
            "VENDOR": "LANCity",
            "BOOTR": "NONE",
            "SW_REV": "1.0.0",
            "MODEL": "LCPET-3"
          }
        },
        "mac_address": "aa:bb:cc:dd:ee:ff",
        "channel_id": 160,
        "num_sample_symbols": 8192,
        "modulation_order": "qam256",
        "complex_unit": "[Real, Imaginary]",
        "soft": { "complex": [[0.0843505859375, 0.000000046875]] },
        "hard": { "complex": [[1.1504474832710556, 1.1504474832710556]] }
      }
    ],
    "primative": [
      {
        "status": "SUCCESS",
        "pnm_header": {
          "file_type": "PNN",
          "file_type_version": 3,
          "major_version": 1,
          "minor_version": 0,
          "capture_time": 1762136604
        },
        "channel_id": 160,
        "mac_address": "aa:bb:cc:dd:ee:ff",
        "subcarrier_zero_frequency": 683600000,
        "first_active_subcarrier_index": -1,
        "subcarrier_spacing": 50000,
        "num_sample_symbols": 8192,
        "sample_length": 16384,
        "value_units": "[Real, Imaginary]",
        "values": [[0.0843505859375, 0.000000046875]]
      }
    ],
    "measurement_stats": [
      {
        "index": 160,
        "channel_id": 160,
        "entry": {
          "docsPnmCmDsConstDispTrigEnable": false,
          "docsPnmCmDsConstDispModOrderOffset": 0,
          "docsPnmCmDsConstDispNumSampleSymb": 8192,
          "docsPnmCmDsConstDispSelModOrder": "qam256",
          "docsPnmCmDsConstDispMeasStatus": "sample_ready",
          "docsPnmCmDsConstDispFileName": "ds_constellation_disp_aabbccddeeff_160_1762136601.bin"
        }
      }
    ]
  }
}
```

## Return Structure

### Top-Level Envelope

| Field         | Type  | Description |
|---------------|-------|-------------|
| `mac_address` | string         | Request echo of the modem MAC.                                            |
| `status`      | int            | 0 on success, non-zero on error.                                          |
| `message`     | string\|null   | Optional message describing status.                                       |
| `data`        | object         | Container for results (`analysis`, `primative`, `measurement_stats`).     |

### `data.analysis[]`

Per-channel analysis view aligned to the typed `ConstellationDisplayAnalysisModel`.

| Field              | Type   | Description |
|--------------------|--------|------------ |
| device_details.*   | object | System descriptor at analysis time.                                |
| pnm_header.*       | object | PNM header (file type, version, capture time).                     |
| mac_address        | string | MAC address (`aa:bb:cc:dd:ee:ff`).                                 |
| channel_id         | int    | OFDM downstream channel ID.                                        |
| num_sample_symbols | int    | Number of constellation sample points.                             |
| modulation_order   | string | QAM order (for example, `qam64`, `qam256`, `qam1024`).             |
| complex_unit       | string | Always `"[Real, Imaginary]"`.                                      |
| soft.complex       | array  | Soft-decision I/Q pairs (`[[real, imag], ...]`).                   |
| hard.complex       | array  | Hard-decision I/Q pairs (`[[real, imag], ...]`).                   |

### `data.primative[]`

Normalized raw capture for export and plotting.

| Field                         | Type         | Description                                         |
|-------------------------------|--------------|-----------------------------------------------------|
| status                        | string       | Result for this capture (for example, `SUCCESS`).   |
| pnm_header.*                  | object       | PNM header (type, version, capture time).           |
| channel_id                    | int          | Channel ID.                                         |
| mac_address                   | string       | MAC address.                                        |
| subcarrier_zero_frequency     | int (Hz)     | Subcarrier 0 frequency.                             |
| first_active_subcarrier_index | int          | First active subcarrier index; `-1` if not present. |
| subcarrier_spacing            | int (Hz)     | Subcarrier spacing.                                 |
| num_sample_symbols            | int          | Number of captured symbols.                         |
| sample_length                 | int          | Total payload samples (often `2 × symbols`).        |
| value_units                   | string       | Always `"[Real, Imaginary]"`.                       |
| values                        | array(float) | I/Q pairs per symbol.                               |

### `data.measurement_stats[]`

Snapshot of device-reported constellation settings at capture time (per channel).

| Field                                    | Type    | Description                                         |
|------------------------------------------|---------|-----------------------------------------------------|
| index                                    | int     | SNMP table row index.                               |
| channel_id                               | int     | OFDM downstream channel ID.                         |
| entry.docsPnmCmDsConstDispTrigEnable     | boolean | Trigger enable state.                               |
| entry.docsPnmCmDsConstDispModOrderOffset | int     | Modulation order offset used for capture.           |
| entry.docsPnmCmDsConstDispNumSampleSymb  | int     | Requested number of constellation symbols.          |
| entry.docsPnmCmDsConstDispSelModOrder    | string  | Selected modulation order (for example, `qam256`).  |
| entry.docsPnmCmDsConstDispMeasStatus     | string  | Measurement status (for example, `sample_ready`).   |
| entry.docsPnmCmDsConstDispFileName       | string  | Device-side filename of the capture.                |

## Additional Notes

* Large payloads are best handled via Postman or automation clients.
* Each object in `data.analysis[]` or `data.primative[]` represents a distinct OFDM channel.
