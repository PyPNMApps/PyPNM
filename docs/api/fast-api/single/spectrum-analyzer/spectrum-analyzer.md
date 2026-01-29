# PNM Operations - Spectrum Analyzer

Downstream Spectrum Capture And Per-Channel Analysis For DOCSIS 3.x/4.0 Cable Modems.

## Overview

[`SpectrumAnalyzerRouter`](http://github.com/PyPNMApps/PyPNM/blob/main/src/pypnm/api/routes/docs/pnm/spectrumAnalyzer/router.py)
exposes four related endpoints that drive downstream spectrum capture and analysis:

* A single spectrum capture endpoint (`/getCapture`) for free-form frequency sweeps.
* A single spectrum capture endpoint with friendly RBW inputs (`/getCapture/friendly`).
* An OFDM-focused endpoint (`/getCapture/ofdm`) that walks all downstream OFDM channels.
* An SC-QAM-focused endpoint (`/getCapture/scqam`) that walks all downstream SC-QAM channels.

Each capture is processed through the common analysis pipeline and can return either a JSON
analysis payload or an archive (ZIP) with Matplotlib plots and CSV exports.

For RBW auto-scale outcomes, see the [Spectrum analyzer RBW permutations](../spectrum-analyzer.md) reference.

> The cable modem must be PNM-ready and the requested frequency range must fall within the
> configured diplexer band. Use the diplexer configuration API to verify allowed frequency
> boundaries.

### Diplexer Configuration Endpoint

| DOCSIS | Endpoint | Description |
|-------|----------|-------------|
| [DOCSIS 3.1](../general/diplexer-configuration.md)                | `POST /docs/if31/system/diplexer`              | Retrieve the diplexer for spectrum capture. |
| [DOCSIS 4.0](../fdd/fdd-system-diplexer-configuration.md) | `POST /docs/fdd/system/diplexer/configuration` | Retrieve the diplexer for spectrum capture. |

## Endpoints

All endpoints share the same base prefix: `/docs/pnm/ds`.

| Purpose                        | Method | Path                                             |
| ------------------------------ | ------ | ------------------------------------------------ |
| Single spectrum capture        | POST   | `/docs/pnm/ds/spectrumAnalyzer/getCapture`       |
| Single spectrum capture (RBW)  | POST   | `/docs/pnm/ds/spectrumAnalyzer/getCapture/friendly` |
| All OFDM downstream channels   | POST   | `/docs/pnm/ds/spectrumAnalyzer/getCapture/ofdm`  |
| All SC-QAM downstream channels | POST   | `/docs/pnm/ds/spectrumAnalyzer/getCapture/scqam` |

Each endpoint accepts a common cable modem block and analysis controls. Capture-specific
settings are provided under `capture_parameters`.

> Note: A modem can only run either downstream or upstream spectrum at a time. The router
> documented here is downstream (`/ds`) only.

## Common Request Shape

Refer to [Common → Request](../../common/request.md).  
These endpoints add optional `analysis` controls and a `capture_parameters` section.

### Analysis Delta Table

| JSON path                | Type   | Allowed values / format | Default | Description                                                                                               |
| ------------------------ | ------ | ----------------------- | ------- | --------------------------------------------------------------------------------------------------------- |
| `analysis.type`          | string | "basic"                 | "basic" | Selects the analysis mode used during processing.                                                         |
| `analysis.output.type`   | string | "json", "archive"       | "json"  | Output format. **`json`** returns inline `data`; **`archive`** returns a ZIP (CSV exports and PNG plots). |
| `analysis.plot.ui.theme` | string | "light", "dark"         | "dark"  | Theme hint for Matplotlib plots (colors, grid, ticks). Does not affect raw metrics/CSV.                   |
| `analysis.spectrum_analysis.moving_average.points` | int | >= 1 | 10 | Window size for the moving average applied to spectrum magnitudes. |

When `analysis.output.type = "archive"`, the HTTP response body is the file (no `data` JSON payload).

## Single Capture - `/spectrumAnalyzer/getCapture`

Single downstream spectrum capture using the modem's generic spectrum engine. This is the
most flexible entry point and allows arbitrary sweep settings (within diplexer limits).

### Single Capture Example Request

```json
{
  "cable_modem": {
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "ip_address": "192.168.0.100",
    "pnm_parameters": {
      "tftp": {
        "ipv4": "192.168.0.10",
        "ipv6": "2001:db8::10"
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
    "output": { "type": "json" },
    "plot": { "ui": { "theme": "dark" } },
    "spectrum_analysis": {
      "moving_average": { "points": 10 }
    }
  },
  "capture_parameters": {
    "inactivity_timeout": 60,
    "first_segment_center_freq": 300000000,
    "last_segment_center_freq": 900000000,
    "segment_freq_span": 1000000,
    "num_bins_per_segment": 256,
    "noise_bw": 150,
    "window_function": 1,
    "num_averages": 1,
    "spectrum_retrieval_type": 1
  }
}
```

### Capture Parameters

| JSON path                                      | Type | Description                                                                  |
| ---------------------------------------------- | ---- | ---------------------------------------------------------------------------- |
| `capture_parameters.inactivity_timeout`        | int  | Timeout (seconds) before aborting idle spectrum acquisition.                 |
| `capture_parameters.first_segment_center_freq` | int  | Center frequency (Hz) of the first sweep segment.                            |
| `capture_parameters.last_segment_center_freq`  | int  | Center frequency (Hz) of the last sweep segment.                             |
| `capture_parameters.segment_freq_span`         | int  | Frequency span (Hz) covered by each sweep segment.                           |
| `capture_parameters.num_bins_per_segment`      | int  | Number of FFT bins per segment.                                              |
| `capture_parameters.noise_bw`                  | int  | Equivalent noise bandwidth in kHz.                                            |
| `capture_parameters.window_function`           | int  | Window function enum value.                                                    |
| `capture_parameters.num_averages`              | int  | Number of averages per segment for noise reduction.                           |
| `capture_parameters.spectrum_retrieval_type`   | int  | Retrieval mode enum value (FILE = 1, SNMP = 2).                                 |

### Note

`pnm_parameters.capture.channel_ids` is not supported for this endpoint. Use the OFDM or SC-QAM endpoints when channel scoping is required.

#### Window Function Values

| Value | Enum name |
| ----- | --------- |
| 0     | OTHER |
| 1     | HANN |
| 2     | BLACKMAN_HARRIS |
| 3     | RECTANGULAR |
| 4     | HAMMING |
| 5     | FLAT_TOP |
| 6     | GAUSSIAN |
| 7     | CHEBYSHEV |

#### Note

> `spectrum_retrieval_type` Use 1 (PNM_FILE) is preferred for most use cases. Use `2` (SNMP) when PNM file transfer is not available.

## Single Capture (Friendly) - `/spectrumAnalyzer/getCapture/friendly`

This variant accepts a resolution bandwidth and a requested window, then derives
the segment span and bin count using the spectrum-analysis-capture-set rules. The
first and last segment center frequencies are adjusted inward by half a segment
span to satisfy the analyzer's scaled window constraints.

### Friendly Capture Example Request

```json
{
  "cable_modem": {
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "ip_address": "192.168.0.100",
    "pnm_parameters": {
      "tftp": {
        "ipv4": "192.168.0.10",
        "ipv6": "2001:db8::10"
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
    "output": { "type": "json" },
    "plot": { "ui": { "theme": "dark" } },
    "spectrum_analysis": {
      "moving_average": { "points": 10 }
    }
  },
  "capture_parameters": {
    "inactivity_timeout": 60,
    "first_segment_center_freq": 300000000,
    "last_segment_center_freq": 900000000,
    "resolution_bw": 30000,
    "noise_bw": 150,
    "window_function": 1,
    "num_averages": 1,
    "spectrum_retrieval_type": 1
  }
}
```

### Friendly Capture Parameters

| JSON path                                      | Type | Description                                                                  |
| ---------------------------------------------- | ---- | ---------------------------------------------------------------------------- |
| `capture_parameters.inactivity_timeout`        | int  | Timeout (seconds) before aborting idle spectrum acquisition.                 |
| `capture_parameters.first_segment_center_freq` | int  | Requested first segment center frequency (Hz) for the capture window.        |
| `capture_parameters.last_segment_center_freq`  | int  | Requested last segment center frequency (Hz) for the capture window.         |
| `capture_parameters.resolution_bw`             | int  | Resolution bandwidth (Hz) used to derive segment span and bin count.         |
| `capture_parameters.noise_bw`                  | int  | Equivalent noise bandwidth in kHz.                                           |
| `capture_parameters.window_function`           | int  | Window function enum value.                                                  |
| `capture_parameters.num_averages`              | int  | Number of averages per segment.                                              |
| `capture_parameters.spectrum_retrieval_type`   | int  | Retrieval mode enum value (FILE = 1, SNMP = 2).                              |

Note: The computed `segment_freq_span`, `num_bins_per_segment`, and adjusted segment
center frequencies are returned in the analysis payload.

### Abbreviated JSON Response (Output Type `"json"`)

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
        "capture_parameters": {
          "inactivity_timeout": 60,
          "first_segment_center_freq": 300000000,
          "last_segment_center_freq": 900000000,
          "segment_freq_span": 1000000,
          "num_bins_per_segment": 100,
          "noise_bw": 0,
          "window_function": 1,
          "num_averages": 1,
          "spectrum_retrieval_type": 1
        },
        "signal_analysis": {
          "bin_bandwidth": 10000,
          "segment_length": 100,
          "frequencies": [],
          "magnitudes": [],
          "window_average": {
            "points": 20,
            "magnitudes": []
          }
        }
      }
    ],
    "primative": [
      {
        "status": "SUCCESS",
        "pnm_header": {
          "file_type": "PNN",
          "file_type_version": 9,
          "major_version": 1,
          "minor_version": 0,
          "capture_time": 1762839675
        },
        "mac_address": "aa:bb:cc:dd:ee:ff",
        "first_segment_center_frequency": 300000000,
        "last_segment_center_frequency": 900000000,
        "segment_frequency_span": 1000000,
        "num_bins_per_segment": 100,
        "equivalent_noise_bandwidth": 110.0,
        "window_function": 1,
        "bin_frequency_spacing": 10000,
        "spectrum_analysis_data_length": 120200,
        "spectrum_analysis_data": "e570e3...40e340"
      }
    ],
    "measurement_stats": [
      {
        "index": 0,
        "entry": {
          "docsIf3CmSpectrumAnalysisCtrlCmdEnable": true,
          "docsIf3CmSpectrumAnalysisCtrlCmdInactivityTimeout": 60,
          "docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency": 300000000,
          "docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency": 900000000,
          "docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan": 1000000,
          "docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment": 100,
          "docsIf3CmSpectrumAnalysisCtrlCmdEquivalentNoiseBandwidth": 110,
          "docsIf3CmSpectrumAnalysisCtrlCmdWindowFunction": 1,
          "docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages": 1,
          "docsIf3CmSpectrumAnalysisCtrlCmdFileEnable": true,
          "docsIf3CmSpectrumAnalysisCtrlCmdMeasStatus": "sample_ready",
          "docsIf3CmSpectrumAnalysisCtrlCmdFileName": "spectrum_analyzer_aabbccddeeff_0_1762839621.bin"
        }
      }
    ]
  }
}
```

### Single-Capture Return Structure

Top-level envelope:

| Field         | Type          | Description                                                               |
| ------------- | ------------- | ------------------------------------------------------------------------- |
| `mac_address` | string        | Request echo of the modem MAC.                                            |
| `status`      | int           | 0 on success, non-zero on error.                                          |
| `message`     | string\|null  | Optional message describing status.                                       |
| `data`        | object        | Container for results (`analysis`, `primative`, `measurement_stats`).     |

**Payload: `data.analysis[]`**

| Field                            | Type   | Description                                                           |
| -------------------------------- | ------ | --------------------------------------------------------------------- |
| device_details.*                 | object | System descriptor captured at analysis time.                          |
| capture_parameters.*             | object | Echo of the capture parameters effective for this run.               |
| signal_analysis.bin_bandwidth    | int    | Effective bin bandwidth (Hz) derived from bin spacing/windowing.     |
| signal_analysis.segment_length   | int    | Number of FFT bins per segment used in analysis.                     |
| signal_analysis.frequencies      | array  | Frequency axis for the analyzed spectrum (per-bin center frequency). |
| signal_analysis.magnitudes       | array  | Amplitude values aligned with `frequencies`.                         |
| signal_analysis.window_average.* | object | Optional moving-average smoothing applied to `magnitudes`.           |

**Payload: `data.primative[]`**

| Field                          | Type       | Description                                               |
| ------------------------------ | ---------- | --------------------------------------------------------- |
| status                         | string     | Result for this capture (e.g., `"SUCCESS"`).              |
| pnm_header.*                   | object     | PNM file header (type, version, capture time).            |
| mac_address                    | string     | MAC address.                                              |
| first_segment_center_frequency | int (Hz)   | Center frequency of the first sweep segment.              |
| last_segment_center_frequency  | int (Hz)   | Center frequency of the last sweep segment.               |
| segment_frequency_span         | int (Hz)   | Frequency span covered by each segment.                   |
| num_bins_per_segment           | int        | Number of FFT bins per segment.                           |
| equivalent_noise_bandwidth     | float (Hz) | Equivalent noise bandwidth used for amplitude scaling.    |
| window_function                | int        | Window function index.                                    |
| bin_frequency_spacing          | float (Hz) | Frequency spacing between adjacent bins.                  |
| spectrum_analysis_data_length  | int        | Byte length of `spectrum_analysis_data`.                  |
| spectrum_analysis_data         | string     | Raw spectrum data encoded as hexadecimal text.            |

**Payload: `data.measurement_stats[]`**

| Field                                                     | Type    | Description                                              |
| --------------------------------------------------------- | ------- | -------------------------------------------------------- |
| index                                                               | int     | SNMP table row index.                                    |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdEnable                        | boolean | Whether capture was enabled for this measurement.        |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdInactivityTimeout             | int     | Inactivity timeout (seconds) used for the capture.       |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency   | int (Hz) | First segment center frequency at capture time.  |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency    | int (Hz) | Last segment center frequency at capture time.   |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan          | int (Hz) | Segment frequency span in Hz.                   |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment             | int     | Number of bins per segment.                      |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdEquivalentNoiseBandwidth      | int     | Equivalent noise bandwidth in Hz.                |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdWindowFunction                | int     | Window function index.                           |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages              | int     | Number of averages used for this capture.        |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdFileEnable                    | boolean | Whether capture-to-file was enabled.             |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdMeasStatus                    | string  | Measurement status (e.g., `"sample_ready"`).     |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdFileName                      | string  | Device-side filename of the captured spectrum.   |

## OFDM Downstream Capture - `/spectrumAnalyzer/getCapture/ofdm`

This endpoint iterates across all downstream OFDM channels on the modem, performing a
spectrum capture per channel and aggregating the results into a multi-analysis structure.

Each per-channel capture is processed like the single capture. Results are returned as:

* `data.analyses[]` - list of per-channel analysis views (one entry per capture).
* `data.primative` - dictionary of raw capture payloads indexed by channel position.
* `data.measurement_stats[]` - flattened SNMP spectrum-analysis entries.

DOCSIS constraints:

* DOCSIS 3.1: up to **2** downstream OFDM channels.  
* DOCSIS 4.0 FDD/FDX: up to **5** downstream OFDM channels.

### OFDM Capture Example Request

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
      "snmpV2C": {
        "community": "private"
      }
    }
  },
  "analysis": {
    "type": "basic",
    "output": { "type": "json" },
    "plot": { "ui": { "theme": "dark" } },
    "spectrum_analysis": {
      "moving_average": { "points": 10 }
    }
  },
  "capture_parameters": {
    "number_of_averages": 10,
    "resolution_bandwidth_hz": 25000,
    "spectrum_retrieval_type": 1
  }
}
```

### OFDM Capture Parameters

| JSON path                                   | Type | Description                                                                  |
| ------------------------------------------- | ---- | ---------------------------------------------------------------------------- |
| `capture_parameters.number_of_averages`     | int  | Number of samples used to compute the per-bin average.                       |
| `capture_parameters.resolution_bandwidth_hz`| int  | Resolution bandwidth (Hz) used to derive segment span and bin count.         |
| `capture_parameters.spectrum_retrieval_type`| int  | Retrieval mode enum value (FILE = 1, SNMP = 2).                              |

> `resolution_bandwidth_hz` is used to auto-scale RBW settings (segment span and bins per segment).

To scope captures to specific OFDM channels, set `pnm_parameters.capture.channel_ids`. Omit or use an empty list to capture all downstream OFDM channels.

### Abbreviated JSON Response (OFDM View)

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": 0,
  "message": null,
  "data": {
    "analyses": [
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
        "capture_parameters": {
          "inactivity_timeout": 60,
          "first_segment_center_freq": 739000000,
          "last_segment_center_freq": 833000000,
          "segment_freq_span": 1000000,
          "num_bins_per_segment": 100,
          "noise_bw": 0,
          "window_function": 1,
          "num_averages": 1,
          "spectrum_retrieval_type": 1
        },
        "signal_analysis": {
          "bin_bandwidth": 10000,
          "segment_length": 100,
          "frequencies": [],
          "magnitudes": [],
          "window_average": {
            "points": 10,
            "magnitudes": []
          }
        }
      }
    ],
    "primative": {
      "0": [
        {
          "status": "SUCCESS",
          "pnm_header": {
            "file_type": "PNN",
            "file_type_version": 9,
            "major_version": 1,
            "minor_version": 0,
            "capture_time": 1762840213
          },
          "channel_id": 0,
          "mac_address": "aa:bb:cc:dd:ee:ff",
          "first_segment_center_frequency": 739000000,
          "last_segment_center_frequency": 833000000,
          "segment_frequency_span": 1000000,
          "num_bins_per_segment": 100,
          "equivalent_noise_bandwidth": 110.0,
          "window_function": 1,
          "bin_frequency_spacing": 10000,
          "spectrum_analysis_data_length": 19000,
          "spectrum_analysis_data": "",
          "amplitude_bin_segments_float": []
        }
      ],
      "1": []
    },
    "measurement_stats": [
      {
        "index": 0,
        "entry": {
          "docsIf3CmSpectrumAnalysisCtrlCmdEnable": true,
          "docsIf3CmSpectrumAnalysisCtrlCmdInactivityTimeout": 30,
          "docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency": 739000000,
          "docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency": 833000000,
          "docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan": 1000000,
          "docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment": 100,
          "docsIf3CmSpectrumAnalysisCtrlCmdEquivalentNoiseBandwidth": 110,
          "docsIf3CmSpectrumAnalysisCtrlCmdWindowFunction": 1,
          "docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages": 2,
          "docsIf3CmSpectrumAnalysisCtrlCmdFileEnable": true,
          "docsIf3CmSpectrumAnalysisCtrlCmdMeasStatus": "sample_ready",
          "docsIf3CmSpectrumAnalysisCtrlCmdFileName": "spectrum_analyzer_aabbccddeeff_0_1762840189.bin"
        }
      },
      {
        "index": 0,
        "entry": {
          "docsIf3CmSpectrumAnalysisCtrlCmdEnable": true,
          "docsIf3CmSpectrumAnalysisCtrlCmdInactivityTimeout": 30,
          "docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency": 619000000,
          "docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency": 737000000,
          "docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan": 1000000,
          "docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment": 100,
          "docsIf3CmSpectrumAnalysisCtrlCmdEquivalentNoiseBandwidth": 110,
          "docsIf3CmSpectrumAnalysisCtrlCmdWindowFunction": 1,
          "docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages": 2,
          "docsIf3CmSpectrumAnalysisCtrlCmdFileEnable": true,
          "docsIf3CmSpectrumAnalysisCtrlCmdMeasStatus": "sample_ready",
          "docsIf3CmSpectrumAnalysisCtrlCmdFileName": "spectrum_analyzer_aabbccddeeff_0_1762840227.bin"
        }
      }
    ]
  }
}
```

### OFDM Multi-Channel Return Structure

**Payload: `data.analyses[]` (OFDM)**

| Field                          | Type   | Description                                                          |
| ------------------------------ | ------ | -------------------------------------------------------------------- |
| `[index]`.device_details.*     | object | System descriptor captured at analysis time for that channel.        |
| `[index]`.capture_parameters.* | object | Effective capture parameters for that OFDM channel.                  |
| `[index]`.signal_analysis.*    | object | Per-channel spectrum analysis (frequencies, magnitudes, smoothing).  |

**Payload: `data.primative` (OFDM)**

| Field           | Type  | Description                                                             |
| --------------- | ----- | ----------------------------------------------------------------------- |
| `"0"`, `"1"`, … | array | Raw per-channel capture payloads for each OFDM channel position.       |

**Payload: `data.measurement_stats[]` (OFDM)**

Reuses the single-capture `measurement_stats` field definitions, repeated per OFDM channel.

## SC-QAM Downstream Capture - `/spectrumAnalyzer/getCapture/scqam`

This endpoint iterates across all downstream SC-QAM channels, performing spectrum captures
per channel and aggregating the results into a multi-analysis view similar to the OFDM
endpoint.

DOCSIS constraints:

* DOCSIS 3.1 and DOCSIS 4.0 support up to **32** downstream SC-QAM channels (implementation-dependent).

The response shape for SC-QAM captures mirrors the OFDM multi-channel layout:

* `data.analyses[]` - list of per-channel analysis views.
* `data.primative` - dictionary of raw capture payloads indexed by channel position.
* `data.measurement_stats[]` - flattened SNMP statistics per captured channel.

### Example Request

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
        "channel_ids": [1, 2]
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
    "output": { "type": "json" },
    "plot": { "ui": { "theme": "dark" } },
    "spectrum_analysis": {
      "moving_average": { "points": 10 }
    }
  },
  "capture_parameters": {
    "number_of_averages": 10,
    "resolution_bandwidth_hz": 25000,
    "spectrum_retrieval_type": 1
  }
}
```

### SC-QAM Capture Parameters

| JSON path                                   | Type | Description                                                                  |
| ------------------------------------------- | ---- | ---------------------------------------------------------------------------- |
| `capture_parameters.number_of_averages`     | int  | Number of samples used to compute the per-bin average.                       |
| `capture_parameters.resolution_bandwidth_hz`| int  | Resolution bandwidth (Hz) used to derive segment span and bin count.         |
| `capture_parameters.spectrum_retrieval_type`| int  | Retrieval mode enum value (FILE = 1, SNMP = 2).                              |

> `resolution_bandwidth_hz` is used to auto-scale RBW settings (segment span and bins per segment).

To scope captures to specific SC-QAM channels, set `pnm_parameters.capture.channel_ids`. Omit or use an empty list to capture all downstream SC-QAM channels.

### SC-QAM Multi-Channel Return Structure

**Payload: `data.analyses[]` (SC-QAM)**

Same as OFDM: each list element represents a per-channel analysis view with
`device_details`, `capture_parameters`, and `signal_analysis`.

**Payload: `data.primative` (SC-QAM)**

| Field           | Type  | Description                                                             |
| --------------- | ----- | ----------------------------------------------------------------------- |
| `"0"`, `"1"`, … | array | Raw per-channel capture payloads for each SC-QAM channel position.     |

**Payload: `data.measurement_stats[]` (SC-QAM)**

Reuses the single-capture `measurement_stats` field definitions, per SC-QAM channel.

## Archive Output

For all three endpoints, when `analysis.output.type = "archive"`:

* The response body is a ZIP file (no JSON `data` envelope).
* Contents typically include:
  * CSV exports of amplitude vs frequency.
  * Matplotlib PNG plots per channel and aggregate views.

Examples of generated plots:

| Standard Plot  | Moving Average Plot  | Description |
| -------------- | -------------------- | ----------- |
| [DS Full Bandwidth](../images/spectrum/spec-analysis-standard.png) | [DS Full Bandwidth](../images/spectrum/spec-analysis-moving-average.png)    | Single-capture standard vs moving-average spectrum views.       |
| [SCQAM](../images/spectrum/scqam-2-spec-analysis-standard.png)     | [SCQAM](../images/spectrum/scqam-2-spec-analysis-moving-average.png)        | Example SC-QAM channel standard and moving-average plots.       |
| [OFDM](../images/spectrum/ofdm-34-spec-analysis-standard.png)      | [OFDM](../images/spectrum/ofdm-34-spec-analysis-moving-average.png)         | Example OFDM channel standard and moving-average plots.         |

## Notes

* Always validate requested frequency ranges against the modem diplexer configuration.  
* Spectrum captures can be long-running operations depending on span and averaging.  
