# DOCSIS 3.0 Upstream ATDMA Pre-Equalization

Provides Access To DOCSIS 3.0 Upstream SC-QAM (ATDMA) Pre-Equalization Tap Data For Plant Analysis (Reflections, Group Delay, Pre-Echo).

## Endpoint

**POST** `/docs/if30/us/atdma/chan/preEqualization`

## Request

Use the SNMP-only format: [Common → Request](../../../../common/request.md)  
TFTP parameters are not required.

## Response

This endpoint returns the standard envelope described in [Common → Response](../../../../common/response.md) (`status`, `message`, `device`, `data`).

`device` is the top-level device identity block and contains `device.mac_address` and `device.system_description` (empty model when unavailable).

`data` is an **object** keyed by the **SNMP table index** of each upstream channel.  
Each value contains decoded tap configuration, coefficients, metrics, group delay, and tap delay annotations when available.

### Abbreviated Example

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": 0,
  "message": "Successfully retrieved upstream pre-equalization coefficients",
  "results": {
    "4": {
      "main_tap_location": 8,
      "taps_per_symbol": 1,
      "num_taps": 24,
      "reserved": 0,
      "header_hex": "08 01 18 00",
      "payload_hex": "08 01 18 00 00 00 00 04 00 07 FF FC FF FD 00 07 00 04",
      "payload_preview_hex": "08 01 18 00 00 00 00 04 00 07 FF FC FF FD 00 07 00 04",
      "taps": [
        { "real": 0, "imag": 4, "magnitude": 4.0, "magnitude_power_dB": 12.04, "real_hex": "0000", "imag_hex": "0004" },
        { "real": 7, "imag": -4, "magnitude": 8.06, "magnitude_power_dB": 18.13, "real_hex": "0007", "imag_hex": "FFFC" }
        /* ... taps elided ... */
      ],
      "metrics": {
        "main_tap_energy": 4177985.0,
        "main_tap_nominal_energy": 8380418.0,
        "pre_main_tap_energy": 10737.0,
        "post_main_tap_energy": 1568.0,
        "total_tap_energy": 4190290.0,
        "main_tap_compression": 0.012772040716584596,
        "main_tap_ratio": 25.308852583836106,
        "frequency_response": {
          "fft_size": 24,
          "frequency_bins": [0.0, 0.041666666666666664, 0.08333333333333333],
          "magnitude": [2051.000000715576, 2003.9331033353867, 1990.4489950200837],
          "magnitude_power_db": [66.24300663848884, 66.03766439043883, 65.97902106653461],
          "magnitude_power_db_normalized": [0.0, -0.20534224805000179, -0.26398557195422256],
          "phase_radians": [0.061445988511636136, -1.7860293780783445, 2.66760487568281]
        }
      },
      "group_delay": {
        "channel_width_hz": 6400000,
        "rolloff": 0.25,
        "taps_per_symbol": 1,
        "symbol_rate": 5120000.0,
        "symbol_time_us": 0.1953125,
        "sample_period_us": 0.1953125,
        "fft_size": 24,
        "delay_samples": [7.0568360839993645, 7.0226031674860145, 7.0170470754941],
        "delay_us": [1.378288297656126, 1.3716021811496122, 1.3705170069324413]
      },
      "tap_delay_summary": {
        "symbol_rate": 5120000.0,
        "taps_per_symbol": 1,
        "symbol_time_us": 0.1953125,
        "sample_period_us": 0.1953125,
        "main_tap_index": 7,
        "main_echo_tap_index": 8,
        "main_echo_tap_offset": 1,
        "main_echo_magnitude": 36.22154055254967,
        "taps": [
          {
            "tap_index": 0,
            "tap_offset": -7,
            "is_main_tap": false,
            "real": 0,
            "imag": 4,
            "magnitude": 4.0,
            "magnitude_power_db": 12.041199826559248,
            "delay_samples": -7.0,
            "delay_us": -1.3671875,
            "cable_delays": [
              {
                "cable_type": "RG6",
                "velocity_factor": 0.85,
                "propagation_speed_m_s": 254823589.29999998,
                "delay_us": -1.3671875,
                "one_way_length_m": -348.3916259960937,
                "one_way_length_ft": -1143.0171456564753,
                "echo_length_m": -174.19581299804685,
                "echo_length_ft": -571.5085728282377
              },
              {
                "cable_type": "RG59",
                "velocity_factor": 0.82,
                "propagation_speed_m_s": 245829815.55999997,
                "delay_us": -1.3671875,
                "one_way_length_m": -336.09545096093746,
                "one_way_length_ft": -1102.6753640450702,
                "echo_length_m": -168.04772548046873,
                "echo_length_ft": -551.3376820225351
              },
              {
                "cable_type": "RG11",
                "velocity_factor": 0.87,
                "propagation_speed_m_s": 260819438.46,
                "delay_us": -1.3671875,
                "one_way_length_m": -356.58907601953126,
                "one_way_length_ft": -1169.9116667307455,
                "echo_length_m": -178.29453800976563,
                "echo_length_ft": -584.9558333653728
              }
            ]
          }
          /* ... taps elided ... */
        ]
      }
    }
    /* ... other upstream channel indices elided ... */
  }
}
```

## Container Keys

| Key (top-level under `data`) | Type   | Description                                                       |
| ---------------------------- | ------ | ----------------------------------------------------------------- |
| `"4"`, `"80"`, …             | string | **SNMP table index** for the upstream channel row (OID instance). |

## Channel-Level Fields

| Field               | Type    | Description                                                 |
| ------------------- | ------- | ----------------------------------------------------------- |
| `main_tap_location` | integer | Location of the main tap (typically near the filter center) |
| `taps_per_symbol`   | integer | Taps per symbol from the pre-EQ header                      |
| `num_taps`          | integer | Total number of taps                                        |
| `reserved`          | integer | Reserved header byte                                        |
| `header_hex`        | string  | Header bytes in hex                                         |
| `payload_hex`       | string  | Full payload hex                                            |
| `payload_preview_hex` | string | Header plus a preview window of taps in hex                 |
| `taps`              | array   | Complex tap coefficients (real/imag pairs)                  |
| `metrics`           | object  | ATDMA pre-equalization key metrics when available           |
| `group_delay`       | object  | Group delay results when channel bandwidth is available     |
| `tap_delay_summary` | object  | Tap delay annotations and cable-length estimates            |

## Coefficient Object Fields

| Field                | Type  | Units | Description                          |
| -------------------- | ----- | ----- | ------------------------------------ |
| `real`               | int   | —     | Real part of the complex coefficient |
| `imag`               | int   | —     | Imaginary part of the coefficient    |
| `magnitude`          | float | —     | Magnitude of the complex tap         |
| `magnitude_power_dB` | float | dB    | Power of the tap in dB               |
| `real_hex`           | string | —    | Raw 2-byte real coefficient (hex)    |
| `imag_hex`           | string | —    | Raw 2-byte imag coefficient (hex)    |

## Metrics Object Fields

| Field                              | Type   | Units | Description                                                |
| ---------------------------------- | ------ | ----- | ---------------------------------------------------------- |
| `main_tap_energy`                  | float  | —     | Main tap energy (MTE).                                     |
| `main_tap_nominal_energy`          | float  | —     | Main tap nominal energy (MTNE).                            |
| `pre_main_tap_energy`              | float  | —     | Pre-main tap energy (PreMTE).                              |
| `post_main_tap_energy`             | float  | —     | Post-main tap energy (PostMTE).                            |
| `total_tap_energy`                 | float  | —     | Total tap energy (TTE).                                    |
| `main_tap_compression`             | float  | dB    | Main tap compression (MTC).                                |
| `main_tap_ratio`                   | float  | dB    | Main tap ratio (MTR).                                      |
| `non_main_tap_energy_ratio`        | float  | dB    | Non-main tap to total energy ratio (NMTER).                |
| `pre_main_tap_total_energy_ratio`  | float  | dB    | Pre-main tap to total energy ratio (PreMTTER).             |
| `post_main_tap_total_energy_ratio` | float  | dB    | Post-main tap to total energy ratio (PostMTTER).           |
| `pre_post_energy_symmetry_ratio`   | float  | dB    | Pre-post energy symmetry ratio (PPESR).                    |
| `pre_post_tap_symmetry_ratio`      | float  | dB    | Pre-post tap symmetry ratio (PPTSR).                       |
| `frequency_response`               | object | —     | Frequency response derived from tap coefficients.          |

## Frequency Response Object Fields

| Field                         | Type  | Units | Description                                               |
| ----------------------------- | ----- | ----- | --------------------------------------------------------- |
| `fft_size`                    | int   | —     | FFT size used to compute the frequency response.          |
| `frequency_bins`              | array | —     | Normalized frequency bins (0 to 1).                       |
| `magnitude`                   | array | —     | Magnitude response for each frequency bin.                |
| `magnitude_power_db`          | array | dB    | Magnitude power in dB for each bin.                       |
| `magnitude_power_db_normalized` | array | dB  | Magnitude power normalized to DC (bin 0).                 |
| `phase_radians`               | array | rad   | Phase response in radians for each frequency bin.         |

## Group Delay Object Fields

| Field             | Type  | Units | Description                                              |
| ----------------- | ----- | ----- | -------------------------------------------------------- |
| `channel_width_hz` | int  | Hz    | Upstream channel width.                                  |
| `rolloff`         | float | —     | DOCSIS roll-off factor used for symbol rate.             |
| `taps_per_symbol` | int   | —     | Taps per symbol from the pre-EQ header.                  |
| `symbol_rate`     | float | sym/s | Symbol rate derived from channel width and roll-off.     |
| `symbol_time_us`  | float | us    | Symbol time in microseconds.                             |
| `sample_period_us` | float | us   | Tap sample period in microseconds.                       |
| `fft_size`        | int   | —     | FFT size used to compute group delay.                    |
| `delay_samples`   | array | —     | Group delay expressed in tap-sample units.               |
| `delay_us`        | array | us    | Group delay expressed in microseconds.                   |

## Tap Delay Summary Object Fields

| Field                 | Type   | Units | Description                                              |
| --------------------- | ------ | ----- | -------------------------------------------------------- |
| `symbol_rate`         | float  | sym/s | Symbol rate used for tap delay mapping.                  |
| `taps_per_symbol`     | int    | —     | Taps per symbol from the pre-EQ header.                  |
| `symbol_time_us`      | float  | us    | Symbol time in microseconds.                             |
| `sample_period_us`    | float  | us    | Tap sample period in microseconds.                       |
| `main_tap_index`      | int    | —     | Main tap index (0-based).                                |
| `main_echo_tap_index` | int    | —     | Strongest post-main tap index when present.              |
| `main_echo_tap_offset` | int   | —     | Offset from main tap for the main echo tap.              |
| `main_echo_magnitude` | float | —     | Magnitude of the main echo tap.                          |
| `taps`                | array | —     | Annotated taps with delay and cable-length estimates.    |

## Tap Delay Entry Fields

| Field             | Type  | Units | Description                                              |
| ----------------- | ----- | ----- | -------------------------------------------------------- |
| `tap_index`       | int   | —     | Tap index in the coefficient array (0-based).            |
| `tap_offset`      | int   | —     | Offset from the main tap (0 is main tap).                |
| `is_main_tap`     | bool  | —     | True when the tap is the main tap.                       |
| `real`            | int   | —     | Tap real component.                                      |
| `imag`            | int   | —     | Tap imaginary component.                                 |
| `magnitude`       | float | —     | Magnitude of the complex tap.                            |
| `magnitude_power_db` | float | dB  | Tap power in dB; null when magnitude is 0.               |
| `delay_samples`   | float | —     | Tap delay relative to the main tap in tap-samples.       |
| `delay_us`        | float | us    | Tap delay relative to the main tap in microseconds.      |
| `cable_delays`    | array | —     | Cable-length equivalents for the tap delay.              |

## Cable Delay Entry Fields

| Field                   | Type  | Units | Description                                              |
| ----------------------- | ----- | ----- | -------------------------------------------------------- |
| `cable_type`            | string | —    | Cable type name (velocity-factor class).                 |
| `velocity_factor`       | float | —     | Velocity factor (fraction of speed of light).            |
| `propagation_speed_m_s` | float | m/s   | Propagation speed for the cable type.                    |
| `delay_us`              | float | us    | Tap delay relative to the main tap in microseconds.      |
| `one_way_length_m`      | float | m     | One-way length equivalent for the tap delay.             |
| `one_way_length_ft`     | float | ft    | One-way length equivalent for the tap delay.             |
| `echo_length_m`         | float | m     | Echo-path length equivalent (round-trip assumed).        |
| `echo_length_ft`        | float | ft    | Echo-path length equivalent (round-trip assumed).        |

## Notes

* Each top-level key under `data` is the DOCSIS **SNMP index** for an upstream SC-QAM (ATDMA) channel.
* Group delay is included only when the upstream channel bandwidth is available.
* Use tap shapes and main-tap offset to infer echo path delay and alignment health.
* Tap coefficients are signed integers; convert to floating-point as needed for analysis.
