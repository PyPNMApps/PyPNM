# DOCSIS 3.0 Downstream SC-QAM Codeword Error Rate

Computes per-channel codeword error statistics for DOCSIS 3.0 downstream SC-QAM channels: uncorrectables, normalized error rates, and codeword throughput over a configurable sampling interval.

## Endpoint

**POST** `/docs/if30/ds/scqam/chan/codewordErrorRate`

## Request

Use the SNMP-only format described in [Common → Request](../../../common/request.md).  
TFTP parameters are not required for this measurement.

### Additional request fields

| JSON path                             | Type   | Default | Description                                                         |
|---------------------------------------|--------|---------|---------------------------------------------------------------------|
| `capture_parameters.sample_time_elapsed` | number | `5`     | Sampling interval in seconds used to compute per-second statistics. |

#### Example

```json
{
  "cable_modem": {
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "ip_address": "192.168.0.100",
    "snmp": {
      "snmpV2C": { "community": "private" }
    }
  },
  "capture_parameters": {
    "sample_time_elapsed": 5
  }
}
```

## Response

This endpoint returns the standard envelope described in [Common → Response](../../../common/response.md) (`status`, `message`, `device`, `data`).

`device` is the top-level device identity block and contains `device.mac_address` and `device.system_description` (empty model when unavailable).

The `data` field is an array of per-channel codeword error summaries for each detected downstream SC-QAM channel.

### Abbreviated example

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": 0,
  "message": "Successfully retrieved codeword error rate",
  "data": [
    {
      "index": 52,
      "channel_id": 32,
      "codeword_totals": {
        "total_codewords": 1290014,
        "total_errors": 0,
        "time_elapsed": 5,
        "error_rate": 0,
        "codewords_per_second": 258002.8,
        "errors_per_second": 0
      }
    },
    {
      "index": 53,
      "channel_id": 31,
      "codeword_totals": {
        "total_codewords": 1290014,
        "total_errors": 0,
        "time_elapsed": 5,
        "error_rate": 0,
        "codewords_per_second": 258002.8,
        "errors_per_second": 0
      }
    },
    { "...": "other channels elided" }
  ]
}
```

### Channel fields

| Field        | Type | Description                                                                 |
|-------------|------|-----------------------------------------------------------------------------|
| `index`     | int  | SNMP table index (OID instance) for this channel row in the CM codeword table. |
| `channel_id`| int  | DOCSIS downstream SC-QAM logical channel ID.                                |

### Codeword total fields

| Field                  | Type   | Description                                                   |
|------------------------|--------|---------------------------------------------------------------|
| `total_codewords`      | int    | Total codewords counted over the sampling interval.           |
| `total_errors`         | int    | Uncorrectable codeword errors over the sampling interval.     |
| `time_elapsed`         | number | Sampling interval used (seconds).                             |
| `error_rate`           | number | Fraction of uncorrectables (`total_errors/total_codewords`).  |
| `codewords_per_second` | number | Normalized codewords per second (s⁻¹).                        |
| `errors_per_second`    | number | Normalized errors per second (s⁻¹).                           |

> Rates use SI unit s⁻¹; multiply `error_rate` by 100 to get a percentage.

## Notes

* Ensure SNMP counters are 64-bit to avoid overflow on high-traffic channels.
* `sample_time_elapsed` defaults to **5 seconds** if omitted; align it with your polling cadence.
* The modem is automatically scanned for all downstream SC-QAM channels—no manual channel list is required.
