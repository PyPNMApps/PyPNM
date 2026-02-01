# DOCSIS 3.0 Downstream SC-QAM Channel Statistics

Provides DOCSIS 3.0 Downstream SC-QAM Channel Configuration And Signal-Quality Metrics (Power, RxMER, Codeword Counters).

## Endpoint

**POST** `/docs/if30/ds/scqam/chan/stats`

## Request

Use the SNMP-only format: [Common → Request](../../../common/request.md)  
TFTP parameters are not required.

## Response

This endpoint returns the standard envelope described in [Common → Response](../../../common/response.md) (`mac_address`, `status`, `message`, `data`).

### Abbreviated Example

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": 0,
  "message": null,
  "data": [
    {
      "index": 52,
      "channel_id": 32,
      "entry": {
        "docsIfDownChannelId": 32,
        "docsIfDownChannelFrequency": 639000000,
        "docsIfDownChannelWidth": 6000000,
        "docsIfDownChannelModulation": "qam256",
        "docsIfDownChannelInterleave": "taps32Increment4",
        "docsIfDownChannelPower": 1.1,
        "docsIfSigQUnerroreds": 260152637,
        "docsIfSigQCorrecteds": 351,
        "docsIfSigQUncorrectables": 0,
        "docsIfSigQMicroreflections": 3,
        "docsIfSigQExtUnerroreds": 129109307889,
        "docsIfSigQExtCorrecteds": 351,
        "docsIfSigQExtUncorrectables": 0,
        "docsIf3SignalQualityExtRxMER": 403
      }
    },
    {
      "index": 53,
      "channel_id": 31,
      "entry": {
        "docsIfDownChannelId": 31,
        "docsIfDownChannelFrequency": 633000000,
        "docsIfDownChannelWidth": 6000000,
        "docsIfDownChannelModulation": "qam256",
        "docsIfDownChannelInterleave": "taps32Increment4",
        "docsIfDownChannelPower": 0.8,
        "docsIfSigQUnerroreds": 89334852,
        "docsIfSigQCorrecteds": 460,
        "docsIfSigQUncorrectables": 0,
        "docsIfSigQMicroreflections": 3,
        "docsIfSigQExtUnerroreds": 128938490104,
        "docsIfSigQExtCorrecteds": 460,
        "docsIfSigQExtUncorrectables": 0,
        "docsIf3SignalQualityExtRxMER": 409
      }
    },
    { "...": "other channels elided" }
  ]
}
```

## Channel Fields

| Field        | Type | Description                                                                 |
| ------------ | ---- | --------------------------------------------------------------------------- |
| `index`      | int  | **SNMP table index** (OID instance) for this channel’s row in the CM table. |
| `channel_id` | int  | DOCSIS downstream SC-QAM logical channel ID.                                |

## Entry Fields

| Field                          | Type  | Units  | Description                                                  |
| ------------------------------ | ----- | ------ | ------------------------------------------------------------ |
| `docsIfDownChannelId`          | int   | —      | Channel ID (mirrors logical ID).                             |
| `docsIfDownChannelFrequency`   | int   | Hz     | Center frequency.                                            |
| `docsIfDownChannelWidth`       | int   | Hz     | Channel width.                                               |
| `docsIfDownChannelModulation`  | string | —      | Modulation name (e.g., `qam256`).                           |
| `docsIfDownChannelInterleave`  | string | —      | Interleaver mode name (e.g., `taps32Increment4`).            |
| `docsIfDownChannelPower`       | float | dBmV   | Received RF power level.                                     |
| `docsIfSigQUnerroreds`         | int   | cw     | Unerrored codewords (base counter).                          |
| `docsIfSigQCorrecteds`         | int   | cw     | Corrected codewords (base counter).                          |
| `docsIfSigQUncorrectables`     | int   | cw     | Uncorrectable codewords (base counter).                      |
| `docsIfSigQMicroreflections`   | int   | —      | Micro-reflections indicator (implementation-specific scale). |
| `docsIfSigQExtUnerroreds`      | int64 | cw     | Unerrored codewords (extended 64-bit), if supported.         |
| `docsIfSigQExtCorrecteds`      | int64 | cw     | Corrected codewords (extended 64-bit), if supported.         |
| `docsIfSigQExtUncorrectables`  | int64 | cw     | Uncorrectable codewords (extended 64-bit), if supported.     |
| `docsIf3SignalQualityExtRxMER` | int   | 0.1 dB | RxMER in tenths of dB (e.g., `403` → 40.3 dB).               |

## Notes

* `docsIfDownChannelModulation` is normalized to a modulation name (e.g., `qam256`).
* Prefer extended (64-bit) counters when available to avoid rollover on high-traffic channels.
* Metrics such as RxMER, Uncorrectables, And Micro-Reflections Are Critical For Diagnosing RF Impairments.
* `docsIfDownChannelInterleave` is normalized to an interleaver mode name.
