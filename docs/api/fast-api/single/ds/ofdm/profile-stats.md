# DOCSIS 3.1 Downstream OFDM Modulation Profile Statistics

Retrieves per-profile statistics from DOCSIS 3.1 downstream OFDM channels (codewords, frames, octets).

## Profiles

Maximum number of **data profiles**: 4 (active at a time). Profile IDs may be any value except `255`, which is reserved for NCP.

| Profile ID | Function     | Notes                                                       |
|------------|--------------|-------------------------------------------------------------|
| 0          | Data + MAC   | Used for user data **and** DOCSIS MAC management messages.  |
| 1-254      | Data profile | Up to **4** data profiles total (including profile 0).      |
| 255        | NCP          | Always present (Next Codeword Pointer / NCP).               |

## Endpoint

**POST** `/docs/if31/ds/ofdm/profile/stats`

Returns per-profile totals (total/corrected/uncorrectable codewords), frame counts, and octet counters per active OFDM channel.

## Request

Use the SNMP-only format: [Common → Request](../../../common/request.md)  
TFTP parameters are not required.

## Response

This endpoint returns the standard envelope described in [Common → Response](../../../common/response.md) (`status`, `message`, `device`, `data`).

`device` is the top-level device identity block and contains `device.mac_address` and `device.system_description` (empty model when unavailable).  
On success, `data` is an array of OFDM channels with per-profile counters.

### Abbreviated example

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": 0,
  "message": null,
  "data": [
    {
      "index": 48,
      "channel_id": 197,
      "profiles": {
        "0": {
          "docsIf31CmDsOfdmProfileStatsConfigChangeCt": 0,
          "docsIf31CmDsOfdmProfileStatsTotalCodewords": 1438502285,
          "docsIf31CmDsOfdmProfileStatsCorrectedCodewords": 2395,
          "docsIf31CmDsOfdmProfileStatsUncorrectableCodewords": 0,
          "docsIf31CmDsOfdmProfileStatsInOctets": 501779131,
          "docsIf31CmDsOfdmProfileStatsInUnicastOctets": 1397,
          "docsIf31CmDsOfdmProfileStatsInMulticastOctets": 454736066,
          "docsIf31CmDsOfdmProfileStatsInFrames": 7840278,
          "docsIf31CmDsOfdmProfileStatsInUnicastFrames": 1,
          "docsIf31CmDsOfdmProfileStatsInMulticastFrames": 7840277,
          "docsIf31CmDsOfdmProfileStatsInFrameCrcFailures": 0,
          "docsIf31CmDsOfdmProfileStatsCtrDiscontinuityTime": 0
        },
        "1":   { "...": "elided" },
        "2":   { "...": "elided" },
        "3":   { "...": "elided" },
        "255": { "...": "elided" }
      }
    },
    { "...": "other channels elided" }
  ]
}
```

## Channel fields

| Field        | Type | Description                                                                 |
|--------------|------|-----------------------------------------------------------------------------|
| `index`      | int  | **SNMP table index** (OID instance) for this channel’s row in the CM table. |
| `channel_id` | int  | DOCSIS downstream OFDM channel ID (as reported by the CM/CMTS).             |

## Per-profile fields

| Field                                                | Type | Description                            |
| ---------------------------------------------------- | ---- | -------------------------------------- |
| `docsIf31CmDsOfdmProfileStatsTotalCodewords`         | int  | Total number of codewords received.    |
| `docsIf31CmDsOfdmProfileStatsCorrectedCodewords`     | int  | Codewords corrected via FEC.           |
| `docsIf31CmDsOfdmProfileStatsUncorrectableCodewords` | int  | Codewords that could not be corrected. |
| `docsIf31CmDsOfdmProfileStatsInOctets`               | int  | Total bytes received for this profile. |
| `docsIf31CmDsOfdmProfileStatsInUnicastOctets`        | int  | Bytes from unicast sources.            |
| `docsIf31CmDsOfdmProfileStatsInMulticastOctets`      | int  | Bytes from multicast sources.          |
| `docsIf31CmDsOfdmProfileStatsInFrames`               | int  | Number of data frames received.        |
| `docsIf31CmDsOfdmProfileStatsInUnicastFrames`        | int  | Count of unicast frames.               |
| `docsIf31CmDsOfdmProfileStatsInMulticastFrames`      | int  | Count of multicast frames.             |
| `docsIf31CmDsOfdmProfileStatsInFrameCrcFailures`     | int  | Number of CRC-failed frames.           |
| `docsIf31CmDsOfdmProfileStatsConfigChangeCt`         | int  | Configuration change counter.          |
| `docsIf31CmDsOfdmProfileStatsCtrDiscontinuityTime`   | int  | Counter discontinuity indicator.       |

## Notes

* See [Common → Response](../../../common/response.md) for envelope semantics and status handling.
* Use this endpoint to assess profile utilization, FEC correction rates, and traffic segmentation across profiles.
