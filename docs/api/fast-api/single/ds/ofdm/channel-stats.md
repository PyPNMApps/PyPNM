# DOCSIS 3.1 Downstream OFDM Channel Statistics

Fetches Downstream OFDM Channel Configuration And Performance Data From A DOCSIS 3.1 Cable Modem Using SNMP.

## Endpoint

**POST** `/docs/if31/ds/ofdm/channel/stats`

## Request

Use the SNMP-only format: [Common → Request](../../../common/request.md)
TFTP parameters are not required.

## Response

This endpoint returns the standard envelope described in [Common → Response](../../../common/response.md) (`mac_address`, `status`, `message`, `data`).

`data` is an **array** of downstream OFDM channels. Each item contains the SNMP table `index`, the `channel_id`, and an `entry` with DS-OFDM configuration and statistics.

### Abbreviated Example

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": 0,
  "message": null,
  "data": [
    {
      "index": 48,
      "channel_id": 34,
      "entry": {
        "docsIf31CmDsOfdmChanChanIndicator": "nonPrimary",
        "docsIf31CmDsOfdmChanSubcarrierZeroFreq": 847100000,
        "docsIf31CmDsOfdmChanFirstActiveSubcarrierNum": 1238,
        "docsIf31CmDsOfdmChanLastActiveSubcarrierNum": 2857,
        "docsIf31CmDsOfdmChanNumActiveSubcarriers": 1583,
        "docsIf31CmDsOfdmChanSubcarrierSpacing": 50,
        "docsIf31CmDsOfdmChanCyclicPrefix": 512,
        "docsIf31CmDsOfdmChanRollOffPeriod": 256,
        "docsIf31CmDsOfdmChanPlcFreq": 954000000,
        "docsIf31CmDsOfdmChanNumPilots": 29,
        "docsIf31CmDsOfdmChanTimeInterleaverDepth": 16,
        "docsIf31CmDsOfdmChanPlcTotalCodewords": 264684790,
        "docsIf31CmDsOfdmChanPlcUnreliableCodewords": 0,
        "docsIf31CmDsOfdmChanNcpTotalFields": 3387947050,
        "docsIf31CmDsOfdmChanNcpFieldCrcFailures": 0
      }
    },
    {
      "index": 49,
      "channel_id": 33,
      "entry": {
        "docsIf31CmDsOfdmChanChanIndicator": "nonPrimary",
        "docsIf31CmDsOfdmChanSubcarrierZeroFreq": 758600000,
        "docsIf31CmDsOfdmChanFirstActiveSubcarrierNum": 1148,
        "docsIf31CmDsOfdmChanLastActiveSubcarrierNum": 2947,
        "docsIf31CmDsOfdmChanNumActiveSubcarriers": 1761,
        "docsIf31CmDsOfdmChanSubcarrierSpacing": 50,
        "docsIf31CmDsOfdmChanCyclicPrefix": 512,
        "docsIf31CmDsOfdmChanRollOffPeriod": 256,
        "docsIf31CmDsOfdmChanPlcFreq": 861000000,
        "docsIf31CmDsOfdmChanNumPilots": 31,
        "docsIf31CmDsOfdmChanTimeInterleaverDepth": 16,
        "docsIf31CmDsOfdmChanPlcTotalCodewords": 264688869,
        "docsIf31CmDsOfdmChanPlcUnreliableCodewords": 0,
        "docsIf31CmDsOfdmChanNcpTotalFields": 3387999936,
        "docsIf31CmDsOfdmChanNcpFieldCrcFailures": 0
      }
    }
  ]
}
```

## Channel Fields

| Field        | Type | Description                                                                            |
| ------------ | ---- | -------------------------------------------------------------------------------------- |
| `index`      | int  | **SNMP table index** (OID instance) for this channel’s row in the CM table.            |
| `channel_id` | int  | DOCSIS downstream OFDM logical channel ID.                                             |
| `entry`      | obj  | DS-OFDM configuration and counters for the channel (see next table for field details). |

## Entry Fields

| Field                                          | Type | Units | Description                                                      |
| ---------------------------------------------- | ---- | ----- | ---------------------------------------------------------------- |
| `docsIf31CmDsOfdmChanChanIndicator`            | string | —   | Channel indicator (e.g., `primary`, `backupPrimary`, `nonPrimary`). |
| `docsIf31CmDsOfdmChanSubcarrierZeroFreq`       | int  | Hz    | Frequency of subcarrier **0**.                                   |
| `docsIf31CmDsOfdmChanFirstActiveSubcarrierNum` | int  | —     | Index of the first active subcarrier.                            |
| `docsIf31CmDsOfdmChanLastActiveSubcarrierNum`  | int  | —     | Index of the last active subcarrier.                             |
| `docsIf31CmDsOfdmChanNumActiveSubcarriers`     | int  | —     | Count of active subcarriers.                                     |
| `docsIf31CmDsOfdmChanSubcarrierSpacing`        | int  | kHz   | Subcarrier spacing (typical downstream values are 25 or 50 kHz). |
| `docsIf31CmDsOfdmChanCyclicPrefix`             | int  | samp  | Cyclic prefix length in samples.                                 |
| `docsIf31CmDsOfdmChanRollOffPeriod`            | int  | samp  | Roll-off (guard) period in samples.                              |
| `docsIf31CmDsOfdmChanPlcFreq`                  | int  | Hz    | PLC (Physical Link Channel) center frequency.                    |
| `docsIf31CmDsOfdmChanNumPilots`                | int  | —     | Number of pilot subcarriers.                                     |
| `docsIf31CmDsOfdmChanTimeInterleaverDepth`     | int  | sym   | Time interleaver depth in OFDM symbols.                          |
| `docsIf31CmDsOfdmChanPlcTotalCodewords`        | int  | —     | Total PLC codewords received.                                    |
| `docsIf31CmDsOfdmChanPlcUnreliableCodewords`   | int  | —     | PLC codewords flagged as unreliable.                             |
| `docsIf31CmDsOfdmChanNcpTotalFields`           | int  | —     | Total NCP (Next Codeword Pointer) fields received.               |
| `docsIf31CmDsOfdmChanNcpFieldCrcFailures`      | int  | —     | NCP fields with CRC failures.                                    |

## Notes

* Useful for visualizing OFDM channel characteristics and error metrics for proactive diagnostics.
* Ensure SNMP access to the modem’s `ip_address` from your collection host.
* Field names align with `DOCSIS-IF3-MIB` DS-OFDM channel objects.
