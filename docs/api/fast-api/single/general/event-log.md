# DOCSIS Device Event Log

Provides Access To A Cable Modem’s Device Event Log For Operational And Troubleshooting Insight (Ranging, T3/T4, Profile Changes, CM-Status).

## Endpoint

**POST** `/docs/dev/eventLog`

## Request

Use the SNMP-only format: [Common → Request](../../common/request.md)
TFTP parameters are not required.

## Response

This endpoint returns the standard envelope described in [Common → Response](../../common/response.md) (`status`, `message`, `device`, `data`).

`device` is the top-level device identity block and contains `device.mac_address` and `device.system_description` (empty model when unavailable).

`data.logs` is an array of log entries reported by the device.

### Abbreviated Example

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": 0,
  "message": null,
  "data": {
    "logs": [
      {
        "docsDevEvFirstTime": "2025-10-19T18:39:24",
        "docsDevEvLastTime": "2025-10-19T18:39:24",
        "docsDevEvCounts": 1,
        "docsDevEvLevel": 6,
        "docsDevEvId": 67061601,
        "docsDevEvText": "US profile assignment change.  US Chan ID: 42; Previous Profile: 12; New Profile: 11.;CM-MAC=aa:bb:cc:dd:ee:ff;CMTS-MAC=aa:bb:cc:dd:ee:ff;CM-QOS=1.1;CM-VER=4.0;"
      },
      {
        "docsDevEvFirstTime": "2025-10-19T18:40:09",
        "docsDevEvLastTime": "2025-10-19T18:40:09",
        "docsDevEvCounts": 3,
        "docsDevEvLevel": 6,
        "docsDevEvId": 74010100,
        "docsDevEvText": "CM-STATUS message sent.  Event Type Code: 5; Chan ID: 13; DSID: N/A; MAC Addr: N/A; OFDM/OFDMA Profile ID: N/A.;CM-MAC=aa:bb:cc:dd:ee:ff;CMTS-MAC=aa:bb:cc:dd:ee:ff;CM-QOS=1.1;CM-VER=4.0;"
      },
      {
        "docsDevEvFirstTime": "2025-10-19T18:41:24",
        "docsDevEvLastTime": "2025-10-19T18:49:14",
        "docsDevEvCounts": 35,
        "docsDevEvLevel": 6,
        "docsDevEvId": 74010100,
        "docsDevEvText": "CM-STATUS message sent.  Event Type Code: 5; Chan ID: 13; DSID: N/A; MAC Addr: N/A; OFDM/OFDMA Profile ID: N/A.;CM-MAC=aa:bb:cc:dd:ee:ff;CMTS-MAC=aa:bb:cc:dd:ee:ff;CM-QOS=1.1;CM-VER=4.0;"
      },
      { "...": "additional log entries elided" }
    ]
  }
}
```

## Response Field Details

| Field                | Type   | Description                                                                            |
| -------------------- | ------ | -------------------------------------------------------------------------------------- |
| `mac_address`        | string | MAC address of the cable modem returned in the common envelope.                        |
| `status`             | int    | Operation status (`0` = success; non-zero indicates failure).                          |
| `message`            | string | Human-readable status or error message (nullable).                                     |
| `data.logs`          | array  | Array of device log entry objects.                                                     |
| `docsDevEvFirstTime` | string | First occurrence of the event (ISO-8601 timestamp).                                    |
| `docsDevEvLastTime`  | string | Most recent occurrence of the event (ISO-8601 timestamp).                              |
| `docsDevEvCounts`    | int    | Number of times the event has occurred.                                                |
| `docsDevEvLevel`     | int    | Syslog-style severity (`0`=Emergency, `1`=Alert, …, `7`=Debug; lower = more critical). |
| `docsDevEvId`        | int    | Numeric event identifier.                                                              |
| `docsDevEvText`      | string | Human-readable message; often includes CM/CMTS MACs, profiles, versions.               |

## Common Event Codes

| Event ID | Description                             |
| -------- | --------------------------------------- |
| 67061601 | US profile assignment change.           |
| 74010100 | CM-STATUS message sent.                 |
| 74010200 | Ranging request sent.                   |
| 74010300 | Ranging response received.              |
| 74020100 | T3 timeout occurred.                    |
| 74020200 | T4 timeout occurred.                    |
| 74030100 | Upstream channel change completed.      |
| 74030200 | Downstream channel change completed.    |
| 74040100 | Ranging success.                        |
| 74040200 | Ranging failure.                        |
| 74040300 | Ranging aborted.                        |
| 74050100 | Power adjustment performed.             |
| 74060100 | Cable modem reset (power cycle).        |
| 74060200 | Firmware download initiated.            |
| 74060300 | Firmware download completed.            |

## CM STATUS

| Event Type Code | Description                                                                                              |
| --------------- | -------------------------------------------------------------------------------------------------------- |
| 0               | Reserved (no use)                                                                                        |
| 1               | Secondary Channel MDD Timeout (the MDD timer on a secondary channel expired)                             |
| 2               | QAM / FEC Lock Failure (loss of QAM or Forward Error Correction lock on downstream)                      |
| 3               | Sequence Out-of-Range (a packet sequence number was out of the expected range)                           |
| 4               | Secondary Channel MDD Recovery (receipt of MDD on a secondary channel)                                   |
| 5               | QAM / FEC Lock Recovery (channel regained lock)                                                          |
| 6               | T4 Timeout (station maintenance / broadcast failure)                                                     |
| 7               | T3 Retries Exceeded (ranging retries maximum exceeded)                                                   |
| 8               | Successful Ranging After T3 Retries Exceeded (ranging recovery)                                          |
| 9               | CM Operating on Battery Backup (loss of A/C power for > 5 seconds)                                       |
| 10              | CM Returned to A/C Power (came back from battery to A/C)                                                 |
| 11              | MAC Removal Event (one or more MAC addresses removed, e.g., in port transition)                          |
| 12-15           | Reserved for future use                                                                                  |
| 16              | DS OFDM Profile Failure (FEC errors exceeded limit on a downstream OFDM profile)                         |
| 17              | Primary Downstream Change (lost primary downstream, switched to backup)                                  |
| 18              | DPD Mismatch (Some mismatch in DPD change count vs NCP odd/even bit)                                     |
| 20              | NCP Profile Failure (FEC errors exceeded limit on NCP profile)                                           |
| 21              | PLC Failure (FEC errors exceeded on PLC)                                                                 |
| 22              | NCP Profile Recovery (FEC recovered on NCP)                                                              |
| 23              | PLC Recovery (FEC recovery on PLC channel)                                                               |
| 24              | OFDM Profile Recovery (FEC recovery on OFDM profile)                                                     |
| 25              | OFDMA Profile Failure (modem unable to support a received profile)                                       |
| 26              | MAP Storage Overflow (maps in CM overflow buffer)                                                        |
| 27              | MAP Storage Almost Full                                                                                  |
| 28-255          | Reserved / for vendor extensions                                                                         |

## Notes

* Event levels follow syslog conventions: **0 (Emergency)** … **7 (Debug)**.
* Entries are semi-structured; downstream analytics may parse `docsDevEvText` for fields like channel IDs, profiles, and MACs.
* Devices may cap or rotate stored logs; poll and archive if long-term history is required.
