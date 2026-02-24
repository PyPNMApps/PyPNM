# DOCSIS 4.0 FDD Diplexer Band-Edge Capability

Exposes A Cable Modem’s Supported FDD Diplexer Band Edges For Downstream And Upstream Planning In DOCSIS 4.0.

## Endpoint

**POST** `/docs/fdd/diplexer/bandEdgeCapability`

## Request

Use the SNMP-only format: [Common → Request](../../common/request.md)
TFTP parameters are not required.

## Response

This endpoint returns the standard envelope described in [Common → Response](../../common/response.md) (`status`, `message`, `device`, `data`).

`device` is the top-level device identity block and contains `device.mac_address` and `device.system_description` (empty model when unavailable).

`data` is an **array** of capability sets. Each item contains a capability `index` and an `entry` with the upstream upper, downstream lower, and downstream upper diplexer band-edge frequencies (in MHz).

### Abbreviated Example

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": 0,
  "message": null,
  "data": [
    {
      "index": 1,
      "entry": {
        "docsFddDiplexerUsUpperBandEdgeCapability": 85,
        "docsFddDiplexerDsLowerBandEdgeCapability": 108,
        "docsFddDiplexerDsUpperBandEdgeCapability": 1794
      }
    },
    {
      "index": 2,
      "entry": {
        "docsFddDiplexerUsUpperBandEdgeCapability": 204,
        "docsFddDiplexerDsLowerBandEdgeCapability": 258,
        "docsFddDiplexerDsUpperBandEdgeCapability": 1794
      }
    },
    {
      "index": 3,
      "entry": {
        "docsFddDiplexerUsUpperBandEdgeCapability": 396,
        "docsFddDiplexerDsLowerBandEdgeCapability": 468,
        "docsFddDiplexerDsUpperBandEdgeCapability": 1794
      }
    }
  ]
}
```

## Response Fields

| Field                                                   | Type   | Units | Description                                           |
| ------------------------------------------------------- | ------ | ----- | ----------------------------------------------------- |
| `mac_address`                                           | string | —     | MAC address of the queried device.                    |
| `status`                                                | int    | —     | Operation status (`0` = success; non-zero = failure). |
| `message`                                               | string | —     | Optional result message.                              |
| `data`                                                  | array  | —     | Array of diplexer capability sets.                    |
| `data[].index`                                          | int    | —     | Capability set identifier.                            |
| `data[].entry.docsFddDiplexerUsUpperBandEdgeCapability` | int    | MHz   | Supported upstream **upper** band-edge frequency.     |
| `data[].entry.docsFddDiplexerDsLowerBandEdgeCapability` | int    | MHz   | Supported downstream **lower** band-edge frequency.   |
| `data[].entry.docsFddDiplexerDsUpperBandEdgeCapability` | int    | MHz   | Supported downstream **upper** band-edge frequency.   |

### Response Summary (Example)

| Index | Upstream Upper (MHz) | Downstream Lower (MHz) | Downstream Upper (MHz) |
| ----: | -------------------: | ---------------------: | ---------------------: |
|     1 |                   85 |                    108 |                   1794 |
|     2 |                  204 |                    258 |                   1794 |
|     3 |                  396 |                    468 |                   1794 |

## Notes

* Frequencies are reported in **MHz** and reflect capability (not necessarily the currently configured split).
* A value of `0` indicates the device does **not** advertise extended spectrum for that band edge.
* Use this data to validate modem-CMTS spectrum compatibility when planning FDD profiles and extended splits.
