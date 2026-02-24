# DOCSIS 4.0 FDD Diplexer Configuration

Retrieves The Currently Configured Diplexer Band-Edge Frequencies On A DOCSIS 4.0 Cable Modem.

## Endpoint

**POST** `/docs/fdd/system/diplexer/configuration`

## Request

Use the SNMP-only format: [Common → Request](../../common/request.md)
TFTP parameters are not required.

## Response

This endpoint returns the standard envelope described in [Common → Response](../../common/response.md) (`status`, `message`, `device`, `data`).

`device` is the top-level device identity block and contains `device.mac_address` and `device.system_description` (empty model when unavailable).

`data` is an **object** with the SNMP `index` and an `entry` containing the configured band-edge frequencies (MHz).

### Abbreviated Example

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": 0,
  "message": null,
  "data": {
    "index": 0,
    "entry": {
      "docsFddCmFddSystemCfgStateDiplexerDsLowerBandEdgeCfg": 258,
      "docsFddCmFddSystemCfgStateDiplexerDsUpperBandEdgeCfg": 1794,
      "docsFddCmFddSystemCfgStateDiplexerUsUpperBandEdgeCfg": 204
    }
  }
}
```

## Response Fields

| Field                                                             | Type       | Units | Description                                           |
| ----------------------------------------------------------------- | ---------- | ----- | ----------------------------------------------------- |
| `mac_address`                                                     | string     | —     | MAC address of the queried device.                    |
| `status`                                                          | int        | —     | Operation status (`0` = success; non-zero = failure). |
| `message`                                                         | string     | —     | Optional result message.                              |
| `data.index`                                                      | int        | —     | SNMP table index for the configuration row.           |
| `data.entry.docsFddCmFddSystemCfgStateDiplexerDsLowerBandEdgeCfg` | Unsigned32 | MHz   | Downstream **lower** band edge (TLV 5.79).            |
| `data.entry.docsFddCmFddSystemCfgStateDiplexerDsUpperBandEdgeCfg` | Unsigned32 | MHz   | Downstream **upper** band edge (TLV 5.80).            |
| `data.entry.docsFddCmFddSystemCfgStateDiplexerUsUpperBandEdgeCfg` | Unsigned32 | MHz   | Upstream **upper** band edge (TLV 5.81).              |

## Notes

* A value of `0` for any band edge indicates the CM is **not** configured for extended-spectrum operation.
* These settings reflect the CM’s active operating split and are read-only (advertised during registration).
