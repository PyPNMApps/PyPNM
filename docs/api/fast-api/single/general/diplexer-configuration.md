# DOCSIS 3.1 System Diplexer

Provides Insight Into The Diplexer Configuration Of A DOCSIS 3.1 Cable Modem (Upstream/Downstream Band Splits, Capabilities, And Configured Band Edges). Use This To Audit Band Plans And Validate Mid-Split/High-Split Compatibility.

## Endpoint

**POST** `/docs/if31/system/diplexer`

## Request

Use the SNMP-only format: [Common → Request](../../common/request.md)
TFTP parameters are not required.

## Response

This endpoint returns the standard envelope described in [Common → Response](../../common/response.md) (`status`, `message`, `device`, `data`).

`device` is the top-level device identity block and contains `device.mac_address` and `device.system_description` (empty model when unavailable).

### Abbreviated Example

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": 0,
  "message": null,
  "data": {
    "diplexer": {
      "diplexer_capability": 28,
      "cfg_band_edge": 204000000,
      "ds_lower_capability": 3,
      "cfg_ds_lower_band_edge": 258000000,
      "ds_upper_capability": 2,
      "cfg_ds_upper_band_edge": 1794000000
    }
  }
}
```

## Diplexer Fields

| Field                    | Type | Units | Description                                   |
| ------------------------ | ---- | ----- | --------------------------------------------- |
| `diplexer_capability`    | int  | —     | Upstream/Downstream diplexer capability code. |
| `cfg_band_edge`          | int  | Hz    | Configured **upstream** band edge frequency.  |
| `ds_lower_capability`    | int  | —     | Downstream lower frequency capability code.   |
| `cfg_ds_lower_band_edge` | int  | Hz    | Configured **downstream** lower band edge.    |
| `ds_upper_capability`    | int  | —     | Downstream upper frequency capability code.   |
| `cfg_ds_upper_band_edge` | int  | Hz    | Configured **downstream** upper band edge.    |

## Notes

* Values are reported in Hertz (Hz).
* Capability codes are device/implementation specific (per CableLabs/vendor definitions).
* Compare configured edges with plant split (e.g., 85 MHz mid-split, 204 MHz high-split) to verify alignment.
