# DOCSIS System Description

Retrieves Basic System Identity And Firmware Metadata From A DOCSIS Cable Modem Using SNMP.

## Endpoint

**POST** `/system/sysDescr`

## Request

Use the SNMP-only format: [Common → Request](../../common/request.md)
TFTP parameters are not required.

## Response

This endpoint returns the standard envelope described in [Common → Response](../../common/response.md) (`status`, `message`, `device`, `results`).

`device` is the top-level device identity block and contains `device.mac_address` and `device.system_description` (empty model when unavailable).
`results.sys_descr` contains parsed fields from the device’s `sysDescr`.

### Example

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": 0,
  "message": null,
  "results": {
    "sys_descr": {
      "HW_REV": "1.0",
      "VENDOR": "LANCity",
      "BOOTR": "NONE",
      "SW_REV": "1.0.0",
      "MODEL": "LCPET-3"
    }
  }
}
```

## Response Field Details

| Field                      | Type    | Description                                           |
| -------------------------- | ------- | ----------------------------------------------------- |
| `mac_address`              | string  | MAC address of the queried device.                    |
| `status`                   | int     | Operation status (`0` = success; non-zero = failure). |
| `message`                  | string  | Optional result message.                              |
| `results`                  | object  | Envelope payload.                                     |
| `results.sys_descr`        | object  | Parsed key/value fields from SNMP `sysDescr`.         |
| `results.sys_descr.HW_REV` | string  | Hardware revision reported by the device.             |
| `results.sys_descr.VENDOR` | string  | Manufacturer name parsed from `sysDescr`.             |
| `results.sys_descr.BOOTR`  | string  | Bootloader version string.                            |
| `results.sys_descr.SW_REV` | string  | Software (firmware) version string.                   |
| `results.sys_descr.MODEL`  | string  | Model identifier reported by the device.              |
| `results.is_empty`         | boolean | `true` if parsing failed or response was empty.       |

## Notes

* Data is derived from the SNMP `sysDescr` OID (`1.3.6.1.2.1.1.1.0`) and parsed using known vendor patterns.
* Useful for populating device metadata dashboards or validation checks.
* `is_empty = true` typically means the response could not be parsed into structured fields.
