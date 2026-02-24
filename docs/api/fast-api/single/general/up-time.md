# DOCSIS System Uptime

Retrieves The Current System Uptime Of A DOCSIS Cable Modem Using SNMP.

## Endpoint

**POST** `/system/upTime`

## Request

Use the SNMP-only format: [Common → Request](../../common/request.md)
TFTP parameters are not required.

## Response

This endpoint returns the standard envelope described in [Common → Response](../../common/response.md) (`status`, `message`, `device`, `results`).

`device` is the top-level device identity block and contains `device.mac_address` and `device.system_description` (empty model when unavailable).

### Abbreviated Example

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": 0,
  "message": null,
  "results": {
    "uptime": "0:13:11.180000"
  }
}
```

## Response Field Details

| Field            | Type   | Description                                           |
| ---------------- | ------ | ----------------------------------------------------- |
| `mac_address`    | string | MAC address of the queried device.                    |
| `status`         | int    | Operation status (`0` = success; non-zero = failure). |
| `results`        | object | Envelope payload.                                     |
| `results.uptime` | string | Formatted uptime (`HH:MM:SS.microseconds`).           |

## Notes

* SNMP OID used: `1.3.6.1.2.1.1.3.0` (system uptime in hundredths of a second).
* The service converts the raw counter into a human-readable duration.
* Use uptime trends to detect unexpected reboots or instability.
