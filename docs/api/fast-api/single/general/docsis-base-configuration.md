# DOCSIS Base Capability

Provides Insight Into The DOCSIS Radio Frequency (RF) Specification Version Supported By A Cable Modem (CM) Or Cable Modem Termination System (CMTS). Based On `docsIf31DocsisBaseCapability` (DOCSIS-IF3-MIB).

## Endpoint

**POST** `/docs/if31/docsis/baseCapability`

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
  "message": "DOCSIS Base Capability Retrieved Successfully.",
  "data": {
    "docsis_version": "DOCSIS_40",
    "clabs_docsis_version": 6
  }
}
```

## Field Definitions

| Field                       | Type   | Description                                                                  |
| --------------------------- | ------ | ---------------------------------------------------------------------------- |
| `mac_address`               | string | Target CM MAC Address Returned In The Common Envelope.                       |
| `status`                    | int    | Status Code (`0` = Success).                                                 |
| `message`                   | string | Human-Readable Result Message.                                               |
| `data.docsis_version`       | string | DOCSIS Version As Enum String (e.g., `DOCSIS_10`, `DOCSIS_31`, `DOCSIS_40`). |
| `data.clabs_docsis_version` | int    | Integer Value From `ClabsDocsisVersion` (`0`=other, `1`=1.0, …, `6`=4.0).    |

### Reference: `ClabsDocsisVersion`

```json
ClabsDocsisVersion ::= TEXTUAL-CONVENTION
    SYNTAX INTEGER {
        other (0),
        docsis10 (1),
        docsis11 (2),
        docsis20 (3),
        docsis30 (4),
        docsis31 (5),
        docsis40 (6)
    }
```

## Notes

* This Object Supersedes `docsIfDocsisBaseCapability` From RFC-4546 And Reflects The Highest RF Version Supported.
* Values Are Sourced From DOCSIS-IF3-MIB (`docsIf31MibObjects`).
