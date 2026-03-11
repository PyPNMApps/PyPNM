# Interface Statistics

Provides Access To Detailed SNMP Interface Statistics For A DOCSIS Cable Modem, Including `ifEntry` And `ifXEntry` (High-Capacity) Counters.

## Endpoint

**POST** `/docs/pnm/interface/stats`

## Request

Use the SNMP-only format: [Common → Request](../../../common/request.md)  
TFTP parameters are not required.

## Response

This endpoint returns the standard envelope described in [Common → Response](../../../common/response.md) (`status`, `message`, `device`, `data`).

`device` is the top-level device identity block and contains `device.mac_address` and `device.system_description` (empty model when unavailable).

`data` is an object keyed by interface family (`ifType` enum name), with each key containing an array of interfaces (for example: `ethernetCsmacd`, `docsCableMaclayer`, `docsCableDownstream`, `docsCableUpstream`, `docsOfdmDownstream`, `docsOfdmaUpstream`, `voiceOverCable`). Each array item contains an `ifEntry` (base counters) and, when supported, an `ifXEntry` (high-capacity counters).

When BRIDGE-MIB is supported on the device, `data` includes grouped bridge schema only:

- `bridge.ifIndexes.<ifIndex>.dot1dBase`
- `bridge.ifIndexes.<ifIndex>.dot1dBasePortEntry`
- `bridge.ifIndexes.<ifIndex>.dot1dTpPortEntry`
- `bridge.ifIndexes.<ifIndex>.dot1dTpFdbEntry`
- `bridge.ifIndexes.<ifIndex>.ifStackEntry`

### Abbreviated Example

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": 0,
  "message": null,
  "data": {
    "docsCableMaclayer": [
      {
        "ifEntry": {
          "ifIndex": 2,
          "ifDescr": "RF MAC Interface",
          "ifType": 127,
          "ifMtu": 1522,
          "ifSpeed": 0,
          "ifPhysAddress": "0xaabbccddeeff",
          "ifAdminStatus": 1,
          "ifOperStatus": 1,
          "ifLastChange": 0,
          "ifInOctets": 332419242,
          "ifInUcastPkts": 2373549,
          "ifInDiscards": 0,
          "ifInErrors": 0,
          "ifInUnknownProtos": 0,
          "ifOutOctets": 1466628040,
          "ifOutUcastPkts": 2269490,
          "ifOutDiscards": 3216,
          "ifOutErrors": 0
        },
        "ifXEntry": {
          "ifName": "cni0",
          "ifInMulticastPkts": 183192,
          "ifOutBroadcastPkts": 183033,
          "ifHCInOctets": 332419242,
          "ifHCOutOctets": 1466628040,
          "ifHCInUcastPkts": 2373549,
          "ifHCOutUcastPkts": 2269490,
          "ifHighSpeed": 0,
          "ifPromiscuousMode": true,
          "ifConnectorPresent": true,
          "ifCounterDiscontinuityTime": 0
        }
      }
    ],
    "docsCableDownstream": [
      {
        "ifEntry": {
          "ifIndex": 52,
          "ifDescr": "RF Downstream Interface 5",
          "ifType": 128,
          "ifMtu": 1764,
          "ifSpeed": 42884296,
          "ifInOctets": 1627744,
          "ifAdminStatus": 1,
          "ifOperStatus": 1
        },
        "ifXEntry": {
          "ifName": "dsch6",
          "ifHCInOctets": 1627744,
          "ifHighSpeed": 43,
          "ifConnectorPresent": true
        }
      },
      { "...": "other downstream interfaces elided" }
    ],
    "docsCableUpstream": [
      {
        "ifEntry": {
          "ifIndex": 80,
          "ifDescr": "RF Upstream Interface 1",
          "ifType": 129,
          "ifMtu": 1764,
          "ifSpeed": 30720000,
          "ifOutOctets": 5931,
          "ifAdminStatus": 1,
          "ifOperStatus": 1
        },
        "ifXEntry": null
      }
    ],
    "docsOfdmDownstream": [
      {
        "ifEntry": {
          "ifIndex": 48,
          "ifDescr": "RF Downstream Interface 1",
          "ifType": 277,
          "ifMtu": 1764,
          "ifSpeed": 2093258880,
          "ifInOctets": 478293088,
          "ifAdminStatus": 1,
          "ifOperStatus": 1
        },
        "ifXEntry": {
          "ifName": "dsch2",
          "ifHCInOctets": 478293088,
          "ifHighSpeed": 2093
        }
      }
    ],
    "docsOfdmaUpstream": [
      {
        "ifEntry": {
          "ifIndex": 4,
          "ifDescr": "RF Upstream Interface",
          "ifType": 278,
          "ifMtu": 1764,
          "ifSpeed": 600089688,
          "ifOutOctets": 376134261,
          "ifAdminStatus": 1,
          "ifOperStatus": 1
        },
        "ifXEntry": null
      }
    ]
  }
}
```

## Field Descriptions

| Field                                          | Source   | Data Type      | Description                                                             |
| ---------------------------------------------- | -------- | -------------- | ----------------------------------------------------------------------- |
| `ifIndex`                                      | ifEntry  | Integer        | Unique index for the interface.                                         |
| `ifDescr`                                      | ifEntry  | String         | Textual description of the interface.                                   |
| `ifType`                                       | ifEntry  | Enum (Integer) | Interface type (e.g., `6` = ethernetCsmacd, `127` = docsCableMaclayer, `198` = voiceOverCable). |
| `ifMtu`                                        | ifEntry  | Integer        | Maximum transmission unit size in bytes.                                |
| `ifSpeed`                                      | ifEntry  | Integer        | Current bandwidth in bits per second.                                   |
| `ifPhysAddress`                                | ifEntry  | String (MAC)   | MAC address of the interface.                                           |
| `ifAdminStatus`                                | ifEntry  | Enum (Integer) | Admin status: `1` = up, `2` = down, `3` = testing.                      |
| `ifOperStatus`                                 | ifEntry  | Enum (Integer) | Operational status: `1` = up, `2` = down, `3` = testing.                |
| `ifLastChange`                                 | ifEntry  | TimeTicks      | Time since the last operational status change.                          |
| `ifInOctets` / `ifOutOctets`                   | ifEntry  | Counter32      | Total bytes received/sent (32-bit).                                     |
| `ifInUcastPkts` / `ifOutUcastPkts`             | ifEntry  | Counter32      | Unicast packets received/sent.                                          |
| `ifInNUcastPkts` / `ifOutNUcastPkts`           | ifEntry  | Counter32      | Non-unicast (multicast/broadcast) packets.                              |
| `ifInDiscards` / `ifOutDiscards`               | ifEntry  | Counter32      | Discarded packets due to resource limits.                               |
| `ifInErrors` / `ifOutErrors`                   | ifEntry  | Counter32      | Packets with errors during reception/transmission.                      |
| `ifInUnknownProtos`                            | ifEntry  | Counter32      | Received packets with unknown protocol.                                 |
| `ifOutQLen`                                    | ifEntry  | Integer        | Length of output packet queue.                                          |
| `ifSpecific`                                   | ifEntry  | OID            | Reserved for future use.                                                |
| `ifName`                                       | ifXEntry | String         | Interface name (system-specific).                                       |
| `ifInMulticastPkts` / `ifOutMulticastPkts`     | ifXEntry | Counter32      | Multicast packets received/sent.                                        |
| `ifInBroadcastPkts` / `ifOutBroadcastPkts`     | ifXEntry | Counter32      | Broadcast packets received/sent.                                        |
| `ifHCInOctets` / `ifHCOutOctets`               | ifXEntry | Counter64      | High-capacity (64-bit) byte counters.                                   |
| `ifHCInUcastPkts` / `ifHCOutUcastPkts`         | ifXEntry | Counter64      | High-capacity unicast packet counters.                                  |
| `ifHCInMulticastPkts` / `ifHCOutMulticastPkts` | ifXEntry | Counter64      | High-capacity multicast packet counters.                                |
| `ifHCInBroadcastPkts` / `ifHCOutBroadcastPkts` | ifXEntry | Counter64      | High-capacity broadcast packet counters.                                |
| `ifLinkUpDownTrapEnable`                       | ifXEntry | Enum (Integer) | SNMP trap setting for link state change.                                |
| `ifHighSpeed`                                  | ifXEntry | Integer (Mbps) | Interface speed in Mbps (informational; prefer `ifSpeed`).              |
| `ifPromiscuousMode`                            | ifXEntry | Boolean        | Promiscuous mode enabled flag.                                          |
| `ifConnectorPresent`                           | ifXEntry | Boolean        | True if a physical connector is present.                                |
| `ifAlias`                                      | ifXEntry | String         | Administrator-assigned name for the interface.                          |
| `ifCounterDiscontinuityTime`                   | ifXEntry | TimeTicks      | Time of last counter reset/discontinuity.                               |

## Notes

* Null fields may indicate unsupported metrics or interface types on the target device.
* Any returned key in `data` maps to an `ifType` enum family and may contain multiple entries.
* `bridge.ifIndexes` groups bridge data by `dot1dBasePortIfIndex`, which aligns to `IF-MIB::ifIndex`.
* `ifStackEntry` rows are derived from `IF-MIB::ifStackStatus` and associated with both higher and lower layer `ifIndex` groups.
* Prefer high-capacity (`HC`) counters when available to avoid 32-bit rollover on high-traffic links.
