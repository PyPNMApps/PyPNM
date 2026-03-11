# SNMP Based DOCSIS System And Channel Statistics Endpoints

Visualize And Validate Core DOCSIS SNMP Objects Before Running PNM Measurements.

[SNMP Based DOCSIS System And Channel Statistics Endpoints](#snmp-based-docsis-system-and-channel-statistics-endpoints)

[Overview](#overview)

[Common Request Model](#common-request-model)

- [Endpoint: /system/sysDescr](#endpoint-system-sysdescr)
- [Endpoint: /system/upTime](#endpoint-system-uptime)
- [Endpoint: /docs/if31/docsis/baseCapability](#endpoint-docsif31docsisbasecapability)
- [Endpoint: /docs/pnm/interface/stats](#endpoint-docspnminterfacestats)
- [Endpoint: /docs/if30/ds/scqam/chan/codewordErrorRate](#endpoint-docsif30dsscqamchancodeworderrorrate)
- [Endpoint: /docs/if31/us/ofdma/channel/stats](#endpoint-docsif31usofdmachannelstats)
- [Endpoint: /docs/if31/ds/ofdm/chan/stats](#endpoint-docsif31dsofdmchanstats)
- [Endpoint: /docs/if31/ds/ofdm/profile/stats](#endpoint-docsif31dsofdmprofilestats)

## Overview

These endpoints provide a thin SNMP based view of DOCSIS system identity, DOCSIS base capability, and downstream and upstream
channel statistics. They are intended to be run before heavier PNM measurements to confirm that the cable modem is reachable,
properly provisioned, and actively passing traffic on DOCSIS 3.0 SC-QAM and DOCSIS 3.1 OFDM or OFDMA channels.

All endpoints share a common `cable_modem` request envelope and return a `CommonMessagingService` style response with
`mac_address`, `status`, `message`, and a `results` object that is specific to each endpoint. This document focuses on how to
invoke each endpoint from the CLI and via raw JSON, not on the detailed response payloads.

## Common Request Model

All SNMP based endpoints use the same top level `cable_modem` request object. The example below shows the default SNMP v2c
community of `private` and the generic MAC and IP used throughout the documentation.

```json
{
  "cable_modem": {
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "ip_address": "192.168.0.100",
    "snmp": {
      "snmpV2C": {
        "community": "private"
      }
    }
  }
}
```

Fields:

| Field                                | Type   | Description                                   |
|--------------------------------------|--------|-----------------------------------------------|
| `cable_modem.mac_address`           | string | Cable modem MAC address in colon notation     |
| `cable_modem.ip_address`            | string | IPv4 address used for SNMP and ICMP           |
| `cable_modem.snmp.snmpV2C.community` | string | SNMP v2c community string (default `private`) |

For measurement style endpoints that run over a fixed interval, an additional `capture_parameters` object is used:

```json
{
  "cable_modem": {
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "ip_address": "192.168.0.100",
    "snmp": {
      "snmpV2C": {
        "community": "private"
      }
    }
  },
  "capture_parameters": {
    "sample_time_elapsed": 5
  }
}
```

| Field                                    | Type | Description                                      |
|------------------------------------------|------|--------------------------------------------------|
| `capture_parameters.sample_time_elapsed` | int  | Measurement duration in seconds (default `5`)    |

## Endpoint: /system/sysDescr {#endpoint-system-sysdescr}

Retrieve Cable Modem System Description Via SNMP.

- **Path:** `/system/sysDescr`
- **Method:** `POST`
- **Purpose:** Read the DOCSIS cable modem `sysDescr` string and expose it as a structured object.

### Request

This endpoint uses the common `cable_modem` request model only.

```json
{
  "cable_modem": {
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "ip_address": "192.168.0.100",
    "snmp": {
      "snmpV2C": {
        "community": "private"
      }
    }
  }
}
```

### Example CLI Usage

```bash
python3 src/pypnm/examples/fast_api/api-system-sysDescr.py   --mac aa:bb:cc:dd:ee:ff   --inet 192.168.0.100
```

## Endpoint: /system/upTime {#endpoint-system-uptime}

Retrieve Cable Modem System Uptime Via SNMP.

- **Path:** `/system/upTime`
- **Method:** `POST`
- **Purpose:** Provide the system uptime as a human friendly string based on the SNMP `sysUpTime` value.

### Request

Same as the common `cable_modem` request model.

### Example CLI Usage

```bash
python3 src/pypnm/examples/fast_api/api-system-upTime.py   --mac aa:bb:cc:dd:ee:ff   --inet 192.168.0.100
```

## Endpoint: /docs/if31/docsis/baseCapability {#endpoint-docsif31docsisbasecapability}

Retrieve DOCSIS Base Capability From SNMP.

- **Path:** `/docs/if31/docsis/baseCapability`
- **Method:** `POST`
- **Purpose:** Determine DOCSIS base capability (for example DOCSIS 3.0, 3.1, or 4.0) from the SNMP `clabProjDocsisBaseCapability` object.

### Request

Uses the common `cable_modem` request model.

### Example CLI Usage

```bash
python3 src/pypnm/examples/fast_api/api-docs-if31-docsis-baseCapability.py   --mac aa:bb:cc:dd:ee:ff   --inet 192.168.0.100
```

## Endpoint: /docs/pnm/interface/stats {#endpoint-docspnminterfacestats}

Retrieve Logical Interface Statistics From SNMP.

- **Path:** `/docs/pnm/interface/stats`
- **Method:** `POST`
- **Purpose:** Aggregate `ifEntry` and `ifXEntry` statistics for DOCSIS interface families, include additional interface types (for example Ethernet and voice/eMTA) when present, and include BRIDGE-MIB tables when available.

Although the path is under `/docs/pnm`, this endpoint is purely SNMP based and returns the current interface counters only.

### Request

Uses the common `cable_modem` request model.

### Example CLI Usage

```bash
python3 src/pypnm/examples/fast_api/api-docs-pnm-interface-stats.py   --mac aa:bb:cc:dd:ee:ff   --inet 192.168.0.100
```

## Endpoint: /docs/if30/ds/scqam/chan/codewordErrorRate {#endpoint-docsif30dsscqamchancodeworderrorrate}

Measure DOCSIS 3.0 SC-QAM Downstream Codeword Error Rate Over A Fixed Interval.

- **Path:** `/docs/if30/ds/scqam/chan/codewordErrorRate`
- **Method:** `POST`
- **Purpose:** Collect total and errored codewords on each DOCSIS 3.0 downstream SC-QAM channel over a user defined sample interval,
  then compute an average codeword error rate.

### Request

This endpoint uses both the common `cable_modem` object and the `capture_parameters` section.

```json
{
  "cable_modem": {
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "ip_address": "192.168.0.100",
    "snmp": {
      "snmpV2C": {
        "community": "private"
      }
    }
  },
  "capture_parameters": {
    "sample_time_elapsed": 5
  }
}
```

### Example CLI Usage

```bash
python3 src/pypnm/examples/fast_api/api-docs-if30-ds-scqam-chan-codewordErrorRate.py   --mac aa:bb:cc:dd:ee:ff   --inet 192.168.0.100   --sample-time-elapsed 5
```

## Endpoint: /docs/if31/us/ofdma/channel/stats {#endpoint-docsif31usofdmachannelstats}

Retrieve DOCSIS 3.1 OFDMA Upstream Channel Statistics.

- **Path:** `/docs/if31/us/ofdma/channel/stats`
- **Method:** `POST`
- **Purpose:** Report OFDMA upstream channel configuration and health indicators, including transmit power, pre-equalization status,
  and T3/T4 timeout counts.

### Request

Uses the common `cable_modem` request model.

### Example CLI Usage

```bash
python3 src/pypnm/examples/fast_api/api-docs-if31-us-ofdma-channel-stats.py   --mac aa:bb:cc:dd:ee:ff   --inet 192.168.0.100
```

## Endpoint: /docs/if31/ds/ofdm/chan/stats {#endpoint-docsif31dsofdmchanstats}

Retrieve DOCSIS 3.1 OFDM Downstream Channel Statistics.

- **Path:** `/docs/if31/ds/ofdm/chan/stats`
- **Method:** `POST`
- **Purpose:** Provide OFDM downstream channel configuration details and PLC or NCP error counters for each OFDM channel.

### Request

Uses the common `cable_modem` request model.

### Example CLI Usage

```bash
python3 src/pypnm/examples/fast_api/api-docs-if31-ds-ofdm-chan-stats.py   --mac aa:bb:cc:dd:ee:ff   --inet 192.168.0.100
```

## Endpoint: /docs/if31/ds/ofdm/profile/stats {#endpoint-docsif31dsofdmprofilestats}

Retrieve DOCSIS 3.1 OFDM Downstream Profile Statistics.

- **Path:** `/docs/if31/ds/ofdm/profile/stats`
- **Method:** `POST`
- **Purpose:** Report per-profile OFDM downstream codeword and frame statistics, including corrected and uncorrectable codewords,
  using the DOCSIS 3.1 `docsIf31CmDsOfdmProfileStats` table.

This endpoint is intentionally kept simple and follows the same request pattern as the other SNMP statistics endpoints.

### Request

Uses the common `cable_modem` request model.

### Example CLI Usage

```bash
python3 src/pypnm/examples/fast_api/api-docs-if31-ds-ofdm-profile-stats.py   --mac aa:bb:cc:dd:ee:ff   --inet 192.168.0.100
```
