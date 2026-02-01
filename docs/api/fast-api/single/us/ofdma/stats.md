# DOCSIS 3.1 Upstream OFDMA Channel Statistics

This API provides visibility into the configuration and runtime status of upstream OFDMA channels from DOCSIS 3.1 cable modems. It includes key metrics such as active subcarrier layout, transmit power, cyclic prefix configuration, and pre-equalization status. Additionally, it tracks upstream timeout counters (T3, T4) and ranging outcomes to help diagnose impairments and channel access issues.

Use this endpoint to support PNM workflows, particularly when analyzing power levels, ranging stability, and OFDMA symbol behavior under varying network conditions.

## Endpoint

**POST** `/docs/if31/us/ofdma/channel/stats`

Retrieves statistics and configuration parameters for upstream OFDMA channels from a DOCSIS 3.1 cable modem. This includes subcarrier layout, transmit power, and upstream timing-related error counters.


## Request Body (JSON)

### Request Fields

| Field          | Type   | Description                       |
| -------------- | ------ | --------------------------------- |
| `mac_address`  | string | MAC address of the cable modem    |
| `ip_address`   | string | IP address of the cable modem     |
| `snmp`         | object | SNMPv2c or SNMPv3 configuration   |
| `snmp.snmpV2C` | object | SNMPv2c options (`community`)     |
| `snmp.snmpV3`  | object | SNMPv3 options (auth & priv keys) |

```json
{
  "cable_modem": {
	"mac_address": "aa:bb:cc:dd:ee:ff",
	"ip_address": "192.168.0.100",
  "snmp": {
    "snmpV2C": {
      "community": "private"
    },
    "snmpV3": {
      "username": "string",
      "securityLevel": "noAuthNoPriv",
      "authProtocol": "MD5",
      "authPassword": "string",
      "privProtocol": "DES",
      "privPassword": "string"
    }
  }
}
```


## Response Body (JSON)

```json
[
  {
    "index": <SNMP_INDEX>,
    "channel_id": <CHANNEL_ID>,
    "entry": {
      "docsIf31CmUsOfdmaChanChannelId": 42,
      "docsIf31CmUsOfdmaChanConfigChangeCt": 1,
      "docsIf31CmUsOfdmaChanSubcarrierZeroFreq": 104800000,
      "docsIf31CmUsOfdmaChanFirstActiveSubcarrierNum": 74,
      "docsIf31CmUsOfdmaChanLastActiveSubcarrierNum": 1969,
      "docsIf31CmUsOfdmaChanNumActiveSubcarriers": 1896,
      "docsIf31CmUsOfdmaChanSubcarrierSpacing": 50,
      "docsIf31CmUsOfdmaChanCyclicPrefix": 192,
      "docsIf31CmUsOfdmaChanRollOffPeriod": 128,
      "docsIf31CmUsOfdmaChanNumSymbolsPerFrame": 10,
      "docsIf31CmUsOfdmaChanTxPower": 17.1,
      "docsIf31CmUsOfdmaChanPreEqEnabled": true,
      "docsIf31CmStatusOfdmaUsT3Timeouts": 0,
      "docsIf31CmStatusOfdmaUsT4Timeouts": 0,
      "docsIf31CmStatusOfdmaUsRangingAborteds": 0,
      "docsIf31CmStatusOfdmaUsT3Exceededs": 0,
      "docsIf31CmStatusOfdmaUsIsMuted": false,
      "docsIf31CmStatusOfdmaUsRangingStatus": "success"
    }
  }
]
```


## Response Field Highlights

| Field                                           | Type  | Description                                     |
| ----------------------------------------------- | ----- | ----------------------------------------------- |
| `docsIf31CmUsOfdmaChanChannelId`                | int   | Upstream channel ID                             |
| `docsIf31CmUsOfdmaChanConfigChangeCt`           | int   | Count of configuration changes since modem boot |
| `docsIf31CmUsOfdmaChanSubcarrierZeroFreq`       | int   | Frequency of subcarrier index 0 (Hz)            |
| `docsIf31CmUsOfdmaChanFirstActiveSubcarrierNum` | int   | First active subcarrier index                   |
| `docsIf31CmUsOfdmaChanLastActiveSubcarrierNum`  | int   | Last active subcarrier index                    |
| `docsIf31CmUsOfdmaChanNumActiveSubcarriers`     | int   | Total active subcarriers                        |
| `docsIf31CmUsOfdmaChanSubcarrierSpacing`        | int   | Subcarrier spacing in Hz                        |
| `docsIf31CmUsOfdmaChanCyclicPrefix`             | int   | Cyclic prefix duration                          |
| `docsIf31CmUsOfdmaChanRollOffPeriod`            | int   | Roll-off period                                 |
| `docsIf31CmUsOfdmaChanNumSymbolsPerFrame`       | int   | Number of OFDMA symbols per frame               |
| `docsIf31CmUsOfdmaChanTxPower`                  | float | Transmit power in dBm                           |
| `docsIf31CmUsOfdmaChanPreEqEnabled`             | bool  | Whether pre-equalization is enabled             |
| `docsIf31CmStatusOfdmaUsT3Timeouts`             | int   | T3 timeout count                                |
| `docsIf31CmStatusOfdmaUsT4Timeouts`             | int   | T4 timeout count                                |
| `docsIf31CmStatusOfdmaUsRangingAborteds`        | int   | Number of aborted ranging attempts              |
| `docsIf31CmStatusOfdmaUsT3Exceededs`            | int   | Number of times T3 retries exceeded             |
| `docsIf31CmStatusOfdmaUsIsMuted`                | bool  | Indicates if the upstream is muted              |
| `docsIf31CmStatusOfdmaUsRangingStatus`          | string | Ranging state name (e.g., `success`).           |


## Notes

* Use this endpoint to monitor upstream channel state, power, and timeouts.
* Useful for diagnosing access failures, ranging issues, or transmit mismatches.
* Each response object corresponds to a separate upstream OFDMA channel.
