# PNM file manager API

REST API for searching, downloading, uploading, and analyzing PNM capture files stored in PyPNM.

> **When to use**
> - You need to grab captures produced by the single- or multi-capture workflows.
> - You want to upload an external capture into the PyPNM ledger so downstream tools can analyze it.
> - You need raw access (download or hexdump) to troubleshoot a specific transaction.

> **Prerequisites**
> - Captures already exist in the transaction database (produced via the capture workflows or uploaded).
> - The FastAPI service is running with access to the `.data/` directories configured in `system.json`.
> - You understand the [standard response schema](../common/response.md) for success/error envelopes.

Endpoints live under the FastAPI router `/docs/pnm/files`.

Typical flow:

1. Capture or upload files so they appear in the transaction database.
2. Search or list files by MAC address or operation.
3. Download single files or grouped ZIPs.
4. Optionally trigger analysis or hexdump inspection on specific transactions.
5. Use results downstream (for example, with the [multi-capture analysis modules](../multi/index.md#advanced-analysis-modules)).

## Endpoints

### 1) Search files by MAC address

**Endpoint**

```text
GET /docs/pnm/files/searchFiles/{mac_address}
```

**Description**

Return a mapping of MAC address to a list of file entries associated with that modem. Each file entry carries the transaction identifier, filename, PNM test type, timestamp, and optional system description metadata.

**Path Parameter**

| Name        | Type   | Description                                                               |
| ----------- | ------ | ------------------------------------------------------------------------- |
| mac_address | string | MAC address of the cable modem. Example: `aa:bb:cc:dd:ee:ff`             |

**Successful Response (200)**

- Content type: `application/json`
- Body schema: `FileQueryResponse`

```json
{
  "files": {
    "aa:bb:cc:dd:ee:ff": [
      {
        "transaction_id": "f67dd3ffb40420d6",
        "filename": "ds_ofdm_rxmer_per_subcar_aa_bb_cc_dd_ee_ff.bin",
        "pnm_test_type": "DS_OFDM_RXMER_PER_SUBCAR",
        "timestamp": 1763736292,
        "system_description": {
          "HW_REV": "1.0",
          "VENDOR": "LANCity",
          "BOOTR": "NONE",
          "SW_REV": "1.0.0",
          "MODEL": "LCPET-3"
        }
      }
    ]
  }
}
```

### 2) Download file by transaction ID

**Endpoint**

```text
GET /docs/pnm/files/download/transactionID/{transaction_id}
```

**Description**

Download a single PNM capture file associated with a given transaction identifier.

**Path Parameter**

| Name           | Type   | Description                                          |
| -------------- | ------ | ---------------------------------------------------- |
| transaction_id | string | Unique transaction identifier for the PNM file.     |

**Successful Response (200)**

- Content type: `application/octet-stream`
- Body: Raw PNM binary file.

If the transaction ID is not found:

```json
{
  "detail": "Transaction ID not found."
}
```

with HTTP 404 status.

### 3) Download uncompressed file by filename

**Endpoint**

```text
GET /docs/pnm/files/download/filename/{filename}
```

**Description**

Resolve the filename against the transaction database, materialize the raw file if it is stored compressed, and return the uncompressed artifact. This is useful when you only have the filename and need a raw PNM file for parsing or offline inspection.

**Path Parameter**

| Name     | Type   | Description                                                                 |
| -------- | ------ | --------------------------------------------------------------------------- |
| filename | string | Stored filename (raw or compressed). Example: `ds_ofdm_rxmer_per_subcar_aa_bb_cc_dd_ee_ff.bin.zst` |

**Successful Response (200)**

- Content type: `application/octet-stream`
- Body: Raw PNM binary file.

If the filename is not found:

```json
{
  "detail": "Filename not found in transaction records."
}
```

with HTTP 404 status.

### 4) Download files by MAC address (ZIP archive)

**Endpoint**

```text
GET /docs/pnm/files/download/macAddress/{mac_address}
```

**Description**

Resolve all transactions for the given MAC address, collect their on-disk PNM files, and return a ZIP archive containing all existing files.

**Path Parameter**

| Name        | Type   | Description                                                               |
| ----------- | ------ | ------------------------------------------------------------------------- |
| mac_address | string | MAC address of the cable modem. Example: `aa:bb:cc:dd:ee:ff`             |

**Successful Response (200)**

- Content type: `application/zip`
- Body: ZIP archive of PNM capture files.

Errors can include:

```json
{
  "detail": "No transactions found for MAC address."
}
```

or

```json
{
  "detail": "No files on disk for MAC address."
}
```

both with HTTP 404 status.

### 5) Download files by operation ID (ZIP archive)

**Endpoint**

```text
GET /docs/pnm/files/download/operationID/{operation_id}
```

**Description**

Resolve the capture group associated with a given operation ID, collect all transactions in that group, and return a ZIP archive containing all corresponding PNM files that exist on disk.

**Path Parameter**

| Name         | Type   | Description                                   |
| ------------ | ------ | --------------------------------------------- |
| operation_id | string | Operation identifier from the capture service.|

**Successful Response (200)**

- Content type: `application/zip`
- Body: ZIP archive of all PNM files associated with the operation.

Example error:

```json
{
  "detail": "No transactions found for Operation ID."
}
```

or

```json
{
  "detail": "No files on disk for Operation ID."
}
```

with HTTP 404 status.

### 6) Upload PNM file

**Endpoint**

```text
POST /docs/pnm/files/upload
```

**Description**

Upload a PNM capture file (for example, RxMER, constellation, histogram, spectrum) via multipart/form-data. The server persists the file, identifies the PNM file type from its header, maps it to a DOCSIS test, and registers a transaction using a placeholder null MAC address (to be backfilled later).

**Request**

- Content type: `multipart/form-data`
- Fields:

| Name | Type        | Description                                                                     |
| ---- | ----------- | ------------------------------------------------------------------------------- |
| file | binary file | Raw PNM capture file payload.                                                   |

**Successful Response (200)**

- Content type: `application/json`
- Body schema: `UploadFileResponse`

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "filename": "ds_ofdm_rxmer_per_subcar_example.bin",
  "transaction_id": "ea18519a572e2487"
}
```

If the file type is unrecognized:

```json
{
  "detail": "Unsupported or unrecognized PNM file type."
}
```

with HTTP 400 status.

### 7) Analyze PNM file

**Endpoint**

```text
POST /docs/pnm/files/getAnalysis
```

**Description**

Trigger an analysis run for a specific PNM file identified by transaction ID. The backend resolves the transaction, locates the PNM file, inspects its header, and routes it to the appropriate analysis pipeline.

The exact request/response schema is defined by `FileAnalysisRequest` and `AnalysisJsonResponse` in the FastAPI OpenAPI documentation. At a high level, the request specifies the transaction ID, analysis type, and output format (JSON or archive).

**Request**

- Content type: `application/json`
- Body schema: `FileAnalysisRequest`

Example (JSON output):

```json
{
  "search": {
    "transaction_id": "ea18519a572e2487"
  },
  "analysis": {
    "type": "BASIC",
    "output": {
      "type": "JSON"
    }
  }
}
```

**Successful Response (200)**

- Content type: `application/json`
- Body schema: `AnalysisJsonResponse`

Example (truncated):

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "pnm_file_type": "RECEIVE_MODULATION_ERROR_RATIO",
  "status": "success",
  "analysis": {
    "device_details": {
      "HW_REV": "1.0",
      "VENDOR": "LANCity",
      "BOOTR": "NONE",
      "SW_REV": "1.0.0",
      "MODEL": "LCPET-3"
    },
    "pnm_header": {
      "file_type": "PNN5",
      "file_type_version": 5,
      "major_version": 1,
      "minor_version": 0,
      "capture_time": 1495481
    },
    "...": "analysis fields omitted for brevity"
  }
}
```

If the transaction is not found:

```json
{
  "detail": "Transaction ID not found for analysis."
}
```

with HTTP 404 status.

### 8) Hexdump of a PNM file via transaction ID

**Endpoint**

```text
GET /docs/pnm/files/getHexdump/transactionID/{transaction_id}
```

**Description**

Generate a textual hexdump view of the raw PNM file associated with a given transaction ID. This is useful for low-level inspection, debugging binary parsing issues, or forensic analysis of the PNM header and payload.

The hexdump is returned as JSON: each line includes a byte offset, hex-encoded bytes, and an ASCII representation.

**Path Parameter**

| Name           | Type   | Description                                              |
| -------------- | ------ | -------------------------------------------------------- |
| transaction_id | string | Unique transaction identifier for the PNM file to dump. |

**Query Parameter**

| Name           | Type | Description                                                                                  |
| -------------- | ---- | -------------------------------------------------------------------------------------------- |
| bytes_per_line | int  | Optional bytes-per-line for each hexdump row. If omitted or non-positive, a default is used.|

**Successful Response (200)**

- Content type: `application/json`
- Body schema: `HexDumpResponse`

Example:

```json
{
  "transaction_id": "8f17fcdd4c0138ef",
  "bytes_per_line": 16,
  "lines": [
    "00000000  50 4e 4d 00 05 01 00 00  00 00 00 00 00 00 00 00  |PNM.............|",
    "00000010  01 23 45 67 89 ab cd ef  00 11 22 33 44 55 66 77  |.#Eg......\"3DUfw|"
  ]
}
```

If the transaction ID or file cannot be resolved, typical errors include:

```json
{
  "detail": "Transaction ID not found."
}
```

or

```json
{
  "detail": "PNM file not found on disk."
}
```

with HTTP 404 status, or:

```json
{
  "detail": "Failed to generate hexdump for PNM file."
}
```

with HTTP 500 status.

## Request and response examples

This section summarizes the core JSON shapes used by the PNM File Manager endpoints. All types are shown as they appear on the wire (FastAPI OpenAPI / SwaggerUI and tools such as Postman or curl).

### FileQueryResponse (search files)

```json
{
  "files": {
    "aa:bb:cc:dd:ee:ff": [
      {
        "transaction_id": "f67dd3ffb40420d6",
        "filename": "ds_ofdm_rxmer_per_subcar_aa_bb_cc_dd_ee_ff.bin",
        "pnm_test_type": "DS_OFDM_RXMER_PER_SUBCAR",
        "timestamp": 1763736292,
        "system_description": {
          "HW_REV": "1.0",
          "VENDOR": "LANCity",
          "BOOTR": "NONE",
          "SW_REV": "1.0.0",
          "MODEL": "LCPET-3"
        }
      }
    ]
  }
}
```

### UploadFileResponse (upload PNM file)

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "filename": "ds_ofdm_rxmer_per_subcar_example.bin",
  "transaction_id": "ea18519a572e2487"
}
```

### AnalysisJsonResponse (analyze PNM file)

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "pnm_file_type": "RECEIVE_MODULATION_ERROR_RATIO",
  "status": "success",
  "analysis": {
    "device_details": {
      "HW_REV": "1.0",
      "VENDOR": "LANCity",
      "BOOTR": "NONE",
      "SW_REV": "1.0.0",
      "MODEL": "LCPET-3"
    },
    "pnm_header": {
      "file_type": "PNN5",
      "file_type_version": 5,
      "major_version": 1,
      "minor_version": 0,
      "capture_time": 1495481
    },
    "...": "analysis fields omitted for brevity"
  }
}
```

## Next steps

- Need to generate new captures? Start with the [single capture](../single/index.md) or [multi capture](../multi/index.md) workflows.
- Looking for where files live on disk? Review the [system configuration reference](../../../system/system-config.md#pnmfileretrieval) for storage paths.
