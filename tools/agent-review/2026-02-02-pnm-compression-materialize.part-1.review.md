## Agent Review Bundle Summary
- Goal: Lower SystemCall logging to debug level.
- Changes: SystemCall now logs execution at debug instead of info.
- Files: See file list below.
- Tests: `ruff check src`, `pytest -q`.
- Notes: None.
# FILE: CODING_AGENTS.md
# General-Purpose AI Coding Guide

This document provides a generic coding guide for AI contributors. It focuses on code style,
reuse, and maintainability.

## Core Principles

- Reuse before adding: prefer existing types, helpers, models, and utilities.
- Keep diffs minimal and focused; avoid formatting churn.
- Preserve existing naming, alignment, and whitespace patterns.
- Favor clarity and explicit typing over clever shortcuts.
- Review this document before making any changes.
  This is a generic guide and does not replace `AGENTS.md`.

## Reuse-First Checklist

Before introducing new types, validators, formats, or storage conventions:

- Search for similar helpers in `src/pypnm/lib/` and `src/pypnm/api/`.
- Check `tools/agent-review/` for any reuse or symbol index guidance.
- Prefer existing semantic aliases over raw `str` identifiers.
- Prefer existing constants over inline values.
- Prefer existing Pydantic models for public data structures.
- Refer to shared utilities and helpers before creating new classes.

## Common Locations To Consult

- Types and semantic aliases: `src/pypnm/lib/types.py`
- Constants: `src/pypnm/lib/constants.py`
- Validators and parsing helpers: `src/pypnm/lib/`
- Config models and defaults: `src/pypnm/config/`
- Shared API models and schemas: `src/pypnm/api/` (including `src/pypnm/api/common/`)

## Coding Style (General)

- Use built-in generics (`list[str]`, `dict[str, int]`) and `A | B` unions.
- Avoid `Any` unless unavoidable; isolate and justify its usage.
- Annotate all function arguments and return types.
- Prefer classes or static methods over standalone functions.
- Use Pydantic `BaseModel` for public interfaces instead of raw dicts.
- Keep public method docstrings detailed; private method docstrings minimal.

## Workflow Guidance

- Validate changes with repository test entry points.
- When adding new behavior, include tests covering the change.
- New classes must have pytest coverage at a minimum for IPC and system calls.
- Use `SystemCall` (`src/pypnm/lib/system_call/`) for subprocess/system calls; do not call `subprocess.run` directly in app code.
- Avoid broad refactors unless explicitly requested.
- Keep a brief summary of user prompts after any request for a commit message and track changes since the most recent commit message request.
- When asked for a commit message, respond with the specified format, keep it succinct, and include all changes since the last commit message request.
- Commit messages must be returned in Markdown text format (use a code block).

### Commit Message Format

- One line summary (max 50 characters)
- Detailed description lines (max 72 characters per line); every line after the first must start with `-`

## Agent Constraints

- General workflow:
  - Make minimal diffs; avoid formatting churn.
  - Preserve whitespace/alignment in existing files (no auto-reflow).
  - Do not add broad refactors unless explicitly requested.
  - Provide an end-of-run Agent Review Bundle summary: goal, changes, files, tests, notes.
- Typing and API style:
  - Strict typing everywhere; avoid `Dict`/`List`/`Tuple`/`Union` and avoid `Any`.
  - Prefer built-in generics (`dict[str, int]`, `list[str]`) and `A | B` rather than `Union`.
  - Prefer Pydantic `BaseModel` over dict returns for public interfaces.
  - `BaseModel` fields must be one-line `Field(...)` declarations with descriptions.
  - Avoid generic returns; every method must have an explicit return type annotation.
  - Every method argument must have an explicit type annotation.
  - Public/shared method types must be defined in `src/pypnm/lib/types.py`.
  - Only define local types in a module when the type is strictly private and not reused.
  - Common folder methods must use types defined in `src/pypnm/lib/types.py`.
- Prefer `match/case` over long if/else chains.
- No one-line if statements (E701 compliance).
- Avoid 3+ nested loops; 2 nested loops discouraged unless necessary.
- If `STATUS` is used as a return type, return `STATUS_OK` or `STATUS_NOK` for readability.
- Code structure and documentation:
  - Prefer classes/static methods; minimize standalone global functions.
  - Public methods must have detailed docstrings; private methods minimal.
  - Keep code self-documented; avoid method-level debug logging.
  - Logger pattern in classes: `self.logger = logging.getLogger(f"{self.__class__.__name__}")`.
- Release hygiene / headers:
  - Code files must include `SPDX-License-Identifier: Apache-2.0`.
  - Copyright lines must include only the year or year range (no author names).
  - Any touched code files must have SPDX copyright year updated per Repo Hygiene rules (single year or range).
  - Do not add SPDX headers to Markdown files.
  - Remove SPDX lines embedded inside Markdown code blocks if encountered (especially SQL appendices).
- Docs / Markdown rules (MkDocs + GitHub compatible):
  - No emojis in docs.
  - No horizontal rules (`---`) in Markdown.
  - Keep tables ~132 characters wide when possible.
  - Use placeholders consistently in examples:
    - MAC: `aa:bb:cc:dd:ee:ff`
    - IP: `192.168.0.100`
    - system_description JSON: `{"HW_REV":"1.0","VENDOR":"LANCity","BOOTR":"NONE","SW_REV":"1.0.0","MODEL":"LCPET-3"}`
  - For code file links in docs: use HTTP GitHub links; relative links only for other Markdown files.
  - Always include a downloadable link at the end of any Markdown you generate (when generating Markdown as an artifact in chat; for repo docs, follow repo conventions).
- Shell scripts:
  - Proper indentation.
  - Emojis allowed only in `install.sh` and `pypnm-cmts` CLI output; do not use emojis elsewhere.
- Testing expectations:
  - Run at least: `python3 -m compileall src`, `ruff check src`, `ruff format --check .`, `pytest -q`.
  - After any code change, run `ruff check src` and `pytest -q`. If only Markdown changes are made, run `mkdocs build -s` instead.
  - If an integration test is optional/gated (for example Postgres DSN), note skips explicitly in the summary.
- Troubleshooting:
  - When debugging endpoint behavior, include `tail -n 25 /home/dev01/Projects/PyPNM/logs/pypnm.log` in the troubleshooting steps.

## Pytest Guidance (PyPNM Pattern)

- Place new tests under `tests/` with `test_*.py` naming.
- Prefer small, focused unit tests that mirror the existing test style.
- Use fixtures for shared data (see current `tests/` patterns).
- Prefer module-level test functions over new class wrappers unless an existing test uses classes.
- Reuse `tests/files/` for binary fixtures and sample data.
- Favor hermetic tests: no live devices, no external services.
- When testing IPC or system calls, isolate behavior with fakes/mocks and assert edge cases.
- Keep tests aligned with existing patterns in similar modules before introducing new structures.
  Start by locating a similar test file and mirror its structure.

## Notes

- This document is intentionally generic. Use `AGENTS.md` for this repository’s
  authoritative rules and workflow constraints.
# FILE: deploy/docker/config/system.json
{
    "CmtsOrchestrator": {
        "adapter": {
            "community": "cmtspublic",
            "hostname": "172.19.122.228",
            "write_community": "cmtspublic"
        }
    },
    "FastApiRequestDefault": {
        "ip_address": "192.168.0.1",
        "mac_address": "aa:bb:cc:dd:ee:ff"
    },
    "PnmBulkDataTransfer": {
        "http": {
            "base_url": "http://files.example.com/",
            "port": 80
        },
        "https": {
            "base_url": "https://files.example.com/",
            "port": 443
        },
        "method": "tftp",
        "tftp": {
            "ip_v4": "172.19.8.28",
            "ip_v6": "::1",
            "remote_dir": ""
        }
    },
    "PnmFileRetrieval": {
        "archive_dir": ".data/archive",
        "capture_group_db": ".data/db/capture_group.json",
        "csv_dir": ".data/csv",
        "json_dir": ".data/json",
        "json_transaction_db": ".data/db/json_transactions.json",
        "msg_rsp_dir": ".data/msg_rsp",
        "operation_db": ".data/db/operation_capture.json",
        "png_dir": ".data/png",
        "pnm_dir": ".data/pnm",
        "retries": 5,
        "retrieval_method": {
            "method": "local",
            "methods": {
                "ftp": {
                    "host": "localhost",
                    "password": "",
                    "password_enc": "",
                    "port": 21,
                    "remote_dir": "/srv/tftp",
                    "timeout": 5,
                    "tls": false,
                    "user": "user"
                },
                "http": {
                    "base_url": "http://STUB/",
                    "password": "",
                    "password_enc": "",
                    "port": 80
                },
                "https": {
                    "base_url": "https://STUB/",
                    "password": "",
                    "password_enc": "",
                    "port": 443
                },
                "local": {
                    "password": "",
                    "password_enc": "",
                    "src_dir": "/srv/tftp"
                },
                "sftp": {
                    "host": "172.19.8.28",
                    "password": "",
                    "password_enc": "",
                    "port": 22,
                    "private_key_path": "~/.ssh/id_rsa_pypnm",
                    "remote_dir": "/srv/tftp",
                    "user": "dev01"
                },
                "tftp": {
                    "host": "localhost",
                    "password": "",
                    "password_enc": "",
                    "port": 69,
                    "remote_dir": "",
                    "timeout": 5
                }
            }
        },
        "session_group_db": ".data/db/session_group.json",
        "transaction_db": ".data/db/transactions.json",
        "xlsx_dir": ".data/xlsx"
    },
    "PnmArtifactStorage": {
        "compression": {
            "enabled": true,
            "min_bytes": 4096,
            "conditional_max_ratio": 0.92,
            "conditional_min_savings_bytes": 8192,
            "deny": [
                "ds_ofdm_chan_est_coef"
            ],
            "always": [
                "ds_ofdm_codeword_error_rate",
                "ds_ofdm_modulation_profile"
            ],
            "conditional": [
                "ds_ofdm_rxmer_per_subcar",
                "us_pre_equalizer_coef"
            ],
            "primary_codec": "zstd",
            "gzip_fallback": true,
            "zstd_level": 3,
            "gzip_level": 6
        },
        "cache": {
            "tmp_root": "/tmp/pypnm",
            "ingress_dir": "ingress",
            "materialized_dir": "materialized",
            "ingress_ttl_seconds": 900,
            "materialized_ttl_seconds": 86400,
            "cleanup_interval_seconds": 3600
        }
    },
    "SNMP": {
        "timeout": 2,
        "version": {
            "2c": {
                "enable": true,
                "read_community": "public",
                "retries": 3,
                "write_community": "public"
            },
            "3": {
                "authPassword": "",
                "authProtocol": "SHA",
                "enable": false,
                "privPassword": "",
                "privProtocol": "AES",
                "retries": 3,
                "securityLevel": "authPriv",
                "username": "user"
            }
        }
    },
    "TestMode": {
        "class_name": {
            "DsScQamChannelSpectrumAnalyzer": {
                "mode": {
                    "enable": true
                }
            }
        },
        "global": {
            "mode": {
                "enable": true
            }
        }
    },
    "logging": {
        "log_dir": "logs",
        "log_filename": "pypnm.log",
        "log_level": "INFO"
    },
    "pypnm-cmts": {
        "cmts": [
            {
                "SNMP": {
                    "timeouts": {
                        "request_seconds": 5,
                        "retries": 1
                    },
                    "version": {
                        "2c": {
                            "enable": true,
                            "port": 161,
                            "read_community": "cmtspublic",
                            "retries": 3,
                            "write_community": "cmtspublic"
                        },
                        "3": {
                            "authPassword": "",
                            "authProtocol": "SHA",
                            "enable": false,
                            "port": 161,
                            "privPassword": "",
                            "privProtocol": "AES",
                            "retries": 3,
                            "securityLevel": "authPriv",
                            "username": "user"
                        }
                    }
                },
                "device": {
                    "hostname": "172.19.122.228",
                    "model": "",
                    "vendor": ""
                }
            }
        ]
    }
}
# FILE: docs/api/fast-api/file-manager/file-manager-api.md
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
# FILE: docs/api/fast-api/multi/capture-operation.md
# Multi‑Capture Operation Overview

When you initiate a **multi-capture** session (e.g., Multi‑RxMER or Multi‑DS‑Channel‑Estimation), PyPNM maintains a lightweight file‑based tracking system and stages resulting PNM binaries for downstream workflows.

**Directory Layout**:

```text
data/
├── db/
│   ├── operation_capture.json      # Maps operations to capture groups
│   ├── capture_group.json          # Records capture groups
│   └── transactions.json           # Lists each staged file transaction
└── pnm/
    └── <.bin files>                # Raw PNM captures retrieved via TFTP
```

## 1. Operation Database (`operation_capture.json`)

Records each background **operation** and its connection to a capture group.

**Example**:

```json
{
  "f6afb2d7df2c4a5c": {
    "capture_group": "10b6ea239641487c",
    "created": 1748280293
  }
}
```

* **Key**: `operation_id` (e.g., `f6afb2d7df2c4a5c`).
* **capture\_group**: Associated `capture_group_id`.
* **created**: Unix timestamp when the operation started.

## 2. Capture Group Database (`capture_group.json`)

Tracks each high‑level invocation as a distinct **capture group**.

**Example**:

```json
{
  "10b6ea239641487c": {
    "created": 1748280293,
    "transactions": [
      "2ee6138bbc1b3c3d",
      "65c04a28d0add931",
      "df4d2b3e3146ef30",
      "6773c9ebc097a579"
    ]
  }
}
```

* **Key**: `capture_group_id` (e.g., `10b6ea239641487c`).
* **created**: Unix timestamp when the group was created.
* **transactions**: List of associated `transaction_id`s (one per file).

## 3. Transactions Manifest (`transactions.json`)

A detailed manifest of every PNM file moved into `data/pnm/` during the capture.

**Example**:

```json
{
  "2ee6138bbc1b3c3d": {
      "timestamp": 1748280294,
      "mac_address": "aa:bb:cc:dd:ee:ff",
      "pnm_test_type": "DS_OFDM_RXMER_PER_SUBCAR",
      "filename": "ds_ofdm_rxmer_per_subcar_aabbccddeeff_34_1748280294.bin.zst",
      "compression": {
          "is_compressed": true,
          "codec": "zstd",
          "level": 3,
          "size_before": 38427,
          "size_after": 21135
      },
      "device_details": {
          "system_description": {
              "HW_REV": "1.0",
              "VENDOR": "LANCity",
              "BOOTR": "NONE",
              "SW_REV": "1.0.0",
              "MODEL": "LCPET-3"
          }
      }
  }
}
```

* **Key**: `transaction_id` (e.g., `2ee6138bbc1b3c3d`).
* **timestamp**: Unix epoch when the file was staged.
* **mac\_address**: Sanitized MAC of the target modem.
* **pnm\_test\_type**: Identifier of the PNM capture type.
* **filename**: Physical filename in `data/pnm/` (includes `.zst` or `.gz` when used).
* **compression**: Compression metadata when stored in compressed form.
* **device\_details.system\_description**: Snapshot of modem metadata at capture time.

## Workflow Summary

1. **Start Multi‑Capture**: System generates a new `operation_id` linked to a new `capture_group_id`.
2. **Periodic Triggers**: SNMP instructs the modem to TFTP-upload the PNM blob.
3. **File Staging**: PyPNM stores each artifact in `data/pnm/` (raw or compressed) and appends a JSON entry.
4. **Database Updates**: Timestamps and transaction lists are updated in both `operation_capture.json` and `capture_group.json`.
5. **Completion**: After the capture ends, the three JSON tables fully describe what was captured, when, and for which operation/group.

> Downstream tools can monitor `transactions.json` as a manifest to automatically discover and process new PNM files—no manual polling required.

1. **Start Multi‑Capture**: System generates a new `operation_id` linked to a new `capture_group_id`.
2. **Periodic Triggers**: SNMP instructs the modem to TFTP-upload the PNM blob.
3. **File Staging**: PyPNM copies each `.bin` into `data/pnm/` and appends a JSON entry.
4. **Database Updates**: Timestamps and transaction lists are updated in both `operation_capture.json` and `capture_group.json`.
5. **Completion**: After the capture ends, the three JSON tables fully describe what was captured, when, and for which operation/group.

> Downstream tools can monitor `transactions.json` as a manifest to automatically discover and process new PNM files—no manual polling required.
# FILE: docs/api/fast-api/pypnm/db/data-base.md
# PyPNM Database

Overview of how PyPNM stores, organizes, and links measurement data for traceability and REST access.

## Table Of Contents

- [Data Repository Layout](#data-repository-layout)
- [Directory Reference](#directory-reference)
- [Operation Capture Linking](#operation-capture-linking)
- [Capture Group Registry](#capture-group-registry)
- [Transaction Records](#transaction-records)
- [JSON Capture Ledger](#json-capture-ledger)
- [Summary Of Relationships](#summary-of-relationships)

## Data Repository Layout

The `.data` tree is the on-disk workspace for all PyPNM captures, intermediate artifacts, plots, and ledgers.

```text
.data
├── archive
│   └── aabbccddeeff_lcpet3_1760940313.zip
├── csv
│   ├── aabbccddeeff_lcpet3_1760940313_ofdm_profile_perf_1_ch33_pid0.csv
│   ├── aabbccddeeff_lcpet3_1760940313_ofdm_profile_perf_1_ch33_pid1.csv
│   ├── aabbccddeeff_lcpet3_1760940313_ofdm_profile_perf_1_ch33_pid3.csv
│   ├── aabbccddeeff_lcpet3_1760940313_ofdm_profile_perf_1_ch34_pid0.csv
│   ├── aabbccddeeff_lcpet3_1760940313_ofdm_profile_perf_1_ch34_pid1.csv
│   └── aabbccddeeff_lcpet3_1760940313_ofdm_profile_perf_1_ch34_pid3.csv
├── db
│   ├── capture_group.json
│   ├── json_transactions.json
│   ├── operation_capture.json
│   └── transactions.json
├── json
│   ├── aabbccddeeff_example_run_1760940313_33_cmdsofdmrxmer_1760940313000000000.json
│   └── aabbccddeeff_example_run_1760940313_34_cmdsofdmrxmer_1760940313999999999.json
├── msg_rsp
├── png
│   ├── aabbccddeeff_lcpet3_1760940313_33_profile_0_ofdm_profile_perf_1.png
│   ├── aabbccddeeff_lcpet3_1760940313_33_profile_1_ofdm_profile_perf_1.png
│   ├── aabbccddeeff_lcpet3_1760940313_33_profile_3_ofdm_profile_perf_1.png
│   ├── aabbccddeeff_lcpet3_1760940313_34_profile_0_ofdm_profile_perf_1.png
│   ├── aabbccddeeff_lcpet3_1760940313_34_profile_1_ofdm_profile_perf_1.png
│   └── aabbccddeeff_lcpet3_1760940313_34_profile_3_ofdm_profile_perf_1.png
├── pnm
│   ├── ds_ofdm_codeword_error_rate_aabbccddeeff_33_1760940254.bin
│   ├── ds_ofdm_codeword_error_rate_aabbccddeeff_33_1760940285.bin
│   ├── ds_ofdm_codeword_error_rate_aabbccddeeff_34_1760940287.bin
│   ├── ds_ofdm_modulation_profile_aabbccddeeff_33_1760940269.bin
│   ├── ds_ofdm_modulation_profile_aabbccddeeff_34_1760940270.bin
│   ├── ds_ofdm_rxmer_per_subcar_aabbccddeeff_33_1760940252.bin
│   └── ds_ofdm_rxmer_per_subcar_aabbccddeeff_33_1760940260.bin
└── xlsx
```

## Directory Reference

Each subdirectory has a well-defined role. The table below summarizes typical contents and how they are used by PyPNM.

| Directory  | Typical Contents                                                | Example Filenames                                                     | Purpose                                                                                           |
| ---------- | --------------------------------------------------------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `archive/` | ZIP archives combining multi-file outputs (CSV, PNG, summaries) | `aabbccddeeff_lcpet3_1760940313.zip`                                  | One-stop bundle for download/sharing and offline review.                                          |
| `csv/`     | Per-measurement CSV exports                                     | `aabbccddeeff_lcpet3_1760940313_ofdm_profile_perf_1_ch34_pid1.csv`    | Tabular data for analysis, BI tools, and spreadsheets.                                            |
| `db/`      | JSON ledgers and indexes                                        | `transactions.json`, `operation_capture.json`, `capture_group.json`   | Traceability: transactions, operation-to-group links, and grouped captures.                       |
| `db/`      | JSON capture ledger                                             | `json_transactions.json`                                              | Index of processed JSON capture files (under `.data/json/`), including size and SHA-256 hashes.  |
| `json/`    | Raw/processed JSON outputs (when enabled)                       | `aabbccddeeff_example_run_1760940313_33_cmdsofdmrxmer_*.json`         | Structured artifacts for programmatic consumption; filenames are recorded in `json_transactions`. |
| `msg_rsp/` | Request/response message snapshots (optional)                   | —                                                                     | Diagnostics and audit of REST or SNMP exchanges.                                                  |
| `png/`     | Visualization images per capture/profile/channel                | `aabbccddeeff_lcpet3_1760940313_34_profile_1_ofdm_profile_perf_1.png` | Quick-look plots for reports and UIs.                                                             |
| `pnm/`     | Binary PNM files pulled from devices or uploads                 | `ds_ofdm_rxmer_per_subcar_aabbccddeeff_33_1760940252.bin`             | Source files used by analyses; include the embedded `pnm_header`.                                |
| `xlsx/`    | Excel workbooks                                                 | —                                                                     | Multi-sheet summaries and cross-linked reports.                                                   |

## Operation Capture Linking

The `.data/db/operation_capture.json` file links a multi-measurement **operation** to a single **capture group**.
An operation represents a higher-level request that may include different PNM test types (RxMER, FEC Summary, Modulation Profile).

```json
"6bc3877d9b374039": {
  "capture_group_id": "91d93f5309944ac8",
  "created": 1751950063
}
```

### Field Overview

| Field              | Type    | Description                                   |
| ------------------ | ------- | --------------------------------------------- |
| `capture_group_id` | string  | Unique ID of the broader capture session.     |
| `created`          | integer | Operation creation timestamp (epoch seconds). |

Common uses:

- Retrieve a complete session by operation ID via REST.
- Persist session context for deferred or repeat analysis.

## Capture Group Registry

The `.data/db/capture_group.json` file is the index of **grouped transactions**.
Capture groups can span multiple test types or measurements and underpin multi-file workflows (Excel generation, correlation, etc.).

```json
"91d93f5309944ac8": {
  "created": 1751950063,
  "transactions": [
    "1e171e1f8ef5377a",
    "3ed8cb029bbba404",
    "d94ad704d79cfce9",
    "53ee3282cef409b5",
    "ce6b8d43b6c8bf0c",
    "fa34f5dea580119b",
    "41f23b8c451af271",
    "2c228e79d86e6bf0",
    "f446c7fec87e5ad3",
    "3889d1976fb68feb"
  ]
}
```

### Field Overview

| Field          | Type    | Description                                                               |
| -------------- | ------- | ------------------------------------------------------------------------- |
| `created`      | integer | Group creation timestamp (epoch seconds; often the first operation time). |
| `transactions` | array   | List of transaction IDs belonging to this capture group.                  |

## Transaction Records

The `.data/db/transactions.json` file is the ledger of all file captures and uploads tracked by PyPNM.
Each entry represents a single file **transaction**, whether:

- Pulled automatically from a cable modem (for example, via TFTP), or
- Manually uploaded by a user via the UI or API.

### Structure

Each transaction is indexed by a unique hash (for example, a digest of filename plus timestamp):

```json
"1e171e1f8ef5377a": {
  "timestamp": 1751950064,
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "pnm_test_type": "DS_OFDM_RXMER_PER_SUBCAR",
  "filename": "ds_ofdm_rxmer_per_subcar_aabbccddeeff_197_1751950064.bin.zst",
  "compression": {
    "is_compressed": true,
    "codec": "zstd",
    "level": 3,
    "size_before": 38427,
    "size_after": 21135
  },
  "device_details": {
    "system_description": {
      "HW_REV": "1.0",
      "VENDOR": "LANCity",
      "BOOTR": "NONE",
      "SW_REV": "1.0.0",
      "MODEL": "LCPET-3"
    }
  }
}
```

### Field Overview

| Field            | Type    | Description                                                                 |
| ---------------- | ------- | --------------------------------------------------------------------------- |
| `timestamp`      | integer | Unix epoch seconds when the file was received or uploaded.                  |
| `mac_address`    | string  | Cable modem MAC address.                                                    |
| `pnm_test_type`  | string  | Test type that produced the file (for example, `DS_OFDM_RXMER_PER_SUBCAR`). |
| `filename`       | string  | Saved binary filename in `.data/pnm/` (includes `.zst` or `.gz` when used). |
| `compression`    | object  | Compression metadata when stored in compressed form.                        |
| `device_details` | object  | Parsed device metadata from SNMP when available.                            |

## JSON Capture Ledger

The `.data/db/json_transactions.json` file is the ledger for JSON capture artifacts saved under `.data/json/`.
It lets PyPNM track processed JSON outputs separately from raw PNM files.

Each entry is keyed by a transaction ID and points to a JSON file created from a particular capture session.

```json
"df448ebff10d2dd203011b53": {
  "timestamp": 1760940313,
  "filename": "aabbccddeeff_example_run_1760940313_34_cmdsofdmrxmer_1760940313999999999.json",
  "byte_size": 585286,
  "sha256": "98509bf7b8dcbb01638953207e6e6691520daee16212f5ddf96bee41b7511779"
},
"94bab9dc131f173f6bdc4fe5": {
  "timestamp": 1760940313,
  "filename": "aabbccddeeff_example_run_1760940313_33_cmdsofdmrxmer_1760940313000000000.json",
  "byte_size": 586564,
  "sha256": "ed1fdc3f816e6037c1e10f4f66c4489a4ad6bc5421d93c970d7812fa456a7315"
}
```

### Field Overview

| Field       | Type    | Description                                                              |
| ---------- | ------- | ------------------------------------------------------------------------ |
| `timestamp` | integer | Unix epoch seconds when the JSON capture file was written.              |
| `filename`  | string  | JSON filename stored under `.data/json/`.                               |
| `byte_size` | integer | Size of the JSON file in bytes, used for quick sanity checks.           |
| `sha256`    | string  | SHA-256 hash of the JSON file contents for integrity and dedup checks.  |

The filename pattern generally encodes:

- Cable modem MAC address (for example, `aa:bb:cc:dd:ee:ff` as `aabbccddeeff`)
- A run label or hostname (for example, `example_run`)
- A base capture timestamp
- Channel or profile identifier (for example, `33` or `34`)
- The test name (for example, `cmdsofdmrxmer`)
- A high-resolution timestamp or unique suffix

This allows you to map JSON artifacts back to their originating modem, run, and test context.

## Summary Of Relationships

- **Operation Capture → Capture Group → Transaction (PNM binary)**  
  An **operation** references a single **capture group**, which aggregates many **transactions** in `transactions.json`. Each transaction points to a PNM file in `.data/pnm/`.

- **Transactions (PNM) → JSON Captures**  
  JSON exports derived from those PNM files are written to `.data/json/` and tracked in `json_transactions.json` with size and checksum metadata.

- **Reporting And REST Access**  
  Use the **operation ID** for API recall, the **capture group** for report generation and correlation across tests, and the **transaction IDs** (PNM and JSON) for raw file or artifact lookup.
# FILE: docs/issues/index.md
# Reporting Issues

If you encounter a bug or unexpected behavior while using PyPNM, please report it
so we can investigate and resolve the issue. This document outlines the steps to
create a support bundle that captures the necessary data for debugging.

[REPORTING ISSUES](reporting-issues.md)

## Support Bundle Script

PyPNM includes a support bundle script that collects relevant logs, database
entries, and configuration files related to your issue. This script helps
sanitize sensitive information before sharing it with the PyPNM support team.

[Support Bundle Builder](support-bundle.md)

## FAQ

Q: Why is extension data missing after processing a PNM transaction record?  
A: Ensure the transaction record includes an `extension` mapping and that the update helper merges the extension into the PNM data before returning the result.

Q: Why does US PreEq SNMP retrieval log validation errors about missing fields?  
A: Some modems return sparse or empty entries for certain indices. Ensure the device supports the table and that the entry is populated; missing required fields will cause the entry to be skipped.

Q: Why do multi US OFDMA Pre-Equalization plots show a Channel Estimation title?  
A: Update to a build that includes the plot title fix; the title now reflects the PNM file type as US PreEqualization (PNN6) or US Last PreEqualization (PNN7).

Q: Why do US OFDMA Pre-Equalization analysis examples reject uppercase analysis types?  
A: The multi-capture analysis endpoints accept the string enum values (`min-avg-max`, `group-delay`, `echo-detection-ifft`) along with the standard analysis output structure.

Q: Why do multi US OFDMA Pre-Equalization plots only show Pre-Equalization data?  
A: Ensure both Pre-Equalization (PNN6) and Last Pre-Equalization (PNN7) files are present; the multi-capture plots now emit both sets when available.

Q: Why do PNM parsers raise a UnicodeDecodeError when reading the file header?  
A: This usually means a compressed artifact was passed directly to the parser. Use the file manager download-by-filename endpoint or materialization utility to get the uncompressed file before parsing.

## TODO

- Add or update a FAQ entry whenever an error is fixed so the resolution is documented.
- Add FAQ entries when SNMP validation errors are addressed to capture the resolution.
- Track FAQ updates for the US OFDMA Pre-Equalization plot title fix.
- Track FAQ updates for the US OFDMA Pre-Equalization analysis request format.
- Track FAQ updates for the US OFDMA Pre-Equalization dual plot output.
- Track FAQ updates for UnicodeDecodeError when compressed artifacts are parsed.
# FILE: docs/system/system-config.md
# System Configuration Reference

Canonical Structure And Field Semantics For `system.json`.

* **Config file**: [`src/pypnm/settings/system.json`](https://github.com/PyPNMApps/PyPNM/blob/main/src/pypnm/settings/system.json)
* **ConfigManager class**: [`src/pypnm/config/config_manager.py`](https://github.com/PyPNMApps/PyPNM/blob/main/src/pypnm/config/config_manager.py)
* **PnmConfigManager class**: [`src/pypnm/config/pnm_config_manager.py`](https://github.com/PyPNMApps/PyPNM/blob/main/src/pypnm/config/pnm_config_manager.py)

## Table Of Contents

* [1. FastApiRequestDefault](#1-fastapirequestdefault)
* [2. SNMP](#2-snmp)
* [3. PnmBulkDataTransfer](#3-pnmbulkdatatransfer)
* [4. PnmFileRetrieval](#pnmfileretrieval)
* [5. PnmArtifactStorage](#pnmartifactstorage)
* [6. Logging](#6-logging)
* [7. TestMode](#7-testmode)
* [Loading Configuration](#loading-configuration)

## 1. FastApiRequestDefault

Default Parameters For REST Requests To The FastAPI Service.

```json
"FastApiRequestDefault": {
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "ip_address": "192.168.0.100"
}
```

| Field       | Type   | Description                       |
| ----------- | ------ | --------------------------------- |
| mac_address | string | Default device MAC address.       |
| ip_address  | string | Default device IP (IPv4 or IPv6). |

## 2. SNMP

Global SNMP Settings, Including Version-Specific Options.

```json
"SNMP": {
  "timeout": 2,
  "version": {
    "2c": {
      "enable": true,
      "retries": 3,
      "read_community": "public",
      "write_community": "private"
    },
    "3": {
      "enable": false,
      "retries": 3,
      "username": "user",
      "securityLevel": "authPriv",
      "authProtocol": "SHA",
      "authPassword": "pass",
      "privProtocol": "AES",
      "privPassword": "privpass"
    }
  }
}
```

**Top-Level**

| Field   | Type   | Description                                  |
| ------- | ------ | -------------------------------------------- |
| timeout | number | Per-request timeout (seconds).               |
| version | object | Container for v2c/v3 configuration versions. |

**SNMP v2c**

| Field           | Type    | Description                     |
| --------------- | ------- | ------------------------------- |
| enable          | boolean | Enable v2c operations.          |
| retries         | number  | Retry count on timeout/failure. |
| read_community  | string  | Community for GET/WALK.         |
| write_community | string  | Community for SET.              |

**SNMP v3**

| Field         | Type    | Description                                  |
| ------------- | ------- | -------------------------------------------- |
| enable        | boolean | Enable v3 operations.                        |
| retries       | number  | Retry count on timeout/failure.              |
| username      | string  | Security name.                               |
| securityLevel | string  | `noAuthNoPriv`, `authNoPriv`, or `authPriv`. |
| authProtocol  | string  | For example `MD5`, `SHA`.                    |
| authPassword  | string  | Required when `auth*` is used.               |
| privProtocol  | string  | For example `DES`, `AES`.                    |
| privPassword  | string  | Required when `*Priv` is used.               |

## 3. PnmBulkDataTransfer

Transport Parameters For CM-Generated Files (for example, RxMER, FEC Summary) Sent To A Server.

```json
"PnmBulkDataTransfer": {
  "method": "tftp",
  "tftp": {
    "ip_v4": "192.168.0.10",
    "ip_v6": "::1",
    "remote_dir": ""
  },
  "http": {
    "base_url": "http://files.example.com/",
    "port": 80
  },
  "https": {
    "base_url": "https://files.example.com/",
    "port": 443
  }
}
```

| Field   | Type   | Description                                                |
| ------- | ------ | ---------------------------------------------------------- |
| method  | string | Preferred bulk method: `tftp`, `http`, or `https`.         |
| tftp.*  | object | TFTP targets for IPv4/IPv6 plus optional remote directory. |
| http.*  | object | HTTP base URL and port for file delivery.                  |
| https.* | object | HTTPS base URL and port for file delivery.                 |

## 4. PnmFileRetrieval {#pnmfileretrieval}

Local Storage Layout And Remote Retrieval Methods.

Related Guide: [File Transfer Methods](pnm-file-retrieval/index.md)

```json
"PnmFileRetrieval": {
  "pnm_dir": ".data/pnm",
  "csv_dir": ".data/csv",
  "json_dir": ".data/json",
  "xlsx_dir": ".data/xlsx",
  "png_dir": ".data/png",
  "archive_dir": ".data/archive",
  "msg_rsp_dir": ".data/msg_rsp",
  "transaction_db": ".data/db/transactions.json",
  "capture_group_db": ".data/db/capture_group.json",
  "session_group_db": ".data/db/session_group.json",
  "operation_db": ".data/db/operation_capture.json",
  "json_transaction_db": ".data/db/json_transactions.json",
  "retries": 5,
  "retrieval_method": {
    "method": "local",
    "methods": {
      "local": {
        "src_dir": "/srv/tftp"
      },
      "tftp": {
        "host": "localhost",
        "port": 69,
        "timeout": 5,
        "remote_dir": ""
      },
      "ftp": {
        "host": "localhost",
        "port": 21,
        "tls": false,
        "timeout": 5,
        "user": "user",
        "password_enc": "",
        "remote_dir": "/srv/tftp"
      },
      "sftp": {
        "host": "localhost",
        "port": 22,
        "user": "user",
        "password_enc": "",
        "private_key_path": "",
        "remote_dir": "/srv/tftp"
      },
      "http": {
        "base_url": "http://STUB/",
        "port": 80
      },
      "https": {
        "base_url": "https://STUB/",
        "port": 443
      }
    }
  }
}
```

`password_enc` is the only supported password field for file retrieval methods. Plaintext `password` is not supported.

**Directories And Databases**

| Field               | Type   | Description                                  |
| ------------------- | ------ | -------------------------------------------- |
| pnm_dir             | string | Local storage for raw PNM binaries.          |
| csv_dir             | string | Local storage for derived CSVs.              |
| json_dir            | string | Local storage for derived JSON.              |
| xlsx_dir            | string | Local storage for Excel reports.             |
| png_dir             | string | Local storage for generated PNGs.            |
| archive_dir         | string | Local storage for analysis ZIP archives.     |
| msg_rsp_dir         | string | Local storage for message/response metadata. |
| transaction_db      | string | JSON ledger of file transactions.            |
| capture_group_db    | string | JSON map of grouped transactions.            |
| session_group_db    | string | JSON map of session groups.                  |
| operation_db        | string | JSON map of operation to capture group.      |
| json_transaction_db | string | JSON map of JSON transaction metadata.       |

**Retrieval Settings**

| Field                                  | Type   | Description                                                           |
| -------------------------------------- | ------ | --------------------------------------------------------------------- |
| retrieval_method.method                 | string | Active retrieval method: `local`, `tftp`, `ftp`, `sftp`, `http`, `https`. |
| retrieval_method.methods.local.src_dir  | string | Source directory to watch/copy from when using `local`.               |
| retrieval_method.methods.tftp.*         | object | TFTP host/port/timeout and remote directory.                          |
| retrieval_method.methods.ftp.*          | object | FTP connection, credentials, and remote directory.                    |
| retrieval_method.methods.sftp.*         | object | SFTP connection and remote directory.                                 |
| retrieval_method.methods.http.*         | object | HTTP base URL and port.                                               |
| retrieval_method.methods.https.*        | object | HTTPS base URL and port.                                              |
| retries                                | number | Max attempts per retrieval operation.                                 |

> The legacy key name `retrival_method` is accepted for backward compatibility.

## 5. PnmArtifactStorage {#pnmartifactstorage}

Policy-Driven Compression And Cache Settings For `.data/pnm` Artifacts And `/tmp` Materialization.

```json
"PnmArtifactStorage": {
  "compression": {
    "enabled": true,
    "min_bytes": 4096,
    "conditional_max_ratio": 0.92,
    "conditional_min_savings_bytes": 8192,
    "deny": [
      "ds_ofdm_chan_est_coef"
    ],
    "always": [
      "ds_ofdm_codeword_error_rate",
      "ds_ofdm_modulation_profile"
    ],
    "conditional": [
      "ds_ofdm_rxmer_per_subcar",
      "us_pre_equalizer_coef"
    ],
    "primary_codec": "zstd",
    "gzip_fallback": true,
    "zstd_level": 3,
    "gzip_level": 6
  },
  "cache": {
    "tmp_root": "/tmp/pypnm",
    "ingress_dir": "ingress",
    "materialized_dir": "materialized",
    "ingress_ttl_seconds": 900,
    "materialized_ttl_seconds": 86400,
    "cleanup_interval_seconds": 3600
  }
}
```

**Compression Policy**

| Field                         | Type   | Description                                          |
| ----------------------------- | ------ | ---------------------------------------------------- |
| enabled                       | bool   | Enables compression decisions for PNM artifacts.     |
| min_bytes                     | int    | Skip compression below this size (bytes).            |
| conditional_max_ratio         | float  | Max compressed/original ratio for conditional types. |
| conditional_min_savings_bytes | int    | Minimum byte savings for conditional compression.    |
| deny                          | array  | PNM types that never compress.                       |
| always                        | array  | PNM types that always compress.                      |
| conditional                   | array  | PNM types that compress if thresholds are met.       |
| primary_codec                 | string | Primary codec (`zstd`).                              |
| gzip_fallback                 | bool   | Allow gzip when zstd is unavailable.                 |
| zstd_level                    | int    | Zstd compression level.                              |
| gzip_level                    | int    | Gzip compression level.                              |

**Cache Settings**

| Field                    | Type   | Description                                     |
| ------------------------ | ------ | ----------------------------------------------- |
| tmp_root                 | string | Root directory for ingress/materialized caches. |
| ingress_dir              | string | Ingress cache directory name under tmp_root.    |
| materialized_dir         | string | Materialized cache directory name under tmp_root. |
| ingress_ttl_seconds      | int    | TTL for ingress cache content.                  |
| materialized_ttl_seconds | int    | TTL for materialized cache content.             |
| cleanup_interval_seconds | int    | Minimum seconds between opportunistic cleanups. |

## 6. Logging

Application Logging Options.

```json
"logging": {
  "log_level": "INFO",
  "log_dir": "logs",
  "log_filename": "pypnm.log"
}
```

| Field        | Type   | Description                                 |
| ------------ | ------ | ------------------------------------------- |
| log_level    | string | `DEBUG`, `INFO`, `WARN`, or `ERROR`.        |
| log_dir      | string | Directory for log files.                    |
| log_filename | string | Log filename (created under `log_dir`).     |

## 7. TestMode

Global And Class-Specific Test-Mode Controls.

```json
"TestMode": {
  "global": {
    "mode": {
      "enable": true
    }
  },
  "class_name": {
    "DsScQamChannelSpectrumAnalyzer": {
      "mode": {
        "enable": true
      }
    }
  }
}
```

| Field                          | Type    | Description                                            |
| ------------------------------ | ------- | ------------------------------------------------------ |
| global.mode.enable             | boolean | Enable or disable global test mode.                    |
| class_name.<Class>.mode.enable | boolean | Per-class override for test mode, keyed by class name. |

## Loading Configuration

Typical Access Pattern Using The Manager Abstractions.

```python
from pypnm.config.config_manager import ConfigManager
from pypnm.config.pnm_config_manager import PnmConfigManager

cfg = ConfigManager()

mac = cfg.get("FastApiRequestDefault", "mac_address")
ip  = cfg.get("FastApiRequestDefault", "ip_address")

pnm_cfg = PnmConfigManager()
tftp_v4 = pnm_cfg.get("PnmBulkDataTransfer", "tftp")["ip_v4"]
```
# FILE: install.sh
#!/usr/bin/env bash
set -euo pipefail

# ────────────────────────────────────────────────────────────────────────────────
# install.sh — Unified OS prerequisite installer and PyPNM bootstrapper
# Usage: ./install.sh [--demo-mode | --production] [--pnm-file-retrieval-setup] [venv_dir]
# ────────────────────────────────────────────────────────────────────────────────

VENV_DIR=".env"
DEMO_MODE="0"
PRODUCTION_MODE="0"
PNM_FILE_RETRIEVAL_SETUP="0"
DEVELOPMENT_MODE="0"
CLEAN_MODE="0"
PURGE_CACHE="0"
UNINSTALL_MODE="0"
GITLEAKS_VERSION="8.18.1"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}"
BANNER_PATH="${PROJECT_ROOT}/tools/banner.txt"

if [[ -f "${BANNER_PATH}" ]]; then
  cat "${BANNER_PATH}"
  echo
fi

usage() {
  cat <<EOF
PyPNM Installer And Bootstrap Script

Usage:
  ./install.sh [--demo-mode | --production] [--pnm-file-retrieval-setup] [venv_dir]
  ./install.sh --development
  ./install.sh --clean [--purge-cache]
  ./install.sh --uninstall [venv_dir]
  ./install.sh --help

Options:
  --development  Install Docker Engine + kind/kubectl + gitleaks for local dev and release workflows.
  --clean        Remove prior install artifacts (venv/build/dist/cache) before installing.
  --purge-cache  Clear pip cache after activating the venv (use with --clean when needed).
  --uninstall    Remove local install artifacts and the secrets key at ~/.ssh/pypnm_secrets.key.

  --demo-mode     Enable demo mode by backing up the default
                  src/pypnm/settings/system.json into backup/src/pypnm/settings/system.json
                  and replacing it with demo/settings/system.json. The demo system.json
                  should point all relevant directories to the demo/ tree.

  --production    Revert to production settings by restoring the backed-up
                  backup/src/pypnm/settings/system.json back to
                  src/pypnm/settings/system.json. This assumes a prior backup exists
                  (created by running with --demo-mode or a normal install).

  --pnm-file-retrieval-setup
                  After installation completes, attempt to run the interactive
                  PNM File Retrieval setup helper:

                      tools/pnm/pnm_file_retrieval_setup.py

                  This lets you choose how PyPNM retrieves PNM files:
                  local / tftp / ftp / scp / sftp / http / https.

                  For CI safety, this step is only executed when:
                    • stdin is a TTY (real terminal), and
                    • CI/GITHUB_ACTIONS are not set.
                  In CI environments, the option is acknowledged but skipped.

  venv_dir        Optional virtual environment directory name. Defaults to ".env".

  --help, -h      Show this help message and exit.

Examples:
  ./install.sh
      Create a venv in ".env" and install PyPNM with dev/docs extras.

  ./install.sh .pyenv
      Create a venv in ".pyenv" instead of ".env".

  ./install.sh --demo-mode
      Install and then switch system.json to the demo configuration
      (backing up the current system.json first).

  ./install.sh --development
      Install Docker Engine + kind/kubectl + gitleaks so release smoke tests can run.
      Tested on Ubuntu 22.04/24.04.

  ./install.sh --clean
      Remove previous install artifacts and rebuild the venv (preserves .data/ and
      src/pypnm/settings/system.json).

  ./install.sh --clean --purge-cache
      Remove previous install artifacts and clear pip cache before reinstalling.

  ./install.sh --uninstall
      Remove local install artifacts and the secrets key at ~/.ssh/pypnm_secrets.key.

  ./install.sh --demo-mode .env-demo
      Create a venv in ".env-demo" and enable demo-mode system.json.

  ./install.sh --production
      Install and then restore system.json from the backup tree, returning
      the configuration to production mode.

  ./install.sh --pnm-file-retrieval-setup
      Install and then invoke the PNM File Retrieval setup helper at the end,
      when running in an interactive, non-CI environment.

After installation, you can also configure how PyPNM retrieves PNM files
(local/TFTP/FTP/SCP/SFTP/HTTP/HTTPS) manually by running:

  ./tools/pnm/pnm_file_retrieval_setup.py
EOF
}

for arg in "$@"; do
  case "$arg" in
    --demo-mode)
      DEMO_MODE="1"
      ;;
    --production)
      PRODUCTION_MODE="1"
      ;;
    --pnm-file-retrieval-setup)
      PNM_FILE_RETRIEVAL_SETUP="1"
      ;;
    --development)
      DEVELOPMENT_MODE="1"
      ;;
    --clean)
      CLEAN_MODE="1"
      ;;
    --purge-cache)
      PURGE_CACHE="1"
      ;;
    --uninstall)
      UNINSTALL_MODE="1"
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      VENV_DIR="$arg"
      ;;
  esac
done

if [[ "$UNINSTALL_MODE" == "1" ]]; then
  if [[ "$DEMO_MODE" == "1" || "$PRODUCTION_MODE" == "1" || "$PNM_FILE_RETRIEVAL_SETUP" == "1" || "$DEVELOPMENT_MODE" == "1" || "$CLEAN_MODE" == "1" || "$PURGE_CACHE" == "1" ]]; then
    echo "❌ --uninstall cannot be combined with other flags."
    usage
    exit 1
  fi
fi

if [[ "$DEMO_MODE" == "1" && "$PRODUCTION_MODE" == "1" ]]; then
  echo "❌ Cannot use --demo-mode and --production together."
  usage
  exit 1
fi

clean_previous_install() {
  echo "🧹 Cleaning previous install artifacts..."

  local remove_paths=(
    "${PROJECT_ROOT}/${VENV_DIR}"
    "${PROJECT_ROOT}/build"
    "${PROJECT_ROOT}/dist"
    "${PROJECT_ROOT}/.pytest_cache"
    "${PROJECT_ROOT}/.ruff_cache"
    "${PROJECT_ROOT}/.mypy_cache"
    "${PROJECT_ROOT}/.pyright"
    "${PROJECT_ROOT}/.coverage"
    "${PROJECT_ROOT}/htmlcov"
    "${PROJECT_ROOT}/test_reports"
  )

  for path in "${remove_paths[@]}"; do
    if [[ -e "${path}" ]]; then
      echo "🗑️  Removing ${path}"
      rm -rf "${path}"
    fi
  done

  find "${PROJECT_ROOT}" -maxdepth 2 -name "*.egg-info" -type d -print0 | while IFS= read -r -d '' item; do
    echo "🗑️  Removing ${item}"
    rm -rf "${item}"
  done

  echo "ℹ️  Preserving ${PROJECT_ROOT}/.data and ${PROJECT_ROOT}/src/pypnm/settings/system.json"
}

install_gitleaks() {
  if command -v gitleaks >/dev/null 2>&1; then
    echo "✅ gitleaks already installed."
    return
  fi

  if [[ "$PM" == "none" ]]; then
    echo "⚠️  gitleaks not found and no package manager available."
    echo "    Install manually: https://github.com/gitleaks/gitleaks"
    return
  fi

  echo "🔧 Installing gitleaks..."
  case "$PM" in
    apt-get) $PM_INSTALL gitleaks || true ;;
    dnf|yum) $PM_INSTALL gitleaks || true ;;
    zypper)  $PM_INSTALL gitleaks || true ;;
    apk)     $PM_INSTALL gitleaks || true ;;
    brew)    $PM_INSTALL gitleaks || true ;;
    *)
      echo "⚠️  Unknown package manager; install gitleaks manually."
      echo "    https://github.com/gitleaks/gitleaks"
      return
      ;;
  esac

  if ! command -v gitleaks >/dev/null 2>&1; then
    if ! command -v curl >/dev/null 2>&1; then
      echo "⚠️  gitleaks install did not complete (curl missing)."
      echo "    Install manually: https://github.com/gitleaks/gitleaks"
      return
    fi
    if ! command -v tar >/dev/null 2>&1; then
      echo "⚠️  gitleaks install did not complete (tar missing)."
      echo "    Install manually: https://github.com/gitleaks/gitleaks"
      return
    fi

    local os arch filename url tmp_dir target_dir bin_path
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    case "$os" in
      linux|darwin) ;;
      *)
        echo "⚠️  Unsupported OS for gitleaks auto-install: ${os}"
        echo "    Install manually: https://github.com/gitleaks/gitleaks"
        return
        ;;
    esac

    arch="$(uname -m)"
    case "$arch" in
      x86_64|amd64) arch="x64" ;;
      aarch64|arm64) arch="arm64" ;;
      *)
        echo "⚠️  Unsupported architecture for gitleaks auto-install: ${arch}"
        echo "    Install manually: https://github.com/gitleaks/gitleaks"
        return
        ;;
    esac

    filename="gitleaks_${GITLEAKS_VERSION}_${os}_${arch}.tar.gz"
    url="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${filename}"
    tmp_dir="$(mktemp -d)"
    echo "⬇️  Downloading gitleaks ${GITLEAKS_VERSION}..."
    if ! curl -fsSL "${url}" -o "${tmp_dir}/${filename}"; then
      echo "⚠️  Failed to download gitleaks from ${url}"
      echo "    Install manually: https://github.com/gitleaks/gitleaks"
      rm -rf "${tmp_dir}"
      return
    fi

    if ! tar -xzf "${tmp_dir}/${filename}" -C "${tmp_dir}"; then
      echo "⚠️  Failed to extract gitleaks archive."
      echo "    Install manually: https://github.com/gitleaks/gitleaks"
      rm -rf "${tmp_dir}"
      return
    fi

    bin_path="${tmp_dir}/gitleaks"
    if [[ ! -f "${bin_path}" ]]; then
      echo "⚠️  gitleaks binary not found after extraction."
      echo "    Install manually: https://github.com/gitleaks/gitleaks"
      rm -rf "${tmp_dir}"
      return
    fi

    target_dir="/usr/local/bin"
    if [[ -w "${target_dir}" ]]; then
      install -m 0755 "${bin_path}" "${target_dir}/gitleaks"
    elif command -v sudo >/dev/null 2>&1; then
      sudo install -m 0755 "${bin_path}" "${target_dir}/gitleaks"
    else
      target_dir="${HOME}/.local/bin"
      mkdir -p "${target_dir}"
      install -m 0755 "${bin_path}" "${target_dir}/gitleaks"
      echo "ℹ️  Added gitleaks to ${target_dir}; ensure it's on PATH."
    fi

    rm -rf "${tmp_dir}"
    if ! command -v gitleaks >/dev/null 2>&1; then
      echo "⚠️  gitleaks install did not complete."
      echo "    Install manually: https://github.com/gitleaks/gitleaks"
      return
    fi
  fi
}

remove_secrets_key() {
  local secrets_key_path
  secrets_key_path="${HOME}/.ssh/pypnm_secrets.key"

  if [[ -f "${secrets_key_path}" ]]; then
    echo "🗑️  Removing ${secrets_key_path}"
    rm -f "${secrets_key_path}"
  else
    echo "ℹ️  Secret key not found at ${secrets_key_path}"
  fi
}

uninstall_pypnm() {
  echo "🧹 Uninstalling PyPNM artifacts..."
  clean_previous_install
  remove_secrets_key
  echo "✅ Uninstall complete."
}

if [[ "$UNINSTALL_MODE" == "1" ]]; then
  uninstall_pypnm
  exit 0
fi

backup_system_settings() {
  echo "🗂  Creating backup of system settings…"
  local backup_root
  backup_root="${PROJECT_ROOT}/backup"
  local src_path
  src_path="${PROJECT_ROOT}/src/pypnm/settings/system.json"
  local dst_path
  dst_path="${backup_root}/src/pypnm/settings/system.json"

  if [[ ! -f "$src_path" ]]; then
    echo "⚠️  System settings file not found at '$src_path'; skipping backup."
    return
  fi

  mkdir -p "$(dirname "$dst_path")"
  cp "$src_path" "$dst_path"
  echo "✅ Backup created at '$dst_path'."
}

restore_system_settings() {
  echo "🗂  Restoring system settings from backup…"
  local backup_root
  backup_root="${PROJECT_ROOT}/backup"
  local backup_path
  backup_path="${backup_root}/src/pypnm/settings/system.json"
  local target
  target="${PROJECT_ROOT}/src/pypnm/settings/system.json"

  if [[ ! -f "$backup_path" ]]; then
    echo "⚠️  Backup system settings not found at '$backup_path'; cannot restore."
    return
  fi

  mkdir -p "$(dirname "$target")"
  cp "$backup_path" "$target"
  echo "✅ System settings restored from backup to '$target'."
}

enable_demo_mode() {
  echo "🎛  Enabling demo mode configuration…"
  local demo_src
  demo_src="${PROJECT_ROOT}/demo/settings/system.json"
  local target
  target="${PROJECT_ROOT}/src/pypnm/settings/system.json"

  if [[ ! -f "$demo_src" ]]; then
    echo "⚠️  Demo settings file not found at '$demo_src'; skipping demo mode."
    return
  fi

  if [[ -f "$target" ]]; then
    echo "ℹ️  Overwriting existing system settings at '$target' with demo template."
  else
    echo "ℹ️  Creating system settings at '$target' from demo template."
  fi

  mkdir -p "$(dirname "$target")"
  cp "$demo_src" "$target"
  echo "✅ Demo mode system settings applied (directories now point to demo/)."
}

echo "🔍 Detecting package manager..."
PM="none"; PM_UPDATE=""; PM_INSTALL=""
if command -v apt-get >/dev/null 2>&1; then
  PM="apt-get"; PM_UPDATE="sudo apt-get update"; PM_INSTALL="sudo apt-get install -y"
  echo "ℹ️  Debian/Ubuntu (apt-get)"
elif command -v dnf >/dev/null 2>&1; then
  PM="dnf"; PM_UPDATE="sudo dnf makecache"; PM_INSTALL="sudo dnf install -y"
  echo "ℹ️  Fedora/RHEL (dnf)"
elif command -v yum >/dev/null 2>&1; then
  PM="yum"; PM_UPDATE="sudo yum makecache"; PM_INSTALL="sudo yum install -y"
  echo "ℹ️  RHEL/CentOS (yum)"
elif command -v zypper >/dev/null 2>&1; then
  PM="zypper"; PM_UPDATE="sudo zypper refresh"; PM_INSTALL="sudo zypper install -y"
  echo "ℹ️  SUSE/openSUSE (zypper)"
elif command -v apk >/dev/null 2>&1; then
  PM="apk"; PM_UPDATE=""; PM_INSTALL="sudo apk add --no-cache"
  echo "ℹ️  Alpine (apk)"
elif command -v brew >/dev/null 2>&1; then
  PM="brew"; PM_UPDATE="brew update"; PM_INSTALL="brew install"
  echo "ℹ️  macOS (brew)"
else
  echo "⚠️  Unsupported OS: please manually install 'ssh', 'sshpass', and Python venv support."
fi

if [[ "$PM" != "none" && -n "${PM_UPDATE:-}" ]]; then
  echo "🔄 Updating package cache..."
  $PM_UPDATE || true
fi

echo "✅ Installing OS prerequisites..."
if ! command -v ssh >/dev/null 2>&1; then
  if [[ "$PM" == "none" ]]; then
    echo "⚠️  No package manager; cannot auto-install 'ssh'."
  else
    echo "🔧 Installing ssh..."
    case "$PM" in
      apt-get) $PM_INSTALL openssh-client ;;
      dnf|yum) $PM_INSTALL openssh-clients ;;
      zypper)  $PM_INSTALL openssh ;;
      apk)     $PM_INSTALL openssh ;;
      brew)    $PM_INSTALL openssh ;;
    esac
  fi
fi

if ! command -v sshpass >/dev/null 2>&1; then
  if [[ "$PM" == "none" ]]; then
    echo "⚠️  No package manager; cannot auto-install 'sshpass'."
  else
    echo "🔧 Installing sshpass..."
    $PM_INSTALL sshpass || true
  fi
fi

echo "🧮 Ensuring SciPy/NumPy build prerequisites (where applicable)..."
case "$PM" in
  apt-get)
    $PM_INSTALL build-essential gfortran libopenblas-dev liblapack-dev || true
    ;;
  dnf|yum)
    $PM_INSTALL gcc gcc-c++ make blas-devel lapack-devel || true
    ;;
  zypper)
    $PM_INSTALL gcc gcc-c++ make libopenblas-devel lapack-devel || true
    ;;
  apk)
    $PM_INSTALL build-base gfortran openblas-dev lapack-dev || true
    ;;
  brew)
    # Homebrew wheels usually bundle BLAS/LAPACK; nothing extra required in most cases.
    :
    ;;
  *)
    echo "⚠️  Skipping SciPy/NumPy build prerequisites for unknown or manual PM."
    ;;
esac

if [[ "$DEVELOPMENT_MODE" == "1" ]]; then
  echo "🧰 Development setup: Docker + kind/kubectl + gitleaks..."
  if [[ "$PM" == "brew" ]]; then
    echo "⚠️  macOS does not support the Docker/kind bootstrap in this script."
    echo "    Skipping Docker/kind install; running gitleaks setup only."
    install_gitleaks
  else
  if ! command -v curl >/dev/null 2>&1; then
    if [[ "$PM" == "none" ]]; then
      echo "❌ curl not found and no package manager available."
      exit 1
    fi
    echo "🔧 Installing curl..."
    case "$PM" in
      apt-get) $PM_INSTALL curl ;;
      dnf|yum) $PM_INSTALL curl ;;
      zypper)  $PM_INSTALL curl ;;
      apk)     $PM_INSTALL curl ;;
      brew)    $PM_INSTALL curl ;;
    esac
  fi

  if [[ "$PM" == "apt-get" ]]; then
    bash "${PROJECT_ROOT}/tools/docker/install-docker-ubuntu.sh"
  else
    echo "⚠️  --development is tested on Ubuntu 22.04/24.04; continuing with kind/kubectl install."
    echo "    Install Docker manually for your OS, then re-run if needed."
  fi

  bash "${PROJECT_ROOT}/tools/k8s/pypnm_kind_vm_bootstrap.sh"
  install_gitleaks
  echo "ℹ️  Docker may require: sudo systemctl start docker"
  echo "ℹ️  For non-sudo Docker: sudo usermod -aG docker \"${USER}\" (then log out/in)"
  fi
fi

if ! command -v python3 >/dev/null 2>&1; then
  if [[ "$PM" == "none" ]]; then
    echo "❌ Python 3.x not found in PATH."
    exit 1
  fi
  echo "🔧 Installing Python 3..."
  case "$PM" in
    apt-get) $PM_INSTALL python3 ;;
    dnf|yum) $PM_INSTALL python3 ;;
    zypper)  $PM_INSTALL python3 ;;
    apk)     $PM_INSTALL python3 ;;
    brew)    $PM_INSTALL python ;;
  esac
fi

PYTHON_VERSION="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "3")"
PYTHON_CMD="python${PYTHON_VERSION}"
if ! command -v "$PYTHON_CMD" >/dev/null 2>&1; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python3"
  else
    echo "❌ Python 3.x not found in PATH."
    exit 1
  fi
fi

echo "🔧 Ensuring venv support is available..."
case "$PM" in
  apt-get) $PM_INSTALL "python${PYTHON_VERSION}-venv" || true ;;
  dnf|yum) $PM_INSTALL python3-virtualenv || true ;;
  zypper)  $PM_INSTALL python3-virtualenv || true ;;
  apk)     $PM_INSTALL python3 || true ;;
  brew)    $PM_INSTALL python || true ;;
  *)       echo "⚠️  Skipping venv package install for unknown PM." ;;
esac

if [[ "$CLEAN_MODE" == "1" ]]; then
  clean_previous_install
fi

echo "🛠  Creating virtual environment in '$VENV_DIR'…"
"$PYTHON_CMD" -m venv "$VENV_DIR"

echo "🚀 Activating '$VENV_DIR'…"
# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"

echo "⬆️  Upgrading pip, setuptools, wheel…"
pip install --upgrade pip setuptools wheel

if [[ "$PURGE_CACHE" == "1" ]]; then
  echo "🧽 Purging pip cache..."
  pip cache purge || true
fi

echo "📥 Installing PyPNM extras: dev + docs…"
pip install -e "${PROJECT_ROOT}[dev,docs]"

echo "📦 Installing required tooling: pytest, mkdocs, mkdocs-material, cryptography…"
pip install "pytest>=7" "mkdocs>=1.6" "mkdocs-material>=9.5" "cryptography>=41"

echo "🔎 Verifying MkDocs install…"
mkdocs --version

echo "🔧 Configuring PYTHONPATH…"
"$PROJECT_ROOT/scripts/install_py_path.sh" "$PROJECT_ROOT" || true

echo "🔐 Ensuring PyPNM secret key exists (~/.ssh/pypnm_secrets.key)…"
if [[ -n "${CI:-}" || -n "${GITHUB_ACTIONS:-}" ]]; then
  echo "ℹ️  Skipping secret key creation (CI environment)."
  echo "    Create it locally with:"
  echo "      ./scripts/init_secrets_key.sh"
else
  if [[ -x "${PROJECT_ROOT}/scripts/init_secrets_key.sh" ]]; then
    "${PROJECT_ROOT}/scripts/init_secrets_key.sh" --quiet || true
  else
    echo "ℹ️  scripts/init_secrets_key.sh is missing or not executable; skipping."
  fi
fi

echo "🧪 Running unit tests…"
cd "$PROJECT_ROOT"
pytest -v

if [[ "$PRODUCTION_MODE" == "1" ]]; then
  restore_system_settings
elif [[ "$DEMO_MODE" == "1" ]]; then
  backup_system_settings
  enable_demo_mode
else
  backup_system_settings
fi

###############################################################################
# Optional: PNM File Retrieval Setup (CI-Safe)
#
# Behavior:
#   - If --pnm-file-retrieval-setup was passed:
#       • Attempt to run tools/pnm/pnm_file_retrieval_setup.py automatically
#         when in an interactive, non-CI environment.
#       • If in CI or non-TTY, print a message and skip.
#
#   - If the flag was NOT passed:
#       • Do NOT prompt interactively.
#       • Just print a short message about the manual helper.
###############################################################################
run_pnm_setup_if_possible() {
  if [[ ! -t 0 || -n "${CI:-}" || -n "${GITHUB_ACTIONS:-}" ]]; then
    echo "ℹ️  Skipping PNM file retrieval setup (non-interactive or CI environment)."
    echo "    You can run it later with:"
    echo "      ./tools/pnm/pnm_file_retrieval_setup.py"
    return
  fi

  if [[ -x "./tools/pnm/pnm_file_retrieval_setup.py" ]]; then
    echo
    echo "Launching PNM file retrieval setup..."
    ./tools/pnm/pnm_file_retrieval_setup.py
  else
    echo "tools/pnm/pnm_file_retrieval_setup.py is missing or not executable."
    echo "You can run it manually later once it is available:"
    echo "  ./tools/pnm/pnm_file_retrieval_setup.py"
  fi
}

run_pnm_alias_installer_if_available() {
  if [[ -x "${PROJECT_ROOT}/scripts/install_aliases.sh" ]]; then
    echo "🔗 Installing PyPNM shell aliases (e.g., config-menu)…"
    "${PROJECT_ROOT}/scripts/install_aliases.sh" || true
  fi
}

run_tmp_cleanup_cron_installer_if_available() {
  if [[ -x "${PROJECT_ROOT}/scripts/install-tmp-cleanup-cron.sh" ]]; then
    echo "🧹 Installing tmp cache cleanup cron job..."
    "${PROJECT_ROOT}/scripts/install-tmp-cleanup-cron.sh" || true
  fi
}

if [[ "$PNM_FILE_RETRIEVAL_SETUP" == "1" ]]; then
  echo
  echo "PNM File Retrieval Configuration (requested via --pnm-file-retrieval-setup)"
  run_pnm_setup_if_possible
else
  echo
  echo "ℹ️  PNM file retrieval setup was not requested."
  echo "    You can configure it later with:"
  echo "      ./tools/pnm/pnm_file_retrieval_setup.py"
fi

run_pnm_alias_installer_if_available
run_tmp_cleanup_cron_installer_if_available

echo "✅ Bootstrap complete."
if [[ "$DEMO_MODE" == "1" ]]; then
  echo "👉 Demo mode is enabled: system settings now reference the demo/ directories."
fi
if [[ "$PRODUCTION_MODE" == "1" ]]; then
  echo "👉 Production mode is restored: system settings have been reverted from backup."
fi
echo "👉 Next steps:"
echo "   1) source '$VENV_DIR/bin/activate'"
echo "   2) (optional) ./tools/pnm/pnm_file_retrieval_setup.py"
echo "   3) mkdocs serve"
# FILE: scripts/install-tmp-cleanup-cron.sh
#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRON_TAG="pypnm-tmp-cache-cleanup"
CRON_SCHEDULE="0 * * * *"

VENV_ACTIVATE="${PROJECT_ROOT}/.env/bin/activate"
if [[ -f "${VENV_ACTIVATE}" ]]; then
  CRON_CMD="cd ${PROJECT_ROOT} && . ${VENV_ACTIVATE} >/dev/null 2>&1 && python3 -m pypnm.tools.tmp_cache_cleanup"
else
  CRON_CMD="cd ${PROJECT_ROOT} && python3 -m pypnm.tools.tmp_cache_cleanup"
fi

EXISTING="$(crontab -l 2>/dev/null || true)"
if echo "${EXISTING}" | grep -q "${CRON_TAG}"; then
  echo "Tmp cache cleanup cron is already installed."
  exit 0
fi

( echo "${EXISTING}"; echo "${CRON_SCHEDULE} ${CRON_CMD} # ${CRON_TAG}" ) | crontab -

echo "Installed tmp cache cleanup cron: ${CRON_SCHEDULE} ${CRON_CMD}"
# FILE: src/pypnm/api/routes/advance/analysis/signal_analysis/multi_ofdma_pre_eq_signal_analysis.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pypnm.api.routes.advance.analysis.signal_analysis.multi_ofdm_chan_signal_analysis import (
    ChannelComplexMap,
    ChannelFrequencyMap,
    ChannelOccupiedBwMap,
    MultiOfdmChanSignalAnalysis,
)
from pypnm.api.routes.advance.common.capture_data_aggregator import (
    CaptureDataAggregator,
)
from pypnm.api.routes.advance.common.transactionsCollection import (
    TransactionCollectionModel,
)
from pypnm.api.routes.common.classes.analysis.analysis import Analysis
from pypnm.api.routes.common.classes.analysis.model.schema import (
    UsOfdmaUsPreEqAnalysisModel,
)
from pypnm.lib.matplot.manager import MatplotManager
from pypnm.lib.types import (
    ChannelId,
    ComplexArray,
    FrequencyHz,
    FrequencySeriesHz,
    StringEnum,
)
from pypnm.pnm.parser.CmUsOfdmaPreEq import CmUsOfdmaPreEq
from pypnm.pnm.parser.pnm_file_type import PnmFileType


class MultiOfdmaPreEqAnalysisType(StringEnum):
    """Enumeration Of Supported Multi-OFDMA-Pre-EQ Analysis Types."""
    MIN_AVG_MAX         = "min-avg-max"
    GROUP_DELAY         = "group-delay"
    ECHO_DETECTION_IFFT = "echo-detection-ifft"


class MultiOfdmaPreEqSignalAnalysis(MultiOfdmChanSignalAnalysis):
    """Performs signal-quality analyses on grouped OFDMA Pre-EQ captures."""

    def __init__(self, capt_data_agg: CaptureDataAggregator, analysis_type: StringEnum) -> None:
        """
        Initialize Multi-OFDMA Pre-EQ analysis state.

        Parameters
        ----------
        capt_data_agg:
            Aggregator providing access to capture records for analysis.
        analysis_type:
            Requested analysis mode to run across the aggregated captures.
        """
        super().__init__(capt_data_agg, analysis_type)
        self._file_type_by_channel: dict[ChannelId, PnmFileType] = {}
        self._available_file_types: set[PnmFileType] = set()
        self._filter_file_type: PnmFileType | None = None

    def _parse_capture(
        self,
        tcm: TransactionCollectionModel,
    ) -> tuple[ChannelId, ComplexArray, FrequencySeriesHz, FrequencyHz, PnmFileType] | None:
        try:
            model = CmUsOfdmaPreEq(tcm.data).to_model()
            result: UsOfdmaUsPreEqAnalysisModel = Analysis.basic_analysis_us_ofdma_pre_equalization_from_model(model)

            try:
                file_type = PnmFileType.fromPnmHeaderModel(model.pnm_header)
            except KeyError as exc:
                self.logger.warning(f"OFDMA pre-eq unknown file type for {tcm.filename}: {exc}")
                file_type = PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS

            self._available_file_types.add(file_type)
            if self._filter_file_type is not None and file_type != self._filter_file_type:
                return None

        except Exception as e:
            self.logger.error(f"OFDMA pre-eq analysis parse failed: {e}")
            return None

        return (
            ChannelId(result.channel_id),
            result.carrier_values.complex,
            result.carrier_values.frequency,
            result.carrier_values.occupied_channel_bandwidth,
            file_type,
        )

    def _extract_channel_data(self) -> tuple[ChannelComplexMap, ChannelFrequencyMap, ChannelOccupiedBwMap]:
        """Collect OFDMA Pre-EQ capture data into analysis-ready maps."""
        channel_data: ChannelComplexMap = {}
        freqs: ChannelFrequencyMap = {}
        obw: ChannelOccupiedBwMap = {}
        self._file_type_by_channel = {}
        self._available_file_types = set()
        models = self._trans_collect.getTransactionCollectionModel()
        self.logger.info(f"OFDMA Pre-EQ captures: count={len(models)}")

        for tcm in models:
            parsed = self._parse_capture(tcm)
            if parsed is None:
                self.logger.debug(f"OFDMA Pre-EQ parse skipped: file={tcm.filename} size={len(tcm.data)}")
                continue

            ch, complex_values, frequency, bandwidth, file_type = parsed
            self.logger.debug(f"OFDMA Pre-EQ parsed: file={tcm.filename} ch={ch} carriers={len(complex_values)}")
            if complex_values:
                channel_data.setdefault(ch, []).append(complex_values)
            freqs[ch] = frequency
            obw[ch] = bandwidth
            existing = self._file_type_by_channel.get(ch)
            if existing is None:
                self._file_type_by_channel[ch] = file_type
            else:
                if existing != file_type:
                    self.logger.warning(
                        "OFDMA pre-eq file type mismatch: channel=%s existing=%s new=%s",
                        ch,
                        existing.name,
                        file_type.name,
                    )
                    if file_type == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE:
                        self._file_type_by_channel[ch] = file_type

        return channel_data, freqs, obw

    def _ordered_file_types(self) -> list[PnmFileType]:
        return [
            PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS,
            PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE,
        ]

    def _collect_available_file_types(self) -> list[PnmFileType]:
        if not self._available_file_types:
            self._extract_channel_data()
        return [ft for ft in self._ordered_file_types() if ft in self._available_file_types]

    def _set_file_type_filter(self, file_type: PnmFileType | None) -> None:
        self._filter_file_type = file_type
        self._results = None
        self._channel_data = None
        self._file_type_by_channel = {}
        self._available_file_types = set()

    def _plot_title_prefix(self, channel_id: ChannelId) -> str:
        """
        Return the plot title prefix based on the PNM file type for the channel.
        """
        file_type = self._file_type_by_channel.get(channel_id)
        if file_type == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE:
            return "US Last PreEqualization"
        return "US PreEqualization"

    def _plot_extra_tags(self, channel_id: ChannelId) -> list[str]:
        """
        Return filename tags based on the PNM file type for the channel.
        """
        file_type = self._file_type_by_channel.get(channel_id)
        if file_type == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE:
            return ["us-last-pre-eq"]
        return ["us-pre-eq"]

    def create_matplot(self, **kwargs: object) -> list[MatplotManager]:
        """
        Generate Matplotlib plots for both Pre-EQ and Last Pre-EQ captures when present.
        """
        file_types = self._collect_available_file_types()
        if not file_types:
            return super().create_matplot(**kwargs)

        plots: list[MatplotManager] = []
        original_filter = self._filter_file_type
        original_results = self._results
        original_channel_data = self._channel_data
        original_file_type_map = dict(self._file_type_by_channel)
        original_available = set(self._available_file_types)

        try:
            for file_type in file_types:
                self._set_file_type_filter(file_type)
                plots.extend(super().create_matplot(**kwargs))
        finally:
            self._filter_file_type = original_filter
            self._results = original_results
            self._channel_data = original_channel_data
            self._file_type_by_channel = original_file_type_map
            self._available_file_types = original_available

        return plots
# FILE: src/pypnm/api/routes/advance/common/capture_data_aggregator.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from pathlib import Path

from pypnm.api.routes.advance.common.transactionsCollection import TransactionCollection
from pypnm.api.routes.advance.common.types.types import TransactionFileCollection
from pypnm.api.routes.common.classes.file_capture.capture_group import CaptureGroup
from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.api.routes.common.classes.file_capture.types import TransactionRecordModel
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.types import FileNameStr, GroupId, TransactionId
from pypnm.pnm.lib.pnm_artifact_store import PnmArtifactStore


class CaptureDataAggregator:
    """
    Collect raw capture files for a given capture group, returning (filename, bytes) pairs.

    Typical usage:
        aggregator = CaptureDataAggregator(capture_group_id)
        file_entries = aggregator.collect()
        collection = aggregator.getPnmCollection()
    """

    def __init__(self, capture_group_id: GroupId) -> None:
        """
        Parameters
        ----------
        capture_group_id : str
            Identifier for the capture group.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self._capture_group_id:GroupId = capture_group_id
        self._pnm_dir = Path(SystemConfigSettings.pnm_dir())
        self._trans_file_bin_entries: TransactionFileCollection = []
        self._trans_collection: TransactionCollection = TransactionCollection()
        self._artifact_store = PnmArtifactStore(pnm_dir=self._pnm_dir)

    # ──────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────
    def collect(self) -> TransactionCollection:
        """
        Gather all capture files for the configured group and read their contents.

        """
        capture_grp = CaptureGroup(self._capture_group_id)
        txn_ids: list[TransactionId] = capture_grp.getTransactionIds()

        if not txn_ids:
            self.logger.warning(f"No transactions found for capture_group_id='{self._capture_group_id}'")
            return TransactionCollection()

        for file_count, txn_id in enumerate(txn_ids, 1):

            record: TransactionRecordModel = PnmFileTransaction().getRecordModel(txn_id)
            if not str(record.filename).strip():
                self.logger.error(f"Capture record missing filename: txn={txn_id}")
                continue

            try:
                compression = record.compression.model_dump() if record.compression else None
                bin:bytes = self._artifact_store.read_bytes(
                    record.transaction_id,
                    FileNameStr(str(record.filename)),
                    compression,
                )
                self.logger.debug(f'Reading capture - count={file_count},  txn={txn_id},  file={record.filename}, size={len(bin)}')

            except FileNotFoundError:
                self.logger.error(f'Capture file not found: {record.filename}')
                raise

            except Exception as exc:
                self.logger.error(f'Error reading file {record.filename}: {exc}')
                continue

            if not self._trans_collection.add(record, bin):
                self.logger.error(f'Unable to add [{record.filename}] to Transaction Collection')
                continue

        return self._trans_collection

    # ──────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────
    def _safe_join(self, base_dir: Path, user_filename: str) -> Path:
        """
        Safely join `user_filename` under `base_dir`, preventing absolute-path override
        and directory traversal.

        Rules:
        - If you *do not* need subdirectories: only allow basename component.
        - If you *do* need subdirectories under base_dir: set allow_subdirs=True below.

        Returns a path that is guaranteed to remain within `base_dir`.
        """
        allow_subdirs = False  # flip to True if legitimate subfolders are expected

        fname = str(user_filename)

        # Option A (default): collapse to basename (blocks any subdir usage).
        candidate = base_dir / Path(fname).name

        # Option B (if allow_subdirs is True): use full user path under base_dir
        if allow_subdirs:
            candidate = base_dir / fname

        # Resolve without touching filesystem; verify it stays within base_dir
        base_resolved = base_dir.resolve(strict=False)
        file_path = candidate.resolve(strict=False)

        try:
            file_path.relative_to(base_resolved)
        except ValueError:
            # Outside of base_dir → reject
            self.logger.error(
                "Rejected filename outside save_dir; group_id=%s base=%s filename=%r resolved=%s",
                self._capture_group_id, base_resolved, fname, file_path)

            return base_resolved / "__invalid__"

        return file_path
