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
