# PyPNM Database

Overview of how PyPNM stores, organizes, and links measurement data for traceability and REST access.

## Table Of Contents

- [Data Repository Layout](#data-repository-layout)
- [Directory Reference](#directory-reference)
- [Operation Capture Linking](#operation-capture-linking)
- [Capture Group Registry](#capture-group-registry)
- [Transaction Records](#transaction-records)
- [JSON Export Artifacts](#json-export-artifacts)
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
│   ├── pypnm.sqlite3
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
| `db/`      | SQLite DB (or external Postgres via DSN)                        | `pypnm.sqlite3`                                                       | DB-backed metadata: transactions, capture groups, operation mappings, and artifacts.             |
| `json/`    | Raw/processed JSON outputs (when enabled)                       | `aabbccddeeff_example_run_1760940313_33_cmdsofdmrxmer_*.json`         | Structured artifacts for programmatic consumption; metadata is tracked in the DB artifact tables. |
| `msg_rsp/` | Request/response message snapshots (optional)                   | —                                                                     | Diagnostics and audit of REST or SNMP exchanges.                                                  |
| `png/`     | Visualization images per capture/profile/channel                | `aabbccddeeff_lcpet3_1760940313_34_profile_1_ofdm_profile_perf_1.png` | Quick-look plots for reports and UIs.                                                             |
| `pnm/`     | Binary PNM files pulled from devices or uploads                 | `ds_ofdm_rxmer_per_subcar_aabbccddeeff_33_1760940252.bin`             | Source files used by analyses; include the embedded `pnm_header`.                                |
| `xlsx/`    | Excel workbooks                                                 | —                                                                     | Multi-sheet summaries and cross-linked reports.                                                   |

## Operation Capture Linking

Operation-to-capture-group mapping is stored in the `operation_captures` DB table.
An operation represents a higher-level request that may include different PNM test types (RxMER, FEC Summary, Modulation Profile).

### Field Overview

| Field              | Type    | Description                                   |
| ------------------ | ------- | --------------------------------------------- |
| `operation_id`     | string  | Operation identifier (primary key).           |
| `capture_group_id` | string  | Unique ID of the broader capture session.     |
| `created_epoch`    | integer | Operation creation timestamp (epoch seconds). |

Common uses:

- Retrieve a complete session by operation ID via REST.
- Persist session context for deferred or repeat analysis.

## Capture Group Registry

Capture groups are stored in `capture_groups`, with ordered membership in `capture_group_transactions`.
Capture groups can span multiple test types or measurements and underpin multi-file workflows (Excel generation, correlation, etc.).

### Field Overview

| Field              | Type    | Description                                                               |
| ------------------ | ------- | ------------------------------------------------------------------------- |
| `capture_group_id` | string  | Group identifier (primary key).                                           |
| `created_epoch`    | integer | Group creation timestamp (epoch seconds; often the first operation time). |
| `transaction_id`   | string  | Transaction ID linked to the group.                                       |
| `position`         | integer | Ordering index for deterministic listing.                                 |

## Transaction Records

Transactions are stored in the `transaction_records` table, with file resolution via `transaction_artifacts`.
Each entry represents a single file **transaction**, whether:

- Pulled automatically from a cable modem (for example, via TFTP), or
- Manually uploaded by a user via the UI or API.

### Structure

Each transaction is indexed by a unique ID (16-char digest) and stored in the DB:

```json
"1e171e1f8ef5377a": {
  "timestamp": 1751950064,
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "pnm_test_type": "DS_OFDM_RXMER_PER_SUBCAR",
  "filename": "ds_ofdm_rxmer_per_subcar_aabbccddeeff_197_1751950064.bin",
  "device_details": {
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

### Field Overview

| Field            | Type    | Description                                                                 |
| ---------------- | ------- | --------------------------------------------------------------------------- |
| `timestamp`      | integer | Unix epoch seconds when the file was received or uploaded.                  |
| `mac_address`    | string  | Cable modem MAC address.                                                    |
| `pnm_test_type`  | string  | Test type that produced the file (for example, `DS_OFDM_RXMER_PER_SUBCAR`). |
| `filename`       | string  | Saved binary filename in `.data/pnm/`.                                      |
| `device_details` | object  | Parsed device metadata from SNMP when available (`sys_descr` fields shown). |

On-disk file resolution uses `transaction_artifacts` with role preference (`pnm_raw`, then `pnm_uploaded_raw`) and joins through `file_artifacts` and `artifact_stores`.

## JSON Export Artifacts

JSON exports are written under `.data/json/` and tracked in the DB-backed artifact tables (`artifact_stores`, `file_artifacts`, `transaction_artifacts`) when linked to a transaction.
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
  An **operation** references a single **capture group**, which aggregates many **transactions** in `transaction_records`. Each transaction resolves to a PNM file via `transaction_artifacts`.

- **Transactions (PNM) → JSON Captures**  
  JSON exports derived from those PNM files are written to `.data/json/` and tracked in the DB artifact tables with size and checksum metadata.

- **Reporting And REST Access**  
  Use the **operation ID** for API recall, the **capture group** for report generation and correlation across tests, and the **transaction IDs** (PNM and JSON) for raw file or artifact lookup.
