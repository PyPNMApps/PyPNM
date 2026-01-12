## Agent Review Bundle Summary
- Goal:
- Changes:
- Files:
- Tests:
- Notes:

### Summary
Removed the duplicated Workflow Summary block in the multi-capture operation doc to keep a single source of truth.

### Modified Files
- docs/api/fast-api/multi/capture-operation.md

### Commands Executed And Results
- None

### Tests
- pytest → not run (docs-only)
- ruff → not run (docs-only)

### Notes / Warnings
- None

### Remaining TODOs / Follow-Ups
- None

# FILE: docs/api/fast-api/multi/capture-operation.md
# Multi‑Capture Operation Overview

When you initiate a **multi-capture** session (e.g., Multi‑RxMER or Multi‑DS‑Channel‑Estimation), PyPNM maintains a lightweight file‑based tracking system and stages resulting PNM binaries for downstream workflows.

**Directory Layout**:

```text
.data/
├── db/
│   ├── operation_capture.json      # Maps operations to capture groups
│   ├── capture_group.json          # Records capture groups
│   └── transactions.json           # Lists each staged file transaction
├── operations/
│   └── <operation_id>.json         # Status + progress for async operations
└── pnm/
    └── <.bin files>                # Raw PNM captures retrieved via TFTP
```

## 1. Operation Status Registry (`operations/<operation_id>.json`)

Each operation has its own status file to support `status`, `result`, and `cancel` endpoints.

**Example**:

```json
{
  "operation_id": "f6afb2d7df2c4a5c",
  "state": "running",
  "created_ts": 1730000000,
  "updated_ts": 1730000010,
  "progress_current": 1,
  "progress_total": 6,
  "message": "Operation running",
  "error": null,
  "artifact_paths": [
    "ds_ofdm_rxmer_per_subcar_aa:bb:cc:dd:ee:ff_160_1730000000.bin"
  ]
}
```

## 2. Operation Database (`operation_capture.json`)

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

## 3. Capture Group Database (`capture_group.json`)

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

## 4. Transactions Manifest (`transactions.json`)

A detailed manifest of every PNM file moved into `.data/pnm/` during the capture.

**Example**:

```json
{
  "2ee6138bbc1b3c3d": {
      "timestamp": 1748280294,
      "mac_address": "aa:bb:cc:dd:ee:ff",
      "pnm_test_type": "DS_OFDM_RXMER_PER_SUBCAR",
      "filename": "ds_ofdm_rxmer_per_subcar_aa:bb:cc:dd:ee:ff_34_1748280294.bin",
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
}
```

* **Key**: `transaction_id` (e.g., `2ee6138bbc1b3c3d`).
* **timestamp**: Unix epoch when the file was staged.
* **mac\_address**: Sanitized MAC of the target modem.
* **pnm\_test\_type**: Identifier of the PNM capture type.
* **filename**: Name of the `.bin` file in `.data/pnm/`.
* **device\_details.sys\_descr**: Snapshot of modem metadata at capture time.

## Workflow Summary

1. **Start Multi‑Capture**: System generates a new `operation_id` linked to a new `capture_group_id`.
2. **Periodic Triggers**: SNMP instructs the modem to TFTP-upload the PNM blob.
3. **File Staging**: PyPNM copies each `.bin` into `.data/pnm/` and appends a JSON entry.
4. **Database Updates**: Timestamps and transaction lists are updated in both `operation_capture.json` and `capture_group.json`.
5. **Completion**: After the capture ends, the three JSON tables fully describe what was captured, when, and for which operation/group.

> Downstream tools can monitor `transactions.json` as a manifest to automatically discover and process new PNM files—no manual polling required.
