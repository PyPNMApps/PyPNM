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
    "capture_group_id": "10b6ea239641487c",
    "created": 1748280293,
    "operation": {
      "name": "multi_rxmer",
      "measure_mode": "continuous"
    },
    "metadata": {
      "mac_address": "aa:bb:cc:dd:ee:ff",
      "system_description": {
        "HW_REV": "1.0",
        "VENDOR": "LANCity",
        "BOOTR": "NONE",
        "SW_REV": "1.0.0",
        "MODEL": "LCPET-3"
      }
    },
    "operation_status": {
      "state": "completed",
      "collected": 12,
      "time_remaining": 0,
      "updated": 1748280413
    }
  }
}
```

* **Key**: `operation_id` (e.g., `f6afb2d7df2c4a5c`).
* **capture_group_id**: Associated `capture_group_id`.
* **created**: Unix timestamp when the operation started.
* **operation**: Canonical operation family and measure mode.
* **metadata**: Persisted device identity captured when the operation started.
* **operation_status**: Persisted runtime or terminal status used when no live in-memory service is available.

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

## Runtime Lifecycle

PyPNM uses two layers during multi-capture execution:

1. **File-backed operation records**
   These live in `operation_capture.json`, `capture_group.json`, and `transactions.json`.
   They are the durable source of truth for operation identity, capture grouping, staged files, and terminal operation status.

2. **In-memory capture services**
   These hold the active asyncio task, per-operation counters, temporary sample lists, and device/session context while the capture is running.

### Memory Ownership

For a running multi-capture operation, memory is primarily owned by:

* the router's in-memory service registry
* the capture service `_ops` entry for the operation
* temporary `CaptureSample` objects collected during the run
* analysis engines and their decoded parser/model objects when analysis is requested

The staged PNM binaries are not kept only in memory. They are written to disk and tracked through the file-backed manifests above.

### Terminal Operation Cleanup

When a multi-capture operation reaches a terminal state (`completed`, `stopped`, or `cancelled`), PyPNM now:

1. Persists the final `state`, `collected`, and `time_remaining` fields into `operation_capture.json`.
2. Clears retained in-memory sample and task references for that operation.
3. Removes the terminal `_ops` entry from the capture service.
4. Evicts the completed service instance from the router's in-memory registry.

This change is intentionally memory-focused. It prevents completed multi-capture operations from remaining strongly referenced in long-lived FastAPI router instances after the run has already been persisted.

### Status After Eviction

Status endpoints continue to work after in-memory eviction for terminal operations.

They now follow this lookup order:

1. Use the live in-memory service when the operation is still active.
2. Fall back to the persisted `operation_status` block in `operation_capture.json` when the live service has already been released.

This means completed operations no longer need to stay in memory just to answer `GET /status/{operation_id}`.

### Memory Notes For Analysis

The multi-capture analysis flows still create large temporary objects:

* decoded parser objects
* Pydantic models
* NumPy arrays for some signal-analysis paths
* archive/report models for CSV, JSON, and plots

PyPNM includes explicit release hooks in the analysis stack to drop payload bytes and analysis intermediates after responses or archives are built. Even with those release paths, process RSS can still remain elevated for some time because Python and the underlying allocator may keep freed arenas for reuse.

The practical takeaway is:

* completed capture services should not remain in memory
* heavy analysis requests can still cause temporary RSS growth
* persistent memory creep after terminal service eviction is more likely to come from analysis-path object retention or allocator behavior than from finished capture sessions themselves
* production FastAPI workers should still use a recycle safety valve such as `pypnm serve --workers 4 --limit-max-requests 2000`

### sysDescr Collection Behavior

For multi-capture workflows, `system_description` is captured once per operation during precheck/start and then reused:
1. The session-level sysDescr snapshot is cached in memory for the operation.
2. Each transaction record in `transactions.json` receives that cached snapshot under `device_details.system_description`.
3. If a transaction is missing sysDescr metadata, PyPNM backfills it from the cached session snapshot.

This avoids repeated per-sample SNMP sysDescr calls while keeping report metadata complete.

### Local Retrieval Reliability

When `PnmFileRetrieval.retrieval_method.method` is `local`, PyPNM now:
1. Retries local file copy using `PnmFileRetrieval.retries` before failing.
2. Uses a user-scoped ingress fallback under `/tmp/pypnm/ingress-<uid>/` if the default ingress directory is not writable.
3. Uses a user-scoped materialized-cache fallback under `/tmp/pypnm/materialized-<uid>/` when report analysis cannot write to the shared materialized cache.

This prevents capture failures in shared or mixed-user environments where `/tmp/pypnm/ingress` permissions can differ by user.

## Workflow Summary

1. **Start Multi‑Capture**: System generates a new `operation_id` linked to a new `capture_group_id`.
2. **Periodic Triggers**: SNMP instructs the modem to TFTP-upload the PNM blob.
3. **File Staging**: PyPNM stores each artifact in `data/pnm/` (raw or compressed) and appends a JSON entry.
4. **Database Updates**: Timestamps, transaction lists, device metadata, and operation status are updated in the file-backed manifests.
5. **Completion**: After the capture ends, terminal status is persisted and the live capture service is released from memory.

> Downstream tools can monitor `transactions.json` as a manifest to automatically discover and process new PNM files—no manual polling required.
