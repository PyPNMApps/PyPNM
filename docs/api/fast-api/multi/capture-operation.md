# Multi‑Capture Operation Overview

When you initiate a **multi-capture** session (e.g., Multi‑RxMER or Multi‑DS‑Channel‑Estimation), PyPNM maintains a DB-backed tracking system and stages resulting PNM binaries for downstream workflows.

**Directory Layout**:

```text
.data/
├── db/
│   ├── pypnm.sqlite3               # SQLite DB (when backend=sqlite)
├── operations/
│   └── <operation_id>.json         # Status + progress for async operations
├── json/
│   └── <*.json>                    # JSON exports (metadata tracked in DB)
└── pnm/
    └── <.bin files>                # Raw PNM captures retrieved via TFTP
```

Capture metadata is stored in the DB (`transaction_records`, `capture_groups`, `capture_group_transactions`, `operation_captures`). Postgres deployments use the configured external DSN instead of a local SQLite file.

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

## 2. Operation Mapping (DB: `operation_captures`)

Operation-to-capture-group links are stored in the `operation_captures` table.

Fields:

* **operation_id**: Operation identifier (primary key).
* **capture_group_id**: Associated capture group (foreign key).
* **created_epoch**: Unix timestamp when the operation started.

Legacy JSON key `capture_group` is accepted only during offline migration; runtime resolution uses the DB.

## 3. Capture Group Registry (DB: `capture_groups` + `capture_group_transactions`)

Capture groups live in `capture_groups`, with ordered membership in `capture_group_transactions`.

Fields:

* **capture_group_id**: Capture group identifier (primary key).
* **created_epoch**: Unix timestamp when the group was created.
* **transaction_id**: Linked transaction identifier (foreign key).
* **position**: Ordering index for deterministic listing.

## 4. Transaction Records (DB: `transaction_records` + `transaction_artifacts`)

Transaction metadata is stored in `transaction_records`, while on-disk files are resolved via `transaction_artifacts` and `file_artifacts`.

**Example (logical record shape)**:

```json
{
  "2ee6138bbc1b3c3d": {
      "timestamp": 1748280294,
      "mac_address": "aa:bb:cc:dd:ee:ff",
      "pnm_test_type": "DS_OFDM_RXMER_PER_SUBCAR",
      "filename": "ds_ofdm_rxmer_per_subcar_aa:bb:cc:dd:ee:ff_34_1748280294.bin",
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
* **filename**: Name of the `.bin` file in `.data/pnm/` (recorded for reference).
* **device\_details.system\_description**: Snapshot of modem metadata at capture time.

Transaction IDs must be non-empty. Blank or whitespace-only IDs are dropped with a warning and are never persisted.
The `mac_address` field is intentionally stored in `transaction_records` (it is not treated as redundant in the SQL-backed schema direction).

## 5. Operation Workflow Endpoints (POST)

Generic workflow endpoints provide a consistent interface for operation status, result, and cancellation.
These endpoints rely on an in-memory OperationRegistry for live stop/status hooks and a filesystem-backed
OperationStore for authoritative state. Cancel requests are best-effort in-process; the OperationStore
status remains authoritative across restarts.

**Request** `POST /advance/operation/start`

```json
{
  "progress_total": 6,
  "message": "Operation created"
}
```

**Response** (start includes legacy + canonical status)

```json
{
  "status": "success",
  "service_status": 0,
  "message": null,
  "operation": {
    "operation_id": "f6afb2d7df2c4a5c",
    "state": "running",
    "created_ts": 1730000000,
    "updated_ts": 1730000000,
    "progress_current": 0,
    "progress_total": 6,
    "message": "Operation created",
    "error": null,
    "artifact_paths": []
  },
  "time_remaining": 0
}
```

**Request** `POST /advance/operation/status`

```json
{
  "operation_id": "f6afb2d7df2c4a5c"
}
```

**Response** (registry status includes legacy + canonical status)

```json
{
  "status": "success",
  "service_status": 0,
  "message": null,
  "operation": {
    "operation_id": "f6afb2d7df2c4a5c",
    "state": "running",
    "created_ts": 1730000000,
    "updated_ts": 1730000010,
    "progress_current": 1,
    "progress_total": 6,
    "message": "Operation running",
    "error": null,
    "artifact_paths": []
  },
  "time_remaining": 0
}
```

**Request** `POST /advance/operation/result`

```json
{
  "operation_id": "f6afb2d7df2c4a5c"
}
```

**Response** (registry result includes legacy + canonical status)

```json
{
  "status": "success",
  "service_status": 0,
  "message": null,
  "operation": {
    "operation_id": "f6afb2d7df2c4a5c",
    "state": "completed",
    "created_ts": 1730000000,
    "updated_ts": 1730000030,
    "progress_current": 6,
    "progress_total": 6,
    "message": "Operation completed",
    "error": null,
    "artifact_paths": []
  }
}
```

**Request** `POST /advance/operation/cancel`

```json
{
  "operation_id": "f6afb2d7df2c4a5c"
}
```

**Response** (registry cancel includes legacy + canonical status)

```json
{
  "status": "success",
  "service_status": 0,
  "message": null,
  "operation": {
    "operation_id": "f6afb2d7df2c4a5c",
    "state": "canceled",
    "created_ts": 1730000000,
    "updated_ts": 1730000020,
    "progress_current": 2,
    "progress_total": 6,
    "message": "Operation canceled",
    "error": null,
    "artifact_paths": []
  }
}
```

## 6. Multi-RxMER Workflow Endpoints (POST)

**Request** `POST /advance/ds/ofdm/rxmer/multi/start`

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "ip_address": "192.168.0.100",
  "duration": 60,
  "interval": 5
}
```

**Request** `POST /advance/ds/ofdm/rxmer/multi/result`

```json
{
  "operation_id": "f6afb2d7df2c4a5c"
}
```

## 7. Multi-ChannelEstimation Workflow Endpoints (POST)

**Request** `POST /advance/multiChannelEstimation/start`

```json
{
  "cable_modem": {
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "ip_address": "192.168.0.100"
  },
  "capture": {
    "parameters": {
      "measurement_duration": 60,
      "sample_interval": 5
    }
  }
}
```

Note: The legacy `measure` payload is currently ignored and will be removed in a future release.

**Request** `POST /advance/multiChannelEstimation/result`

```json
{
  "operation_id": "f6afb2d7df2c4a5c"
}
```

Result behavior:
- Missing transaction records are skipped with warnings.
- If no transaction records resolve, the endpoint returns HTTP 404.

Start response fields:
- capture_group_id is canonical.
- group_id is legacy and will be deprecated.
- status is ServiceStatusCode.SUCCESS when the operation starts; operation_state indicates RUNNING.
Status semantics:
- Top-level status is always a ServiceStatusCode value.
- operation.state carries running/stopped/completed semantics.
- Registry endpoints return legacy status string plus service_status as the canonical ServiceStatusCode.

## Workflow Summary

1. **Start Multi‑Capture**: System generates a new `operation_id` linked to a new `capture_group_id`.
2. **Periodic Triggers**: SNMP instructs the modem to TFTP-upload the PNM blob.
3. **File Staging**: PyPNM copies each `.bin` into `.data/pnm/` and inserts DB metadata (transaction record + artifact linkage).
4. **Database Updates**: `operation_captures`, `capture_groups`, and `capture_group_transactions` reflect the capture state.
5. **Completion**: After the capture ends, the DB tables fully describe what was captured, when, and for which operation/group.

> Downstream tools should query the DB-backed APIs (for example, `searchFiles` or `getMacAddresses`) to discover new PNM files.
