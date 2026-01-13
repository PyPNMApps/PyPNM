## Agent Review Bundle Summary
- Goal: Remove SPDX headers from Markdown docs and validate CaptureGroup docstring example and header year policy.
- Changes: Removed SPDX HTML comment headers from docs, restored 2025-2026 SPDX year range in CaptureGroup, docstring example already correct.
- Files: docs/system/system-config.md, docs/design/db/addemdum.md, docs/design/db/pnm_compression_sampling.md, src/pypnm/api/routes/common/classes/file_capture/capture_group.py
- Tests: rg -n "SPDX" docs; python3 -m compileall src; ruff check src; ruff format --check .; pytest -q
- Notes: Postgres-gated tests skipped when PYPNM_DB_POSTGRES_DSN not set; PNM_CM_IT hardware tests skipped.

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
* [4. PnmFileRetrieval](#4-pnmfileretrieval)
* [5. Database](#5-database)
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

## 4. PnmFileRetrieval

Local Storage Layout And Remote Retrieval Methods.

Related Guide: [File Transfer Methods](pnm-file-retrieval/index.md)

Runtime DB location policy: SQLite DB files live under `.data/db/` (demo uses `demo/.data/db/`), while Postgres is external and does not create a local DB file.

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

`password_enc` is the preferred password field for file retrieval methods. Plaintext `password` is supported only as a legacy fallback and is deprecated.
Legacy JSON ledger paths remain for offline migration or diagnostics only. Runtime persistence for transactions, capture groups, operation mappings, and session groups is DB-backed.

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
| transaction_db      | string | Legacy JSON ledger for file transactions (migration only). |
| capture_group_db    | string | Legacy JSON map of grouped transactions (migration only).  |
| session_group_db    | string | Legacy JSON map of session groups (migration only).        |
| operation_db        | string | Legacy JSON map of operation to capture group (migration only). |
| json_transaction_db | string | Legacy JSON map of JSON transaction metadata (migration only). |

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

## 5. Database

Database Backend Selection And Connection Settings.

```json
"Database": {
  "backend": "sqlite",
  "sqlite": {
    "path": ".data/db/pypnm.sqlite3"
  },
  "postgres": {
    "dsn": ""
  }
}
```

Backend selection is set at install time (SQLite default; Postgres recommended for multi-worker deployments). Set `PYPNM_DB_BACKEND` to override the backend selection (`sqlite` or `postgres`). SQLite stores its DB file under `.data/db/` (demo uses `demo/.data/db/`), while Postgres is external and does not create a local DB file. For Postgres, supply the DSN via `PYPNM_DB_POSTGRES_DSN` to avoid storing plaintext credentials in tracked JSON files. Blank strings for required values are invalid when the backend is active.

On startup, PyPNM applies the schema for the selected backend and seeds the canonical `UNKNOWN` sysDescr row and the default artifact store entry.

DB backend migration is in progress; legacy ledger keys remain until Phase M6.

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

# FILE: docs/design/db/addemdum.md
# PyPNM DB Backend · Locked Decisions (Selection Summary)

This file captures the decision set you selected:

`1A, 2B+2.1B, 3B, 4A(SQLite)+4C(Postgres when PyPNM-CMTS/multi-worker), 5C+5.1A, 6B+6.1A, 7B, 8A`

## Insert Into Design Doc

Add this as a new section (recommended placement: after **4. Design Requirements** or after **7. Backend Selection And Installation Contract**).

### Design Decision Register

1) **Persistence Ownership (1A)**  
   PyPNM owns persistence, schema initialization, and DB access APIs. PyPNM-CMTS must use PyPNM DB APIs only and must not implement a separate backend selector or schema manager.

2) **Installer Behavior (2B)**  
   `install.sh` supports explicit flags and a safe default:
   - `--db-install-sqlite` (default when no flag provided)
   - `--db-install-postgres`
   - If no flag is provided: interactive prompt with default `sqlite`.

3) **Secrets / Credential Handling (2.1B)**  
   Postgres credentials are not required to be stored in tracked JSON.  
   Required behavior:
   - Support env var overrides (and/or `.env`) for DSN/password
   - CI/dev may use `pypnm/pypnm` defaults, but docs must label them “development only”.

4) **Schema Application Model (3B)**  
   Schema init is performed via an idempotent SQL apply step using the shipped DDL assets:
   - `docs/design/db/schema_sqlite.sql`
   - `docs/design/db/schema_postgres.sql`  
   The apply step must:
   - Create tables/indexes idempotently
   - Seed canonical `UNKNOWN` sysDescr row idempotently
   - Seed default `artifact_stores` row idempotently (prod and demo, as applicable)
   - Enable SQLite FK enforcement (`PRAGMA foreign_keys = ON`).

5) **Concurrency And Backend Guidance (4A + 4C)**  
   - **SQLite (4A)** is supported for single-process, single-writer deployments (typical PyPNM standalone use).  
   - **Postgres (4C)** is the recommended backend when running **PyPNM-CMTS** and/or any **multi-worker / multi-process** deployment mode.  
   Installer and docs must communicate this clearly (no ambiguity).

6) **Artifact Store + Path Portability (5C + 5.1A)**  
   The DB stores only portable, app-root relative paths:
   - `artifact_stores.root_path` is app-root relative (prod: `.data/pnm`; demo: `demo/.data/pnm`)
   - `file_artifacts.relative_path` is relative to the store root  
   Runtime resolution:
   `absolute_path = Path(app_root) / artifact_stores.root_path / file_artifacts.relative_path`

7) **CI Policy And Postgres Validation (6B + 6.1A)**  
   - SQLite tests are mandatory in CI.  
   - Postgres tests are validated in CI using a service container (recommended: required, not “allowed failure”), with DSN provided via env vars.  
   CI credential defaults are acceptable for the service container only.

8) **Cutover / Legacy Ledger Strategy (8A)**  
   Treat JSON ledger persistence as deprecated and removed from the design and code paths.  
   Optional: a one-time offline migrator may be added later, but it must not be required for normal installs and must not ship populated DBs.

## Burndown Deltas

If these items are not already explicit in the burndown, add them so Codex cannot miss them.

### Phase 1 (M1) · Installer

- [ ] Add install-time warning text:
  - [ ] SQLite is recommended for standalone PyPNM/single-writer.
  - [ ] Postgres is recommended for PyPNM-CMTS and/or multi-worker.
- [ ] Postgres prompt path:
  - [ ] Allow DSN entry OR discrete fields that render into a DSN.
  - [ ] Ensure password can be provided via env var override (no plaintext requirement in JSON).

### Phase 2 (M2) · Schema Apply

- [ ] Seed `artifact_stores` idempotently:
  - [ ] prod store: `.data/pnm`
  - [ ] demo store: `demo/.data/pnm` (only if demo enabled/used)

### Phase 6 (M6) · Docs + Mermaid

- [ ] Remove/replace all doc references to:
  - `.data/db/transactions.json`
  - `.data/db/capture_group.json`
  - `.data/db/operation_capture.json`
- [ ] Add Mermaid support for docs builds:
  - [ ] Add Mermaid plugin dependency to docs extras in `pyproject.toml` (example: `mkdocs-mermaid2-plugin`)
  - [ ] Update MkDocs config to render Mermaid fences (`pymdownx.superfences` mermaid custom fence)

### Phase 7 (M7) · Pytest + GitHub Actions

- [ ] Replace legacy ledger fixtures/tests with DB fixtures:
  - [ ] temporary SQLite DB under `tmp_path` + schema init helper
  - [ ] default artifact store seed helper
  - [ ] UNKNOWN sysDescr seed helper
- [ ] Add CI job for Postgres:
  - [ ] `postgres` service container
  - [ ] env var DSN provided to tests
  - [ ] schema init executed during test setup (idempotent)

## Optional Text For Docs

Use this wording (or equivalent) in the design doc and install docs:

- SQLite is intended for single-writer deployments and local/lab usage.
- For PyPNM-CMTS and/or multi-worker deployments, Postgres is recommended to avoid SQLite write contention and locked-database failure modes.

# FILE: docs/design/db/pnm_compression_sampling.md
# PNM Compression Sampling

This note captures a 10-file random sample from `tests/files` and records size savings plus single-run compress/decompress time per algorithm.

## Per-File Results

| File | Orig (B) | gzip (B, %, c_ms, d_ms) | bzip2 (B, %, c_ms, d_ms) | xz (B, %, c_ms, d_ms) | zstd (B, %, c_ms, d_ms) |
|---|---:|---:|---:|---:|---:|
| rxmer.bin | 7508 | 4388, 41.6%, 1.06, 0.78 | 4171, 44.4%, 1.74, 1.14 | 4436, 40.9%, 3.64, 1.33 | 4098, 45.4%, 1.32, 0.97 |
| us_pre_equalizer_coef_last.bin | 7138 | 4960, 30.5%, 1.03, 0.86 | 4847, 32.1%, 2.01, 1.17 | 4244, 40.5%, 3.98, 1.53 | 5885, 17.6%, 1.31, 1.02 |
| histogram.bin | 1053 | 615, 41.6%, 0.93, 0.81 | 768, 27.1%, 1.07, 0.86 | 616, 41.5%, 2.42, 1.02 | 580, 44.9%, 1.39, 1.08 |
| channel_estimation.bin | 29948 | 28652, 4.3%, 1.49, 1.01 | 28213, 5.8%, 4.44, 2.41 | 28080, 6.2%, 7.90, 2.80 | 28626, 4.4%, 1.37, 1.09 |
| spectrum_analyzer_snmp.bin | 42020 | 25855, 38.5%, 1.83, 1.12 | 19334, 54.0%, 4.72, 2.46 | 22992, 45.3%, 7.51, 2.54 | 28824, 31.4%, 1.69, 1.34 |
| const_display.bin | 32798 | 26229, 20.0%, 1.99, 1.12 | 22953, 30.0%, 3.86, 2.48 | 26428, 19.4%, 7.28, 2.81 | 26117, 20.4%, 1.46, 1.17 |
| us_pre_equalizer_coef.bin | 7138 | 6748, 5.5%, 0.97, 0.95 | 7002, 1.9%, 2.21, 1.25 | 6564, 8.0%, 3.89, 1.51 | 6797, 4.8%, 1.30, 1.01 |
| spectrum_analyzer.bin | 41511 | 28142, 32.2%, 1.97, 1.18 | 20450, 50.7%, 4.18, 2.21 | 25244, 39.2%, 7.47, 2.88 | 31838, 23.3%, 1.41, 1.23 |
| modulation_profile.bin | 1881 | 259, 86.2%, 0.89, 0.73 | 243, 87.1%, 1.00, 0.83 | 244, 87.0%, 1.70, 1.05 | 210, 88.8%, 1.29, 0.99 |
| fec_summary.bin | 48030 | 7532, 84.3%, 1.32, 0.99 | 4150, 91.4%, 3.22, 1.46 | 2708, 94.4%, 3.74, 1.25 | 4401, 90.8%, 1.33, 1.17 |

## Averages

| Algo | Avg savings | Avg comp (ms) | Avg decomp (ms) |
|---|---:|---:|---:|
| gzip | 38.5% | 1.35 | 0.96 |
| bzip2 | 42.4% | 2.84 | 1.63 |
| xz | 42.3% | 4.95 | 1.87 |
| zstd | 37.2% | 1.39 | 1.11 |

## Script Used

```python
import json
import random
import shutil
import subprocess
import time
from pathlib import Path

def tool_exists(cmd: str) -> bool:
    return shutil.which(cmd) is not None

def run_with_output(cmd: list[str], data: bytes) -> tuple[int, bytes, bytes]:
    proc = subprocess.run(cmd, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    return proc.returncode, proc.stdout, proc.stderr

def compress(algo: str, data: bytes) -> tuple[bytes, float]:
    start = time.perf_counter()
    if algo == "gzip":
        rc, out, _ = run_with_output(["gzip", "-c", "-1"], data)
    elif algo == "bzip2":
        rc, out, _ = run_with_output(["bzip2", "-c", "-1"], data)
    elif algo == "xz":
        rc, out, _ = run_with_output(["xz", "-c", "-1"], data)
    elif algo == "zstd":
        rc, out, _ = run_with_output(["zstd", "-c", "-1"], data)
    else:
        raise ValueError(f"unsupported algo: {algo}")
    if rc != 0:
        raise RuntimeError(f"{algo} failed")
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return out, elapsed_ms

def decompress(algo: str, data: bytes) -> tuple[bytes, float]:
    start = time.perf_counter()
    if algo == "gzip":
        rc, out, _ = run_with_output(["gzip", "-dc"], data)
    elif algo == "bzip2":
        rc, out, _ = run_with_output(["bzip2", "-dc"], data)
    elif algo == "xz":
        rc, out, _ = run_with_output(["xz", "-dc"], data)
    elif algo == "zstd":
        rc, out, _ = run_with_output(["zstd", "-dc"], data)
    else:
        raise ValueError(f"unsupported algo: {algo}")
    if rc != 0:
        raise RuntimeError(f"{algo} decompress failed")
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return out, elapsed_ms

def main() -> None:
    base_dir = Path("/home/dev01/Projects/PyPNM/tests/files")
    files = [p for p in base_dir.iterdir() if p.is_file()]
    if len(files) < 10:
        raise RuntimeError("not enough files")

    random.seed(0xC0DEC0)
    sample = random.sample(files, 10)

    algos = ["gzip", "bzip2", "xz", "zstd"]
    algos = [a for a in algos if tool_exists(a)]

    rows = []
    for p in sample:
        data = p.read_bytes()
        row = {"file": p.name, "orig": len(data)}
        for algo in algos:
            comp, comp_ms = compress(algo, data)
            decomp, decomp_ms = decompress(algo, comp)
            if decomp != data:
                raise RuntimeError(f"roundtrip mismatch for {p.name} {algo}")
            row[algo] = len(comp)
            row[f"{algo}_c_ms"] = comp_ms
            row[f"{algo}_d_ms"] = decomp_ms
        rows.append(row)

    print(json.dumps({"algos": algos, "rows": rows}, indent=2))

if __name__ == "__main__":
    main()
```

# FILE: src/pypnm/api/routes/common/classes/file_capture/capture_group.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
import time
import uuid
from pathlib import Path

from pypnm.lib.db.capture_group_repository import CaptureGroupRepository
from pypnm.lib.db.transaction_repository import TransactionRepository
from pypnm.lib.types import GroupId, TimestampSec, TransactionId


class CaptureGroup:
    """
    Manage sessions of capture operations (e.g., multi-RxMER runs) by grouping
    multiple file-transfer transactions under a single UUID-based group ID.

    Features:
      - Persist groups and their transaction lists in the DB backend.
      - Generate or load a 16-character hexadecimal group ID per session.
      - Add, list, delete transactions; prune stale groups.

    Example:
        # New session
        cg = CaptureGroup()
        group_id = cg.create_group()

        # Existing session
        cg2 = CaptureGroup(group_id=group_id)
        txns = cg2.getTransactionIds()
    """

    def __init__(
        self, group_id: GroupId | None = None, db_path: Path | None = None
    ) -> None:
        """
        Initialize the CaptureGroup manager.

        Args:
            group_id: Optional existing group ID to load; generates a new one if None.
            db_path: Deprecated legacy JSON path override. Ignored; DB is authoritative.

        Raises:
            OSError: If the parent directory cannot be created.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        if db_path is not None:
            self.logger.warning(
                "Deprecated db_path override ignored; DB is authoritative"
            )

        self._repo = CaptureGroupRepository.from_system_config()
        self._transaction_repo = TransactionRepository.from_system_config()

        self._grp_id: GroupId | None = group_id
        self._create_group_id()

    def _create_group_id(self) -> GroupId:
        """
        Ensure a group ID is set (use existing or generate new).
        Returns the active group ID.
        """
        if not self._grp_id:
            self._grp_id = GroupId(uuid.uuid4().hex[:16])
        return self._grp_id

    def get_group_id(self) -> GroupId:
        """
        Get the current active group ID.
        Raises AssertionError if uninitialized.
        """
        assert self._grp_id, "Group ID not initialized"
        return self._grp_id

    def create_group(self) -> GroupId:
        """
        Add the current group to the DB (no-op if exists).
        Returns the group ID.
        """
        gid = self.get_group_id()
        created_epoch = TimestampSec(int(time.time()))
        self._repo.create_capture_group(gid, created_epoch)
        self.logger.info(f"Created new group: {gid}")
        return gid

    def add_transaction(self, txn_id: str) -> None:
        """
        Append a transaction ID to this group, saving the DB.
        Raises ValueError if group missing.
        """
        tx_id = str(txn_id).strip()
        if not tx_id:
            self.logger.warning("Skipping empty transaction_id persistence")
            return
        gid = self.get_group_id()
        if not self._repo.capture_group_exists(gid):
            raise ValueError("Group not found; create_group() first")
        if self._transaction_repo.get_transaction_record(TransactionId(tx_id)) is None:
            self.logger.warning(
                "Skipping capture_group link for missing transaction_id=%s",
                tx_id,
            )
            return
        created_epoch = TimestampSec(int(time.time()))
        self._repo.add_transaction_next_position(
            gid, TransactionId(tx_id), created_epoch
        )
        self.logger.debug(f"Added txn {tx_id} to group {gid}")

    def getTransactionIds(self) -> list[TransactionId]:
        """
        Return all transaction IDs for this group (empty list if none).
        """
        return self._repo.list_transactions(self.get_group_id())

    def delete_group(self) -> None:
        """
        Remove this group and its transactions from the DB; resets group ID.
        """
        gid = self.get_group_id()
        self._repo.delete_capture_group(gid)
        self.logger.info(f"Deleted group: {gid}")
        self._grp_id = None

    def list_groups(self) -> list[str]:
        """
        List all group IDs currently in the DB.
        """
        return [str(group_id) for group_id in self._repo.list_capture_groups()]

    def prune_older_than(self, seconds: int) -> None:
        """
        Remove groups older than the given age (seconds).
        """
        cutoff = TimestampSec(int(time.time()) - seconds)
        deleted = self._repo.delete_older_than(cutoff)
        if deleted:
            self.logger.info(f"Pruned groups: {len(deleted)}")
