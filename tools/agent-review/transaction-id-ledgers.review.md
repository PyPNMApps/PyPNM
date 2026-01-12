## Agent Review Bundle Summary
- Goal:
- Changes:
- Files:
- Tests:
- Notes:

### Summary
Added empty/whitespace transaction_id guards to session_group and transaction_db persistence, plus tests and doc note to standardize the contract across JSON ledgers.

### Modified Files
- docs/api/fast-api/multi/capture-operation.md
- src/pypnm/api/routes/common/classes/file_capture/pnm_file_transaction.py
- src/pypnm/api/routes/common/classes/file_capture/session_group.py
- tests/test_transaction_id_persistence_guards.py

### Commands Executed And Results
- `python3 -m compileall src` → pass
- `ruff check .` → pass
- `ruff format --check .` → pass
- `pytest -k "transaction_id and empty" -q` → pass (5 passed, 541 deselected)

### Tests
- `pytest -k "transaction_id and empty" -q` → pass (5 passed, 541 deselected)
- `ruff` → pass (`ruff check .`)

### Notes / Warnings
- Pytest logs warnings for expected skips and missing JSON DB file before first write.

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

Transaction IDs must be non-empty. Blank or whitespace-only IDs are dropped with a warning and are never persisted.
The `mac_address` field is intentionally stored in `transaction_records` (it is not treated as redundant in the SQL-backed schema direction).

## Workflow Summary

1. **Start Multi‑Capture**: System generates a new `operation_id` linked to a new `capture_group_id`.
2. **Periodic Triggers**: SNMP instructs the modem to TFTP-upload the PNM blob.
3. **File Staging**: PyPNM copies each `.bin` into `.data/pnm/` and appends a JSON entry.
4. **Database Updates**: Timestamps and transaction lists are updated in both `operation_capture.json` and `capture_group.json`.
5. **Completion**: After the capture ends, the three JSON tables fully describe what was captured, when, and for which operation/group.

> Downstream tools can monitor `transactions.json` as a manifest to automatically discover and process new PNM files—no manual polling required.

# FILE: src/pypnm/api/routes/common/classes/file_capture/pnm_file_transaction.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path

from pypnm.api.routes.common.classes.file_capture.transaction_record_parser import (
    TransactionRecordParser,
)
from pypnm.api.routes.common.classes.file_capture.types import TransactionRecordModel
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.sysDescr import SystemDescriptor
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import FileName, TransactionId
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest


class PnmFileTransaction:
    """
    Manages persistent tracking of PNM file transactions across the PyPNM system.

    Each transaction corresponds to a PNM test result file (e.g., RxMER, Spectrum Analysis),
    whether generated through automated measurements or manually uploaded by a user.

    A transaction includes:
        - A unique transaction ID (16-char SHA-256 digest)
        - Timestamp (epoch time)
        - MAC address of the cable modem
        - PNM test type (e.g., DS_RXMER, SPECTRUM_ANALYZER)
        - Filename of the associated binary data file

    Transactions are stored in a central JSON file defined in system config at:
    `PnmFileRetrieval.transaction_db`.

    Usage Scenarios:
        - When a measurement test completes and produces a file.
        - When a user uploads a file manually via the REST API.
        - When retrieving metadata about previously captured test files.

    Attributes:
        transaction_db_path (Path): Path to the JSON file where all transactions are recorded.

    Record:
        {
            "<transaction_id>": {
                "timestamp": int,
                "mac_address": "<cable modem mac address>",
                "pnm_test_type": "<PNM Test Type>",
                "filename": "<FileName>",
                "device_details": {
                    "system_description": { ... }
                }
            }
        }
    """

    PNM_TEST_TYPE = "pnm_test_type"
    FILE_NAME = "filename"
    DEVICE_DETAILS = "device_details"
    MAC_ADDRESS = "mac_address"

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self.transaction_db_path = Path(SystemConfigSettings.transaction_db())
        self.transaction_db_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.transaction_db_path.exists():
            self.transaction_db_path.write_text(json.dumps({}))

    async def insert(
        self, cable_modem: CableModem, pnm_test_type: DocsPnmCmCtlTest, filename: str
    ) -> TransactionId:
        """
        Record A Transaction Initiated From An Actual Cable Modem Test.

        This method is invoked by measurement services once a PNM capture has
        successfully completed and produced a result file. It pulls the current
        system description from the cable modem, generates a new transaction
        identifier, and appends a normalized record into the transaction
        database.

        Parameters
        ----------
        cable_modem:
            Live `CableModem` instance representing the device under test. Used
            to obtain the MAC address and system description snapshot.
        pnm_test_type:
            Enumeration value describing which PNM test produced the file
            (for example, DS_RXMER, DS_OFDM_HISTOGRAM, DS_CONSTELLATION).
        filename:
            Relative or absolute path to the generated PNM binary file, as
            stored by the calling measurement service.

        Returns
        -------
        str
            Newly generated transaction identifier (16-character SHA-256
            digest prefix) suitable for later lookup (download and analysis).
        """
        sd: SystemDescriptor = await cable_modem.getSysDescr()
        return self._insert_generic(
            mac_address=cable_modem.get_mac_address,
            pnm_test_type=pnm_test_type,
            filename=filename,
            system_description=sd.to_dict(),
        )

    @staticmethod
    def set_file_by_user(
        mac_address: MacAddress, pnm_test_type: DocsPnmCmCtlTest, filename: FileName
    ) -> TransactionId:
        """
        Record A Transaction For A Manually Supplied File (User Upload).

        This path is used when the file is not the result of an automated test
        initiated by PyPNM, but rather provided by the user (for example, a
        lab-captured PNM file uploaded via REST). The record is normalized into
        the same transaction database used for automated captures.

        Parameters
        ----------
        mac_address:
            MAC address of the cable modem associated with the uploaded file.
        pnm_test_type:
            Enumeration describing the semantic PNM test type for the file,
            allowing downstream analysis routing to behave consistently.
        filename:
            Filesystem path or name where the uploaded file has been stored on
            the server.

        Returns
        -------
        str
            Newly generated transaction identifier bound to the uploaded file.
        """
        txn = PnmFileTransaction()
        return txn._insert_generic(
            mac_address=mac_address,
            pnm_test_type=pnm_test_type,
            filename=filename,
        )

    # ---------------------------
    # Safe read helpers (no recursion)
    # ---------------------------

    def _load_record_dict(self, transaction_id: TransactionId) -> dict | None:
        """
        Load The Raw JSON Record For A Transaction Identifier.

        This helper reads the on-disk transaction database and returns the
        underlying dictionary for the requested transaction identifier, if
        present. It does not perform any schema normalization or conversion.

        Parameters
        ----------
        transaction_id:
            Unique transaction identifier to resolve.

        Returns
        -------
        dict | None
            Raw JSON-compatible dictionary for the transaction when present,
            or `None` if no record exists for the supplied identifier.
        """
        db = self._load_db()
        return db.get(transaction_id)

    def get_record(self, transaction_id: TransactionId) -> dict | None:
        """
        Fetch A Plain Dictionary Representation Of A Transaction Record.

        This method provides a minimal, schema-free view into the transaction
        database. It is intended for low-level callers that need direct access
        to the stored fields without constructing a Pydantic model.

        Parameters
        ----------
        transaction_id:
            Unique transaction identifier for the record to retrieve.

        Returns
        -------
        dict | None
            The underlying transaction record as a dictionary, or `None` when
            the identifier does not exist in the database.
        """
        rec = self._load_record_dict(transaction_id)
        return rec if rec else None

    def get(self, transaction_id: TransactionId) -> dict | None:
        return self.get_record(transaction_id)

    def getRecordModel(self, transaction_id: TransactionId) -> TransactionRecordModel:
        """
        Build A Canonical TransactionRecordModel For A Transaction Identifier.

        This convenience wrapper resolves the raw JSON record and delegates to
        `TransactionRecordParser` to construct the normalized Pydantic model.
        If the record does not exist, a `null()` sentinel model is returned.

        Parameters
        ----------
        transaction_id:
            Unique transaction identifier for which a model representation is
            requested.

        Returns
        -------
        TransactionRecordModel
            Canonical, fully-normalized transaction model, or the sentinel
            `TransactionRecordModel.null()` instance for missing records.
        """
        rec = self._load_record_dict(transaction_id)
        if not rec:
            return TransactionRecordModel.null()
        return TransactionRecordParser.from_id(transaction_id)

    def get_file_info_via_macaddress(
        self, mac_address: MacAddress
    ) -> list[TransactionRecordModel]:
        """
        Retrieve All Transaction Records Associated With A Given MAC Address.

        This method scans the transaction database and collects all entries
        whose stored `mac_address` matches the supplied cable modem MAC (case-
        insensitive). Each matching record is returned as a fully normalized
        `TransactionRecordModel`, using the same parsing logic as individual
        lookups.

        Typical usage patterns include:
        - Building a catalog of all PNM files available for a modem.
        - Populating UI tables of historical captures keyed by MAC address.
        - Providing selection lists for downstream download or analysis calls.

        Parameters
        ----------
        mac_address:
            Cable modem MAC address used as the primary lookup key. The value
            is normalized to lower-case for comparison against stored records.

        Returns
        -------
        List[TransactionRecordModel]
            List of canonical `TransactionRecordModel` instances for all
            transactions associated with the given MAC address. The list is
            empty when no matching records are found.
        """
        db = self._load_db()
        mac_str = str(mac_address).lower()
        self.logger.info(f"Searching for files with MAC address: {mac_str}")
        records: list[TransactionRecordModel] = []

        for txn_id, record in db.items():
            if record.get(self.MAC_ADDRESS, "").lower() != mac_str:
                self.logger.info(
                    f"Skipping file with MAC address: {record.get(self.MAC_ADDRESS, '').lower()}"
                )
                continue
            records.append(TransactionRecordParser.from_id(txn_id))

        return records

    def get_all_record_models(self) -> list[TransactionRecordModel]:
        """
        Retrieve All Transaction Records As Canonical Models.

        This scans the transaction database and returns each record as a fully
        normalized `TransactionRecordModel`. Any per-record parse failures are
        logged and skipped so callers can still operate on partial data.

        Returns
        -------
        list[TransactionRecordModel]
            List of all transaction models currently stored in the transaction
            database. The list is empty when no records exist.
        """
        db = self._load_db()
        if not db:
            return []

        records: list[TransactionRecordModel] = []
        for txn_id in db:
            record = self._safe_parse_record(txn_id)
            if record is not None:
                records.append(record)

        return records

    def _safe_parse_record(self, txn_id: str) -> TransactionRecordModel | None:
        """
        Safely Parse A Single Transaction Record.

        Parameters
        ----------
        txn_id:
            Transaction identifier to parse.

        Returns
        -------
        TransactionRecordModel | None
            Parsed record model or None if parsing fails.
        """
        try:
            return TransactionRecordParser.from_id(TransactionId(txn_id))
        except Exception as e:
            self.logger.warning(
                "Skipping transaction %s due to parse error: %s", txn_id, e
            )
            return None

    # ---------------------------
    # Write helpers
    # ---------------------------

    def _insert_generic(
        self,
        mac_address: MacAddress,
        pnm_test_type: DocsPnmCmCtlTest,
        filename: str,
        system_description: dict[str, str] | None = None,
    ) -> TransactionId:
        """
        Common Logic For Creating And Persisting A Transaction Record.

        This internal helper generates a new transaction identifier, assembles
        the JSON-serializable record structure, and writes the updated
        transaction database back to disk.

        Parameters
        ----------
        mac_address:
            MAC address of the cable modem associated with the transaction.
        pnm_test_type:
            Enumeration describing the PNM test type that produced or owns the
            associated file.
        filename:
            Path or name of the PNM data file linked to this transaction.
        system_description:
            Optional system description snapshot dictionary, typically produced
            via `SystemDescriptor.to_dict()`. When omitted, an empty mapping is
            stored under `device_details.system_description`.

        Returns
        -------
        str
            Newly created transaction identifier associated with the record.
        """
        timestamp = int(time.time())
        hash_input = f"{filename}{timestamp}".encode()
        transaction_id = TransactionId(hashlib.sha256(hash_input).hexdigest()[:16])
        tx_id = str(transaction_id)
        if not tx_id.strip():
            self.logger.warning(
                "Skipping transaction_db insert for empty transaction_id (filename=%s, mac=%s)",
                filename,
                mac_address,
            )
            return TransactionId("")

        db = self._load_db()
        db[transaction_id] = {
            "timestamp": timestamp,
            "mac_address": str(mac_address),
            "pnm_test_type": pnm_test_type.name,
            "filename": filename,
            "device_details": {
                "system_description": system_description or {},
            },
        }
        self._save_db(db)
        return transaction_id

    def _load_db(self) -> dict:
        """
        Load The Transaction Database From JSON Storage.

        This helper reads the transaction database file configured by
        `SystemConfigSettings.transaction_db` and returns its contents as a
        dictionary. If JSON parsing fails, an empty dictionary is returned to
        avoid propagating the error to callers.

        Returns
        -------
        dict
            Dictionary of all transaction records keyed by transaction
            identifier. An empty dictionary is returned on parse errors.
        """
        try:
            with self.transaction_db_path.open("r") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            return {}
        if not isinstance(data, dict):
            self.logger.error(
                "Transaction DB root is not an object: %s",
                type(data).__name__,
            )
            return {}

        cleaned: dict = {}
        for key, value in data.items():
            if not str(key).strip():
                self.logger.warning("Skipping empty transaction_id in transaction_db")
                continue
            cleaned[key] = value
        return cleaned

    def _save_db(self, db: dict) -> None:
        """
        Persist The Transaction Database To Disk.

        Parameters
        ----------
        db:
            Fully realized transaction database dictionary to be serialized and
            written to the configured JSON file.
        """
        with self.transaction_db_path.open("w") as f:
            json.dump(db, f, indent=4)

# FILE: src/pypnm/api/routes/common/classes/file_capture/session_group.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
import logging
import time
import uuid
from json import JSONDecodeError
from pathlib import Path
from typing import Any

from pypnm.config.system_config_settings import SystemConfigSettings


class SessionGroup:
    """
    Manage sessions of measure operations (e.g., RxMER runs that contains multiple OFDM Channels within a single session) by grouping
    multiple file-transfer transactions under a single UUID-based group ID.

    Features:
      - Persist groups and their transaction lists in a JSON file across runs.
      - Generate or load a 16-character hexadecimal group ID per session.
      - Add, list, delete transactions; prune stale groups.

    JSON schema (DB file):
    {
        "<session_id>": {
            "created": <unix_epoch_seconds>,
            "transactions": ["<txn1>", "<txn2>", ...]
        },
        ...
    }

    Example:
        # New session
        cg = CaptureGroup()
        group_id = cg.create_group()

        # Existing session
        cg2 = SessionGroup(group_id=group_id)
        txns = cg2.get_transactions()
    """

    def __init__(
        self, session_id: str | None = None, db_path: Path | None = None
    ) -> None:
        """
        Initialize the SessionGroup manager.

        Args:
            session_id: Optional existing session ID to load; generates a new one if None.
            db_path: Optional Path for the JSON DB file. Defaults to config [PnmFileRetrieval].session_group_db.

        Raises:
            OSError: If the parent directory cannot be created.
        """
        self.logger = logging.getLogger(self.__class__.__name__)

        # Resolve DB file path
        if db_path:
            self.db_path = Path(db_path)

        else:
            cfg_db_path = SystemConfigSettings.session_group_db()
            self.db_path = Path(cfg_db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Create empty DB if missing
        if not self.db_path.exists():
            self._atomic_write_db({})

        # Load in-memory state
        self._db: dict[str, Any] = {}
        self._grp_id = session_id
        self._load_db()
        self._create_group_id()

    def _load_db(self) -> None:
        """
        Load the JSON DB into memory; resets on error.
        """
        try:
            with self.db_path.open("r", encoding="utf-8") as f:
                self._db = json.load(f)
        except (ValueError, JSONDecodeError):
            self.logger.warning("Corrupt DB file; resetting to empty")
            self._db = {}
        except Exception as e:
            self.logger.error(f"Error loading DB: {e}")
            self._db = {}

    def _atomic_write_db(self, data: dict[str, Any]) -> None:
        """
        Atomically write the given data dict to the JSON DB file.
        """
        temp_path = self.db_path.with_suffix(".tmp")
        with temp_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        temp_path.replace(self.db_path)

    def _save_db(self) -> None:
        """
        Persist the in-memory DB to disk using atomic write.
        """
        try:
            self._atomic_write_db(self._db)
        except Exception as e:
            self.logger.error(f"Failed to save DB: {e}")

    def _create_group_id(self) -> str:
        """
        Ensure a session ID is set (use existing or generate new).
        Returns the active session ID.
        """
        if not self._grp_id:
            self._grp_id = uuid.uuid4().hex[:16]
        return self._grp_id

    def get_session_id(self) -> str:
        """
        Get the current active session ID.
        Raises AssertionError if uninitialized.
        """
        assert self._grp_id, "session ID not initialized"
        return self._grp_id

    def create_session(self) -> str:
        """
        Add the current session to the DB (no-op if exists).
        Returns the session ID.
        """
        gid = self.get_session_id()
        if gid not in self._db:
            self._db[gid] = {"created": int(time.time()), "transactions": []}
            self._save_db()
            self.logger.info(f"Created new session: {gid}")
        else:
            self.logger.debug(f"session {gid} already exists")
        return gid

    def add_transaction(self, txn_id: str) -> None:
        """
        Append a transaction ID to this session, saving the DB.
        Raises ValueError if session missing.
        """
        if not txn_id or not txn_id.strip():
            self.logger.warning(
                "Skipping empty transaction_id persistence in session_group_db for session_id=%s",
                self.get_session_id(),
            )
            return
        gid = self.get_session_id()
        if gid not in self._db:
            raise ValueError("session not found; create_session() first")
        txns = self._db[gid].setdefault("transactions", [])
        if txn_id not in txns:
            txns.append(txn_id)
            self._save_db()
            self.logger.debug(f"Added txn {txn_id} to session {gid}")

    def get_transactions(self) -> list[str]:
        """
        Return all transaction IDs for this session (empty list if none).
        """
        return list(self._db.get(self.get_session_id(), {}).get("transactions", []))

    def delete_session(self) -> None:
        """
        Remove this session and its transactions from the DB; resets session ID.
        """
        gid = self.get_session_id()
        if gid in self._db:
            del self._db[gid]
            self._save_db()
            self.logger.info(f"Deleted session: {gid}")
        self._grp_id = None

    def list_sessions(self) -> list[str]:
        """
        List all session IDs currently in the DB.
        """
        return list(self._db.keys())

    def prune_older_than(self, seconds: int) -> None:
        """
        Remove sessions older than the given age (seconds).
        """
        cutoff = int(time.time()) - seconds
        to_delete = [
            gid for gid, info in self._db.items() if info.get("created", 0) < cutoff
        ]
        for gid in to_delete:
            del self._db[gid]
        if to_delete:
            self._save_db()
            self.logger.info(f"Pruned sessions: {to_delete}")

# FILE: tests/test_transaction_id_persistence_guards.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.api.routes.common.classes.file_capture.session_group import SessionGroup
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cable_modem import CableModem
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import TransactionId
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest


def _configure_transaction_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    db_path = tmp_path / "transactions.json"
    monkeypatch.setattr(
        SystemConfigSettings,
        "transaction_db",
        classmethod(lambda cls: str(db_path)),
    )
    return db_path


def _configure_session_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    db_path = tmp_path / "session_group.json"
    monkeypatch.setattr(
        SystemConfigSettings,
        "session_group_db",
        classmethod(lambda cls: str(db_path)),
    )
    return db_path


def _empty_sha256() -> object:
    class _Hasher:
        def update(self, _data: bytes) -> None:
            return None

        def hexdigest(self) -> str:
            return ""

    return _Hasher()


def test_session_group_skips_empty_transaction_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    db_path = _configure_session_db(tmp_path, monkeypatch)
    caplog.set_level("WARNING")
    group = SessionGroup()
    session_id = group.create_session()

    group.add_transaction("")
    group.add_transaction("   ")
    group.add_transaction("txn-1")

    with db_path.open("r", encoding="utf-8") as handle:
        db = json.load(handle)
    assert db[session_id]["transactions"] == ["txn-1"]
    assert (
        "Skipping empty transaction_id persistence in session_group_db" in caplog.text
    )


def test_pnm_file_transaction_skips_empty_transaction_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    db_path = _configure_transaction_db(tmp_path, monkeypatch)
    caplog.set_level("WARNING")
    monkeypatch.setattr(
        "pypnm.api.routes.common.classes.file_capture.pnm_file_transaction.hashlib.sha256",
        lambda _data=None: _empty_sha256(),
    )

    txn_store = PnmFileTransaction()
    cm = CableModem(
        mac_address=MacAddress("aa:bb:cc:dd:ee:ff"),
        inet=Inet("192.168.0.100"),
        write_community="public",
    )
    txn_id = txn_store._insert_generic(
        mac_address=cm.get_mac_address,
        pnm_test_type=DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR,
        filename="rxmer.bin",
    )

    assert str(txn_id) == ""
    assert "Skipping transaction_db insert for empty transaction_id" in caplog.text

    with db_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    assert data == {}


def test_pnm_file_transaction_persists_valid_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_transaction_db(tmp_path, monkeypatch)
    txn_store = PnmFileTransaction()
    cm = CableModem(
        mac_address=MacAddress("aa:bb:cc:dd:ee:ff"),
        inet=Inet("192.168.0.100"),
        write_community="public",
    )
    txn_id = txn_store._insert_generic(
        mac_address=cm.get_mac_address,
        pnm_test_type=DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR,
        filename="rxmer.bin",
    )

    with db_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    assert TransactionId(str(txn_id)) in {TransactionId(k) for k in data}
