## Agent Review Bundle Summary
- Goal:
- Changes:
- Files:
- Tests:
- Notes:

### Summary
Prevented empty or whitespace transaction IDs from being persisted to capture_group.json while preserving in-memory error samples, and added a focused test for the skip behavior.

### Modified Files
- src/pypnm/api/routes/common/classes/file_capture/capture_group.py
- tests/test_capture_group_empty_transaction.py

### Commands Executed And Results
- `python3 -m compileall src` → pass
- `ruff check .` → pass
- `ruff format --check .` → pass
- `pytest -k "capture_group and empty_transaction" -q` → pass (1 passed, 539 deselected)

### Tests
- `pytest -k "capture_group and empty_transaction" -q` → pass (1 passed, 539 deselected)
- `ruff` → pass (`ruff check .`)

### Notes / Warnings
- None

### Remaining TODOs / Follow-Ups
- None

# FILE: src/pypnm/api/routes/common/classes/file_capture/capture_group.py
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
from pypnm.lib.types import GroupId, TransactionId


class CaptureGroup:
    """
    Manage sessions of capture operations (e.g., multi-RxMER runs) by grouping
    multiple file-transfer transactions under a single UUID-based group ID.

    Features:
      - Persist groups and their transaction lists in a JSON file across runs.
      - Generate or load a 16-character hexadecimal group ID per session.
      - Add, list, delete transactions; prune stale groups.

    JSON schema (DB file):
    {
        "<group_id>": {
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
        cg2 = CaptureGroup(group_id=group_id)
        txns = cg2.get_transactions()
    """

    def __init__(
        self, group_id: GroupId | None = None, db_path: Path | None = None
    ) -> None:
        """
        Initialize the CaptureGroup manager.

        Args:
            group_id: Optional existing group ID to load; generates a new one if None.
            db_path: Optional Path for the JSON DB file. Defaults to config [PnmFileRetrieval].capture_group_db.

        Raises:
            OSError: If the parent directory cannot be created.
        """
        self.logger = logging.getLogger(self.__class__.__name__)

        # Resolve DB file path
        if db_path:
            self.db_path = Path(db_path)
        else:
            cfg_db_path = SystemConfigSettings.capture_group_db()
            self.db_path = Path(cfg_db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Create empty DB if missing
        if not self.db_path.exists():
            self._atomic_write_db({})

        # Load in-memory state
        self._db: dict[str, Any] = {}
        self._grp_id: GroupId = group_id
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
        Ensure a group ID is set (use existing or generate new).
        Returns the active group ID.
        """
        if not self._grp_id:
            self._grp_id = uuid.uuid4().hex[:16]
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
        if gid not in self._db:
            self._db[gid] = {"created": int(time.time()), "transactions": []}
            self._save_db()
            self.logger.info(f"Created new group: {gid}")
        else:
            self.logger.debug(f"Group {gid} already exists")
        return gid

    def add_transaction(self, txn_id: str) -> None:
        """
        Append a transaction ID to this group, saving the DB.
        Raises ValueError if group missing.
        """
        if not txn_id or not txn_id.strip():
            self.logger.warning("Skipping empty transaction_id persistence")
            return
        gid = self.get_group_id()
        if gid not in self._db:
            raise ValueError("Group not found; create_group() first")
        txns = self._db[gid].setdefault("transactions", [])
        if txn_id not in txns:
            txns.append(txn_id)
            self._save_db()
            self.logger.debug(f"Added txn {txn_id} to group {gid}")

    def getTransactionIds(self) -> list[TransactionId]:
        """
        Return all transaction IDs for this group (empty list if none).
        """
        return list(self._db.get(self.get_group_id(), {}).get("transactions", []))

    def delete_group(self) -> None:
        """
        Remove this group and its transactions from the DB; resets group ID.
        """
        gid = self.get_group_id()
        if gid in self._db:
            del self._db[gid]
            self._save_db()
            self.logger.info(f"Deleted group: {gid}")
        self._grp_id = None

    def list_groups(self) -> list[str]:
        """
        List all group IDs currently in the DB.
        """
        return list(self._db.keys())

    def prune_older_than(self, seconds: int) -> None:
        """
        Remove groups older than the given age (seconds).
        """
        cutoff = int(time.time()) - seconds
        to_delete = [
            gid for gid, info in self._db.items() if info.get("created", 0) < cutoff
        ]
        for gid in to_delete:
            del self._db[gid]
        if to_delete:
            self._save_db()
            self.logger.info(f"Pruned groups: {to_delete}")

# FILE: tests/test_capture_group_empty_transaction.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pypnm.api.routes.common.classes.file_capture.capture_group import CaptureGroup
from pypnm.config.system_config_settings import SystemConfigSettings


def _configure_capture_group_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    db_path = tmp_path / "capture_group.json"
    monkeypatch.setattr(
        SystemConfigSettings,
        "capture_group_db",
        classmethod(lambda cls: str(db_path)),
    )
    return db_path


def test_add_transaction_skips_empty_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_capture_group_db(tmp_path, monkeypatch)
    capture_group = CaptureGroup()
    group_id = capture_group.create_group()

    capture_group.add_transaction("")
    capture_group.add_transaction("   ")
    capture_group.add_transaction("txn-1")

    with db_path.open("r", encoding="utf-8") as handle:
        db = json.load(handle)

    transactions = db[group_id]["transactions"]
    assert transactions == ["txn-1"]
