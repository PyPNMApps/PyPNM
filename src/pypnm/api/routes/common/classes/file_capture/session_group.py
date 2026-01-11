# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

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
