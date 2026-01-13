# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
import time
import uuid

from pypnm.lib.db.session_group_repository import SessionGroupRepository
from pypnm.lib.types import GroupId, TimestampSec, TransactionId


class SessionGroup:
    """
    Manage sessions of measure operations (e.g., RxMER runs that contains multiple
    OFDM Channels within a single session) by grouping multiple file-transfer
    transactions under a single UUID-based group ID.

    Features:
      - Persist groups and their transaction membership in the configured DB backend.
      - Generate or load a 16-character hexadecimal group ID per session.
      - Add, list, delete transactions; prune stale groups.

    Example:
        # New session
        sg = SessionGroup()
        session_id = sg.create_session()

        # Existing session
        sg2 = SessionGroup(session_id=session_id)
        txns = sg2.get_transactions()
    """

    def __init__(
        self, session_id: GroupId | None = None, db_path: str | None = None
    ) -> None:
        """
        Initialize the SessionGroup manager.

        Args:
            session_id: Optional existing session ID to load; generates a new one if None.
            db_path: Legacy JSON DB path (deprecated; ignored in DB-backed storage).
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        if db_path:
            self.logger.debug(
                "Ignoring legacy session_group_db path override: %s",
                db_path,
            )
        self._repo = SessionGroupRepository.from_system_config()
        self._grp_id: GroupId | None = session_id
        self._create_group_id()

    def _create_group_id(self) -> GroupId:
        """
        Ensure a session ID is set (use existing or generate new).
        Returns the active session ID.
        """
        if not self._grp_id:
            self._grp_id = GroupId(uuid.uuid4().hex[:16])
        return self._grp_id

    def get_session_id(self) -> GroupId:
        """
        Get the current active session ID.
        Raises AssertionError if uninitialized.
        """
        assert self._grp_id, "session ID not initialized"
        return self._grp_id

    def create_session(self) -> GroupId:
        """
        Add the current session to the DB (no-op if exists).
        Returns the session ID.
        """
        gid = self.get_session_id()
        if not self._repo.session_exists(gid):
            created_epoch = TimestampSec(int(time.time()))
            self._repo.create_session_group(gid, created_epoch)
            self.logger.info("Created new session: %s", gid)
        else:
            self.logger.debug("Session %s already exists", gid)
        return gid

    def add_transaction(self, txn_id: TransactionId | str) -> None:
        """
        Append a transaction ID to this session, saving the DB.
        Raises ValueError if session missing.
        """
        txn_value = str(txn_id)
        if not txn_value or not txn_value.strip():
            self.logger.warning(
                "Skipping empty transaction_id persistence in session_group for session_id=%s",
                self.get_session_id(),
            )
            return
        gid = self.get_session_id()
        if not self._repo.session_exists(gid):
            raise ValueError("session not found; create_session() first")
        self._repo.add_transaction(
            gid, TransactionId(txn_value), TimestampSec(int(time.time()))
        )
        self.logger.debug("Added txn %s to session %s", txn_value, gid)

    def get_transactions(self) -> list[TransactionId]:
        """
        Return all transaction IDs for this session (empty list if none), ordered
        by added timestamp then transaction ID.
        """
        return self._repo.list_transactions(self.get_session_id())

    def delete_session(self) -> None:
        """
        Remove this session and its transactions from the DB; resets session ID.
        """
        gid = self.get_session_id()
        self._repo.delete_session(gid)
        self.logger.info("Deleted session: %s", gid)
        self._grp_id = None

    def list_sessions(self) -> list[GroupId]:
        """
        List all session IDs currently in the DB.
        """
        return self._repo.list_sessions()

    def prune_older_than(self, seconds: int) -> None:
        """
        Remove sessions older than the given age (seconds).
        """
        cutoff = TimestampSec(int(time.time()) - seconds)
        pruned = self._repo.delete_older_than(cutoff)
        if pruned:
            self.logger.info("Pruned sessions: %s", pruned)
