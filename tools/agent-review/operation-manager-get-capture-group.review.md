### Summary
Aligned OperationManager.get_capture_group to return GroupId | None with canonical/legacy key support, removed empty-string sentinels, and added tests for canonical, legacy, and missing record behavior.

### Modified Files
- src/pypnm/api/routes/advance/common/operation_manager.py
- tests/test_operation_manager_get_capture_group.py

### Commands Executed And Results
- `python3 -m compileall src` → pass
- `ruff check .` → pass
- `ruff format --check .` → pass
- `pytest -q` → pass (560 passed, 4 skipped)

### Tests
- `pytest` → pass (560 passed, 4 skipped)
- `ruff` → pass
- `python3 -m compileall src` → pass

### Notes / Warnings
- Pytest logs include expected warnings from existing tests; no deprecation warnings observed.

### Remaining TODOs / Follow-Ups
- None

# FILE: src/pypnm/api/routes/advance/common/operation_manager.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
from __future__ import annotations

import json
import logging
import time
import uuid
from pathlib import Path
from typing import Any

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.constants import cast
from pypnm.lib.types import GroupId, OperationId


class OperationManager:
    """
    Manager for mapping background capture operations to their capture group IDs.

    Each operation is assigned a unique operation_id and linked to a
    capture_group_id. Mappings are persisted in a JSON file so that
    captures can be looked up later by operation ID.

    JSON schema:
    {
        "<operation_id>": {
            "capture_group_id": "<group_id>",
            "created": <unix_epoch_seconds>
        },
        ...
    }
    """

    def __init__(self, capture_group_id: GroupId, db_path: Path | None = None) -> None:
        """
        Initialize a new operation manager for a given capture group.

        Args:
            capture_group_id: The ID of the capture group to associate.
            db_path: Optional path to the operations DB file; if None,
                     retrieves from ConfigManager under
                     [PnmFileRetrieval].operation_db.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.capture_group_id: GroupId = capture_group_id
        self.operation_id: OperationId = cast(OperationId, uuid.uuid4().hex[:16])

        # Resolve DB file path
        if db_path:
            self.db_path = db_path
        else:
            db_str = SystemConfigSettings.operation_db()
            self.db_path = Path(db_str)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Ensure DB exists
        if not self.db_path.exists():
            self._atomic_write({})

    def _load(self) -> dict[str, Any]:
        """
        Load the operations DB from disk.

        Returns:
            Dict of operation mappings, or empty dict on parse error.
        """
        try:
            with self.db_path.open("r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            self.logger.warning(f"Failed to load operation DB, resetting: {e}")
            return {}

    def _atomic_write(self, data: dict[str, Any]) -> None:
        """
        Atomically write the given data to the DB file.
        """
        temp = self.db_path.with_suffix(".tmp")
        with temp.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        temp.replace(self.db_path)

    def _save(self, data: dict[str, Any]) -> None:
        """
        Persist the given operations dict to disk with atomic write.
        """
        try:
            self._atomic_write(data)
        except Exception as e:
            self.logger.error(f"Failed to save operation DB: {e}")

    def register(self) -> OperationId:
        """
        Register this operation with its capture group ID in the DB.

        Verifies that the associated capture group exists before registration.

        Returns:
            The operation_id assigned.

        Raises:
            ValueError: If the capture_group_id is not present in the CaptureGroup database.
        """
        # Verify that the capture group exists, or fail hard
        from pypnm.api.routes.common.classes.file_capture.capture_group import (
            CaptureGroup,
        )

        cg = CaptureGroup(group_id=self.capture_group_id)
        if self.capture_group_id not in cg.list_groups():
            raise ValueError(f"CaptureGroup '{self.capture_group_id}' does not exist")

        db = self._load()
        db[self.operation_id] = {
            "capture_group_id": self.capture_group_id,
            "created": int(time.time()),
        }
        self._save(db)
        self.logger.info(
            f"Registered operation {self.operation_id} for group {self.capture_group_id}"
        )
        return self.operation_id

    @classmethod
    def get_capture_group(
        cls, operation_id: OperationId, db_path: Path | None = None
    ) -> GroupId | None:
        """
        Retrieve the capture_group_id for a given operation_id.

        Args:
            operation_id: The operation ID to look up.
            db_path: Optional override for the operations DB file.

        Returns:
            capture_group_id if found, otherwise None.
        """
        logger = logging.getLogger(cls.__name__)
        if not db_path:
            db_str = SystemConfigSettings.operation_db()
            db_path = Path(db_str)
        try:
            with db_path.open("r", encoding="utf-8") as f:
                db = json.load(f)
            rec = db.get(operation_id)
            if isinstance(rec, dict):
                capture_group_id = rec.get("capture_group_id")
                if capture_group_id:
                    return GroupId(str(capture_group_id))
                legacy_capture_group = rec.get("capture_group")
                if legacy_capture_group:
                    logger.warning(
                        "Operation record for %s uses legacy 'capture_group' field",
                        operation_id,
                    )
                    return GroupId(str(legacy_capture_group))
            return None
        except Exception as e:
            logger.error(f"Error retrieving capture group for {operation_id}: {e}")
            return None

    @classmethod
    def list_operations(cls, db_path: Path | None = None) -> list[str]:
        """
        List all registered operation IDs.

        Args:
            db_path: Optional override for the operations DB file.

        Returns:
            List of operation_id strings.
        """
        if not db_path:
            db_str = SystemConfigSettings.operation_db()
            db_path = Path(db_str)
        try:
            with db_path.open("r", encoding="utf-8") as f:
                return list(json.load(f).keys())
        except Exception as e:
            logging.getLogger(cls.__name__).error(f"Error listing operations: {e}")
            return []

# FILE: tests/test_operation_manager_get_capture_group.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pypnm.api.routes.advance.common.operation_manager import OperationManager
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.types import GroupId, OperationId


def _configure_operation_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    base_dir = tmp_path / ".data"
    db_dir = base_dir / "db"
    db_dir.mkdir(parents=True, exist_ok=True)

    operation_db = db_dir / "operation_capture.json"
    monkeypatch.setattr(
        SystemConfigSettings,
        "operation_db",
        classmethod(lambda cls: str(operation_db)),
    )
    return operation_db


def test_get_capture_group_returns_group_id_for_canonical_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    operation_db = _configure_operation_db(tmp_path, monkeypatch)
    operation_id = OperationId("op-200")
    capture_group_id = GroupId("group-200")

    operation_db.write_text(
        json.dumps(
            {
                str(operation_id): {
                    "capture_group_id": str(capture_group_id),
                    "created": 1,
                }
            }
        ),
        encoding="utf-8",
    )

    resolved = OperationManager.get_capture_group(operation_id)
    assert resolved == capture_group_id


def test_get_capture_group_returns_group_id_for_legacy_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    operation_db = _configure_operation_db(tmp_path, monkeypatch)
    operation_id = OperationId("op-201")
    capture_group_id = GroupId("group-201")

    operation_db.write_text(
        json.dumps(
            {
                str(operation_id): {
                    "capture_group": str(capture_group_id),
                    "created": 1,
                }
            }
        ),
        encoding="utf-8",
    )

    resolved = OperationManager.get_capture_group(operation_id)
    assert resolved == capture_group_id


def test_get_capture_group_returns_none_when_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_db(tmp_path, monkeypatch)
    operation_id = OperationId("op-202")

    resolved = OperationManager.get_capture_group(operation_id)
    assert resolved is None
