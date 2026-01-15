# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from pypnm.config.pnm_config_manager import SystemConfigSettings
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.db.json_transaction import JsonTransactionDb
from pypnm.lib.types import DatabaseBackend, DatabaseDsn, DatabasePath


def _configure_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    db_path = tmp_path / "pypnm.sqlite3"
    json_dir = tmp_path / "json"
    json_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(
        SystemConfigSettings,
        "pnm_dir",
        classmethod(lambda cls: str(tmp_path / "pnm")),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "json_dir",
        classmethod(lambda cls: str(json_dir)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_backend",
        classmethod(lambda cls: DatabaseBackend.SQLITE),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_sqlite_path",
        classmethod(lambda cls: DatabasePath(str(db_path))),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_postgres_dsn",
        classmethod(lambda cls: DatabaseDsn("")),
    )

    DatabaseSchemaManager.from_system_config().initialize_schema()
    return db_path


def test_write_json_without_transaction_id_does_not_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_db(tmp_path, monkeypatch)
    db = JsonTransactionDb()

    db.write_json({"alpha": 1}, fname="payload", extension="json")

    with sqlite3.connect(db_path) as conn:
        cursor = conn.execute("SELECT COUNT(*) FROM transaction_artifacts;")
        row = cursor.fetchone()
        assert row is not None
        assert int(row[0]) == 0
