## Agent Review Bundle Summary
- Goal:
- Changes:
- Files:
- Tests:
- Notes:
# FILE: docs/issues/index.md
# Reporting Issues

If you encounter a bug or unexpected behavior while using PyPNM, please report it
so we can investigate and resolve the issue. This document outlines the steps to
create a support bundle that captures the necessary data for debugging.

[REPORTING ISSUES](reporting-issues.md)

## Support Bundle Script

PyPNM includes a support bundle script that collects relevant logs, database
entries, and configuration files related to your issue. This script helps
sanitize sensitive information before sharing it with the PyPNM support team.

[Support Bundle Builder](support-bundle.md)

## FAQ

### Multi-capture results return 404 with legacy operation_capture.json

The canonical key is `capture_group_id`, but `capture_group` is still accepted
as a fallback for existing persisted JSON during this transition. If multi-
capture result endpoints return 404 while `operation_capture.json` stores the
legacy key, upgrade to a build that accepts it and backfills the mapping into
the DB.

### Transaction records store an unexpected MAC address value

The canonical MAC address stored in `transaction_records` is a lowercase string.
Earlier builds could persist a non-string value when `PnmFileTransaction.insert`
was passed a callable. Upgrade to a build with the fix and re-run captures to
refresh affected entries.

# FILE: docs/todo/todo.md
# TODO

- Validate FAQ entry for the PnmFileTransaction MAC address persistence fix
  in docs/issues/index.md.

# FILE: tests/test_transaction_id_persistence_guards.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.api.routes.common.classes.file_capture.session_group import SessionGroup
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.sysDescr import SystemDescriptor
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import DatabaseBackend, DatabaseDsn, DatabasePath
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest

_TRANSACTION_ID_LENGTH: int = 16
_TIME_NS_FIRST: int = 100
_TIME_NS_SECOND: int = 101


def _configure_transaction_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    db_path = tmp_path / "pypnm.sqlite3"
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
    assert "Skipping transaction insert for empty transaction_id" in caplog.text

    connection = sqlite3.connect(db_path)
    try:
        cursor = connection.execute("SELECT COUNT(1) FROM transaction_records;")
        row = cursor.fetchone()
        assert row is not None
        assert int(row[0]) == 0
    finally:
        connection.close()


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

    connection = sqlite3.connect(db_path)
    try:
        cursor = connection.execute(
            "SELECT COUNT(1) FROM transaction_records WHERE transaction_id = ?;",
            (str(txn_id),),
        )
        row = cursor.fetchone()
        assert row is not None
        assert int(row[0]) == 1
    finally:
        connection.close()


@pytest.mark.asyncio
async def test_pnm_file_transaction_insert_persists_mac_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_transaction_db(tmp_path, monkeypatch)
    txn_store = PnmFileTransaction()
    cm = CableModem(
        mac_address=MacAddress("aa:bb:cc:dd:ee:ff"),
        inet=Inet("192.168.0.100"),
        write_community="public",
    )

    async def _fake_sysdescr() -> SystemDescriptor:
        return SystemDescriptor.empty()

    monkeypatch.setattr(cm, "getSysDescr", _fake_sysdescr)

    txn_id = await txn_store.insert(
        cable_modem=cm,
        pnm_test_type=DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR,
        filename="rxmer.bin",
    )

    connection = sqlite3.connect(db_path)
    try:
        cursor = connection.execute(
            "SELECT mac_address FROM transaction_records WHERE transaction_id = ?;",
            (str(txn_id),),
        )
        row = cursor.fetchone()
        assert row is not None
        assert row[0] == "aa:bb:cc:dd:ee:ff"
    finally:
        connection.close()


def test_pnm_file_transaction_id_is_unique_and_16_chars(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_transaction_db(tmp_path, monkeypatch)

    time_ns_values = iter([_TIME_NS_FIRST, _TIME_NS_SECOND])

    def _fake_time_ns() -> int:
        return next(time_ns_values)

    monkeypatch.setattr(
        "pypnm.api.routes.common.classes.file_capture.pnm_file_transaction.time.time_ns",
        _fake_time_ns,
    )

    txn_store = PnmFileTransaction()
    mac_address = MacAddress("aa:bb:cc:dd:ee:ff")
    first_id = txn_store._insert_generic(
        mac_address=mac_address,
        pnm_test_type=DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR,
        filename="rxmer.bin",
    )
    second_id = txn_store._insert_generic(
        mac_address=mac_address,
        pnm_test_type=DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR,
        filename="rxmer.bin",
    )

    assert str(first_id) != str(second_id)
    assert len(str(first_id)) == _TRANSACTION_ID_LENGTH
    assert len(str(second_id)) == _TRANSACTION_ID_LENGTH
