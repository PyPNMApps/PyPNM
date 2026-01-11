# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import cast

from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.db.transaction_repository import (
    DeviceDetailsRepository,
    SystemDescriptionRepository,
    TransactionRepository,
)
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    FileName,
    TimestampSec,
    TransactionId,
)

PNM_TEST_TYPE: str = "DS_RXMER"

SYS_DESCR: dict[str, str] = {
    "HW_REV": "1.0",
    "VENDOR": "ACME",
    "BOOTR": "1.1",
    "SW_REV": "2.0.1",
    "MODEL": "ACME-123",
}

MAC_ONE = MacAddress("aa:bb:cc:dd:ee:ff")
MAC_TWO = MacAddress("11:22:33:44:55:66")

TRANSACTION_ONE = TransactionId("aaaaaaaaaaaaaaaa")
TRANSACTION_TWO = TransactionId("bbbbbbbbbbbbbbbb")
TRANSACTION_THREE = TransactionId("cccccccccccccccc")

FILENAME_ONE = FileName("rxmer_one.bin")
FILENAME_TWO = FileName("rxmer_two.bin")
FILENAME_THREE = FileName("rxmer_three.bin")

TIMESTAMP_ONE: int = 1700000000
TIMESTAMP_TWO: int = 1700000100

EXPECTED_SYS_DESCR_COUNT: int = 1
EXPECTED_DEVICE_DETAILS_COUNT: int = 1
EXPECTED_DISTINCT_MACS: int = 2


class _RepoFixture:
    @staticmethod
    def build(
        tmp_path: Path,
    ) -> tuple[
        SystemDescriptionRepository,
        DeviceDetailsRepository,
        TransactionRepository,
        Path,
    ]:
        db_path = tmp_path / "pypnm.sqlite3"
        sqlite_path = cast(DatabasePath, str(db_path))
        postgres_dsn = cast(DatabaseDsn, "")

        manager = DatabaseSchemaManager.from_overrides(
            DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
        )
        manager.initialize_schema()

        sys_repo = SystemDescriptionRepository.from_overrides(
            DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
        )
        device_repo = DeviceDetailsRepository.from_overrides(
            DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
        )
        txn_repo = TransactionRepository.from_overrides(
            DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
        )

        return sys_repo, device_repo, txn_repo, db_path

    @staticmethod
    def insert_transaction(
        sys_repo: SystemDescriptionRepository,
        device_repo: DeviceDetailsRepository,
        txn_repo: TransactionRepository,
        transaction_id: TransactionId,
        timestamp_epoch: int,
        mac_address: MacAddress,
        filename: FileName,
        sysdescr: dict[str, str],
    ) -> None:
        sysdescr_id = sys_repo.get_or_create_sysdescr_id(sysdescr)
        device_details: dict[str, object] = {"system_description": sysdescr}
        device_detail_id = device_repo.get_or_create_device_detail_id(
            device_details, sysdescr_id
        )
        txn_repo.insert_transaction(
            transaction_id=transaction_id,
            timestamp_epoch=TimestampSec(timestamp_epoch),
            mac_address=mac_address,
            pnm_test_type=PNM_TEST_TYPE,
            filename=filename,
            device_detail_id=device_detail_id,
        )


def test_sysdescr_dedup(tmp_path: Path) -> None:
    sys_repo, device_repo, txn_repo, db_path = _RepoFixture.build(tmp_path)

    _RepoFixture.insert_transaction(
        sys_repo,
        device_repo,
        txn_repo,
        TRANSACTION_ONE,
        TIMESTAMP_ONE,
        MAC_ONE,
        FILENAME_ONE,
        SYS_DESCR,
    )
    _RepoFixture.insert_transaction(
        sys_repo,
        device_repo,
        txn_repo,
        TRANSACTION_TWO,
        TIMESTAMP_TWO,
        MAC_ONE,
        FILENAME_TWO,
        SYS_DESCR,
    )

    connection = sqlite3.connect(db_path)
    try:
        cursor = connection.execute(
            "SELECT COUNT(1) FROM system_description_dim WHERE is_unknown = 0;"
        )
        row = cursor.fetchone()
        assert row is not None
        assert int(row[0]) == EXPECTED_SYS_DESCR_COUNT
    finally:
        connection.close()


def test_device_details_dedup(tmp_path: Path) -> None:
    sys_repo, device_repo, txn_repo, db_path = _RepoFixture.build(tmp_path)

    _RepoFixture.insert_transaction(
        sys_repo,
        device_repo,
        txn_repo,
        TRANSACTION_ONE,
        TIMESTAMP_ONE,
        MAC_ONE,
        FILENAME_ONE,
        SYS_DESCR,
    )
    _RepoFixture.insert_transaction(
        sys_repo,
        device_repo,
        txn_repo,
        TRANSACTION_TWO,
        TIMESTAMP_TWO,
        MAC_TWO,
        FILENAME_TWO,
        SYS_DESCR,
    )

    connection = sqlite3.connect(db_path)
    try:
        cursor = connection.execute("SELECT COUNT(1) FROM device_details;")
        row = cursor.fetchone()
        assert row is not None
        assert int(row[0]) == EXPECTED_DEVICE_DETAILS_COUNT
    finally:
        connection.close()


def test_list_macs_returns_distinct(tmp_path: Path) -> None:
    sys_repo, device_repo, txn_repo, _db_path = _RepoFixture.build(tmp_path)

    _RepoFixture.insert_transaction(
        sys_repo,
        device_repo,
        txn_repo,
        TRANSACTION_ONE,
        TIMESTAMP_ONE,
        MAC_ONE,
        FILENAME_ONE,
        SYS_DESCR,
    )
    _RepoFixture.insert_transaction(
        sys_repo,
        device_repo,
        txn_repo,
        TRANSACTION_TWO,
        TIMESTAMP_TWO,
        MAC_ONE,
        FILENAME_TWO,
        SYS_DESCR,
    )
    _RepoFixture.insert_transaction(
        sys_repo,
        device_repo,
        txn_repo,
        TRANSACTION_THREE,
        TIMESTAMP_TWO,
        MAC_TWO,
        FILENAME_THREE,
        SYS_DESCR,
    )

    mac_entries = txn_repo.list_macs()
    assert len(mac_entries) == EXPECTED_DISTINCT_MACS
    macs = {entry.mac_address for entry in mac_entries}
    assert str(MAC_ONE) in macs
    assert str(MAC_TWO) in macs


def test_list_transactions_for_mac_orders_by_timestamp(tmp_path: Path) -> None:
    sys_repo, device_repo, txn_repo, _db_path = _RepoFixture.build(tmp_path)

    _RepoFixture.insert_transaction(
        sys_repo,
        device_repo,
        txn_repo,
        TRANSACTION_ONE,
        TIMESTAMP_TWO,
        MAC_ONE,
        FILENAME_ONE,
        SYS_DESCR,
    )
    _RepoFixture.insert_transaction(
        sys_repo,
        device_repo,
        txn_repo,
        TRANSACTION_TWO,
        TIMESTAMP_ONE,
        MAC_ONE,
        FILENAME_TWO,
        SYS_DESCR,
    )

    records = txn_repo.list_transactions_for_mac(MAC_ONE)
    timestamps = [int(record.timestamp_epoch) for record in records]
    assert timestamps == [TIMESTAMP_ONE, TIMESTAMP_TWO]
