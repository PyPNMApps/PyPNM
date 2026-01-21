#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass
from pathlib import Path

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.data_type.sysDescr import SystemDescriptor
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.db.transaction_repository import (
    DeviceDetailsRepository,
    SystemDescriptionRepository,
    TransactionRepository,
)
from pypnm.lib.types import (
    ExitCode,
    FileName,
    JsonValue,
    MacAddressStr,
    StringArray,
    TimestampSec,
    TransactionId,
)

_DEFAULT_LOG_FORMAT: str = "%(levelname)s %(name)s: %(message)s"
_DEFAULT_LEDGER_PATH: str = ".data/db/transactions.json"
_TIMESTAMP_KEYS: tuple[str, ...] = ("timestamp", "timestamp_epoch", "timestampEpoch")
_TXN_ID_KEYS: tuple[str, ...] = ("transaction_id", "transactionId", "transactionIdHex")
_MAC_KEYS: tuple[str, ...] = ("mac_address", "macAddress", "mac")
_PNM_TEST_TYPE_KEYS: tuple[str, ...] = ("pnm_test_type", "pnmTestType")
_FILENAME_KEYS: tuple[str, ...] = ("filename", "file_name", "fileName")
_DEVICE_DETAILS_KEYS: tuple[str, ...] = ("device_details", "deviceDetails")


@dataclass(frozen=True)
class TransactionRecord:
    transaction_id: TransactionId
    timestamp_epoch: TimestampSec
    mac_address: MacAddressStr
    pnm_test_type: str
    filename: FileName
    device_details: dict[str, object]


class TransactionMigrator:
    """
    Import legacy transactions.json into the DB-backed transaction_records tables.
    """

    EXIT_OK: ExitCode = ExitCode(0)
    EXIT_USAGE: ExitCode = ExitCode(2)
    EXIT_FAILURE: ExitCode = ExitCode(1)

    def __init__(self) -> None:
        self.logger = logging.getLogger(f"{self.__class__.__name__}")

    @staticmethod
    def _load_json(path: Path) -> JsonValue:
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def _resolve_default_path() -> Path:
        app_root = DatabaseSchemaManager.from_system_config().resolve_app_root()
        return app_root / _DEFAULT_LEDGER_PATH

    @staticmethod
    def _extract_string(entry: dict[str, object], keys: tuple[str, ...]) -> str:
        for key in keys:
            raw = entry.get(key)
            if isinstance(raw, str):
                return raw
        return ""

    @staticmethod
    def _extract_timestamp(entry: dict[str, object]) -> TimestampSec | None:
        for key in _TIMESTAMP_KEYS:
            raw = entry.get(key)
            if isinstance(raw, int):
                return TimestampSec(int(raw))
            if isinstance(raw, float):
                return TimestampSec(int(raw))
            if isinstance(raw, str) and raw.isdigit():
                return TimestampSec(int(raw))
        return None

    @staticmethod
    def _extract_device_details(entry: dict[str, object]) -> dict[str, object]:
        for key in _DEVICE_DETAILS_KEYS:
            raw = entry.get(key)
            if isinstance(raw, dict):
                return raw
        return {}

    def _parse_entry(
        self, transaction_id: str, entry: object
    ) -> TransactionRecord | None:
        if not isinstance(entry, dict):
            return None
        tx_id = transaction_id.strip()
        if not tx_id:
            return None
        timestamp = self._extract_timestamp(entry)
        if timestamp is None:
            return None
        mac_address = self._extract_string(entry, _MAC_KEYS).strip()
        if not mac_address:
            return None
        pnm_test_type = self._extract_string(entry, _PNM_TEST_TYPE_KEYS).strip()
        if not pnm_test_type:
            return None
        filename = self._extract_string(entry, _FILENAME_KEYS).strip()
        if not filename:
            return None
        device_details = self._extract_device_details(entry)
        return TransactionRecord(
            transaction_id=TransactionId(tx_id),
            timestamp_epoch=timestamp,
            mac_address=MacAddressStr(mac_address),
            pnm_test_type=pnm_test_type,
            filename=FileName(filename),
            device_details=device_details,
        )

    def _parse_payload(self, payload: JsonValue) -> tuple[list[TransactionRecord], int]:
        records: list[TransactionRecord] = []
        skipped = 0
        if isinstance(payload, dict):
            for transaction_id, entry in payload.items():
                if not isinstance(transaction_id, str):
                    skipped += 1
                    continue
                record = self._parse_entry(transaction_id, entry)
                if record is None:
                    skipped += 1
                    continue
                records.append(record)
            return records, skipped
        if isinstance(payload, list):
            for entry in payload:
                if not isinstance(entry, dict):
                    skipped += 1
                    continue
                tx_id = self._extract_string(entry, _TXN_ID_KEYS).strip()
                record = self._parse_entry(tx_id, entry)
                if record is None:
                    skipped += 1
                    continue
                records.append(record)
            return records, skipped
        raise ValueError("transactions.json must be a JSON object or list")

    def _migrate_records(self, records: list[TransactionRecord]) -> tuple[int, int, int]:
        sys_repo = SystemDescriptionRepository.from_system_config()
        device_repo = DeviceDetailsRepository.from_system_config()
        txn_repo = TransactionRepository.from_system_config()
        imported = 0
        failed = 0
        duplicates = 0
        for record in records:
            if txn_repo.get_transaction_record(record.transaction_id) is not None:
                duplicates += 1
                continue
            try:
                sysdescr_payload: dict[str, str] = {}
                system_description = record.device_details.get("system_description")
                if isinstance(system_description, dict):
                    cleaned = {
                        str(key): str(value) for key, value in system_description.items()
                    }
                    sysdescr_payload = SystemDescriptor.load_from_dict(cleaned).to_dict()
                sysdescr_id = sys_repo.get_or_create_sysdescr_id(sysdescr_payload)
                device_detail_id = device_repo.get_or_create_device_detail_id(
                    record.device_details, sysdescr_id
                )
                txn_repo.insert_transaction(
                    transaction_id=record.transaction_id,
                    timestamp_epoch=record.timestamp_epoch,
                    mac_address=record.mac_address,
                    pnm_test_type=record.pnm_test_type,
                    filename=record.filename,
                    device_detail_id=device_detail_id,
                )
                imported += 1
            except Exception as exc:
                failed += 1
                self.logger.error(
                    "Failed to import transaction_id=%s: %s",
                    record.transaction_id,
                    exc,
                )
        return imported, duplicates, failed

    def run(self, argv: StringArray) -> ExitCode:
        parser = argparse.ArgumentParser(
            description="Migrate legacy transactions.json into the DB backend."
        )
        parser.add_argument(
            "--input",
            type=Path,
            help="Path to legacy transactions.json (defaults to .data/db/transactions.json).",
        )

        args = parser.parse_args(argv)
        SystemConfigSettings.reload()

        input_path = args.input
        if input_path is None:
            input_path = self._resolve_default_path()

        if not input_path.exists():
            self.logger.warning("Legacy transactions.json not found: %s", input_path)
            return self.EXIT_OK

        try:
            payload = self._load_json(input_path)
            records, skipped = self._parse_payload(payload)
        except Exception as exc:
            self.logger.error("Failed to read legacy transactions.json: %s", exc)
            return self.EXIT_FAILURE

        DatabaseSchemaManager.from_system_config().initialize_schema()

        imported, duplicates, failed = self._migrate_records(records)
        self.logger.info(
            "Migrated %d transaction records from %s (duplicates=%d, skipped=%d, failed=%d)",
            imported,
            input_path,
            duplicates,
            skipped,
            failed,
        )
        return self.EXIT_OK


def main() -> None:
    logging.basicConfig(level=logging.INFO, format=_DEFAULT_LOG_FORMAT)
    migrator = TransactionMigrator()
    raise SystemExit(migrator.run(sys.argv[1:]))


if __name__ == "__main__":
    main()
