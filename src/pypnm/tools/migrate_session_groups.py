#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.db.session_group_repository import SessionGroupRepository
from pypnm.lib.types import ExitCode, GroupId, JsonObject, StringArray, TimestampSec, TransactionId

_DEFAULT_LOG_FORMAT: str = "%(levelname)s %(name)s: %(message)s"
_CREATED_EPOCH_KEYS: tuple[str, ...] = ("created_epoch", "created", "timestamp", "created_at")


@dataclass(frozen=True)
class SessionGroupRecord:
    session_id: GroupId
    created_epoch: TimestampSec
    transactions: list[TransactionId]


class SessionGroupMigrator:
    """
    Import legacy session_group.json into the DB-backed session group tables.
    """

    EXIT_OK: ExitCode = ExitCode(0)
    EXIT_USAGE: ExitCode = ExitCode(2)
    EXIT_FAILURE: ExitCode = ExitCode(1)

    def __init__(self) -> None:
        self.logger = logging.getLogger(f"{self.__class__.__name__}")

    @staticmethod
    def _load_json(path: Path) -> JsonObject:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("session_group.json must contain a JSON object")
        return payload

    @staticmethod
    def _extract_transactions(entry: object) -> list[TransactionId]:
        if isinstance(entry, dict):
            candidates = (
                entry.get("transactions"),
                entry.get("transaction_ids"),
                entry.get("transaction_id_list"),
            )
            for candidate in candidates:
                if isinstance(candidate, list):
                    return SessionGroupMigrator._normalize_transactions(candidate)
            return []
        if isinstance(entry, list):
            return SessionGroupMigrator._normalize_transactions(entry)
        return []

    @staticmethod
    def _normalize_transactions(items: list[object]) -> list[TransactionId]:
        transactions: list[TransactionId] = []
        for item in items:
            if not isinstance(item, str):
                continue
            cleaned = item.strip()
            if cleaned:
                transactions.append(TransactionId(cleaned))
        return transactions

    @staticmethod
    def _extract_created_epoch(entry: object, fallback: TimestampSec) -> TimestampSec:
        if isinstance(entry, dict):
            for key in _CREATED_EPOCH_KEYS:
                raw = entry.get(key)
                if isinstance(raw, int):
                    return TimestampSec(int(raw))
                if isinstance(raw, float):
                    return TimestampSec(int(raw))
                if isinstance(raw, str) and raw.isdigit():
                    return TimestampSec(int(raw))
        return fallback

    def _parse_records(self, payload: JsonObject) -> list[SessionGroupRecord]:
        records: list[SessionGroupRecord] = []
        now = TimestampSec(int(time.time()))
        for session_id, entry in payload.items():
            if not isinstance(session_id, str):
                continue
            normalized_session = session_id.strip()
            if not normalized_session:
                continue
            created_epoch = self._extract_created_epoch(entry, now)
            transactions = self._extract_transactions(entry)
            records.append(
                SessionGroupRecord(
                    session_id=GroupId(normalized_session),
                    created_epoch=created_epoch,
                    transactions=transactions,
                )
            )
        return records

    def _migrate_records(self, records: list[SessionGroupRecord]) -> tuple[int, int]:
        repo = SessionGroupRepository.from_system_config()
        session_count = 0
        transaction_count = 0
        for record in records:
            repo.create_session_group(record.session_id, record.created_epoch)
            session_count += 1
            for txn_id in record.transactions:
                repo.add_transaction(record.session_id, txn_id, record.created_epoch)
                transaction_count += 1
        return session_count, transaction_count

    def run(self, argv: StringArray) -> ExitCode:
        parser = argparse.ArgumentParser(
            description="Migrate legacy session_group.json into the DB backend."
        )
        parser.add_argument(
            "--input",
            type=Path,
            help="Path to legacy session_group.json (defaults to system.json config).",
        )

        args = parser.parse_args(argv)
        SystemConfigSettings.reload()

        input_path = args.input
        if input_path is None:
            configured = SystemConfigSettings.session_group_db()
            if not configured:
                self.logger.error("No session_group_db configured and --input not provided.")
                return self.EXIT_USAGE
            input_path = Path(configured)

        if not input_path.exists():
            self.logger.error("Legacy session_group.json not found: %s", input_path)
            return self.EXIT_USAGE

        try:
            payload = self._load_json(input_path)
        except Exception as exc:
            self.logger.error("Failed to read legacy session_group.json: %s", exc)
            return self.EXIT_FAILURE

        DatabaseSchemaManager.from_system_config().initialize_schema()

        records = self._parse_records(payload)
        session_count, transaction_count = self._migrate_records(records)

        self.logger.info(
            "Migrated %d session groups and %d transactions from %s",
            session_count,
            transaction_count,
            input_path,
        )
        return self.EXIT_OK


def main() -> None:
    logging.basicConfig(level=logging.INFO, format=_DEFAULT_LOG_FORMAT)
    migrator = SessionGroupMigrator()
    raise SystemExit(migrator.run(sys.argv[1:]))


if __name__ == "__main__":
    main()
