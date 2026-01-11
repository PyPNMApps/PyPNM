# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from pydantic import ValidationError

from pypnm.config.pnm_config_manager import SystemConfigSettings
from pypnm.lib.db.model.json_trans_model import (
    JsonReturnModel,
    JsonTransactionDbModel,
    JsonTransactionRecordModel,
)
from pypnm.lib.file_processor import FileProcessor
from pypnm.lib.types import HashStr, PathLike, TimeStamp, TransactionId
from pypnm.lib.utils import Generate

JsonPayload = Mapping[str, Any]


class JsonTransactionDb:
    """
    JSON-Based Transaction Database Manager.

    This class provides configuration-aware helpers for reading and writing
    JSON database files that track transaction metadata. It delegates all
    filesystem operations to ``FileProcessor`` while using
    ``SystemConfigSettings`` to resolve paths against the configured PyPNM
    data layout. The on-disk JSON layout is expected to have transaction
    identifiers as top-level keys:

    .. code-block:: json

        {
          "<transaction_id>": {
            "timestamp": 1721760000,
            "filename": "<filename>.json",
            "byte_size": 1024,
            "sha256": "<file+timestamp-sha256-hash>"
          }
        }
    """

    def __init__(self) -> None:
        """
        Initialize The JSON Transaction Database Manager.

        Configuration is obtained directly from ``SystemConfigSettings`` using
        class-level attributes such as ``json_db`` and ``json_dir``. The JSON
        DB file path and JSON payload directory are taken as-is from these
        settings; no additional base-directory inference is performed.
        """
        self._json_db = Path(SystemConfigSettings.json_db())
        self._json_dir = Path(SystemConfigSettings.json_dir())
        self.logger = logging.getLogger(f"{self.__class__.__name__}")
        self.logger.debug(
            f"Initialized JSON Transaction DB Manager with json_db={self._json_db}, json_dir={self._json_dir}"
        )

    def read_json(self, transaction_id: TransactionId) -> JsonReturnModel:
        """
        Read A Transaction Payload And Metadata For A Given Transaction Id.

        This method performs the following steps:

        * Loads the JSON transaction database file.
        * Looks up the record associated with ``transaction_id``.
        * Reads the referenced JSON payload file from disk (under ``json_dir``).
        * Recomputes the SHA-256 hash over the file contents plus the
          record's timestamp and verifies it against the stored value.
        * Returns a ``JsonReturnModel`` containing the metadata fields and
          the raw JSON payload as a string.

        If any step fails (missing DB, missing transaction, read failure,
        hash mismatch, or decode error), an "empty" ``JsonReturnModel`` is
        returned with zeroed or blank fields and an empty payload string.

        Parameters
        ----------
        transaction_id:
            Identifier for the transaction whose payload should be retrieved.

        Returns
        -------
        JsonReturnModel
            Model containing transaction metadata and JSON payload text. All
            fields are zero/empty when the transaction cannot be resolved.
        """
        db_model = self._load_db_model()

        record = db_model.records.get(transaction_id)
        if not record:
            self.logger.error(f"Transaction '{transaction_id}' not found in JSON DB")
            return JsonReturnModel(
                timestamp=TimeStamp(0),
                filename="",
                byte_size=0,
                sha256=cast(HashStr, ""),
                data="",
            )

        payload_path = self._json_dir / str(record.filename)
        payload_processor = FileProcessor(payload_path)
        raw_bytes = payload_processor.read_file()

        if not raw_bytes:
            self.logger.error(
                f"Failed to read payload for transaction '{transaction_id}' at {payload_path}"
            )
            return JsonReturnModel(
                timestamp=TimeStamp(0),
                filename=record.filename,
                byte_size=0,
                sha256=record.sha256,
                data="",
            )

        recalculated_hash = self._calculate_file_hash(payload_path, record.timestamp)
        if not recalculated_hash or recalculated_hash != record.sha256:
            self.logger.error(
                f"Hash verification failed for transaction '{transaction_id}': "
                f"expected={record.sha256}, got={recalculated_hash}"
            )
            return JsonReturnModel(
                timestamp=record.timestamp,
                filename=record.filename,
                byte_size=record.byte_size,
                sha256=record.sha256,
                data="",
            )

        try:
            payload_text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            self.logger.error(
                f"Failed to decode JSON payload for transaction '{transaction_id}' at {payload_path}: {exc}"
            )
            return JsonReturnModel(
                timestamp=record.timestamp,
                filename=record.filename,
                byte_size=record.byte_size,
                sha256=record.sha256,
                data="",
            )

        return JsonReturnModel(
            timestamp=record.timestamp,
            filename=record.filename,
            byte_size=record.byte_size,
            sha256=record.sha256,
            data=payload_text,
        )

    def write_json(
        self, data: JsonPayload, fname: PathLike, extension: str = ""
    ) -> JsonTransactionDbModel:
        """
        Persist A New Transaction Payload And Update The JSON Transaction Database.

        This method performs the following steps:

        * Validates that ``data`` is JSON-serializable.
        * Allocates a new transaction identifier via ``_transaction_id``.
        * Generates a payload filename (``<fname>.<extension>``) and writes
          the JSON payload to disk inside the configured ``json_dir`` using
          ``FileProcessor``.
        * Measures the payload file size in bytes.
        * Computes a SHA-256 hash over the file contents and the current
          timestamp.
        * Loads the existing JSON transaction database model.
        * Inserts or updates a ``JsonTransactionRecordModel`` under the new
          transaction identifier.
        * Writes the updated database back to disk.
        * Returns the updated ``JsonTransactionDbModel``.

        Parameters
        ----------
        data:
            JSON-serializable mapping representing the transaction payload.
        fname:
            Base filename (without extension) to use for the payload file.
        extension:
            File extension to use for the payload file (default: "").

        Returns
        -------
        JsonTransactionDbModel
            Updated transaction database model containing the newly inserted
            transaction record.

        Raises
        ------
        ValueError
            If ``data`` cannot be serialized as JSON.
        RuntimeError
            If writing the payload file or database file fails.
        """
        try:
            json.dumps(data)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Provided data is not JSON-serializable: {exc}") from exc

        if extension:
            fname = f"{fname}.{extension.lstrip('.')}"

        timestamp: TimeStamp = TimeStamp(int(time.time()))
        transaction_id = self._transaction_id()
        filename: PathLike = fname
        payload_path = self._json_dir / filename
        payload_processor = FileProcessor(payload_path)

        write_ok = payload_processor.write_file(dict(data), append=False)
        if not write_ok:
            raise RuntimeError(f"Failed to write transaction payload to {payload_path}")

        try:
            byte_size = payload_path.stat().st_size
        except OSError as exc:
            raise RuntimeError(
                f"Failed to stat payload file at {payload_path}: {exc}"
            ) from exc

        sha256_hash = self._calculate_file_hash(payload_path, timestamp)
        if not sha256_hash:
            raise RuntimeError(
                f"Failed to calculate hash for payload file at {payload_path}"
            )

        record = JsonTransactionRecordModel(
            timestamp=timestamp,
            filename=filename,
            byte_size=byte_size,
            sha256=sha256_hash,
        )

        db_model = self._load_db_model()
        db_model = self._update_json_db_model(db_model, record, transaction_id)
        self._write_db_model(db_model)

        return db_model

    def _transaction_id(self) -> TransactionId:
        """
        Allocate A New Transaction Identifier.

        This helper provides a single point where the transaction ID allocation
        policy is defined. The default implementation uses a UUID4-derived
        string, but it can be replaced with a project-specific generator
        (for example, a dedicated TransactionId factory) without changing
        call sites.
        """
        return Generate.transaction_id()

    def _calculate_file_hash(self, filename: PathLike, timestamp: TimeStamp) -> HashStr:
        """
        Calculate The SHA-256 Hash For A Given File And Timestamp.

        The hash is computed over the concatenation of the file's binary
        contents and the string representation of the provided timestamp.

        Parameters
        ----------
        filename:
            Path to the file for which the hash is to be calculated.
        timestamp:
            Unix timestamp (in seconds) to be included in the hash computation.

        Returns
        -------
        HashStr
            Hex-Encoded SHA-256 Digest. Returns An Empty Hash String If The
            File Cannot Be Opened Or Read.
        """
        path = Path(filename)
        if not path.exists():
            self.logger.error(f"Cannot calculate hash for missing file: {path}")
            return cast(HashStr, "")

        digest = hashlib.sha256()
        try:
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(8192), b""):
                    digest.update(chunk)
        except OSError as exc:
            self.logger.error(
                f"Failed to read file while calculating hash for {path}: {exc}"
            )
            return cast(HashStr, "")

        digest.update(str(timestamp).encode("utf-8"))
        return cast(HashStr, digest.hexdigest())

    def _update_json_db_model(
        self,
        model: JsonTransactionDbModel,
        record: JsonTransactionRecordModel,
        transaction_id: TransactionId,
    ) -> JsonTransactionDbModel:
        """
        Update The JSON Transaction Database Model With A New Record.

        Parameters
        ----------
        model:
            Existing JSON transaction database model to be updated.
        record:
            New transaction record to insert into the model.
        transaction_id:
            Identifier for the transaction associated with the record.

        Returns
        -------
        JsonTransactionDbModel
            Updated JSON transaction database model with the new record
            inserted or replaced under the given transaction identifier.
        """
        model.records[transaction_id] = record
        return model

    def _load_db_model(self) -> JsonTransactionDbModel:
        """
        Load The JSON Transaction Database Model From Disk.

        This helper reads and parses the JSON DB file defined in
        ``SystemConfigSettings.json_db`` and converts it into a
        ``JsonTransactionDbModel``. Invalid entries are skipped with errors
        logged.

        Returns
        -------
        JsonTransactionDbModel
            Parsed JSON transaction database model, or an empty model when the
            DB file is missing or invalid.
        """
        db_path = self._json_db
        processor = FileProcessor(db_path)
        raw_bytes = processor.read_file()

        if not raw_bytes:
            self.logger.warning(f"No data available to decode JSON DB from {db_path}")
            return JsonTransactionDbModel()

        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            self.logger.error(
                f"Failed to decode JSON DB file {db_path} as UTF-8: {exc}"
            )
            return JsonTransactionDbModel()

        try:
            obj = json.loads(text)
        except json.JSONDecodeError as exc:
            self.logger.error(f"Failed to parse JSON DB file {db_path}: {exc}")
            return JsonTransactionDbModel()

        if not isinstance(obj, dict):
            self.logger.error(
                f"JSON DB root in {db_path} is not an object, got {type(obj).__name__}"
            )
            return JsonTransactionDbModel()

        records: dict[TransactionId, JsonTransactionRecordModel] = {}
        for tx_id, payload in obj.items():
            if not isinstance(payload, dict):
                self.logger.error(
                    f"Transaction '{tx_id}' in {db_path} is not an object; skipping"
                )
                continue
            try:
                record = JsonTransactionRecordModel(**payload)
            except ValidationError as exc:
                self.logger.error(
                    f"Invalid transaction record for '{tx_id}' in {db_path}: {exc}"
                )
                continue
            records[TransactionId(tx_id)] = record

        return JsonTransactionDbModel(records=records)

    def _write_db_model(self, model: JsonTransactionDbModel) -> None:
        """
        Write The JSON Transaction Database Model Back To Disk.

        Parameters
        ----------
        model:
            JSON transaction database model to be serialized and persisted.

        Raises
        ------
        RuntimeError
            If the underlying file write operation fails.
        """
        db_path = self._json_db
        processor = FileProcessor(db_path)

        payload = {
            tx_id: record.model_dump() for tx_id, record in model.records.items()
        }

        success = processor.write_file(payload, append=False)
        if not success:
            raise RuntimeError(f"Failed to write JSON DB to {db_path}")
