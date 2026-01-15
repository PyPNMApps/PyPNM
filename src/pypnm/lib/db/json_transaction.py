# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
import logging
import time
from collections.abc import Mapping
from pathlib import Path

from pypnm.config.pnm_config_manager import SystemConfigSettings
from pypnm.lib.db.artifact_repository import ArtifactRepository
from pypnm.lib.file_processor import FileProcessor
from pypnm.lib.types import PathLike, TimestampSec, TransactionId

JsonPayload = Mapping[str, object]


class JsonTransactionDb:
    """
    JSON export writer with DB-backed artifact tracking.

    The legacy JSON ledger file is no longer used. This helper writes JSON
    payloads under the configured json_dir and registers the artifact in the
    DB-backed artifact tables. When a transaction_id is supplied, the JSON
    artifact is linked via transaction_artifacts using the JSON export role.
    """

    def __init__(self) -> None:
        """
        Initialize the JSON export writer.

        Configuration comes from SystemConfigSettings.json_dir(), and artifacts
        are registered via ArtifactRepository using the configured DB backend.
        """
        self._json_dir = Path(SystemConfigSettings.json_dir())
        self._artifact_repo = ArtifactRepository.from_system_config()
        self.logger = logging.getLogger(f"{self.__class__.__name__}")

    def write_json(
        self,
        data: JsonPayload,
        fname: PathLike,
        extension: str = "",
        transaction_id: TransactionId | None = None,
    ) -> Path:
        """
        Persist a JSON payload and register the artifact in the DB.

        Parameters
        ----------
        data:
            JSON-serializable mapping representing the payload.
        fname:
            Base filename (without extension) to use for the payload file.
        extension:
            File extension to use for the payload file (default: "").
        transaction_id:
            Optional transaction identifier to link the JSON artifact to an
            existing transaction record.

        Returns
        -------
        Path
            Full path to the JSON payload file on disk.

        Raises
        ------
        ValueError
            If ``data`` cannot be serialized as JSON.
        RuntimeError
            If writing the payload file fails.
        """
        try:
            json.dumps(data)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Provided data is not JSON-serializable: {exc}") from exc

        filename = str(fname)
        if extension:
            filename = f"{filename}.{extension.lstrip('.')}"

        payload_path = self._json_dir / filename
        payload_processor = FileProcessor(payload_path)
        write_ok = payload_processor.write_file(dict(data), append=False)
        if not write_ok:
            raise RuntimeError(f"Failed to write transaction payload to {payload_path}")

        created_epoch = TimestampSec(int(time.time()))
        self._artifact_repo.register_json_export(
            file_path=payload_path,
            created_epoch=created_epoch,
            transaction_id=transaction_id,
        )

        return payload_path
