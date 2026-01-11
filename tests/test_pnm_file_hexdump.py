# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

# tests/test_pnm_file_hexdump.py

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi import HTTPException

from pypnm.api.routes.docs.pnm.files.service import PnmFileService, PnmFileTransaction
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.types import TransactionId


@pytest.mark.pnm
def test_hexdump_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Verify that get_hexdump_by_transaction_id returns a structured HexDumpResponse
    for a valid transaction with an on-disk PNM file.
    """
    transaction_id: TransactionId = TransactionId("8f17fcdd4c0138ef")
    filename = "test_pnm_file.bin"

    def _fake_pnm_dir(cls: type[SystemConfigSettings]) -> str:
        return str(tmp_path)

    # Point the PNM directory at a temporary location for the test
    monkeypatch.setattr(
        SystemConfigSettings,
        "pnm_dir",
        classmethod(_fake_pnm_dir),
        raising=False,
    )

    # Create a small synthetic PNM-like binary payload
    file_path = tmp_path / filename
    payload = bytes(range(32))  # 0x00..0x1F
    file_path.write_bytes(payload)

    def fake_get_record(
        self: PnmFileTransaction, txn_id: TransactionId
    ) -> dict[str, Any] | None:
        if txn_id == transaction_id:
            return {"filename": filename}
        return None

    # Patch PnmFileTransaction.get_record used inside PnmFileService
    monkeypatch.setattr(
        PnmFileTransaction,
        "get_record",
        fake_get_record,
        raising=True,
    )

    service = PnmFileService()
    bytes_per_line = 16

    rsp = service.get_hexdump_by_transaction_id(
        transaction_id=transaction_id,
        bytes_per_line=bytes_per_line,
    )

    assert rsp.transaction_id == transaction_id
    assert rsp.bytes_per_line == bytes_per_line
    assert isinstance(rsp.lines, list)
    assert len(rsp.lines) > 0
    # Basic sanity: first line should start at offset 0
    assert rsp.lines[0].startswith("00000000")


@pytest.mark.pnm
def test_hexdump_missing_transaction_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Ensure that a missing transaction ID results in an HTTP 404 error.
    """
    transaction_id: TransactionId = TransactionId("deadbeefdeadbeef")

    def _fake_pnm_dir(cls: type[SystemConfigSettings]) -> str:
        return str(tmp_path)

    # Point PNM directory somewhere harmless (no files needed for this branch)
    monkeypatch.setattr(
        SystemConfigSettings,
        "pnm_dir",
        classmethod(_fake_pnm_dir),
        raising=False,
    )

    def fake_get_record(
        self: PnmFileTransaction, txn_id: TransactionId
    ) -> dict[str, Any] | None:
        return None

    monkeypatch.setattr(
        PnmFileTransaction,
        "get_record",
        fake_get_record,
        raising=True,
    )

    service = PnmFileService()

    with pytest.raises(HTTPException) as excinfo:
        service.get_hexdump_by_transaction_id(
            transaction_id=transaction_id,
            bytes_per_line=16,
        )

    err = excinfo.value
    assert err.status_code == 404
    assert "Transaction ID not found" in str(err.detail)
