# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.mac_address import MacAddress
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest


def _patch_transaction_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = tmp_path / "transactions.json"

    def _fake_transaction_db(cls: type[SystemConfigSettings]) -> str:
        return str(db_path)

    monkeypatch.setattr(
        SystemConfigSettings,
        "transaction_db",
        classmethod(_fake_transaction_db),
        raising=False,
    )


class _FailingCableModem:
    get_mac_address = MacAddress("aa:bb:cc:dd:ee:ff")

    async def getSysDescr(self) -> object:
        raise AssertionError("getSysDescr should not be called when system_description is provided")


def test_insert_uses_supplied_system_description_without_snmp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_transaction_db(tmp_path, monkeypatch)
    txn = PnmFileTransaction()

    sys_descr = {
        "HW_REV": "1.0",
        "VENDOR": "LANCity",
        "BOOTR": "NONE",
        "SW_REV": "1.0.0",
        "MODEL": "LCPET-3",
    }
    txid = asyncio.run(
        txn.insert(
            _FailingCableModem(),
            DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR,
            "sample.bin",
            system_description=sys_descr,
        ),
    )

    rec = txn.get_record(txid)
    assert rec is not None
    assert rec["device_details"]["system_description"] == sys_descr
