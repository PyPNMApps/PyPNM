# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest

from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.api.routes.common.extended.common_measure_service import CommonMeasureService
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cable_modem import CableModem
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import TransactionId
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest


def _configure_pnm_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pnm_dir = tmp_path / "pnm"
    pnm_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(
        SystemConfigSettings,
        "pnm_dir",
        classmethod(lambda cls: str(pnm_dir)),
    )


@pytest.mark.asyncio
async def test_pnm_file_generator_skips_empty_transaction_id_mapping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _configure_pnm_dir(tmp_path, monkeypatch)
    caplog.set_level("WARNING")

    async def _fake_insert(
        self: PnmFileTransaction,
        cable_modem: CableModem,
        pnm_test_type: DocsPnmCmCtlTest,
        filename: str,
    ) -> TransactionId:
        return TransactionId("")

    monkeypatch.setattr(PnmFileTransaction, "insert", _fake_insert)

    cm = CableModem(
        mac_address=MacAddress("aa:bb:cc:dd:ee:ff"),
        inet=Inet("192.168.0.100"),
        write_community="public",
    )
    service = CommonMeasureService(
        pnm_test_type=DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR,
        cable_modem=cm,
        tftp_servers=(Inet("192.168.0.100"), Inet("::1")),
    )

    filename = await service._pnm_file_generator(
        DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR
    )

    assert filename
    assert service._transactionId_pnmFile == {}
    assert "Skipping transaction mapping for empty transaction_id" in caplog.text


@pytest.mark.asyncio
async def test_pnm_file_generator_skips_whitespace_transaction_id_mapping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _configure_pnm_dir(tmp_path, monkeypatch)
    caplog.set_level("WARNING")

    async def _fake_insert(
        self: PnmFileTransaction,
        cable_modem: CableModem,
        pnm_test_type: DocsPnmCmCtlTest,
        filename: str,
    ) -> TransactionId:
        return TransactionId("   ")

    monkeypatch.setattr(PnmFileTransaction, "insert", _fake_insert)

    cm = CableModem(
        mac_address=MacAddress("aa:bb:cc:dd:ee:ff"),
        inet=Inet("192.168.0.100"),
        write_community="public",
    )
    service = CommonMeasureService(
        pnm_test_type=DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR,
        cable_modem=cm,
        tftp_servers=(Inet("192.168.0.100"), Inet("::1")),
    )

    filename = await service._pnm_file_generator(
        DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR
    )

    assert filename
    assert service._transactionId_pnmFile == {}
    assert "Skipping transaction mapping for empty transaction_id" in caplog.text
