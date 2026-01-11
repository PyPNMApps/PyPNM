# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import pytest

from pypnm.api.routes.advance.common.transactionsCollection import TransactionCollection
from pypnm.api.routes.common.classes.file_capture.types import (
    DeviceDetailsModel,
    TransactionRecordModel,
)
from pypnm.docsis.cm_snmp_operation import SystemDescriptor
from pypnm.lib.types import FileName, MacAddressStr, TimestampSec, TransactionId


def test_transaction_collection_skips_empty_transaction_id(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("WARNING")
    collection = TransactionCollection()
    record = TransactionRecordModel(
        transaction_id=TransactionId(""),
        timestamp=TimestampSec(1),
        mac_address=MacAddressStr("aa:bb:cc:dd:ee:ff"),
        pnm_test_type="DS_OFDM_RXMER_PER_SUBCAR",
        filename=FileName("rxmer.bin"),
        device_details=DeviceDetailsModel(
            system_description=SystemDescriptor.empty().to_model()
        ),
    )

    added = collection.add(record, b"payload")

    assert added is False
    assert collection.length() == 0
    assert "Skipping TransactionCollection add for empty transaction_id" in caplog.text


def test_transaction_collection_skips_whitespace_transaction_id(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("WARNING")
    collection = TransactionCollection()
    record = TransactionRecordModel(
        transaction_id=TransactionId("   "),
        timestamp=TimestampSec(1),
        mac_address=MacAddressStr("aa:bb:cc:dd:ee:ff"),
        pnm_test_type="DS_OFDM_RXMER_PER_SUBCAR",
        filename=FileName("rxmer.bin"),
        device_details=DeviceDetailsModel(
            system_description=SystemDescriptor.empty().to_model()
        ),
    )

    added = collection.add(record, b"payload")

    assert added is False
    assert collection.length() == 0
    assert "Skipping TransactionCollection add for empty transaction_id" in caplog.text
