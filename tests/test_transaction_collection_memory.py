# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026

from __future__ import annotations

from pypnm.api.routes.advance.common.transactionsCollection import TransactionCollection
from pypnm.api.routes.common.classes.file_capture.types import (
    CompressionMetadataModel,
    DeviceDetailsModel,
    TransactionRecordModel,
)
from pypnm.docsis.cm_snmp_operation import SystemDescriptor


def test_transaction_collection_release_payload_bytes() -> None:
    collection = TransactionCollection()
    record = TransactionRecordModel(
        transaction_id="tx-1",
        timestamp=1,
        mac_address="aa:bb:cc:dd:ee:ff",
        pnm_test_type="DS_OFDM_RXMER",
        filename="sample.bin",
        compression=CompressionMetadataModel(
            is_compressed=False,
            codec="none",
            level=0,
            size_before=7,
            size_after=7,
        ),
        device_details=DeviceDetailsModel(system_description=SystemDescriptor.empty().to_model()),
    )

    collection.add(record, b"payload")

    assert collection.getTransactionBytes() == [b"payload"]
    assert collection.getTransactionCollectionModel()[0].data == b"payload"

    collection.release_payload_bytes()

    assert collection.getTransactionBytes() == [b""]
    assert collection.getTransactionCollectionModel()[0].data == b""
    assert collection.getTransactionIds() == ["tx-1"]
