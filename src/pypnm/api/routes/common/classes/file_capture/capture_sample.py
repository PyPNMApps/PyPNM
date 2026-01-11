from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
from pydantic import BaseModel, Field

from pypnm.lib.types import TimeStamp, TransactionId


class CaptureSample(BaseModel):
    """
    Represents a single RxMER capture iteration and its associated metadata.

    Attributes:
        timestamp (TimeStamp):
            Unix epoch time when the capture was initiated.
        transaction_id (TransactionId):
            Unique TFTP transaction identifier provided by the cable modem.
        filename (str):
            Name of the file uploaded via TFTP containing the capture data.
        error (Optional[str]):
            Error message explaining why the capture or upload failed, if applicable.

    Example:
        ```python
        sample = CaptureSample(
            timestamp=1684500000.0,
            transaction_id="txn12345",
            filename="rxmer_txn12345.json",
            error=None
        )
        ```
    """

    timestamp: TimeStamp = Field(
        ...,
        description="Unix timestamp (seconds since epoch) when the capture was triggered",
    )
    transaction_id: TransactionId = Field(
        ..., description="TFTP transaction ID returned by the cable modem"
    )
    filename: str = Field(
        ..., description="Name of the uploaded capture file containing RxMER data"
    )
    error: str | None = Field(
        None, description="Error message if capture or upload failed (otherwise None)"
    )
