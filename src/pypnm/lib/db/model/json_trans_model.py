# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from pydantic import BaseModel, Field

from pypnm.lib.types import HashStr, PathLike, TimeStamp, TransactionId


class JsonTransactionRecordModel(BaseModel):
    timestamp: TimeStamp = Field(
        ..., description="Unix Timestamp In Seconds For Transaction Creation"
    )
    filename: PathLike = Field(
        ..., description="Transaction Payload Filename Associated With This Record"
    )
    byte_size: int = Field(
        ..., description="Size In Bytes Of The Associated Payload File"
    )
    sha256: HashStr = Field(
        ..., description="Hex-Encoded SHA-256 Hash Derived From File And Timestamp"
    )


class JsonTransactionDbModel(BaseModel):
    records: dict[TransactionId, JsonTransactionRecordModel] = Field(
        default_factory=dict,
        description="Mapping Of Transaction Id To Metadata Records",
    )


class JsonReturnModel(JsonTransactionRecordModel):
    data: str = Field(description="")
