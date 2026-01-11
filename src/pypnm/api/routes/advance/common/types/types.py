# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
from __future__ import annotations

import enum
from typing import Any, TypedDict

from pypnm.docsis.data_type.sysDescr import SystemDescriptor, SystemDescriptorModel
from pypnm.lib.types import (
    CaptureTime,
    ChannelId,
    FileName,
    MacAddressStr,
    TransactionId,
)

DeviceDetailsPayload = (
    SystemDescriptorModel | SystemDescriptor | str | dict[str, Any] | None
)


class EntryDict(TypedDict):
    transaction_id: TransactionId
    file_name: FileName
    file_type: str
    capture_time: CaptureTime
    channel_id: ChannelId | None
    device_details: DeviceDetailsPayload
    data: bytes
    mac_address: MacAddressStr


class Sort(enum.Enum):
    CHANNEL_ID = enum.auto()
    ASCEND_EPOCH = enum.auto()
    PNM_FILE_TYPE = enum.auto()
    MAC_ADDRESS = enum.auto()


TransactionFile = tuple[TransactionId, FileName, bytes]
TransactionFileCollection = list[TransactionFile]
FlatIndex = dict[MacAddressStr, list[EntryDict]]
GroupedIndex = dict[MacAddressStr, dict[int, list[EntryDict]]]
SortOrder = list[Sort]
