# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from abc import ABC
from typing import Literal

from pydantic import BaseModel, Field

from pypnm.lib.types import ChannelId


class InterfaceParameters(BaseModel, ABC):
    """
    Abstract base class for DOCSIS measurement interface parameters.

    Defines a common interface for downstream and upstream configuration classes,
    such as `DownstreamOfdmParameters` and `UpstreamOfdmaParameters`. This base class
    ensures that all concrete parameter classes implement necessary attributes for
    DOCSIS measurement operations.
    """

    pass


class DownstreamOfdmParameters(InterfaceParameters):
    """
    Configuration options for DOCSIS downstream OFDM (Orthogonal Frequency Division Multiplexing) channels.

    Attributes:
        type (Literal["ofdm"]): The direction type. Always set to "ofdm" for downstream configurations.
        channel_id (Optional[List[int]]): A list of downstream OFDM channel IDs to target.
            If None (default), all available OFDM channels will be included.

    Example:
        DownstreamOfdmParameters(channel_id=[1, 2, 3])
            - Targets only OFDM channels with IDs 1, 2, and 3.

        DownstreamOfdmParameters()
            - Targets all available OFDM channels (default behavior).
    """

    type: Literal["ofdm"] = Field(default="ofdm")
    channel_id: list[ChannelId] | None = Field(default=None)


class UpstreamOfdmaParameters(InterfaceParameters):
    """
    Configuration options for DOCSIS upstream OFDMA (Orthogonal Frequency Division Multiple Access) channels.

    Attributes:
        type (Literal["ofdma"]): The direction type. Always set to "ofdma" for upstream configurations.
        channel_id (Optional[List[int]]): A list of upstream OFDMA channel IDs to target.
            If None (default), all available OFDMA channels will be included.

    Example:
        UpstreamOfdmaParameters(channel_id=[1, 2, 3])
            - Targets only OFDMA channels with IDs 1, 2, and 3.

        UpstreamOfdmaParameters()
            - Targets all available OFDMA channels (default behavior).
    """

    type: Literal["ofdma"] = Field(default="ofdma")
    channel_id: list[ChannelId] | None = Field(default=None)
