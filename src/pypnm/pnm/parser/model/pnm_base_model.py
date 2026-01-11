# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from pydantic import ConfigDict, Field

from pypnm.lib.constants import (
    INVALID_CHANNEL_ID,
    INVALID_SUB_CARRIER_ZERO_FREQ,
    ZERO_FREQUENCY,
)
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import ChannelId, FrequencyHz, MacAddressStr
from pypnm.pnm.parser.pnm_header import PnmHeaderModel, PnmHeaderParameters


class PnmBaseModel(PnmHeaderModel):
    """
    Base fields shared by PNM analysis models.

    Attributes
    ----------
    channel_id : int
        Downstream channel identifier (0 if unknown).
    mac_address : str
        Device MAC address; defaults to `MacAddress.null()`.
    subcarrier_zero_frequency : int
        Frequency of subcarrier k=0 in Hz (absolute or system-defined reference).
    first_active_subcarrier_index : int
        0-based index of the first active OFDM subcarrier.
    subcarrier_spacing : int
        Subcarrier spacing Δf in Hz.

    Notes
    -----
    - All frequencies are expressed in Hertz (Hz).
    - Indices are 0-based.
    - This base model does not enforce domain limits; downstream models may add validation.
    """

    model_config = ConfigDict(populate_by_name=True)
    pnm_header: PnmHeaderParameters = Field(
        default_factory=PnmHeaderParameters, description=""
    )
    channel_id: ChannelId = Field(
        default=INVALID_CHANNEL_ID, description="Downstream channel ID"
    )
    mac_address: MacAddressStr = Field(
        default=MacAddress.null(), description="Device MAC address"
    )
    subcarrier_zero_frequency: FrequencyHz = Field(
        default=INVALID_SUB_CARRIER_ZERO_FREQ,
        description="Frequency of subcarrier 0 (Hz)",
    )
    first_active_subcarrier_index: int = Field(
        default=-1, description="Index of the first active subcarrier"
    )
    subcarrier_spacing: FrequencyHz = Field(
        default=ZERO_FREQUENCY, description="Subcarrier spacing (Hz)"
    )
