# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from pydantic import BaseModel, Field

from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_response import (
    BaseDeviceResponse,
)


class OfdmProfileStat(BaseModel):
    """
    Individual OFDM profile statistics counters.

    Attributes:
        docsIf31CmDsOfdmProfileStatsConfigChangeCt: Number of configuration changes.
        docsIf31CmDsOfdmProfileStatsTotalCodewords: Total codewords received.
        docsIf31CmDsOfdmProfileStatsCorrectedCodewords: Number of corrected codewords.
        docsIf31CmDsOfdmProfileStatsUncorrectableCodewords: Number of uncorrectable codewords.
        docsIf31CmDsOfdmProfileStatsInOctets: Total octets received.
        docsIf31CmDsOfdmProfileStatsInUnicastOctets: Unicast octets received.
        docsIf31CmDsOfdmProfileStatsInMulticastOctets: Multicast octets received.
        docsIf31CmDsOfdmProfileStatsInFrames: Total frames received.
        docsIf31CmDsOfdmProfileStatsInUnicastFrames: Unicast frames received.
        docsIf31CmDsOfdmProfileStatsInMulticastFrames: Multicast frames received.
        docsIf31CmDsOfdmProfileStatsInFrameCrcFailures: CRC failures in frames.
        docsIf31CmDsOfdmProfileStatsCtrDiscontinuityTime: Discontinuity timestamp.
    """

    docsIf31CmDsOfdmProfileStatsConfigChangeCt: int | None = Field(
        default=0, description="Number of configuration changes"
    )
    docsIf31CmDsOfdmProfileStatsTotalCodewords: int | None = Field(
        default=0, description="Total codewords received"
    )
    docsIf31CmDsOfdmProfileStatsCorrectedCodewords: int | None = Field(
        default=0, description="Number of corrected codewords"
    )
    docsIf31CmDsOfdmProfileStatsUncorrectableCodewords: int | None = Field(
        default=0, description="Number of uncorrectable codewords"
    )
    docsIf31CmDsOfdmProfileStatsInOctets: int | None = Field(
        default=0, description="Total octets received"
    )
    docsIf31CmDsOfdmProfileStatsInUnicastOctets: int | None = Field(
        default=0, description="Unicast octets received"
    )
    docsIf31CmDsOfdmProfileStatsInMulticastOctets: int | None = Field(
        default=0, description="Multicast octets received"
    )
    docsIf31CmDsOfdmProfileStatsInFrames: int | None = Field(
        default=0, description="Total frames received"
    )
    docsIf31CmDsOfdmProfileStatsInUnicastFrames: int | None = Field(
        default=0, description="Unicast frames received"
    )
    docsIf31CmDsOfdmProfileStatsInMulticastFrames: int | None = Field(
        default=0, description="Multicast frames received"
    )
    docsIf31CmDsOfdmProfileStatsInFrameCrcFailures: int | None = Field(
        default=0, description="CRC failures in frames"
    )
    docsIf31CmDsOfdmProfileStatsCtrDiscontinuityTime: int | None = Field(
        default=0, description="Counter discontinuity time"
    )


class FlatOfdmChannelProfileStats(BaseModel):
    """
    Flat representation of OFDM channel profile stats keyed by profile index.

    Attributes:
        index: Channel index.
        channel_id: Channel identifier.
        profiles: Mapping of profile index to statistics.
    """

    index: int = Field(default=0, description="Channel index")
    channel_id: int = Field(default=0, description="Channel identifier")
    profiles: dict[int, OfdmProfileStat] = Field(
        default_factory=dict, description="Mapping of profile index to profile stats"
    )


class OfdmProfileStatsResponse(BaseDeviceResponse):
    """
    Response model for downstream OFDM profile statistics.

    Attributes:
        status: Status code ('0' indicates success).
        data: List of flat channel profile stats.
    """

    data: list[FlatOfdmChannelProfileStats] = Field(
        default_factory=list, description="List of channel profile statistics"
    )
