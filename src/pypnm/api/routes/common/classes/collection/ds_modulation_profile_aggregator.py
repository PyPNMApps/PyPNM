# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
from typing import overload

from pydantic import BaseModel, Field
from typing_extensions import override

from pypnm.api.routes.common.classes.analysis.analysis import Analysis
from pypnm.api.routes.common.classes.analysis.model.schema import (
    DsModulationProfileAnalysisModel,
)
from pypnm.api.routes.common.classes.collection.abstract.multi_pnm_aggreator import (
    MultiPnmCollection,
    MultiPnmCollectionObject,
)
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import CaptureTime, ChannelId, FrequencySeriesHz, MacAddressStr
from pypnm.pnm.parser.CmDsOfdmModulationProfile import (
    CmDsOfdmModulationProfile,
    ModulationProfileModel,
    ProfileId,
)


class ModulationCaptureModel(BaseModel):
    capture_time: CaptureTime = Field(..., ge=0, description="Epoch seconds.")
    channel_id: ChannelId = Field(..., ge=0, description="OFDM channel id.")
    mac_address: MacAddressStr = Field(
        default=MacAddress.null(),
        description="Normalized MAC (e.g., 00:1a:2b:3c:4d:5e).",
    )
    frequency: FrequencySeriesHz = Field(
        ..., description="Per-subcarrier center frequencies (Hz)."
    )


class DsModulationProfileAggregator(MultiPnmCollection):
    """
    Aggregates OFDM modulation profiles by channel and timestamp.

    - Ingests `CmDsOfdmModulationProfile` via `add()`
    - Enforces a single MAC across the collection
    - Stores by channel → capture_time
    - Exposes helpers to list profiles / ids and run basic analysis
    """

    def __init__(self) -> None:
        super().__init__(CmDsOfdmModulationProfile)
        self.logger = logging.getLogger(self.__class__.__name__)

    @override
    def add(self, obj: MultiPnmCollectionObject) -> None:
        if not isinstance(obj, CmDsOfdmModulationProfile):
            raise TypeError(
                f"DsModulationProfileAggregator only accepts CmDsOfdmModulationProfile instances, got {type(obj)}"
            )
        super().add(obj)

    # -------------------------
    # Profiles extraction
    # -------------------------

    @overload
    def get_profiles(
        self, channel_id: ChannelId
    ) -> dict[CaptureTime, list[ModulationProfileModel]]: ...
    @overload
    def get_profiles(
        self, channel_id: ChannelId, capture_time: CaptureTime
    ) -> list[ModulationProfileModel]: ...

    def get_profiles(
        self, channel_id: ChannelId, capture_time: CaptureTime | None = None
    ):
        """
        Return modulation profiles as **models** (not dicts).

        Returns
        -------
        - channel only  -> {capture_time: [ModulationProfileModel, ...]} (times sorted ascending)
        - channel+time  -> [ModulationProfileModel, ...] for that snapshot

        Raises
        ------
        KeyError if the specified channel or capture_time is not found.
        """
        if capture_time is None:
            out: dict[CaptureTime, list[ModulationProfileModel]] = {}
            for ct, obj in self.get(channel_id):
                cap: CmDsOfdmModulationProfile = obj  # type: ignore[assignment]
                out[ct] = list(cap.to_model().profiles)
            return dict(sorted(out.items(), key=lambda kv: kv[0]))

        capture: CmDsOfdmModulationProfile | None = self.get(channel_id, capture_time)  # type: ignore[assignment]
        if capture is None:
            raise KeyError(
                f"No capture for channel_id={channel_id} capture_time={capture_time}"
            )
        return list(capture.to_model().profiles)

    # -------------------------
    # Profile IDs
    # -------------------------

    @overload
    def get_profile_ids(self, channel_id: ChannelId) -> list[ProfileId]: ...
    @overload
    def get_profile_ids(
        self, channel_id: ChannelId, capture_time: CaptureTime
    ) -> list[ProfileId]: ...

    def get_profile_ids(
        self, channel_id: ChannelId, capture_time: CaptureTime | None = None
    ) -> list[ProfileId]:
        """
        List profile IDs.

        - channel only  -> unique profile IDs across all captures on that channel (sorted)
        - channel+time  -> profile IDs for that snapshot (sorted)
        """
        if capture_time is None:
            ids: set[ProfileId] = set()
            for ct, obj in self.get(channel_id):
                cap: CmDsOfdmModulationProfile = obj  # type: ignore[assignment]
                for p in cap.to_model().profiles:
                    ids.add(p.profile_id)
                    self.logger.debug(
                        "[get_profile_ids] ch=%s ct=%s pid=%s",
                        channel_id,
                        ct,
                        p.profile_id,
                    )
            return sorted(ids)

        capture: CmDsOfdmModulationProfile | None = self.get(channel_id, capture_time)  # type: ignore[assignment]
        if capture is None:
            raise KeyError(
                f"No capture for channel_id={channel_id} capture_time={capture_time}"
            )
        for p in capture.to_model().profiles:
            self.logger.debug(
                "[get_profile_ids] ch=%s ct=%s pid=%s",
                channel_id,
                capture_time,
                p.profile_id,
            )
        return sorted([p.profile_id for p in capture.to_model().profiles])

    # -------------------------
    # Basic analysis
    # -------------------------

    @overload
    def basic_analysis(
        self,
    ) -> dict[ChannelId, list[DsModulationProfileAnalysisModel]]: ...
    @overload
    def basic_analysis(
        self, channel_id: ChannelId
    ) -> dict[ChannelId, list[DsModulationProfileAnalysisModel]]: ...
    @overload
    def basic_analysis(
        self, channel_id: ChannelId, capture_time: CaptureTime
    ) -> dict[ChannelId, list[DsModulationProfileAnalysisModel]]: ...

    def basic_analysis(
        self,
        channel_id: ChannelId | None = None,
        capture_time: CaptureTime | None = None,
    ) -> dict[ChannelId, list[DsModulationProfileAnalysisModel]]:
        """
        Perform basic modulation profile analysis via
        `Analysis.basic_analysis_ds_modulation_profile_from_model`.

        Returns
        -------
        Dict[ChannelId, List[DsModulationProfileAnalysisModel]]
            - no args         → results for **all channels**
            - channel only    → {channel_id: results for all captures (time-ordered)}
            - channel+time    → {channel_id: [result for that single snapshot]}

        Notes
        -----
        - Each capture is converted with `.to_model()` before analysis.
        - Raises KeyError for missing channel/snapshot when specified.
        """
        out: dict[ChannelId, list[DsModulationProfileAnalysisModel]] = {}

        # --- Case 1: No channel_id → process all channels ---
        if channel_id is None:
            for ch in self.get_channel_ids():
                results: list[DsModulationProfileAnalysisModel] = []
                for _, obj in self.get(ch):
                    cap: CmDsOfdmModulationProfile = obj  # type: ignore[assignment]
                    model = cap.to_model()
                    result = Analysis.basic_analysis_ds_modulation_profile_from_model(
                        model
                    )
                    results.append(result)
                out[ch] = results
            return out

        # --- Case 2: Specific channel, all captures ---
        if capture_time is None:
            results: list[DsModulationProfileAnalysisModel] = []
            for _, obj in self.get(channel_id):
                cap: CmDsOfdmModulationProfile = obj  # type: ignore[assignment]
                model = cap.to_model()
                result = Analysis.basic_analysis_ds_modulation_profile_from_model(model)
                results.append(result)
            return {channel_id: results}

        # --- Case 3: Specific channel + specific capture ---
        capture: CmDsOfdmModulationProfile | None = self.get(channel_id, capture_time)  # type: ignore[assignment]
        if capture is None:
            raise KeyError(
                f"No capture for channel_id={channel_id} capture_time={capture_time}"
            )

        model = capture.to_model()
        result = Analysis.basic_analysis_ds_modulation_profile_from_model(model)
        return {channel_id: [result]}
