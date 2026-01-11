# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import cast, overload

from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import CaptureTime, ChannelId, MacAddressStr, TimeStamp
from pypnm.pnm.parser.CmDsOfdmFecSummary import CmDsOfdmFecSummary
from pypnm.pnm.parser.CmDsOfdmModulationProfile import CmDsOfdmModulationProfile
from pypnm.pnm.parser.CmDsOfdmRxMer import CmDsOfdmRxMer

MultiPnmCollectionObject = (
    CmDsOfdmRxMer | CmDsOfdmModulationProfile | CmDsOfdmFecSummary
)
MultiPnmCollectionType = (
    type[CmDsOfdmRxMer] | type[CmDsOfdmModulationProfile] | type[CmDsOfdmFecSummary]
)


class MultiPnmCollection(ABC):
    """
    Concrete base for a multi-channel, time-indexed collection of PNM capture objects.

    Stores one of (CmDsOfdmRxMer, CmDsOfdmModulationProfile, CmDsOfdmFecSummary)
    at (channel_id, capture_time). Provides common add/get/list behavior.
    """

    def __init__(
        self,
        collection_type: MultiPnmCollectionType | tuple[MultiPnmCollectionType, ...],
    ) -> None:
        """
        Initialize the collection with the allowed capture object type(s).

        Parameters
        ----------
        collection_type : type | tuple[type, ...]
            A single class or tuple of classes that instances must be to be accepted
            by `add(...)`. Typical values include `CmDsOfdmRxMer`, `CmDsOfdmModulationProfile`,
            `CmDsOfdmFecSummary`, or a tuple of these.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self._mac_address: MacAddressStr = MacAddress.null()
        self._store: dict[ChannelId, dict[CaptureTime, MultiPnmCollectionObject]] = {}

        if isinstance(collection_type, tuple):
            self._collection_types: tuple[MultiPnmCollectionType, ...] = collection_type
        else:
            self._collection_types = (collection_type,)

    def get_mac_address(self) -> MacAddressStr:
        """
        Return the canonical cable-modem MAC address for this collection.

        Notes
        -----
        The MAC is established on the first successful `add(...)` and must match
        for all subsequent additions. A mismatch raises `ValueError`.
        """
        return self._mac_address

    @abstractmethod
    def add(self, obj: MultiPnmCollectionObject) -> None:
        """
        Insert or replace a capture object at its (channel_id, capture_time).

        Parameters
        ----------
        obj : MultiPnmCollectionObject
            A capture object of an allowed type (see constructor). Its model must
            provide `channel_id`, `pnm_header.capture_time`, and `mac_address`.

        Raises
        ------
        TypeError
            If `obj` is not an instance of the allowed `collection_type(s)`.
        ValueError
            If `capture_time` is missing/None, or if the object's MAC address
            conflicts with the collection's established MAC.
        """
        if not isinstance(obj, self._collection_types):
            allowed = ", ".join(t.__name__ for t in self._collection_types)
            raise TypeError(
                f"Unsupported capture object type: {type(obj).__name__}. Allowed: {allowed}."
            )

        m = obj.to_model()
        channel_id: ChannelId = m.channel_id

        if isinstance(obj, CmDsOfdmFecSummary):
            capture_time = self.__get_fec_summary_capture_time(obj)
        else:
            capture_time: CaptureTime = m.pnm_header.capture_time
            if capture_time is None:
                raise ValueError("capture_time is None in provided object model.")

        if channel_id not in self._store:
            self._store[channel_id] = {}

        self.logger.debug(
            f"Adding {obj.__class__.__name__} for Channel={channel_id} at captureTime={capture_time}"
        )
        self._store[channel_id][capture_time] = obj

        self.__update_mac(cast(MacAddressStr, m.mac_address))

    def get_channel_ids(self) -> list[ChannelId]:
        """
        Return all channel IDs currently present in the collection, sorted ascending.
        """
        return sorted(self._store.keys())

    def length(self, channel_id: ChannelId | None = None) -> int:
        """
        Return the number of stored captures.

        Parameters
        ----------
        channel_id : ChannelId | None
            If provided, returns the count for that specific channel.
            If None, returns the total across all channels.

        Returns
        -------
        int
            Count of captures at the specified granularity.
        """
        if channel_id is not None:
            if channel_id not in self._store:
                return 0
            return len(self._store[channel_id])
        return sum(len(captures) for captures in self._store.values())

    def get_capture_times(self, channel_id: ChannelId) -> list[CaptureTime]:
        """
        Return all capture timestamps for a given channel, sorted ascending.

        Parameters
        ----------
        channel_id : ChannelId
            Channel whose capture times should be returned.

        Returns
        -------
        List[CaptureTime]
            Sorted list of timestamps, or an empty list if the channel is absent.
        """
        if channel_id not in self._store:
            return []
        return sorted(self._store[channel_id].keys())

    @overload
    def get(
        self, channel_id: ChannelId
    ) -> list[tuple[CaptureTime, MultiPnmCollectionObject]]: ...
    @overload
    def get(
        self, channel_id: ChannelId, capture_time: CaptureTime
    ) -> MultiPnmCollectionObject | None: ...

    def get(self, channel_id: ChannelId, capture_time: CaptureTime | None = None):
        """
        Retrieve capture data for a channel.

        Behavior
        --------
        - If only `channel_id` is provided: returns a list of (capture_time, obj)
          sorted ascending by capture_time. Returns [] if the channel is unknown.
        - If both `channel_id` and `capture_time` are provided: returns the object
          at that timestamp, or None if absent.

        Parameters
        ----------
        channel_id : ChannelId
            Target channel.
        capture_time : CaptureTime | None
            Optional timestamp within the channel.

        Returns
        -------
        List[Tuple[CaptureTime, MultiPnmCollectionObject]] | Optional[MultiPnmCollectionObject]
            Per overload description above.
        """
        channel = self._store.get(channel_id)
        if not channel:
            return [] if capture_time is None else None

        if capture_time is not None:
            return channel.get(capture_time)

        return sorted(channel.items(), key=lambda kv: kv[0])

    def __update_mac(self, mac: MacAddressStr) -> bool:
        """
        Initialize or validate the collection's MAC address.

        Behavior
        --------
        - If unset (or `MacAddress.null()`), the provided `mac` becomes the collection MAC.
        - If already set, the new `mac` must match or a `ValueError` is raised.

        Parameters
        ----------
        mac : MacAddressStr
            Normalized MAC address string.

        Returns
        -------
        bool
            True if the MAC was set or matched successfully.
        """
        if not self._mac_address or self._mac_address == MacAddress.null():
            self._mac_address = mac
            return True

        if self._mac_address != mac:
            raise ValueError(
                f"MAC mismatch in MultiPnmCollection: existing={self._mac_address}, new={mac}"
            )

        return True

    def __get_fec_summary_capture_time(
        self, fec_summary: CmDsOfdmFecSummary
    ) -> CaptureTime:
        """
        Extract the canonical capture time for a CmDsOfdmFecSummary object.

        The FEC summary contains multiple timestamps (one per aggregation window).
        This method returns the earliest timestamp as the representative capture time.

        Parameters
        ----------
        fec_summary : CmDsOfdmFecSummary
            The FEC summary object to extract the capture time from.

        Returns
        -------
        CaptureTime
            The earliest timestamp in the summary's `timestamp` list.

        Raises
        ------
        ValueError
            If the `timestamp` list is empty.
        """
        model = fec_summary.to_model()
        timestamps: list[TimeStamp] = model.fec_summary_data[
            0
        ].codeword_entries.timestamp
        return min(timestamps)
