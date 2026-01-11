from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
import logging

from pypnm.snmp.compiled_oids import COMPILED_OIDS
from pypnm.snmp.snmp_v2c import Snmp_v2c


class DocsIf31CmDsOfdmProfileStatsEntry:
    """
    Represents the DocsIf31CmDsOfdmProfileStatsEntry from the DOCSIS MIB.

    This class retrieves statistics related to OFDM profile usage at the cable modem,
    organized per profile ID under a given OFDM channel index.
    """

    index: int
    channel_id: int
    profile_stats: dict[int, dict[str, int | None]]

    def __init__(self, index: int, snmp: Snmp_v2c) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self.index = index
        self.snmp = snmp
        self.channel_id = None
        self.profile_stats = {}

    async def start(self) -> bool:
        """
        Asynchronously populates the OFDM profile statistics data from SNMP.

        Returns:
            bool: True if SNMP queries succeed (even if some values are None), False otherwise.
        """
        fields = {
            "docsIf31CmDsOfdmProfileStatsConfigChangeCt": int,
            "docsIf31CmDsOfdmProfileStatsTotalCodewords": int,
            "docsIf31CmDsOfdmProfileStatsCorrectedCodewords": int,
            "docsIf31CmDsOfdmProfileStatsUncorrectableCodewords": int,
            "docsIf31CmDsOfdmProfileStatsInOctets": int,
            "docsIf31CmDsOfdmProfileStatsInUnicastOctets": int,
            "docsIf31CmDsOfdmProfileStatsInMulticastOctets": int,
            "docsIf31CmDsOfdmProfileStatsInFrames": int,
            "docsIf31CmDsOfdmProfileStatsInUnicastFrames": int,
            "docsIf31CmDsOfdmProfileStatsInMulticastFrames": int,
            "docsIf31CmDsOfdmProfileStatsInFrameCrcFailures": int,
            "docsIf31CmDsOfdmProfileStatsCtrDiscontinuityTime": int,
        }

        try:
            profile_idx_list = await self._get_profile_id_indexes()
            self.channel_id = await self._get_channel_id()
            self.logger.info(
                f"Number of profiles: {profile_idx_list} for OFDM index: {self.index} - ChannelID: {self.channel_id}"
            )
            self.profile_stats = {}

            for profile_index in profile_idx_list:
                profile_data = {}
                try:
                    for attr, transform in fields.items():
                        oid = f"{COMPILED_OIDS[attr]}.{self.index}.{profile_index}"
                        result = await self.snmp.get(oid)
                        value_list = Snmp_v2c.get_result_value(result)

                        if not value_list:
                            self.logger.warning(f"Invalid value for {oid}")
                            profile_data[attr] = None
                        else:
                            profile_data[attr] = transform(value_list)
                except Exception as e:
                    self.logger.warning(
                        f"Failed to fetch data for profile {profile_index}: {e}"
                    )
                    # Fill remaining fields with None
                    for attr in fields:
                        if attr not in profile_data:
                            profile_data[attr] = None

                self.profile_stats[profile_index] = profile_data

            return True

        except Exception as e:
            self.logger.exception(
                f"Unexpected error during SNMP population, error: {e}"
            )
            return False

    def to_dict(self, nested: bool = True) -> dict:
        """
        Converts the instance into a dictionary. If `nested` is True, returns {index: {profile_index: {...}}}.
        Otherwise, returns a flat dictionary.

        Args:
            nested (bool): Whether to return the dictionary in nested form.

        Returns:
            dict: Dictionary representation of the instance.

        Raises:
            ValueError: If statistics have not been populated yet.
        """
        if not self.profile_stats:
            raise ValueError("Profile statistics not populated. Call 'start' first.")

        if nested:
            return {self.index: self.profile_stats}

        return {
            "index": self.index,
            "channel_id": self.channel_id,  # ← correct key
            "profiles": self.profile_stats,
        }

    async def _get_profile_id_indexes(self) -> list[int]:
        """
        Retrieves the list of OFDM profile IDs (last index) for the given CM index.

        Returns:
            List[int]: A list of profile ID indices.
        """
        result = await self.snmp.walk(
            f"{COMPILED_OIDS['docsIf31CmDsOfdmProfileStatsTotalCodewords']}.{self.index}"
        )

        profile_indices = set()
        for oid_str in result:
            oid_parts = str(oid_str[0]).split(".")
            if len(oid_parts) >= 2:
                profile_idx = int(oid_parts[-1])
                profile_indices.add(profile_idx)

        return sorted(profile_indices)

    async def _get_channel_id(self) -> int:
        result = await self.snmp.get(
            f"{COMPILED_OIDS['docsIf31CmDsOfdmChanChannelId']}.{self.index}"
        )
        self.channel_id = int(Snmp_v2c.get_result_value(result))
        return self.channel_id
