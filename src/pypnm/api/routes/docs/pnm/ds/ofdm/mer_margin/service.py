# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging

from pypnm.api.routes.docs.pnm.ds.ofdm.mer_margin.schemas import (
    MerMarginMeasurementProfile,
    MerMarginParams,
)
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.OfdmProfiles import OfdmProfiles


class CmDsOfdmMerMarginService:
    """
    Service class for handling Downstream OFDM MER Margin measurement operations.

    This class wraps methods to:
    - Trigger MER Margin measurement on the cable modem
    - Retrieve measurement statistics and results
    """

    def __init__(self, cable_modem: CableModem) -> None:
        """
        Initialize the MER Margin service.

        Args:
            cable_modem (CableModem): The cable modem instance to operate on.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.cable_modem = cable_modem

    async def set(self) -> None:
        """
        Initiates the MER Margin measurement on the cable modem.

        NOTE: Implementation pending—will configure SNMP set values for trigger params.
        """
        pass

    async def getMeasurementTemplate(self) -> dict[str, list[dict]]:
        """
        Creates a MER Margin measurement template for each OFDM profile found on each downstream channel.

        Returns:
            Dict[str, List[Dict]]: A dictionary where each key is a channel index and each value is a list of
                                   profile measurement configurations.
        """
        template: dict[str, list[dict]] = {}

        try:
            profiles: list[
                tuple[int, OfdmProfiles]
            ] = await self.cable_modem.getOfdmProfiles()

            for index, ofdm_profile in profiles:
                template[str(index)] = []

                for profile_id in ofdm_profile.list_profiles():
                    self.logger.info(f"Idx: {index} - Profiles: {profile_id}")
                    profile = MerMarginMeasurementProfile(
                        channel_id=index,
                        profile_id=profile_id,
                        params=MerMarginParams(
                            MerMarThrshldOffset=4,
                            MerMarMeasEnable=True,
                            MerMarNumSymPerSubCarToAvg=8,
                            MerMarReqAvgMer=360,
                        ),
                    )

                    template[str(index)].append(profile.model_dump())

        except Exception as e:
            self.logger.exception(
                "Failed to construct MER Margin measurement template, error: %s", e
            )

        return template

    async def getMeasurementStatus(self) -> dict[str, list[dict]]:
        """
        Retrieves MER Margin measurement entries from the cable modem.

        Returns:
            Dict[str, List[Dict]]: A dictionary containing a list of MER Margin entries,
            keyed by "DS_MER_MARGIN".
        """
        try:
            entries = await self.cable_modem.getDocsPnmCmDsOfdmMerMarEntry()
            return {"DS_MER_MARGIN": [e.model_dump() for e in entries]}

        except Exception as e:
            self.logger.exception("Failed to retrieve MER Margin entries, error: %s", e)
            return {"DS_MER_MARGIN": []}
