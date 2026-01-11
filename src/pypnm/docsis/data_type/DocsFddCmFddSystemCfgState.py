from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
import logging

from pypnm.snmp.compiled_oids import COMPILED_OIDS
from pypnm.snmp.snmp_v2c import Snmp_v2c


class DocsFddCmFddSystemCfgState:
    """
    Represents the FDD (Frequency Division Duplex) band edge configuration state
    for a DOCSIS 4.0 cable modem, retrieved via SNMP.

    This class captures the Advanced Diplexer configuration for:
      - Downstream Lower Band Edge
      - Downstream Upper Band Edge
      - Upstream Upper Band Edge

    The frequency values are reported in MHz and aligned with TLVs 5.79, 5.80, and 5.81
    in the DOCSIS 4.0 specifications (CM-SP-MULPIv4.0, CM-SP-PHYv4.0).

    A value of `0` indicates the modem is not configured with an extended spectrum channel
    for that band edge.
    """

    def __init__(self, index: int, snmp: Snmp_v2c) -> None:
        """
        Initialize the FDD system config state object.

        Args:
            index (int): SNMP table index.
            snmp (Snmp_v2c): SNMPv2c client instance.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.index = index
        self.snmp = snmp

        self.docsFddCmFddSystemCfgStateDiplexerDsLowerBandEdgeCfg: int | None = None
        self.docsFddCmFddSystemCfgStateDiplexerDsUpperBandEdgeCfg: int | None = None
        self.docsFddCmFddSystemCfgStateDiplexerUsUpperBandEdgeCfg: int | None = None

    async def start(self) -> bool:
        """
        Fetches and populates the diplexer band edge settings from SNMP.

        Returns:
            bool: True if fetch completed successfully.
        """
        fields = {
            "docsFddCmFddSystemCfgStateDiplexerDsLowerBandEdgeCfg": int,
            "docsFddCmFddSystemCfgStateDiplexerDsUpperBandEdgeCfg": int,
            "docsFddCmFddSystemCfgStateDiplexerUsUpperBandEdgeCfg": int,
        }

        try:
            for attr, transform in fields.items():
                oid = COMPILED_OIDS.get(attr)
                if not oid:
                    self.logger.error(f"OID not found for attribute: {attr}")
                    setattr(self, attr, None)
                    continue

                try:
                    result = await self.snmp.get(f"{oid}.{self.index}")
                    values = Snmp_v2c.get_result_value(result)

                    if not values:
                        self.logger.warning(f"No SNMP result for {oid}.{self.index}")
                        setattr(self, attr, None)
                        continue

                    setattr(self, attr, transform(values))
                except Exception as e:
                    self.logger.warning(f"Failed to fetch/transform {attr}: {e}")
                    setattr(self, attr, None)

            return True
        except Exception as e:
            self.logger.exception(
                "Unexpected error during SNMP population, error: %s", e
            )
            return False

    def to_dict(self) -> dict:
        """
        Convert the populated attributes into a structured dictionary.

        Returns:
            dict: Dictionary with the SNMP index and populated fields.

        Raises:
            ValueError: If required attributes have not been populated.
        """
        entry = {
            "docsFddCmFddSystemCfgStateDiplexerDsLowerBandEdgeCfg": self.docsFddCmFddSystemCfgStateDiplexerDsLowerBandEdgeCfg,
            "docsFddCmFddSystemCfgStateDiplexerDsUpperBandEdgeCfg": self.docsFddCmFddSystemCfgStateDiplexerDsUpperBandEdgeCfg,
            "docsFddCmFddSystemCfgStateDiplexerUsUpperBandEdgeCfg": self.docsFddCmFddSystemCfgStateDiplexerUsUpperBandEdgeCfg,
        }

        if any(v is None for v in entry.values()):
            missing = [k for k, v in entry.items() if v is None]
            raise ValueError(
                f"Attributes not populated (call start() first): {missing}"
            )

        return {"index": self.index, "entry": entry}
