from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
import logging

from pypnm.snmp.compiled_oids import COMPILED_OIDS
from pypnm.snmp.snmp_v2c import Snmp_v2c


class DocsFddCmFddBandEdgeCapabilities:
    """
    Represents the FDD diplexer band edge capabilities for a DOCSIS 4.0 cable modem,
    retrieved via SNMP.

    This class fetches entries from the following conceptual tables:
      - docsFddDiplexerUsUpperBandEdgeCapabilityTable
      - docsFddDiplexerDsLowerBandEdgeCapabilityTable
      - docsFddDiplexerDsUpperBandEdgeCapabilityTable

    Frequency values are in MHz. A value of 0 indicates the modem does not support
    the extended spectrum configuration for the corresponding band edge.
    """

    def __init__(self, index: int, snmp: Snmp_v2c) -> None:
        """
        Initialize the FDD diplexer capability object.

        Args:
            index (int): SNMP table index.
            snmp (Snmp_v2c): SNMPv2c client instance.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.index = index
        self.snmp = snmp

        self.docsFddDiplexerUsUpperBandEdgeCapability: int | None = None
        self.docsFddDiplexerDsLowerBandEdgeCapability: int | None = None
        self.docsFddDiplexerDsUpperBandEdgeCapability: int | None = None

        self._started: bool = False

    async def start(self) -> bool:
        """
        Fetches and populates the diplexer capability attributes from SNMP.

        Returns:
            bool: True if fetch completed successfully.
        """
        fields = {
            "docsFddDiplexerUsUpperBandEdgeCapability": int,
            "docsFddDiplexerDsLowerBandEdgeCapability": int,
            "docsFddDiplexerDsUpperBandEdgeCapability": int,
        }

        # This should only be run once
        if self.is_start():
            return True

        self._started = True

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
                f"Unexpected error during SNMP population, error: {e}"
            )
            return False

    def is_start(self) -> bool:
        return self._started

    def to_dict(self) -> dict:
        """
        Convert the populated attributes into a structured dictionary.

        Returns:
            dict: Dictionary with the SNMP index and populated fields.

        Raises:
            ValueError: If required attributes have not been populated.
        """
        entry = {
            "docsFddDiplexerUsUpperBandEdgeCapability": self.docsFddDiplexerUsUpperBandEdgeCapability,
            "docsFddDiplexerDsLowerBandEdgeCapability": self.docsFddDiplexerDsLowerBandEdgeCapability,
            "docsFddDiplexerDsUpperBandEdgeCapability": self.docsFddDiplexerDsUpperBandEdgeCapability,
        }

        if any(v is None for v in entry.values()):
            missing = [k for k, v in entry.items() if v is None]
            raise ValueError(
                f"Attributes not populated (call start() first): {missing}"
            )

        return {"index": self.index, "entry": entry}
