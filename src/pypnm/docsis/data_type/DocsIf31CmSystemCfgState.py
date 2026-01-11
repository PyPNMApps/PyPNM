from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
import logging

from pypnm.snmp.compiled_oids import COMPILED_OIDS
from pypnm.snmp.snmp_v2c import Snmp_v2c


class DocsIf31CmSystemCfgDiplexState:
    """
    A class to manage DOCSIS 3.1 CM System Configuration State.

    This class includes methods to asynchronously retrieve and populate
    DOCS-IF31-MIB state information, such as diplexer capabilities, band edges,
    and lower/upper band edge configurations.

    Attributes:
        index (int): The index to identify the specific configuration state.
        docsIf31CmSystemCfgStateDiplexerCapability (Optional[int]): Diplexer capability.
        docsIf31CmSystemCfgStateDiplexerCfgBandEdge (Optional[int]): Configuration band edge for the diplexer.
        docsIf31CmSystemCfgStateDiplexerDsLowerCapability (Optional[int]): Diplexer downstream lower capability.
        docsIf31CmSystemCfgStateDiplexerCfgDsLowerBandEdge (Optional[int]): Configuration lower band edge for downstream.
        docsIf31CmSystemCfgStateDiplexerDsUpperCapability (Optional[int]): Diplexer downstream upper capability.
        docsIf31CmSystemCfgStateDiplexerCfgDsUpperBandEdge (Optional[int]): Configuration upper band edge for downstream.

    Methods:
        start() -> bool:
            Asynchronously fetches and populates the configuration state attributes.
        to_dict(nested: bool = True) -> dict:
            Converts the instance to a dictionary.
    """

    index: int = 0
    docsIf31CmSystemCfgStateDiplexerCapability: int | None = None
    docsIf31CmSystemCfgStateDiplexerCfgBandEdge: int | None = None
    docsIf31CmSystemCfgStateDiplexerDsLowerCapability: int | None = None
    docsIf31CmSystemCfgStateDiplexerCfgDsLowerBandEdge: int | None = None
    docsIf31CmSystemCfgStateDiplexerDsUpperCapability: int | None = None
    docsIf31CmSystemCfgStateDiplexerCfgDsUpperBandEdge: int | None = None

    def __init__(self, snmp: Snmp_v2c) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self.snmp = snmp

    async def start(self) -> bool:
        """
        Asynchronously retrieves and populates the DOCS-IF31-MIB configuration state values.

        This method fetches the diplexer capabilities, band edges, and other relevant
        configuration information from SNMP and populates the corresponding attributes.

        Returns:
            bool: True if SNMP queries succeed (even if some values are None), False otherwise.
        """

        fields = {
            "docsIf31CmSystemCfgStateDiplexerCapability": (
                "docsIf31CmSystemCfgStateDiplexerCapability",
                int,
            ),
            "docsIf31CmSystemCfgStateDiplexerCfgBandEdge": (
                "docsIf31CmSystemCfgStateDiplexerCfgBandEdge",
                int,
            ),
            "docsIf31CmSystemCfgStateDiplexerDsLowerCapability": (
                "docsIf31CmSystemCfgStateDiplexerDsLowerCapability",
                int,
            ),
            "docsIf31CmSystemCfgStateDiplexerCfgDsLowerBandEdge": (
                "docsIf31CmSystemCfgStateDiplexerCfgDsLowerBandEdge",
                int,
            ),
            "docsIf31CmSystemCfgStateDiplexerDsUpperCapability": (
                "docsIf31CmSystemCfgStateDiplexerDsUpperCapability",
                int,
            ),
            "docsIf31CmSystemCfgStateDiplexerCfgDsUpperBandEdge": (
                "docsIf31CmSystemCfgStateDiplexerCfgDsUpperBandEdge",
                int,
            ),
        }

        try:
            for attr, (oid_key, transform) in fields.items():
                try:
                    result = await self.snmp.get(
                        f"{COMPILED_OIDS[oid_key]}.{self.index}"
                    )
                    value_list = Snmp_v2c.get_result_value(result)

                    if not value_list:
                        self.logger.warning(
                            f"Invalid value returned for {oid_key}.{self.index}: {value_list}"
                        )
                        setattr(self, attr, None)
                        continue

                    value = transform(value_list)
                    setattr(self, attr, value)
                except Exception as e:
                    self.logger.warning(
                        f"Failed to fetch or transform {attr} ({oid_key}): {e}"
                    )
                    setattr(self, attr, None)

            return True

        except Exception as e:
            self.logger.exception(
                f"Unexpected error during SNMP population, error: {e}"
            )
            return False

    def to_dict(self, nested: bool = True) -> dict:
        """
        Converts the instance into a dictionary. If `nested` is True, returns {index: {field: value, ...}}.
        Otherwise, returns a flat dictionary with 'index' as a field.

        Args:
            nested (bool): Whether to return the dictionary in nested form. Defaults to True.

        Returns:
            dict: Dictionary representation of the instance.

        Raises:
            ValueError: If any required attribute is not populated.
        """
        data = {}
        for attr in self.__annotations__:
            value = getattr(self, attr, None)
            if value is None:
                raise ValueError(
                    f"Attribute '{attr}' is not populated. Please call 'start' first."
                )
            data[attr] = value

        if nested:
            return {
                data["index"]: {
                    key: value for key, value in data.items() if key != "index"
                }
            }

        return data
