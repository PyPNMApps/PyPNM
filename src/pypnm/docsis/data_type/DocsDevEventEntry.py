from __future__ import annotations

import logging

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
from binascii import unhexlify

from pypnm.snmp.compiled_oids import COMPILED_OIDS
from pypnm.snmp.snmp_v2c import Snmp_v2c


class DocsDevEventEntry:
    index: int
    docsDevEvFirstTime: bytes = None
    docsDevEvLastTime: bytes = None
    docsDevEvCounts: int = 0
    docsDevEvLevel: int = 0
    docsDevEvId: int = 0
    docsDevEvText: str = ""

    def __init__(self, index: int, snmp: Snmp_v2c) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self.index = index
        self.snmp = snmp

    async def start(self) -> bool:
        """
        Asynchronously populates the event entry data from SNMP.

        Returns:
            bool: True if SNMP queries succeed (even if some values are None), False otherwise.

            "docsDevEvLastTime": ("docsDevEvLastTime", bytes),

        """
        fields = {
            "docsDevEvFirstTime": ("docsDevEvFirstTime", Snmp_v2c.parse_snmp_datetime),
            "docsDevEvLastTime": ("docsDevEvLastTime", Snmp_v2c.parse_snmp_datetime),
            "docsDevEvCounts": ("docsDevEvCounts", int),
            "docsDevEvLevel": ("docsDevEvLevel", int),
            "docsDevEvId": ("docsDevEvId", int),
            "docsDevEvText": ("docsDevEvText", str),
        }

        try:
            for attr, (oid_key, transform) in fields.items():
                try:
                    result = await self.snmp.get(
                        f"{COMPILED_OIDS[oid_key]}.{self.index}"
                    )
                    value_result = Snmp_v2c.get_result_value(result)

                    if isinstance(value_result, str) and value_result.startswith("0x"):
                        value_result = unhexlify(value_result[2:])

                    if not value_result:
                        self.logger.warning(
                            f"Invalid value returned for {oid_key}.{self.index}: {value_result}"
                        )
                        setattr(self, attr, None)
                        continue

                    setattr(self, attr, transform(value_result))
                except Exception as e:
                    self.logger.warning(
                        f"Failed to fetch or transform {attr} ({oid_key}): {e}"
                    )
                    setattr(self, attr, None)

        except Exception as e:
            self.logger.exception(
                f"Unexpected error during SNMP population, error: {e}"
            )
            return False

        return True

    def to_dict(self, nested: bool = True) -> dict:
        """
        Converts the instance into a dictionary.

        Args:
            nested (bool): Whether to return nested structure {index: {...}}.

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
            return {data["index"]: {k: v for k, v in data.items() if k != "index"}}

        return data
