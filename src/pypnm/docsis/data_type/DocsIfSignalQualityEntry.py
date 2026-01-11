from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
import logging

from pypnm.snmp.compiled_oids import COMPILED_OIDS
from pypnm.snmp.snmp_v2c import Snmp_v2c


class DocsIfSignalQuality:
    """
    Represents DOCSIS downstream signal quality metrics retrieved via SNMP for a specific channel index.

    Attributes:
        index (int): The downstream channel index used for SNMP OID addressing.
        snmp (Snmp_v2c): SNMP client used to perform the SNMP GET requests.

    Retrieved metrics:
        - docsIfSigQUnerroreds (int)
        - docsIfSigQCorrecteds (int)
        - docsIfSigQUncorrectables (int)
        - docsIfSigQMicroreflections (int)
        - docsIfSigQExtUnerroreds (int)
        - docsIfSigQExtCorrecteds (int)
        - docsIfSigQExtUncorrectables (int)
        - docsIf3SignalQualityExtRxMER (float, in dB)
    """

    index: int
    docsIfSigQUnerroreds: int
    docsIfSigQCorrecteds: int
    docsIfSigQUncorrectables: int
    docsIfSigQMicroreflections: int
    docsIfSigQExtUnerroreds: int
    docsIfSigQExtCorrecteds: int
    docsIfSigQExtUncorrectables: int
    docsIf3SignalQualityExtRxMER: float

    def __init__(self, index: int, snmp: Snmp_v2c) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self.index = index
        self.snmp = snmp

    async def start(self) -> bool:
        """
        Asynchronously populates this DocsIfSignalQuality instance by performing SNMP GETs.

        Returns:
            bool: True if all SNMP queries completed (even if some values are missing), False otherwise if a critical error occurred.
        """

        def safe_float_div10(value: str) -> float | None:
            try:
                return float(value) / 10.0
            except Exception:
                return None

        fields = {
            "docsIfSigQUnerroreds": ("docsIfSigQUnerroreds", int),
            "docsIfSigQCorrecteds": ("docsIfSigQCorrecteds", int),
            "docsIfSigQUncorrectables": ("docsIfSigQUncorrectables", int),
            "docsIfSigQMicroreflections": ("docsIfSigQMicroreflections", int),
            "docsIfSigQExtUnerroreds": ("docsIfSigQExtUnerroreds", int),
            "docsIfSigQExtCorrecteds": ("docsIfSigQExtCorrecteds", int),
            "docsIfSigQExtUncorrectables": ("docsIfSigQExtUncorrectables", int),
            "docsIf3SignalQualityExtRxMER": (
                "docsIf3SignalQualityExtRxMER",
                safe_float_div10,
            ),
        }

        try:
            for attr, (oid_key, transform) in fields.items():
                try:
                    result = await self.snmp.get(
                        f"{COMPILED_OIDS[oid_key]}.{self.index}"
                    )
                    value_list = Snmp_v2c.get_result_value(result)

                    if not value_list or not value_list:
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

    def to_dict(self, nested: bool = False) -> dict:
        """
        Converts the instance into a dictionary. If `nested` is True, returns {index: {field: value, ...}}.
        Otherwise, returns a flat dictionary with 'index' as a field.

        Args:
            nested (bool): Whether to return the dictionary in nested form. Defaults to False.

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
