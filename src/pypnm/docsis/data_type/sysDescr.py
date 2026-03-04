# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import ClassVar

from pydantic import BaseModel, Field


class SystemDescriptorModel(BaseModel):
    """
    Pydantic v2 model that mirrors the `SystemDescriptor` dataclass.
    """
    HW_REV:   str  = Field("",  description="Hardware revision.")
    VENDOR:   str  = Field("",  description="Device vendor.")
    BOOTR:    str  = Field("",  description="Bootloader revision.")
    SW_REV:   str  = Field("",  description="Software/firmware revision.")
    MODEL:    str  = Field("",  description="Device model.")
    is_empty: bool = Field(default=True, description="True if derived from an empty descriptor.")

@dataclass(frozen=True)
class SystemDescriptor:
    """
    Parsed representation of a sysDescr string with fields:
      - hw_rev   : hardware revision
      - vendor   : device vendor
      - boot_rev : bootloader revision
      - sw_rev   : software revision
      - model    : device model

    Provides parsing, serialization, and an "empty" factory.
    """
    hw_rev: str     = ""
    vendor: str     = ""
    boot_rev: str   = ""
    sw_rev: str     = ""
    model: str      = ""
    _is_empty:bool  = True

    _PATTERN: ClassVar[re.Pattern] = re.compile(r"<<\s*(.*?)\s*>>")

    @classmethod
    def parse(cls, system_description: str) -> SystemDescriptor:
        """
        Parse a sysDescr string of the form:
           <<HW_REV: xxx; VENDOR: xxx; BOOTR: xxx; SW_REV: xxx; MODEL: xxx>>
        Returns a SysDescr instance.
        """
        match = cls._PATTERN.search(system_description)
        if not match:
            raise ValueError(f"Invalid format, missing <<...>>: {system_description}")
        content = match.group(1)
        entries = [item.strip() for item in content.split(";") if item.strip()]
        data: dict[str, str] = {}
        for entry in entries:
            if ':' not in entry:
                raise ValueError(f"Invalid field entry '{entry}' in sysDescr")
            key, val = [part.strip() for part in entry.split(':', 1)]
            data[key] = val
        try:
            empty:bool = False
            if data.get('HW_REV') == '':
                empty = True

            return cls(
                hw_rev      =   data.get('HW_REV', ''),
                vendor      =   data.get('VENDOR', ''),
                boot_rev    =   data.get('BOOTR', ''),
                sw_rev      =   data.get('SW_REV', ''),
                model       =   data.get('MODEL', ''),
                _is_empty   =   empty
            )

        except KeyError as e:
            raise ValueError(f"Missing expected field {e.args[0]} in sysDescr: {system_description}") from e

    def to_model(self) -> SystemDescriptorModel:
        """
        Convert to a Pydantic model representation.
        """
        return SystemDescriptorModel(
            HW_REV      =   self.hw_rev,
            VENDOR      =   self.vendor,
            BOOTR       =   self.boot_rev,
            SW_REV      =   self.sw_rev,
            MODEL       =   self.model,
            is_empty    =   self.is_empty()
        )

    def to_dict(self) -> dict[str, str]:
        """
        Serialize the SysDescr fields to a dict.
        """
        return self.to_model().model_dump(exclude={'is_empty'})

    def to_json(self) -> str:
        """
        Serialize the SysDescr fields to a JSON string.
        """
        return json.dumps(self.to_dict())

    def is_empty(self) -> bool:
        return self._is_empty

    @classmethod
    def load_from_dict(cls, data: dict[str, str]) -> SystemDescriptor:
        """
        Load a SysDescr from a dictionary.
        """
        hw_rev   = data.get('HW_REV', '')
        vendor   = data.get('VENDOR', '')
        boot_rev = data.get('BOOTR', '')
        sw_rev   = data.get('SW_REV', '')
        model    = data.get('MODEL', '')
        is_empty = not any(str(v).strip() for v in (hw_rev, vendor, boot_rev, sw_rev, model))

        return cls(
            hw_rev  =   hw_rev,
            vendor  =   vendor,
            boot_rev=   boot_rev,
            sw_rev  =   sw_rev,
            model   =   model,
            _is_empty = is_empty,
        )

    @classmethod
    def empty(cls) -> SystemDescriptor:
        """
        Return an empty SysDescr (all fields blank).
        """
        cls._is_empty = True
        return cls(hw_rev="", vendor="", boot_rev="", sw_rev="", model="")

    def __str__(self) -> str:
        """
        Return a string representation of the SysDescr.
        """
        return f"<< HW_REV: {self.hw_rev}; VENDOR: {self.vendor}; BOOTR: {self.boot_rev}; SW_REV: {self.sw_rev}; MODEL: {self.model} >>"

    def __hash__(self) -> int:
        return hash((self.hw_rev, self.vendor, self.boot_rev, self.sw_rev, self.model))

    def __repr__(self) -> str:
        return f"SystemDescriptor(hw_rev={self.hw_rev!r}, vendor={self.vendor!r}, boot_rev={self.boot_rev!r}, sw_rev={self.sw_rev!r}, model={self.model!r})"
