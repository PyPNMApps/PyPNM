# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025

from __future__ import annotations

import logging
from enum import IntEnum
from struct import calcsize, unpack
from typing import TYPE_CHECKING, Annotated, Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field

from pypnm.lib.constants import KHZ
from pypnm.lib.types import FrequencySeriesHz, ProfileId
from pypnm.pnm.parser.pnm_file_type import PnmFileType
from pypnm.pnm.parser.pnm_header import PnmHeader

# TODO: Need to fix circular import
if TYPE_CHECKING:
    from pypnm.pnm.parser.model.parser_rtn_models import CmDsOfdmModulationProfileModel


class ModulationOrderType(IntEnum):
    zero_bit_loaded = 0
    continuous_pilot = 1
    qpsk = 2
    reserved_3 = 3
    qam_16 = 4
    reserved_5 = 5
    qam_64 = 6
    qam_128 = 7
    qam_256 = 8
    qam_512 = 9
    qam_1024 = 10
    qam_2048 = 11
    qam_4096 = 12
    qam_8192 = 13
    qam_16384 = 14
    exclusion = 16
    plc = 20


class RangeModulationProfileSchemaModel(BaseModel):
    """Schema 0: contiguous range of subcarriers at a single modulation order."""

    model_config = ConfigDict(use_enum_values=True, extra="ignore")
    schema_type: Literal[0] = Field(0, description="0 = range modulation")
    modulation_order: str = Field(
        ..., description="Modulation-Order-Type for this range"
    )
    num_subcarriers: int = Field(
        ..., ge=0, description="Number of subcarriers in the range"
    )


class SkipModulationProfileSchemaModel(BaseModel):
    """Schema 1: alternating/skip pattern (main vs skip modulation)."""

    model_config = ConfigDict(use_enum_values=True, extra="ignore")
    schema_type: Literal[1] = Field(1, description="1 = skip modulation")
    main_modulation_order: str = Field(
        ..., description="Main (kept) subcarrier Modulation-Order-Type"
    )
    skip_modulation_order: str = Field(
        ..., description="Skipped subcarrier Modulation-Order-Type"
    )
    num_subcarriers: int = Field(
        ..., ge=0, description="Number of affected subcarriers"
    )


SchemeModel = Annotated[
    RangeModulationProfileSchemaModel | SkipModulationProfileSchemaModel,
    Field(discriminator="schema_type"),
]


class ModulationProfileModel(BaseModel):
    """One OFDM modulation profile (profile_id + list of scheme chunks)."""

    model_config = ConfigDict(extra="ignore")
    profile_id: ProfileId = Field(..., ge=0, description="Profile identifier")
    schemes: list[SchemeModel] = Field(
        default_factory=list, description="Schema chunks composing the profile"
    )


class CmDsOfdmModulationProfile(PnmHeader):
    """
    Parser for DOCSIS OFDM Modulation Profile PNM files.

    This class unpacks the binary stream, validates the file type,
    and produces a structured Pydantic model (`CmDsOfdmModulationProfileModel`).

    Example
    -------
    >>> parser = CmDsOfdmModulationProfile(binary_blob)
    >>> model = parser.to_model()
    >>> print(model.model_dump_json(indent=2))
    """

    RANGE_MODULATION: int = 0
    SKIP_MODULATION: int = 1

    def __init__(self, binary_data: bytes) -> None:
        super().__init__(binary_data)
        self.logger = logging.getLogger(self.__class__.__name__)
        self._model: CmDsOfdmModulationProfileModel
        self.__process()

    def __process(self) -> None:
        # Validate file type
        pnm_file_type = self.get_pnm_file_type()
        if pnm_file_type != PnmFileType.OFDM_MODULATION_PROFILE:
            want = PnmFileType.OFDM_MODULATION_PROFILE.get_pnm_cann()
            got = pnm_file_type.get_pnm_cann() if pnm_file_type else "None"
            raise ValueError(f"PNM stream type mismatch: expected {want}, got {got}")

        # Local header (after the common PNM header already handled by PnmHeader)
        # Layout: >B 6s B I H B I
        #          |  |  | | | | |
        #          |  |  | | | | +-- profile_data_length_bytes: I
        #          |  |  | | | +---- subcarrier_spacing_khz: B
        #          |  |  | | +------ first_active_subcarrier_index: H
        #          |  |  | +-------- subcarrier_zero_frequency: I
        #          |  |  +---------- num_profiles: B
        #          |  +------------- mac_address: 6s
        #          +---------------- channel_id: B
        header_fmt = ">B6sBIHBI"
        header_sz = calcsize(header_fmt)
        try:
            (
                channel_id,
                mac6,
                num_profiles,
                subcarrier_zero_frequency,
                first_active_subcarrier_index,
                subcarrier_spacing_khz,
                profile_data_length_bytes,
            ) = unpack(header_fmt, self.pnm_data[:header_sz])

        except Exception as e:
            raise ValueError(f"Failed to unpack modulation profile header: {e}") from e

        mac_address = mac6.hex(":")
        subcarrier_spacing_hz = int(int(subcarrier_spacing_khz) * KHZ)
        profile_blob = self.pnm_data[header_sz:]

        profiles = self._parse_profiles(profile_blob)

        from pypnm.pnm.parser.model.parser_rtn_models import (
            CmDsOfdmModulationProfileModel,
        )

        self._model = CmDsOfdmModulationProfileModel(
            pnm_header=self.getPnmHeaderParameterModel(),
            channel_id=channel_id,
            mac_address=mac_address,
            subcarrier_zero_frequency=subcarrier_zero_frequency,
            first_active_subcarrier_index=first_active_subcarrier_index,
            subcarrier_spacing=subcarrier_spacing_hz,
            num_profiles=num_profiles,
            profile_data_length_bytes=profile_data_length_bytes,
            profiles=profiles,
        )

    def _parse_profiles(self, blob: bytes) -> list[ModulationProfileModel]:
        """
        Parse a profile section from the binary blob.

        Layout
        ------
        - Profile header: [profile_id:1][length:2]
        - Payload (length bytes): sequence of schema chunks
            * schema 0 (range): [0:1][mod_order:1][num_subcarriers:2]
            * schema 1 (skip):  [1:1][main_order:1][skip_order:1][num_subcarriers:2]
        """
        offset = 0
        results: list[ModulationProfileModel] = []

        # Discover each [profile_id, payload]
        while offset < len(blob):
            try:
                hdr_fmt = ">BH"
                hdr_sz = calcsize(hdr_fmt)
                profile_id, length = unpack(hdr_fmt, blob[offset : offset + hdr_sz])
                start = offset + hdr_sz
                end = start + length
                if end > len(blob):
                    raise ValueError(
                        f"Profile payload overruns buffer (offset={offset}, length={length})"
                    )
                payload = blob[start:end]
                offset = end
            except Exception as e:
                raise ValueError(
                    f"Failed to read profile header at offset {offset}: {e}"
                ) from e

            # Decode payload
            pos = 0
            schemes: list[SchemeModel] = []

            while pos < len(payload):
                try:
                    scheme_type = payload[pos]
                    pos += 1

                    if scheme_type == 0:
                        fmt = ">BH"
                        size = calcsize(fmt)
                        mod_val, num_sc = unpack(fmt, payload[pos : pos + size])
                        pos += size
                        schemes.append(
                            RangeModulationProfileSchemaModel(
                                schema_type=0,
                                modulation_order=ModulationOrderType(mod_val).name,
                                num_subcarriers=num_sc,
                            )
                        )

                    elif scheme_type == 1:
                        fmt = ">BBH"
                        size = calcsize(fmt)
                        main_val, skip_val, num_sc = unpack(
                            fmt, payload[pos : pos + size]
                        )
                        pos += size
                        schemes.append(
                            SkipModulationProfileSchemaModel(
                                schema_type=1,
                                main_modulation_order=ModulationOrderType(
                                    main_val
                                ).name,
                                skip_modulation_order=ModulationOrderType(
                                    skip_val
                                ).name,
                                num_subcarriers=num_sc,
                            )
                        )

                    else:
                        self.logger.warning(
                            "Unknown scheme type %s in profile %s; stopping schema parse for this profile",
                            scheme_type,
                            profile_id,
                        )
                        break  # can't safely advance without a known format

                except Exception as exc:
                    self.logger.exception(
                        "Error decoding scheme (profile %s at pos %s): %s",
                        profile_id,
                        pos,
                        exc,
                    )
                    break

            results.append(
                ModulationProfileModel(profile_id=profile_id, schemes=schemes)
            )

        return results

    def get_frequencies(self) -> FrequencySeriesHz:
        """
        Compute per-subcarrier center frequencies (Hz).

        Formula
        -------
        f[k] = subcarrier_zero_frequency + subcarrier_spacing * (first_active_subcarrier_index + k)

        Returns
        -------
        FrequencySeriesHz
            List of per-subcarrier frequencies in Hz, one entry per RxMER value.
        """
        spacing = int(self._model.subcarrier_spacing)
        f_zero = int(self._model.subcarrier_zero_frequency)
        first_idx = int(self._model.first_active_subcarrier_index)
        # TODO: Need to calculate the number of subcarries using Profile-A
        n = 0

        if spacing <= 0 or n <= 0:
            return []

        start = f_zero + spacing * first_idx
        freqs: FrequencySeriesHz = cast(
            FrequencySeriesHz, [start + i * spacing for i in range(n)]
        )
        return freqs

    def to_model(self) -> CmDsOfdmModulationProfileModel:
        """
        Return the parsed modulation profile as a validated Pydantic model.

        Returns
        -------
        CmDsOfdmModulationProfileModel
            Full structured dataset including header fields and profiles.

        Example
        -------
        >>> model = parser.to_model()
        >>> print(model.num_profiles)
        2
        """
        return self._model

    def to_dict(self) -> dict[str, Any]:
        """
        Return the parsed modulation profile as a Python dictionary.

        Returns
        -------
        dict
            Dictionary representation of the parsed modulation profile.

        Example
        -------
        >>> dct = parser.to_dict()
        >>> print(dct)
        {
            "pnm_header": {...},
            "channel_id": 1,
            "mac_address": "aa:bb:cc:dd:ee:ff",
            "subcarrier_zero_frequency": 120000000,
            "first_active_subcarrier_index": 128,
            "subcarrier_spacing": 25000,
            "num_profiles": 2,
            "profile_data_length_bytes": 64,
            "profiles": [
                {
                    "profile_id": 1,
                    "schemes": [
                        {
                            "schema_type": 0,
                            "modulation_order": qam_16,         <- ModulationOrderType()
                            "num_subcarriers": 192
                        },
                        {
                            "schema_type": 1,
                            "main_modulation_order": qam_256,   <- ModulationOrderType()
                            "skip_modulation_order": qam_512,   <- ModulationOrderType()
                            "num_subcarriers": 48
                        }
                    ]
                }
            ]
        }
        """
        return self._model.model_dump()

    def __str__(self) -> str:
        return f"{self.__class__.__name__}"
