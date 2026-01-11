# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
    field_serializer,
    model_validator,
)

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
from pypnm.lib.constants import FEC_SUMMARY_TYPE_LABEL, INVALID_CHANNEL_ID
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.qam.types import CodeWordArray
from pypnm.lib.types import (
    ChannelId,
    ComplexArray,
    FloatSeries,
    FrequencyHz,
    FrequencySeriesHz,
    IntSeries,
    MacAddressStr,
    ProfileId,
    TimeStamp,
)
from pypnm.pnm.lib.signal_statistics import SignalStatisticsModel
from pypnm.pnm.parser.CmDsOfdmModulationProfile import ModulationProfileModel
from pypnm.pnm.parser.model.configuration.spect_config_model import (
    SpecAnalysisSnmpConfigModel,
)
from pypnm.pnm.parser.model.pnm_base_model import PnmBaseModel
from pypnm.pnm.parser.pnm_file_type import PnmFileType
from pypnm.pnm.parser.pnm_header import PnmHeaderParameters


class CmDsOfdmChanEstimateCoefModel(PnmBaseModel):
    """
    Canonical payload for DOCSIS OFDM downstream channel-estimation coefficients.

    Notes
    -----
    - `value_units` is fixed to "complex".
    - `data_length` is the byte length of the coefficient payload (2 bytes real + 2 bytes imag per subcarrier).
    - Number of complex points = `data_length // 4`.
    - `occupied_channel_bandwidth` = (#points) * subcarrier_spacing (Hz).
    """

    data_length: int = Field(
        ..., ge=0, description="Coefficient payload length (bytes)"
    )
    occupied_channel_bandwidth: FrequencyHz = Field(
        ..., ge=0, description="OFDM Occupied Bandwidth (Hz)"
    )
    value_units: str = Field(default="complex", description="Non-mutable")
    values: ComplexArray = Field(..., description="Per-subcarrier [real, imag] pairs")


class CmDsHistModel(BaseModel):
    pnm_header: PnmHeaderParameters = Field(..., description="")
    mac_address: MacAddressStr = Field(
        default=MacAddress.null(), description="Device MAC address"
    )
    symmetry: int = Field(
        ..., description="Histogram symmetry indicator (device-specific meaning)."
    )
    dwell_count_values_length: int = Field(
        ..., description="Number of dwell count entries reported."
    )
    dwell_count_values: IntSeries = Field(
        ..., description="Dwell count values per bin."
    )
    hit_count_values_length: int = Field(
        ..., description="Number of hit count entries reported."
    )
    hit_count_values: IntSeries = Field(..., description="Hit count values per bin.")


class CmDsConstDispMeasModel(PnmBaseModel):
    actual_modulation_order: int = Field(..., ge=0, description="")
    num_sample_symbols: int = Field(
        ..., ge=0, description="Number of constellation soft-decision symbol samples"
    )
    sample_length: int = Field(
        ..., ge=0, description="Number of constellation soft-decision complex pairs"
    )
    sample_units: str = Field(
        default="[Real(I), Imaginary(Q)]", description="Non-mutable"
    )
    samples: ComplexArray = Field(
        ..., description="Constellation soft-decision samples"
    )


class CmDsOfdmRxMerModel(PnmBaseModel):
    data_length: int = Field(
        ..., ge=0, description="Number of RxMER points (subcarriers)"
    )
    occupied_channel_bandwidth: FrequencyHz = Field(
        ..., ge=0, description="OFDM Occupied Bandwidth (Hz)"
    )
    value_units: str = Field(default="dB", description="Non-mutable")
    values: FloatSeries = Field(
        ..., description="RxMER values per active subcarrier (dB)"
    )
    signal_statistics: SignalStatisticsModel = Field(
        ..., description="Aggregate statistics computed from values"
    )
    modulation_statistics: dict[str, Any] = Field(
        ..., description="Shannon-based modulation metrics"
    )


class CmUsOfdmaPreEqModel(PnmBaseModel):
    model_config = ConfigDict(extra="ignore")
    cmts_mac_address: MacAddressStr = Field(
        ..., description="CMTS MAC address associated with this measurement."
    )
    value_length: int = Field(
        ..., ge=0, description="Number of complex coefficient pairs (non-negative)."
    )
    value_unit: Literal["[Real, Imaginary]"] = Field(
        "[Real, Imaginary]", description="Unit representation of complex values."
    )
    values: ComplexArray = Field(
        ...,
        min_length=1,
        description="Pre-equalization coefficients as [real, imaginary] pairs.",
    )
    occupied_channel_bandwidth: FrequencyHz = Field(
        ..., ge=0, description="OFDM Occupied Bandwidth (Hz)"
    )


class CmSpectrumAnalysisSnmpModel(BaseModel):
    """
    Canonical payload for SNMP-based CM Spectrum Analysis amplitude results.

    This model aggregates the flattened frequency and amplitude vectors across
    all parsed spectrum groups along with the associated configuration header
    and the raw amplitude bytes.
    """

    model_config = ConfigDict(
        extra="ignore", populate_by_name=True, ser_json_bytes="base64"
    )
    spectrum_config: SpecAnalysisSnmpConfigModel = Field(
        ...,
        description="Spectrum configuration header derived from the first parsed spectrum group.",
    )
    pnm_file_type: str = Field(
        default=PnmFileType.CM_SPECTRUM_ANALYSIS_SNMP_AMP_DATA.name,
        description="(Special Case) PNM file type identifier.",
    )
    total_samples: int = Field(
        ...,
        ge=0,
        description="Total number of amplitude samples parsed across all spectrum groups.",
    )
    frequency: FrequencySeriesHz = Field(
        ...,
        description="Flattened frequency bin values in Hz across all spectrum groups.",
    )
    amplitude: FloatSeries = Field(
        ...,
        description="Flattened amplitude values in dBmV corresponding to each frequency bin.",
    )
    amplitude_bytes: bytes = Field(
        ...,
        description="Raw concatenated amplitude bytes across all parsed spectrum groups.",
    )

    @field_serializer("amplitude_bytes")
    def _ser_amplitude_bytes(
        self,
        value: bytes,
    ) -> str:
        return value.hex()


class OfdmFecSumCodeWordEntryModel(BaseModel):
    """
    Parallel arrays holding per-interval codeword statistics for a single OFDM profile.
    """

    timestamp: list[TimeStamp] = Field(
        ..., description="Unix timestamps (seconds) for each aggregation interval"
    )
    total_codewords: CodeWordArray = Field(
        ..., description="Total codewords observed in each interval"
    )
    corrected: CodeWordArray = Field(
        ..., description="FEC-corrected codewords per interval"
    )
    uncorrectable: CodeWordArray = Field(
        ..., description="Uncorrectable codewords per interval"
    )

    @model_validator(mode="after")
    def _validate_lengths(self) -> OfdmFecSumCodeWordEntryModel:
        n = len(self.timestamp)
        if not (
            len(self.total_codewords)
            == len(self.corrected)
            == len(self.uncorrectable)
            == n
        ):
            raise ValueError(
                "timestamp, total_codewords, corrected, uncorrectable must have equal lengths"
            )
        return self


class OfdmFecSumDataModel(BaseModel):
    """
    FEC summary dataset for a single OFDM modulation profile.
    """

    profile_id: ProfileId = Field(..., description="OFDM modulation profile identifier")
    number_of_sets: int = Field(
        ..., description="Number of time-ordered codeword statistic sets"
    )
    codeword_entries: OfdmFecSumCodeWordEntryModel = Field(
        ..., description="Per-interval codeword stats (parallel arrays)"
    )

    @model_validator(mode="after")
    def _validate_number_of_sets(self) -> OfdmFecSumDataModel:
        if self.number_of_sets != len(self.codeword_entries.timestamp):
            raise ValueError(
                f"number_of_sets={self.number_of_sets} does not match entries={len(self.codeword_entries.timestamp)}"
            )
        return self


class CmDsOfdmFecSummaryModel(BaseModel):
    """
    Canonical model for DOCSIS downstream OFDM FEC summary.
    """

    model_config = ConfigDict(populate_by_name=True)

    pnm_header: PnmHeaderParameters = Field(
        ..., description="PNM header metadata for this capture"
    )
    channel_id: ChannelId = Field(
        INVALID_CHANNEL_ID, description="Downstream channel ID"
    )
    mac_address: MacAddressStr = Field(
        default_factory=MacAddress.null, description="Cable modem MAC address"
    )
    summary_type: int = Field(
        ...,
        description="CM-OSSI SummaryType enum: other(1), interval10min(2), interval24hr(3)",
    )
    num_profiles: int = Field(
        ..., description="Number of OFDM profiles reported in this summary"
    )
    fec_summary_data: list[OfdmFecSumDataModel] = Field(
        ..., description="Per-profile FEC summary datasets"
    )

    @computed_field
    @property
    def summary_type_label(self) -> str:
        """
        Human-friendly label for summary_type using docsPnmCmDsOfdmFecSumType.

        Mapping:
        1 -> other
        2 -> 10-minute interval (1s cadence, 600 samples)
        3 -> 24-hour interval (60s cadence, 1440 samples)
        """
        return FEC_SUMMARY_TYPE_LABEL.get(
            self.summary_type, f"unknown({self.summary_type})"
        )


class CmDsOfdmModulationProfileModel(PnmBaseModel):
    """
    Canonical payload for DS OFDM Modulation Profile.

    Inherits the following from PnmBaseModel (do NOT re-declare):
      - pnm_header : PnmHeaderParameters
      - channel_id : int
      - mac_address : str
      - subcarrier_zero_frequency : int
      - first_active_subcarrier_index : int
      - subcarrier_spacing : int   (Hz)

    Additional fields:
      - num_profiles : total number of profiles found
      - profile_data_length_bytes : raw length of the profile data section
      - profiles : parsed profile structures
    """

    model_config = ConfigDict(extra="ignore", use_enum_values=True)
    num_profiles: int = Field(
        ..., ge=0, description="Number of profiles in this capture"
    )
    profile_data_length_bytes: int = Field(
        ..., ge=0, description="Length of the profile data block (bytes)"
    )
    profiles: list[ModulationProfileModel] = Field(
        default_factory=list, description="Parsed modulation profiles"
    )
