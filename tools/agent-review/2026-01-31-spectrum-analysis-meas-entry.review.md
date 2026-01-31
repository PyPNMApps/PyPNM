## Agent Review Bundle Summary
- Goal: Add SNMP spectrum measurement entry BaseModel and retrieval helper.
- Changes: Add DocsIf3CmSpectrumAnalysisMeasEntry model; add meas-entry index/lookup in cm_snmp_operation; add tests for scaling and missing fields.
- Files: src/pypnm/docsis/data_type/DocsIf3CmSpectrumAnalysisMeasEntry.py; src/pypnm/docsis/cm_snmp_operation.py; tests/test_docs_if3_cm_spectrum_analysis_meas_entry.py
- Tests: ruff check src; pytest -q
- Notes: Hardware integration tests skipped by default.

# FILE: src/pypnm/docsis/data_type/DocsIf3CmSpectrumAnalysisMeasEntry.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import ClassVar

from pydantic import BaseModel, Field

from pypnm.lib.types import FrequencyHz, PowerdBmV
from pypnm.snmp.casts import as_int
from pypnm.snmp.snmp_v2c import Snmp_v2c

SPECTRUM_TOTAL_SEGMENT_POWER_SCALE: float = 0.1


class DocsIf3CmSpectrumAnalysisMeasEntryFields(BaseModel):
    docsIf3CmSpectrumAnalysisMeasFrequency: FrequencyHz = Field(..., description="Measured center frequency for the spectrum analysis segment in Hz.")
    docsIf3CmSpectrumAnalysisMeasAmplitudeData: bytes = Field(..., description="Raw AmplitudeData payload encoded per DOCSIS SNMP textual convention.")
    docsIf3CmSpectrumAnalysisMeasTotalSegmentPower: PowerdBmV = Field(..., description="Total segment power in dBmV (tenths-of-dBmV scaled to decimal).")


class DocsIf3CmSpectrumAnalysisMeasEntry(BaseModel):
    index: int = Field(..., description="SNMP row index for the spectrum analysis measurement entry.")
    entry: DocsIf3CmSpectrumAnalysisMeasEntryFields = Field(..., description="Spectrum analysis measurement values for the given index.")

    DEBUG: ClassVar[bool] = False

    @classmethod
    async def from_snmp(cls, index: int, snmp: Snmp_v2c) -> DocsIf3CmSpectrumAnalysisMeasEntry:
        """
        Fetch A Single Spectrum Analysis Measurement Row Via SNMP.

        Parameters
        ----------
        index : int
            Row index to query.
        snmp : Snmp_v2c
            Configured SNMP v2c client.

        Returns
        -------
        DocsIf3CmSpectrumAnalysisMeasEntry
            Typed measurement entry with total segment power scaled by 0.1.

        Raises
        ------
        ValueError
            If any required field is missing from the SNMP response.
        """
        log = logging.getLogger(cls.__name__)

        async def fetch_value(sym: str, caster: Callable[[str], int] | None = None) -> int | str | None:
            try:
                res = await snmp.get(f"{sym}.{index}")
                raw_values = Snmp_v2c.get_result_value(res)
                raw = raw_values[0] if raw_values else None
                if raw is None:
                    return None
                return caster(raw) if caster else raw
            except Exception as exc:
                if cls.DEBUG and log.isEnabledFor(logging.DEBUG):
                    log.debug("idx=%s %s error=%r", index, sym, exc)
                return None

        async def fetch_bytes(sym: str) -> bytes | None:
            try:
                res = await snmp.get(f"{sym}.{index}")
                raw_bytes = Snmp_v2c.snmp_get_result_bytes(res)
                return raw_bytes[0] if raw_bytes else None
            except Exception as exc:
                if cls.DEBUG and log.isEnabledFor(logging.DEBUG):
                    log.debug("idx=%s %s error=%r", index, sym, exc)
                return None

        freq = await fetch_value("docsIf3CmSpectrumAnalysisMeasFrequency", as_int)
        amp = await fetch_bytes("docsIf3CmSpectrumAnalysisMeasAmplitudeData")
        power_raw = await fetch_value("docsIf3CmSpectrumAnalysisMeasTotalSegmentPower")

        missing = {
            k: v for k, v in dict(
                frequency=freq,
                amplitude_data=amp,
                total_segment_power=power_raw,
            ).items() if v is None
        }
        if missing:
            raise ValueError(
                f"SpectrumAnalysisMeas idx={index}: missing required fields: {', '.join(missing.keys())}"
            )

        power_value = float(power_raw) * SPECTRUM_TOTAL_SEGMENT_POWER_SCALE
        entry = DocsIf3CmSpectrumAnalysisMeasEntryFields(
            docsIf3CmSpectrumAnalysisMeasFrequency=FrequencyHz(int(freq)),
            docsIf3CmSpectrumAnalysisMeasAmplitudeData=bytes(amp),
            docsIf3CmSpectrumAnalysisMeasTotalSegmentPower=PowerdBmV(power_value),
        )
        return cls(index=index, entry=entry)

    @classmethod
    async def get(cls, snmp: Snmp_v2c, indices: list[int]) -> list[DocsIf3CmSpectrumAnalysisMeasEntry]:
        """
        Batch Fetch Spectrum Analysis Measurement Rows.

        Parameters
        ----------
        snmp : Snmp_v2c
            Configured SNMP v2c client used for all row queries.
        indices : list[int]
            List of row indices to query.

        Returns
        -------
        list[DocsIf3CmSpectrumAnalysisMeasEntry]
            Collected entries in the same order as `indices`. Empty if none.
        """
        if not indices:
            return []
        return [await cls.from_snmp(idx, snmp) for idx in indices]

# FILE: src/pypnm/docsis/cm_snmp_operation.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import asyncio
import logging
import time
from enum import Enum, IntEnum
from typing import Any, cast

from pysnmp.proto.rfc1902 import Gauge32, Integer32, OctetString

from pypnm.config.pnm_config_manager import SystemConfigSettings
from pypnm.docsis.data_type.ClabsDocsisVersion import ClabsDocsisVersion
from pypnm.docsis.data_type.DocsDevEventEntry import DocsDevEventEntry
from pypnm.docsis.data_type.DocsFddCmFddCapabilities import (
    DocsFddCmFddBandEdgeCapabilities,
)
from pypnm.docsis.data_type.DocsFddCmFddSystemCfgState import DocsFddCmFddSystemCfgState
from pypnm.docsis.data_type.DocsIf3CmSpectrumAnalysisMeasEntry import (
    DocsIf3CmSpectrumAnalysisMeasEntry,
)
from pypnm.docsis.data_type.DocsIf31CmDsOfdmChanEntry import (
    DocsIf31CmDsOfdmChanChannelEntry,
    DocsIf31CmDsOfdmChanEntry,
)
from pypnm.docsis.data_type.DocsIf31CmDsOfdmProfileStatsEntry import (
    DocsIf31CmDsOfdmProfileStatsEntry,
)
from pypnm.docsis.data_type.DocsIf31CmSystemCfgState import (
    DocsIf31CmSystemCfgDiplexState,
)
from pypnm.docsis.data_type.DocsIf31CmUsOfdmaChanEntry import DocsIf31CmUsOfdmaChanEntry
from pypnm.docsis.data_type.DocsIfDownstreamChannel import DocsIfDownstreamChannelEntry
from pypnm.docsis.data_type.DocsIfDownstreamChannelCwErrorRate import (
    DocsIfDownstreamChannelCwErrorRate,
    DocsIfDownstreamCwErrorRateEntry,
)
from pypnm.docsis.data_type.DocsIfSignalQualityEntry import DocsIfSignalQuality
from pypnm.docsis.data_type.DocsIfUpstreamChannelEntry import DocsIfUpstreamChannelEntry
from pypnm.docsis.data_type.DsCmConstDisplay import CmDsConstellationDisplayConst
from pypnm.docsis.data_type.enums import MeasStatusType
from pypnm.docsis.data_type.InterfaceStats import InterfaceStats
from pypnm.docsis.data_type.OfdmProfiles import OfdmProfiles
from pypnm.docsis.data_type.pnm.DocsIf3CmSpectrumAnalysisEntry import (
    DocsIf3CmSpectrumAnalysisEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmDsConstDispMeasEntry import (
    DocsPnmCmDsConstDispMeasEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmDsHistEntry import DocsPnmCmDsHistEntry
from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmFecEntry import DocsPnmCmDsOfdmFecEntry
from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmMerMarEntry import (
    DocsPnmCmDsOfdmMerMarEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmModProfEntry import (
    DocsPnmCmDsOfdmModProfEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmRxMerEntry import (
    DocsPnmCmDsOfdmRxMerEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmOfdmChanEstCoefEntry import (
    DocsPnmCmOfdmChanEstCoefEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmUsPreEqEntry import DocsPnmCmUsPreEqEntry
from pypnm.docsis.data_type.sysDescr import SystemDescriptor
from pypnm.docsis.lib.pnm_bulk_data import DocsPnmBulkDataGroup
from pypnm.lib.constants import DEFAULT_SPECTRUM_ANALYZER_INDICES
from pypnm.lib.inet import Inet
from pypnm.lib.inet_utils import InetGenerate
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import (
    BandwidthHz,
    ChannelId,
    EntryIndex,
    FrequencyHz,
    InterfaceIndex,
    SnmpCommunity,
)
from pypnm.lib.utils import Generate
from pypnm.pnm.data_type.DocsEqualizerData import DocsEqualizerData
from pypnm.pnm.data_type.DocsIf3CmSpectrumAnalysisCtrlCmd import (
    DocsIf3CmSpectrumAnalysisCtrlCmd,
    SpectrumRetrievalType,
)
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest
from pypnm.snmp.compiled_oids import COMPILED_OIDS
from pypnm.snmp.modules import DocsisIfType, DocsPnmBulkUploadControl
from pypnm.snmp.snmp_v2c import Snmp_v2c
from pypnm.snmp.snmp_v3 import Snmp_v3


class DocsPnmBulkFileUploadStatus(Enum):
    """Represents the upload status of a DOCSIS PNM bulk data file."""
    OTHER                   = 1
    AVAILABLE_FOR_UPLOAD    = 2
    UPLOAD_IN_PROGRESS      = 3
    UPLOAD_COMPLETED        = 4
    UPLOAD_PENDING          = 5
    UPLOAD_CANCELLED        = 6
    ERROR                   = 7

    def describe(self) -> str:
        """Returns a human-readable description of the enum value."""
        return {
            self.OTHER: "Other: unspecified condition",
            self.AVAILABLE_FOR_UPLOAD: "Available: ready for upload",
            self.UPLOAD_IN_PROGRESS: "In progress: upload ongoing",
            self.UPLOAD_COMPLETED: "Completed: upload successful",
            self.UPLOAD_PENDING: "Pending: blocked until conditions clear",
            self.UPLOAD_CANCELLED: "Cancelled: upload was stopped",
            self.ERROR: "Error: upload failed",
        }.get(self, "Unknown status")

    def to_dict(self) -> dict:
        """Serializes the status for API or JSON usage."""
        return {"name": self.name, "value": self.value, "description": self.describe()}

    def __str__(self) -> str:
        return super().__str__()

class DocsPnmCmCtlStatus(Enum):
    """
    Enum representing the overall status of the PNM test platform.

    Based on the SNMP object `docsPnmCmCtlStatus`, this enum is used to manage
    test initiation constraints on the Cable Modem (CM).
    """

    OTHER               = 1
    READY               = 2
    TEST_IN_PROGRESS    = 3
    TEMP_REJECT         = 4
    SNMP_ERROR          = 255

    def __str__(self) -> str:
        return self.name.lower()

class FecSummaryType(Enum):
    """
    Enum for FEC Summary Type used in DOCSIS PNM SNMP operations.
    """
    TEN_MIN             = 2
    TWENTY_FOUR_HOUR    = 3

    @classmethod
    def choices(cls) -> dict[str, int]:
        ''' Returns a dictionary [key,value] of enum names and their corresponding values. '''
        return {e.name: e.value for e in cls}

    @classmethod
    def from_value(cls, value: int) -> FecSummaryType:
        try:
            return cls(value)
        except ValueError as err:
            raise ValueError(f"Invalid FEC Summary Type value: {value}") from err

class CmSnmpOperation:
    """
    Cable Modem SNMP Operation Handler.

    This class provides methods to perform SNMP operations
    (GET, WALK, etc.) specifically for Cable Modems.

    Attributes:
        _inet (str): IP address of the Cable Modem.
        _community (str): SNMP community string used for authentication.
        _port (int): SNMP port (default: 161).
        _snmp (Snmp_v2c): SNMP client instance for communication.
        logger (logging.Logger): Logger instance for this class.
    """

    class SnmpVersion(IntEnum):
        _SNMPv2C = 0
        _SNMPv3  = 1

    def __init__(self, inet: Inet, write_community: SnmpCommunity, port: int = Snmp_v2c.SNMP_PORT) -> None:
        """
        Initialize a CmSnmpOperation instance.

        Args:
            inet (str): IP address of the Cable Modem.
            write_community (str): SNMP community string (usually 'private' for read/write access).
            port (int, optional): SNMP port number. Defaults to standard SNMP port 161.

        """
        self.logger = logging.getLogger(self.__class__.__name__)

        if not isinstance(inet, Inet):
            self.logger.error(f'CmSnmpOperation() inet is of an Invalid Type: {type(inet)} , expecting Inet')
            exit(1)

        self._inet:Inet = inet
        self._community = write_community
        self._port = port
        self._snmp = self.__load_snmp_version()

    def __load_snmp_version(self) -> Snmp_v2c | Snmp_v3:
        """
        Select and instantiate the appropriate SNMP client.

        Precedence:
        1) If SNMPv3 is explicitly enabled and parameters are valid -> return Snmp_v3
        2) Else if SNMPv2c is enabled -> return Snmp_v2c
        3) Else -> error
        """

        if SystemConfigSettings.snmp_v3_enable():
            '''
            self.logger.debug("SNMPv3 enabled in configuration; validating parameters...")
            try:
                p = PnmConfigManager.get_snmp_v3_params()
            except Exception as e:
                self.logger.error(f"Failed to load SNMPv3 parameters: {e}. Falling back to SNMPv2c.")
                p = None

            # Minimal required fields for a usable v3 session
            required = ("user", "auth_key", "priv_key", "auth_protocol", "priv_protocol")
            if p and all(p.get(k) for k in required):
                self.logger.debug("Using SNMPv3")
                return Snmp_v3(
                    host=self._inet,
                    user=p["user"],
                    auth_key=p["auth_key"],
                    priv_key=p["priv_key"],
                    auth_protocol=p["auth_protocol"],
                    priv_protocol=p["priv_protocol"],
                    port=self._port,
                )
            else:
                self.logger.warning(
                    "SNMPv3 is enabled but parameters are incomplete or invalid; "
                    "falling back to SNMPv2c."
                )
            '''
            # Keep the implementation stubbed for now.
            # Force an explicit failure instead of silently falling back.
            raise NotImplementedError(
                "SNMPv3 is enabled in configuration, but the SNMPv3 client is not implemented yet. "
                "Disable SNMPv3 to use SNMPv2c.")

        if SystemConfigSettings.snmp_enable():
            self.logger.debug("Using SNMPv2c")
            return Snmp_v2c(host=self._inet, community=self._community, port=self._port)

        # Neither protocol is usable
        msg = "No SNMP protocol enabled or properly configured (v3 disabled/invalid and v2c disabled)."
        self.logger.error(msg)
        raise ValueError(msg)

    async def _get_value(self, oid_suffix: str, value_type: type | str = str) -> str | bytes | int | None:
        """
        Retrieves a value from SNMP for the given OID suffix, processes the value based on the expected type,
        and handles any error cases that may arise during the process.

        Parameters:
        - oid_suffix (str): The suffix of the OID to query.
        - value_type (type or str): The type to which the value should be converted. Defaults to `str`.

        Returns:
        - Optional[Union[str, bytes, int]]: The value retrieved from SNMP, converted to the specified type,
          or `None` if there was an error or no value could be obtained.
        """
        result = await self._snmp.get(f"{oid_suffix}.0")

        if result is None:
            logging.warning(f"Failed to get value for {oid_suffix}")
            return None

        val = Snmp_v2c.snmp_get_result_value(result)[0]
        logging.debug(f"get_value() -> Val:{val}")

        # Check if the result is an error message, and return None if it is
        if isinstance(val, str) and "No Such Instance currently exists at this OID" in val:
            logging.warning(f"SNMP error for {oid_suffix}: {val}")
            return None

        # Handle string and bytes conversions explicitly
        if value_type is str:
            if isinstance(val, bytes):  # if val is bytes, decode it
                return val.decode('utf-8', errors='ignore')  # or replace with appropriate encoding
            return str(val)

        if value_type is bytes:
            if isinstance(val, str):  # if val is a string, convert to bytes
                # Remove any '0x' prefix or spaces before converting
                val = val.strip().lower()
                if val.startswith('0x'):
                    val = val[2:]  # Remove '0x' prefix

                # Ensure the string is a valid hex format
                try:
                    return bytes.fromhex(val)  # convert the cleaned hex string to bytes
                except ValueError as e:
                    logging.error(f"Invalid hex string: {val}. Error: {e}")
                    return None
            return val  # assuming it's already in bytes

        # Default case (int conversion)
        try:
            return value_type(val)
        except ValueError as e:
            logging.error(f"Failed to convert value for {oid_suffix}: {val}. Error: {e}")
            return None

    ######################
    # SNMP Get Operation #
    ######################

    def getWriteCommunity(self) -> str:
        return self._community

    async def getIfTypeIndex(self, doc_if_type: DocsisIfType) -> list[InterfaceIndex]:
        """
        Retrieve interface indexes that match the specified DOCSIS IANA ifType.

        Args:
            doc_if_type (DocsisIfType): The DOCSIS interface type to filter by.

        Returns:
            List[int]: A list of interface indexes matching the given ifType.
        """
        self.logger.debug(f"Starting getIfTypeIndex for ifType: {doc_if_type}")

        indexes: list[int] = []

        # Perform SNMP walk
        results = await self._snmp.walk("ifType")

        if not results:
            self.logger.warning("No results found during SNMP walk for ifType.")
            return indexes

        # Iterate through results and filter by the specified DOCSIS interface type
        ifType_name = doc_if_type.name
        ifType_value = doc_if_type.value

        try:
            for result in results:
                # Compare ifType value with the result value
                if ifType_value == int(result[1]):
                    self.logger.debug(f"ifType-Name: ({ifType_name}) -> ifType-Value: ({ifType_value}) -> Found: {result}")

                    # Extract index using a helper method (ensure it returns a valid index)
                    index = Snmp_v2c.get_oid_index(str(result[0]))
                    if index is not None:
                        indexes.append(index)
                    else:
                        self.logger.warning(f"Invalid OID index for result: {result}")
        except Exception as e:
            self.logger.error(f"Error processing results: {e}")

        # Return the list of found indexes
        return indexes

    async def getSysDescr(self, timeout: int | None = None, retries: int | None = None) -> SystemDescriptor:
        """
        Retrieves and parses the sysDescr SNMP value into a SysDescr dataclass.

        Returns:
            SysDescr if successful, otherwise empty SysDescr.empty().
        """
        timeout = timeout if timeout is not None else self._snmp._timeout
        retries = retries if retries is not None else self._snmp._retries

        self.logger.debug(f"Retrieving sysDescr for {self._inet}, timeout: {timeout}, retries: {retries}")

        try:
            result = await self._snmp.get(f'{"sysDescr"}.0', timeout=timeout, retries=retries)
        except Exception as e:
            self.logger.error(f"Error occurred while retrieving sysDescr: {e}")
            return SystemDescriptor.empty()

        if not result:
            self.logger.warning("SNMP get failed or returned empty for sysDescr.")
            return SystemDescriptor.empty()

        self.logger.debug(f"SysDescr Results: {result} before get_result_value")
        values = Snmp_v2c.get_result_value(result)

        if not values:
            self.logger.warning("No sysDescr value parsed.")
            return SystemDescriptor.empty()

        if not result:
            self.logger.warning("SNMP get failed or returned empty for sysDescr.")
            return SystemDescriptor.empty()

        values = Snmp_v2c.get_result_value(result)

        if not values:
            self.logger.warning("No sysDescr value parsed.")
            return SystemDescriptor.empty()

        self.logger.debug(f"SysDescr: {values}")

        try:
            parsed = SystemDescriptor.parse(values)
            self.logger.debug(f"Successfully parsed sysDescr: {parsed}")
            return parsed

        except ValueError as e:
            self.logger.error(f"Failed to parse sysDescr: {values}. Error: {e}")
            return SystemDescriptor.empty()

    async def getDocsPnmBulkDataGroup(self) -> DocsPnmBulkDataGroup:
        """
        Retrieves the current DocsPnmBulkDataGroup SNMP configuration from the device.

        Returns:
            DocsPnmBulkDataGroup: A dataclass populated with SNMP values.
        """

        return DocsPnmBulkDataGroup(
            docsPnmBulkDestIpAddrType   =   await self._get_value("docsPnmBulkDestIpAddrType", int),
            docsPnmBulkDestIpAddr       =   InetGenerate.binary_to_inet(await self._get_value("docsPnmBulkDestIpAddr", bytes)),
            docsPnmBulkDestPath         =   await self._get_value("docsPnmBulkDestPath", str),
            docsPnmBulkUploadControl    =   await self._get_value("docsPnmBulkUploadControl", int)
        )

    async def getDocsPnmCmCtlStatus(self, max_retry:int=1) -> DocsPnmCmCtlStatus:
        """
        Fetches the current Docs PNM CmCtlStatus.

        This method retrieves the Docs PNM CmCtlStatus and retries up to a specified number of times
        if the response is not valid. The possible statuses are:
        - 1: other
        - 2: ready
        - 3: testInProgress
        - 4: tempReject

        Parameters:
        - max_retry (int, optional): The maximum number of retries to obtain the status (default is 1).

        Returns:
        - DocsPnmCmCtlStatus: The Docs PNM CmCtlStatus as an enum value. Possible values:
        - DocsPnmCmCtlStatus.OTHER
        - DocsPnmCmCtlStatus.READY
        - DocsPnmCmCtlStatus.TEST_IN_PROGRESS
        - DocsPnmCmCtlStatus.TEMP_REJECT

        If the status cannot be retrieved after the specified retries, the method will return `DocsPnmCmCtlStatus.TEMP_REJECT`.
        """
        count = 1
        while True:

            result = await self._snmp.get(f'{"docsPnmCmCtlStatus"}.0')

            if result is None:
                time.sleep(2)
                self.logger.warning(f"Not getting a proper docsPnmCmCtlStatus response, retrying: ({count} of {max_retry})")

                if count >= max_retry:
                    self.logger.error(f"Reached max retries: ({max_retry})")
                    return DocsPnmCmCtlStatus.TEMP_REJECT

                count += 1
                continue
            else:
                break

        if not result:
            self.logger.error(f'No results found for docsPnmCmCtlStatus: {DocsPnmCmCtlStatus.SNMP_ERROR}')
            return DocsPnmCmCtlStatus.SNMP_ERROR

        status_value = int(Snmp_v2c.snmp_get_result_value(result)[0])

        return DocsPnmCmCtlStatus(status_value)

    async def getIfPhysAddress(self, if_type: DocsisIfType = DocsisIfType.docsCableMaclayer) -> MacAddress:
        """
        Retrieve the physical (MAC) address of the specified interface type.
        Args:
            if_type (DocsisIfType): The DOCSIS interface type to query. Defaults to docsCableMaclayer.
        Returns:
            MacAddress: The MAC address of the interface.
        Raises:
            RuntimeError: If no interfaces are found or SNMP get fails.
            ValueError: If the retrieved MAC address is invalid.
        """
        self.logger.debug(f"Getting ifPhysAddress for ifType: {if_type.name}")

        if_indexes = await self.getIfTypeIndex(if_type)
        self.logger.debug(f"{if_type.name} -> {if_indexes}")
        if not if_indexes:
            raise RuntimeError(f"No interfaces found for {if_type.name}")

        idx = if_indexes[0]
        resp = await self._snmp.get(f"ifPhysAddress.{idx}")
        self.logger.debug(f"getIfPhysAddress() -> {resp}")
        if not resp:
            raise RuntimeError(f"SNMP get failed for ifPhysAddress.{idx}")

        # Prefer grabbing raw bytes directly from the varbind
        try:
            varbind = resp[0]
            value = varbind[1]  # should be OctetString
            if isinstance(value, (OctetString, bytes, bytearray)):
                mac_bytes = bytes(value)
            else:
                # Fallback: use helper and try to coerce
                raw = Snmp_v2c.snmp_get_result_value(resp)[0]
                if isinstance(raw, (bytes, bytearray)):
                    mac_bytes = bytes(raw)
                elif isinstance(raw, str):
                    s = raw.strip().lower()
                    if s.startswith("0x"):
                        s = s[2:]
                    s = s.replace(":", "").replace("-", "").replace(" ", "")
                    mac_bytes = bytes.fromhex(s)
                else:
                    raise ValueError(f"Unsupported ifPhysAddress type: {type(raw)}")
        except Exception as e:
            # Log and rethrow with context
            self.logger.error(f"Failed to parse ifPhysAddress.{idx}: {e}")
            raise

        if len(mac_bytes) != 6:
            raise ValueError(f"Invalid MAC length {len(mac_bytes)} from ifPhysAddress.{idx}")

        mac_hex = mac_bytes.hex()
        return MacAddress(mac_hex)

    async def getDocsIfCmDsScQamChanChannelIdIndex(self) -> list[InterfaceIndex]:
        """
        Retrieve the list of DOCSIS 3.0 downstream SC-QAM channel indices.

        Returns:
            List[int]: A list of SC-QAM channel indices present on the device.
        """
        try:
            return await self.getIfTypeIndex(DocsisIfType.docsCableDownstream)

        except Exception as e:
            self.logger.error(f"Failed to retrieve SC-QAM Indexes: {e}")
            return []

    async def getDocsIf31CmDsOfdmChannelIdIndex(self) -> list[InterfaceIndex]:
        """
        Retrieve the list of Docsis 3.1 downstream OFDM channel indices.

        Returns:
            List[int]: A list of channel indices present on the device.
        """
        return await self.getIfTypeIndex(DocsisIfType.docsOfdmDownstream)

    async def getDocsIf31CmDsOfdmChanPlcFreq(self) -> list[tuple[InterfaceIndex, FrequencyHz]]:
        """
        Retrieve the PLC frequencies of DOCSIS 3.1 downstream OFDM channels.

        Returns:
            List[Tuple[int, int]]: A list of tuples where each tuple contains:
                - the index (int) of the OFDM channel
                - the PLC frequency (int, in Hz)
        """
        oid = "docsIf31CmDsOfdmChanPlcFreq"
        self.logger.debug(f"Walking OID for PLC frequencies: {oid}")

        try:
            results = await self._snmp.walk(oid)
            idx_plc_freqs = cast(list[tuple[InterfaceIndex, FrequencyHz]], Snmp_v2c.snmp_get_result_last_idx_value(results))

            self.logger.debug(f"Retrieved PLC Frequencies: {idx_plc_freqs}")
            return idx_plc_freqs

        except Exception as e:
            self.logger.error(f"Failed to retrieve PLC frequencies from OID {oid}: {e}")
            return []

    async def getDocsPnmCmOfdmChEstCoefMeasStatus(self, ofdm_idx: InterfaceIndex) -> int:
        '''
        Retrieves the measurement status of OFDM channel estimation coefficients.

        Parameters:
        - ofdm_idx (int): The OFDM index.

        Returns:
        int: The measurement status.
        '''
        result = await self._snmp.get(f'{"docsPnmCmOfdmChEstCoefMeasStatus"}.{ofdm_idx}')
        return int(Snmp_v2c.snmp_get_result_value(result)[0])

    async def getCmDsOfdmProfileStatsConfigChangeCt(self, ofdm_idx: InterfaceIndex) -> dict[int,dict[int,int]]:
        """
        Retrieve the count of configuration change events for a specific OFDM profile.

        Parameters:
        - ofdm_idx (int): The index of the OFDM profile.

        Returns:
            dict[ofdm_idx, dict[profile_id, count_change]]

        TODO: Need to get back, not really working

        """
        result = self._snmp.walk(f'{"docsIf31CmDsOfdmProfileStatsConfigChangeCt"}.{ofdm_idx}')
        profile_change_count = Snmp_v2c.snmp_get_result_value(result)[0]
        return profile_change_count

    async def _getDocsIf31CmDsOfdmChanEntry(self) -> list[DocsIf31CmDsOfdmChanEntry]:
        """
        Asynchronously retrieve all DOCSIS 3.1 downstream OFDM channel entries.

        This method queries SNMP for each available OFDM channel index
        and populates a DocsIf31CmDsOfdmChanEntry object with its SNMP attributes.

        NOTE:
            This is an async method. You must use 'await' when calling it.

        Returns:
            List[DocsIf31CmDsOfdmChanEntry]:
                A list of populated DocsIf31CmDsOfdmChanEntry objects,
                each representing one OFDM downstream channel.

        Raises:
            Exception: If SNMP queries fail or unexpected errors occur.
        """
        entries: list[DocsIf31CmDsOfdmChanEntry] = []

        # Get all OFDM Channel Indexes
        channel_indices = await self.getDocsIf31CmDsOfdmChannelIdIndex()

        for idx in channel_indices:
            self.logger.debug(f"Processing OFDM Channel Index: {idx}")
            oce = DocsIf31CmDsOfdmChanEntry(ofdm_idx=idx)

            # Iterate over all member attributes
            for member_name in oce.get_member_list():
                oid_base = COMPILED_OIDS.get(member_name)

                if not oid_base:
                    self.logger.warning(f"OID base not found for {member_name}")
                    continue

                oid = f"{oid_base}.{idx}"
                result = await self._snmp.get(oid)

                if result is not None:
                    self.logger.debug(f"Retrieved SNMP value for Member: {member_name} -> OID: {oid}")
                    try:
                        value = Snmp_v2c.snmp_get_result_value(result)
                        setattr(oce, member_name, value)
                    except (ValueError, TypeError) as e:
                        self.logger.error(f"Failed to set '{member_name}' with value '{result}': {e}")
                else:
                    self.logger.warning(f"No SNMP response received for OID: {oid}")

            entries.append(oce)

        return entries

    async def getDocsIfSignalQuality(self) -> list[DocsIfSignalQuality]:
        """
        Retrieves signal quality metrics for all downstream QAM channels.

        This method queries the SNMP agent for the list of downstream QAM channel indexes,
        and for each index, creates a `DocsIfSignalQuality` instance, populates it with SNMP data,
        and collects it into a list.

        Returns:
            List[DocsIfSignalQuality]: A list of signal quality objects, one per downstream channel.
        """
        sig_qual_list: list[DocsIfSignalQuality] = []

        indices = await self.getDocsIfCmDsScQamChanChannelIdIndex()
        if not indices:
            self.logger.warning("No downstream channel indices found.")
            return sig_qual_list

        for idx in indices:
            obj = DocsIfSignalQuality(index=idx, snmp=self._snmp)
            await obj.start()
            sig_qual_list.append(obj)

        return sig_qual_list

    async def getDocsIfDownstreamChannel(self) -> list[DocsIfDownstreamChannelEntry]:
        """
        Retrieves signal quality metrics for all downstream SC-QAM channels.

        This method queries the SNMP agent for the list of downstream SC-QAM channel indexes,
        and for each index, fetches and builds a DocsIfDownstreamChannelEntry.

        Returns:
            List[DocsIfDownstreamChannelEntry]: A list of populated downstream channel entries.
        """
        try:
            indices = await self.getDocsIfCmDsScQamChanChannelIdIndex()

            if not indices:
                self.logger.warning("No downstream SC-QAM channel indices found.")
                return []

            entries = await DocsIfDownstreamChannelEntry.get(snmp=self._snmp, indices=indices)

            return entries

        except Exception as e:
            self.logger.exception("Failed to retrieve downstream SC-QAM channel entries, error: %s", e)
            return []

    async def getDocsIfDownstreamChannelCwErrorRate(self, sample_time_elapsed: float = 5.0) -> \
        list[DocsIfDownstreamCwErrorRateEntry] | dict[str, Any]:
        """
        Retrieves codeword error rate for all downstream SC-QAM channels.

        1. Fetch initial SNMP snapshot for all channels.
        2. Wait asynchronously for `sample_time_elapsed` seconds.
        3. Fetch second SNMP snapshot.
        4. Compute per-channel & aggregate CW error metrics.
        """
        try:
            # 1) Discover all downstream SC-QAM (index, channel_id) indices
            idx_chanid_indices:list[tuple[int, int]] = await self.getDocsIfDownstreamChannelIdIndexStack()

            if not idx_chanid_indices:
                self.logger.warning("No downstream SC-QAM channel indices found.")
                return {"entries": [], "aggregate_error_rate": 0.0}

            self.logger.debug(f"Found {len(idx_chanid_indices)} downstream SC-QAM channel indices: {idx_chanid_indices}")
            # Extract only the first element of each tuple
            idx_indices:list[int] = [index[0] for index in idx_chanid_indices]

            # 2) First snapshot
            initial_entry = await DocsIfDownstreamChannelEntry.get(snmp=self._snmp, indices=idx_indices)
            self.logger.debug(f"Initial snapshot: {len(initial_entry)} channels")

            # 3) Wait the sample interval
            await asyncio.sleep(sample_time_elapsed)

            # 4) Second snapshot
            later_entry = await DocsIfDownstreamChannelEntry.get(snmp=self._snmp, indices=idx_indices)
            self.logger.debug(f"Second snapshot after {sample_time_elapsed}s: {len(later_entry)} channels")

            # 5) Calculate error rates
            calculator = DocsIfDownstreamChannelCwErrorRate(
                            entries_1=initial_entry,
                            entries_2=later_entry,
                            channel_id_index_stack=idx_chanid_indices,
                            time_elapsed=sample_time_elapsed)
            return calculator.get()

        except Exception:
            self.logger.exception("Failed to retrieve downstream SC-QAM codeword error rates")
            return {"entries": [], "aggregate_error_rate": 0.0}

    async def getEventEntryIndex(self) -> list[EntryIndex]:
        """
        Retrieves the list of index values for the docsDevEventEntry table.

        Returns:
            List[int]: A list of SNMP index integers.
        """
        oid = "docsDevEvId"

        results = await self._snmp.walk(oid)

        if not results:
            self.logger.warning(f"No results found for OID {oid}")
            return []

        return cast(list[EntryIndex], Snmp_v2c.extract_last_oid_index(results))

    async def getDocsDevEventEntry(self, to_dict: bool = False) -> list[DocsDevEventEntry] | list[dict]:
        """
        Retrieves all DocsDevEventEntry SNMP table entries.

        Args:
            to_dict (bool): If True, returns a list of dictionaries instead of DocsDevEventEntry instances.

        Returns:
            Union[List[DocsDevEventEntry], List[dict]]: A list of event log entries.
        """
        event_entries = []

        try:
            indices = await self.getEventEntryIndex()

            if not indices:
                self.logger.warning("No DocsDevEventEntry indices found.")
                return event_entries

            for idx in indices:
                entry = DocsDevEventEntry(index=idx, snmp=self._snmp)
                await entry.start()
                event_entries.append(entry.to_dict() if to_dict else entry)

        except Exception as e:
            self.logger.exception("Failed to retrieve DocsDevEventEntry entries, error: %s", e)

        return event_entries

    async def getDocsIf31CmDsOfdmChanEntry(self) -> list[DocsIf31CmDsOfdmChanChannelEntry]:
        """
        Asynchronously retrieves and populates a list of `DocsIf31CmDsOfdmChanEntry` entries.

        This method fetches the indices of the DOCSIS 3.1 CM DS OFDM channels, creates
        `DocsIf31CmDsOfdmChanEntry` objects for each index, and populates their attributes
        by making SNMP queries. The entries are returned as a list.

        Returns:
            List[DocsIf31CmDsOfdmChanEntry]: A list of `DocsIf31CmDsOfdmChanEntry` objects.

        Raises:
            Exception: If any unexpected error occurs during the process of fetching or processing.
        """

        ofdm_chan_entry: list[DocsIf31CmDsOfdmChanChannelEntry] = []

        try:
            indices = await self.getDocsIf31CmDsOfdmChannelIdIndex()

            if not indices:
                self.logger.warning("No DocsIf31CmDsOfdmChanChannelId indices found.")
                return ofdm_chan_entry

            ofdm_chan_entry.extend(await DocsIf31CmDsOfdmChanChannelEntry.get(self._snmp, indices))

        except Exception as e:
            self.logger.exception("Failed to retrieve DocsIf31CmDsOfdmChanEntry entries, error: %s", e)

        return ofdm_chan_entry

    async def getDocsIf31CmSystemCfgDiplexState(self) -> DocsIf31CmSystemCfgDiplexState:
        """
        Asynchronously retrieves the DOCS-IF31-MIB system configuration state and populates the `DocsIf31CmSystemCfgState` object.

        This method will fetch the necessary MIB data, populate the attributes of the
        `DocsIf31CmSystemCfgState` object, and return the object.

        Returns:
            DocsIf31CmSystemCfgState: An instance of the `DocsIf31CmSystemCfgState` class with populated data.
        """
        obj = DocsIf31CmSystemCfgDiplexState(self._snmp)
        await obj.start()

        return obj

    async def getDocsIf31CmDsOfdmProfileStatsEntry(self) -> list[DocsIf31CmDsOfdmProfileStatsEntry]:
        """
        Asynchronously retrieves the DOCS-IF31-MIB system configuration state and populates the `DocsIf31CmSystemCfgState` object.

        This method will fetch the necessary MIB data, populate the attributes of the
        `DocsIf31CmSystemCfgState` object, and return the object.

        Returns:
            DocsIf31CmSystemCfgState: An instance of the `DocsIf31CmSystemCfgState` class with populated data.
        """

        ofdm_profile_entry: list[DocsIf31CmDsOfdmProfileStatsEntry] = []

        try:
            indices = await self.getDocsIf31CmDsOfdmChannelIdIndex()

            if not indices:
                self.logger.warning("No DocsIf31CmDsOfdmChanChannelIdIndex indices found.")
                return ofdm_profile_entry

            for idx in indices:
                entry = DocsIf31CmDsOfdmProfileStatsEntry(index=idx, snmp=self._snmp)
                await entry.start()
                ofdm_profile_entry.append(entry)

        except Exception as e:
            self.logger.exception("Failed to retrieve DocsIf31CmDsOfdmProfileStatsEntry entries, error: %s", e)

        return ofdm_profile_entry

    async def getPnmMeasurementStatus(self, test_type: DocsPnmCmCtlTest, ofdm_ifindex: int = 0) -> MeasStatusType:
        """
        Retrieve the measurement status for a given PNM test type.

        Depending on the test type, the appropriate SNMP OID is selected,
        and the required interface index is either used directly or derived
        based on DOCSIS interface type conventions.

        Args:
            test_type (DocsPnmCmCtlTest): Enum specifying the PNM test type.
            ofdm_ifindex (int): Interface index for OFDM-based tests. This may be
                                ignored or overridden for specific test types.

        Returns:
            MeasStatusType: Parsed status value from SNMP response.

        Notes:
            - `DS_SPECTRUM_ANALYZER` uses a fixed ifIndex of 0.
            - `LATENCY_REPORT` dynamically resolves the ifIndex of the DOCSIS MAC layer.
            - If the test type is unsupported or SNMP fails, `MeasStatusType.OTHER | ERROR` is returned.
        """

        oid_key_map = {
            DocsPnmCmCtlTest.SPECTRUM_ANALYZER: "docsIf3CmSpectrumAnalysisCtrlCmdMeasStatus",
            DocsPnmCmCtlTest.DS_OFDM_SYMBOL_CAPTURE: "docsPnmCmDsOfdmSymMeasStatus",
            DocsPnmCmCtlTest.DS_OFDM_CHAN_EST_COEF: "docsPnmCmOfdmChEstCoefMeasStatus",
            DocsPnmCmCtlTest.DS_CONSTELLATION_DISP: "docsPnmCmDsConstDispMeasStatus",
            DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR: "docsPnmCmDsOfdmRxMerMeasStatus",
            DocsPnmCmCtlTest.DS_OFDM_CODEWORD_ERROR_RATE: "docsPnmCmDsOfdmFecMeasStatus",
            DocsPnmCmCtlTest.DS_HISTOGRAM: "docsPnmCmDsHistMeasStatus",
            DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF: "docsPnmCmUsPreEqMeasStatus",
            DocsPnmCmCtlTest.DS_OFDM_MODULATION_PROFILE: "docsPnmCmDsOfdmModProfMeasStatus",
            DocsPnmCmCtlTest.LATENCY_REPORT: "docsCmLatencyRptCfgMeasStatus",
        }

        if test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER:
            ofdm_ifindex = 0
        elif test_type == DocsPnmCmCtlTest.LATENCY_REPORT:
            ofdm_ifindex = await self.getIfTypeIndex(DocsisIfType.docsCableMaclayer)[0]

        oid = oid_key_map.get(test_type)
        if not oid:
            self.logger.warning(f"Unsupported test type provided: {test_type}")
            return MeasStatusType.OTHER

        oid = f"{oid}.{ofdm_ifindex}"

        try:
            result = await self._snmp.get(oid)
            status_value = int(Snmp_v2c.snmp_get_result_value(result)[0])
            return MeasStatusType(status_value)

        except Exception as e:
            self.logger.error(f"[{test_type.name}] SNMP fetch failed on OID {oid}: {e}")
            self.logger.error(f'[{test_type.name}] {result}')
            return MeasStatusType.ERROR

    async def getDocsIfDownstreamChannelIdIndexStack(self) -> list[tuple[InterfaceIndex, ChannelId]]:
        """
        Retrieve SC-QAM channel index ↔ channelId tuples for DOCSIS 3.0 downstream channels,
        ensuring we only return true SC-QAM channels ( skips OFDM / zero entries ).

        Returns:
            List[Tuple[int, int]]: (entryIndex, channelId) pairs, or [] if none found.
        """
        # 1) fetch indices of all SC-QAM interfaces
        try:
            scqam_if_indices = await self.getIfTypeIndex(DocsisIfType.docsCableDownstream)
        except Exception:
            self.logger.error("Failed to retrieve SC-QAM interface indices", exc_info=True)
            return []
        if not scqam_if_indices:
            self.logger.debug("No SC-QAM interface indices found")
            return []

        # 2) do a single walk of the SC-QAM ChannelId table
        try:
            responses = await self._snmp.walk("docsIfDownChannelId")
        except Exception:
            self.logger.error("SNMP walk failed for docsIfDownChannelId", exc_info=True)
            return []
        if not responses:
            self.logger.debug("No entries returned from docsIfDownChannelId walk")
            return []

        # 3) parse into (idx, chanId), forcing chanId → int
        try:
            raw_pairs: list[tuple[int, int]] = Snmp_v2c.snmp_get_result_last_idx_force_value_type(responses,
                                                                                                  value_type=int)

        except Exception:
            self.logger.error("Failed to parse index/channel-ID pairs", exc_info=True)
            return []

        # 4) filter out non-SC-QAM and zero entries (likely OFDM)
        scqam_set = set(scqam_if_indices)
        filtered: list[tuple[InterfaceIndex, ChannelId]] = []

        for idx, chan_id in raw_pairs:
            if idx not in scqam_set:
                self.logger.debug("Skipping idx %s not in SC-QAM interface list", idx)
                continue
            if chan_id == 0:
                self.logger.debug("Skipping idx %s with channel_id=0 (likely OFDM)", idx)
                continue
            filtered.append((InterfaceIndex(idx), ChannelId(chan_id)))

        return filtered

    async def getDocsIf31CmDsOfdmChannelIdIndexStack(self) -> list[tuple[InterfaceIndex, ChannelId]]:
        """
        Retrieve a list of tuples representing OFDM channel index and their associated channel IDs
        for DOCSIS 3.1 downstream OFDM channels.

        Returns:
            List[Tuple[int, int]]: Each tuple contains (index, channelId). Returns an empty list if no data is found.
        """
        result = await self._snmp.walk(f'{"docsIf31CmDsOfdmChanChannelId"}')

        if not result:
            return []

        raw_pairs: list[tuple[int, int]] = Snmp_v2c.snmp_get_result_last_idx_force_value_type(
            result,
            value_type=int,
        )
        idx_channel_id: list[tuple[InterfaceIndex, ChannelId]] = [
            (InterfaceIndex(idx), ChannelId(chan_id)) for idx, chan_id in raw_pairs
        ]

        return idx_channel_id or []

    async def getSysUpTime(self) -> str | None:
        """
        Retrieves the system uptime of the SNMP target device.

        This method performs an SNMP GET operation on the `sysUpTime` OID (1.3.6.1.2.1.1.3.0),
        which returns the time (in hundredths of a second) since the network management portion
        of the system was last re-initialized.

        Returns:
            Optional[int]: The system uptime in hundredths of a second if successful,
            otherwise `None` if the SNMP request fails or the result cannot be parsed.

        Logs:
            - A warning if the SNMP GET fails or returns no result.
            - An error if the value cannot be converted to an integer.
        """
        result = await self._snmp.get(f'{"sysUpTime"}.0')

        if not result:
            self.logger.warning("SNMP get failed or returned empty for sysUpTime.")
            return None

        try:
            value = Snmp_v2c.get_result_value(result)
            return Snmp_v2c.ticks_to_duration(int(value))

        except (ValueError, TypeError) as e:
            self.logger.error(f"Failed to parse sysUpTime value: {value} - {e}")
            return None

    async def isAmplitudeDataPresent(self) -> bool:
        """
        Check if DOCSIS spectrum amplitude data is available via SNMP.

        Returns:
            bool: True if amplitude data exists; False otherwise.
        """
        oid = COMPILED_OIDS.get("docsIf3CmSpectrumAnalysisMeasAmplitudeData")
        if not oid:
            return False

        try:

            # TODO: Uncomment when ready to use
            #results = await self._snmp.walk(oid)

            results = await self._snmp.bulk_walk(oid, max_repetitions=1)

        except Exception as e:
            self.logger.warning(f"Amplitude data bulk walk failed for {oid}: {e}")
            return False

        return bool(results)

    async def getSpectrumAmplitudeData(self) -> bytes:
        """
        Retrieve and return the raw spectrum analyzer amplitude data from the cable modem via SNMP.

        This method queries the 'docsIf3CmSpectrumAnalysisMeasAmplitudeData' table, collects all
        returned byte-chunks, and concatenates them into a single byte stream. It logs a warning
        if no data is found, and logs the first 128 bytes of the raw result (in hex) for inspection.

        Returns:
            A bytes object containing the full amplitude data stream. If no data is returned, an
            empty bytes object is returned.

        Raises:
            RuntimeError: If SNMP walk returns an unexpected data type or if any underlying SNMP
                          operation fails.
        """
        # OID for the amplitude data (should be a ByteString/Textual convention)
        oid = COMPILED_OIDS.get("docsIf3CmSpectrumAnalysisMeasAmplitudeData")
        if oid is None:
            msg = "OID 'docsIf3CmSpectrumAnalysisMeasAmplitudeData' is not defined in COMPILED_OIDS."
            self.logger.error(msg)
            raise RuntimeError(msg)

        # Perform SNMP WALK asynchronously
        try:
            results = await self._snmp.walk(oid)
        except Exception as e:
            self.logger.error(f"SNMP walk for OID {oid} failed: {e}")
            raise RuntimeError(f"SNMP walk failed: {e}") from e

        # If the SNMP WALK returned no varbinds, warn and return empty bytes
        if not results:
            self.logger.warning(f"No results found for OID {oid}")
            return b""

        # Extract raw byte-chunks from the SNMP results
        raw_chunks = []
        for idx, chunk in enumerate(Snmp_v2c.snmp_get_result_bytes(results)):
            # Ensure we got a bytes-like object
            if not isinstance(chunk, (bytes, bytearray)):
                self.logger.error(
                    f"Unexpected data type for chunk #{idx}: {type(chunk).__name__}. "
                    "Expected bytes or bytearray."
                )
                raise RuntimeError(f"Invalid SNMP result type: {type(chunk)}")

            # Log the first 128 bytes of each chunk (hex) for debugging
            preview = chunk[:128].hex()
            self.logger.debug(f"Raw SNMP chunk #{idx} (first 128 bytes): {preview}")

            raw_chunks.append(bytes(chunk))  # ensure immutability

        # Concatenate all chunks into a single bytes object
        varbind_bytes = b"".join(raw_chunks)

        # Log total length for reference
        total_length = len(varbind_bytes)
        if total_length == 0:
            self.logger.warning(f"OID {oid} returned an empty byte stream after concatenation.")
        else:
            self.logger.debug(f"Retrieved {total_length} bytes of amplitude data for OID {oid}.")

        return varbind_bytes

    async def getBulkFileUploadStatus(self, filename: str) -> DocsPnmBulkFileUploadStatus:
        """
        Retrieve the upload‐status enum of a bulk data file by its filename.

        Args:
            filename: The exact file name to search for in the BulkDataFile table.

        Returns:
            DocsPnmBulkFileUploadStatus:
            - The actual upload status if found
            - DocsPnmBulkFileUploadStatus.ERROR if the filename is not present or any SNMP error occurs
        """
        self.logger.debug(f"Starting getBulkFileUploadStatus for filename: {filename}")

        name_oid = "docsPnmBulkFileName"
        status_oid = "docsPnmBulkFileUploadStatus"

        # 1) Walk file‐name column
        try:
            name_rows = await self._snmp.walk(name_oid)
        except Exception as e:
            self.logger.error(f"SNMP walk failed for BulkFileName: {e}")
            return DocsPnmBulkFileUploadStatus.ERROR

        if not name_rows:
            self.logger.warning("BulkFileName table is empty.")
            return None

        # 2) Loop through (index, name) pairs
        for idx, current_name in Snmp_v2c.snmp_get_result_last_idx_value(name_rows):
            if current_name != filename:
                continue

            # 3) Fetch the status OID for this index
            full_oid = f"{status_oid}.{idx}"
            try:
                resp = await self._snmp.get(full_oid)
            except Exception as e:
                self.logger.error(f"SNMP get failed for {full_oid}: {e}")
                return DocsPnmBulkFileUploadStatus.ERROR

            if not resp:
                self.logger.warning(f"No response for status OID {full_oid}")
                return DocsPnmBulkFileUploadStatus.ERROR

            # 4) Parse and convert to enum
            try:
                _, val = resp[0]
                status_int = int(val)
                status_enum = DocsPnmBulkFileUploadStatus(status_int)
            except ValueError as ve:
                self.logger.error(f"Invalid status value {val}: {ve}")
                return DocsPnmBulkFileUploadStatus.ERROR
            except Exception as e:
                self.logger.error(f"Unexpected error parsing status: {e}")
                return DocsPnmBulkFileUploadStatus.ERROR

            self.logger.debug(f"Bulk file '{filename}' upload status: {status_enum.name}")
            return status_enum

        # not found
        self.logger.warning(f"Filename '{filename}' not found in BulkDataFile table.")
        return DocsPnmBulkFileUploadStatus.ERROR

    async def getDocsisBaseCapability(self) -> ClabsDocsisVersion:
        """
        Retrieve the DOCSIS version capability reported by the device.

        This method queries the SNMP OID `docsIf31CmDocsisBaseCapability`, which reflects
        the supported DOCSIS Radio Frequency specification version.

        Returns:
            ClabsDocsisVersion: Enum indicating the DOCSIS version supported by the device, or None if unavailable.

        SNMP MIB Reference:
            - OID: docsIf31DocsisBaseCapability
            - SYNTAX: ClabsDocsisVersion (INTEGER enum from 0 to 6)
            - Affected Devices:
                - CMTS: reports highest supported DOCSIS version.
                - CM: reports supported DOCSIS version.

            This attribute replaces `docsIfDocsisBaseCapability` from RFC 4546.
        """
        self.logger.debug("Fetching docsIf31DocsisBaseCapability")

        try:
            rsp = await self._snmp.get('docsIf31DocsisBaseCapability.0')
            docsis_version_raw = Snmp_v2c.get_result_value(rsp)

            if docsis_version_raw is None:
                self.logger.error("Failed to retrieve DOCSIS version: SNMP result is None")
                return None

            try:
                docsis_version = int(docsis_version_raw)
            except (ValueError, TypeError):
                self.logger.error(f"Failed to cast DOCSIS version to int: {docsis_version_raw}")
                return None

            cdv = ClabsDocsisVersion.from_value(docsis_version)

            if cdv == ClabsDocsisVersion.OTHER:
                self.logger.warning(f"Unknown DOCSIS version: {docsis_version} -> Enum: {cdv.name}")
            else:
                self.logger.debug(f"DOCSIS version: {cdv.name}")

            return cdv

        except Exception as e:
            self.logger.exception(f"Exception during DOCSIS version retrieval: {e}")
            return None

    async def getInterfaceStatistics(self, interface_types: type[Enum] = DocsisIfType) -> dict[str, list[dict]]:
        """
        Retrieves interface statistics grouped by provided Enum of interface types.

        Args:
            interface_types (Type[Enum]): Enum class representing interface types.

        Returns:
            Dict[str, List[Dict]]: Mapping of interface type name to list of interface stats.
        """
        stats: dict[str, list[dict]] = {}

        for if_type in interface_types:
            interfaces = await InterfaceStats.from_snmp(self._snmp, if_type)
            if interfaces:
                stats[if_type.name] = [iface.model_dump() for iface in interfaces]

        return stats

    async def getDocsIf31CmUsOfdmaChanChannelIdIndex(self) -> list[InterfaceIndex]:
        """
        Get the Docsis 3.1 upstream OFDMA channels.

        Returns:
            List[int]: A list of OFDMA channel indices present on the device.
        """
        return await self.getIfTypeIndex(DocsisIfType.docsOfdmaUpstream)

    async def getDocsIf31CmUsOfdmaChanEntry(self) -> list[DocsIf31CmUsOfdmaChanEntry]:
        """
        Retrieves and initializes all OFDMA channel entries from Snmp_v2c.

        Returns:
            List[DocsIf31CmUsOfdmaChanEntry]: List of populated OFDMA channel objects.
        """
        results: list[DocsIf31CmUsOfdmaChanEntry] = []

        indices = await self.getDocsIf31CmUsOfdmaChanChannelIdIndex()
        if not indices:
            self.logger.warning("No upstream OFDMA indices found.")
            return results

        return await DocsIf31CmUsOfdmaChanEntry.get(snmp=self._snmp, indices=indices)

    async def getDocsIfUpstreamChannelEntry(self) -> list[DocsIfUpstreamChannelEntry]:
        """
        Retrieves and initializes all ATDMA US channel entries from Snmp_v2c.

        Returns:
            List[DocsIfUpstreamChannelEntry]: List of populated ATDMA channel objects.
        """
        try:
            indices = await self.getDocsIfCmUsTdmaChanChannelIdIndex()

            if not indices:
                self.logger.warning("No upstream ATDMA indices found.")
                return []

            entries = await DocsIfUpstreamChannelEntry.get(
                snmp=self._snmp,
                indices=indices
            )

            return entries

        except Exception as e:
            self.logger.exception("Failed to retrieve ATDMA upstream channel entries, error: %s", e)
            return []

    async def getDocsIf31CmUsOfdmaChannelIdIndexStack(self) -> list[tuple[InterfaceIndex, ChannelId]]:
        """
        Retrieve a list of tuples representing OFDMA channel index and their associated channel IDs
        for DOCSIS 3.1 upstream OFDMA channels.

        Returns:
            List[Tuple[InterfaceIndex, ChannelId]]: Each tuple contains (index, channelId). Returns an empty list if no data is found.
        """
        result = await self._snmp.walk(f'{"docsIf31CmUsOfdmaChanChannelId"}')

        if not result:
            return []

        raw_pairs: list[tuple[int, int]] = Snmp_v2c.snmp_get_result_last_idx_force_value_type(
            result,
            value_type=int,
        )
        idx_channel_id_list: list[tuple[InterfaceIndex, ChannelId]] = [
            (InterfaceIndex(idx), ChannelId(chan_id)) for idx, chan_id in raw_pairs
        ]

        return idx_channel_id_list or []

    async def getDocsIfCmUsTdmaChanChannelIdIndex(self) -> list[InterfaceIndex]:
        """
        Retrieve the list of DOCSIS 3.0 upstream TDMA/ATDMA channel indices (i.e., TDMA or ATDMA).

        Returns:
            List[int]: A list of TDMA/ATDMA channel indices present on the device.
        """
        idx_list: list[int] = []
        oid_channel_id = "docsIfUpChannelId"

        try:
            results = await self._snmp.walk(oid_channel_id)
            if not results:
                self.logger.warning(f"No results found for OID {oid_channel_id}")
                return []

            index_list = Snmp_v2c.extract_last_oid_index(results)

            oid_modulation = "docsIfUpChannelType"

            for idx in index_list:

                result = await self._snmp.get(f'{oid_modulation}.{idx}')

                if not result:
                    self.logger.warning(f"SNMP get failed or returned empty docsIfUpChannelType for index {idx}.")
                    continue

                val = Snmp_v2c.snmp_get_result_value(result)[0]

                try:
                    channel_type = int(val)

                except ValueError:
                    self.logger.warning(f"Failed to convert channel-type value '{val}' to int for index {idx}. Skipping.")
                    continue

                '''
                    DocsisUpstreamType ::= TEXTUAL-CONVENTION
                    STATUS          current
                    DESCRIPTION
                            "Indicates the DOCSIS Upstream Channel Type.
                            'unknown' means information not available.
                            'tdma' is related to TDMA, Time Division
                            Multiple Access; 'atdma' is related to A-TDMA,
                            Advanced Time Division Multiple Access,
                            'scdma' is related to S-CDMA, Synchronous
                            Code Division Multiple Access.
                            'tdmaAndAtdma is related to simultaneous support of
                            TDMA and A-TDMA modes."
                    SYNTAX INTEGER {
                        unknown(0),
                        tdma(1),
                        atdma(2),
                        scdma(3),
                        tdmaAndAtdma(4)
                    }

                '''

                if channel_type != 0: # 0 means OFDMA in this case
                    idx_list.append(idx)

            return idx_list

        except Exception as e:
            self.logger.error(f"Failed to retrieve SC-QAM channel indices from {oid_channel_id}: {e}")
            return []


    """
    Measurement Entries
    """

    async def getDocsPnmCmDsOfdmRxMerEntry(self) -> list[DocsPnmCmDsOfdmRxMerEntry]:
        """
        Retrieve RxMER (per-subcarrier) entries for all downstream OFDM channels.

        Returns
        -------
        List[DocsPnmCmDsOfdmRxMerEntry]
            A list of Pydantic models with values already coerced to floats
            where appropriate (e.g., dB fields scaled by 1/100).
        """
        self.logger.debug('Entering into -> getDocsPnmCmDsOfdmRxMerEntry()')
        entries: list[DocsPnmCmDsOfdmRxMerEntry] = []
        try:
            indices = await self.getDocsIf31CmDsOfdmChannelIdIndex()

            if not indices:
                self.logger.warning("No DocsIf31CmDsOfdmChanChannelIdIndex indices found.")
                return entries

            # De-dupe and sort for predictable iteration (optional but nice for logs)
            unique_indices = sorted(set(int(i) for i in indices))
            self.logger.debug(f"RxMER fetch: indices={unique_indices}")

            entries = await DocsPnmCmDsOfdmRxMerEntry.get(snmp=self._snmp, indices=unique_indices)

            # Helpful summary log—count only; detailed per-field logs happen in the entry fetcher
            self.logger.debug("RxMER fetch complete: %d entries", len(entries))
            return entries

        except Exception as e:
            # Keep the exception in logs for debugging (stacktrace included)
            self.logger.exception("Failed to retrieve DocsPnmCmDsOfdmRxMerEntry entries: %s", e)
            return entries

    async def getDocsPnmCmOfdmChanEstCoefEntry(self) -> list[DocsPnmCmOfdmChanEstCoefEntry]:
        """
        Retrieves downstream OFDM Channel Estimation Coefficient entries from the cable modem via SNMP.

        This method:
        - Queries for all available downstream OFDM channel indices using `getDocsIf31CmDsOfdmChannelIdIndex()`.
        - For each index, requests a structured set of coefficient data points including amplitude ripple,
          group delay characteristics, mean values, and measurement status.
        - Constructs a list of `DocsPnmCmOfdmChanEstCoefEntry` objects, each encapsulating the raw
          coefficients for one OFDM channel.

        Returns:
            List[DocsPnmCmOfdmChanEstCoefEntry]: A list of populated OFDM channel estimation entries. Each entry
            includes both metadata and coefficient fields defined in `DocsPnmCmOfdmChanEstCoefFields`.
        """
        entries: list[DocsPnmCmOfdmChanEstCoefEntry] = []

        try:
            indices = await self.getDocsIf31CmDsOfdmChannelIdIndex()

            if not indices:
                self.logger.warning("No DocsIf31CmDsOfdmChanChannelIdIndex indices found.")
                return entries

            entries = await DocsPnmCmOfdmChanEstCoefEntry.get(snmp=self._snmp, indices=indices)

        except Exception as e:
            self.logger.exception("Failed to retrieve DocsPnmCmOfdmChanEstCoefEntry entries, error: %s", e)

        return entries

    async def getDocsPnmCmDsConstDispMeasEntry(self) -> list[DocsPnmCmDsConstDispMeasEntry]:
        """
        Retrieves Constellation Display measurement entries for all downstream OFDM channels.

        This method:
        - Discovers available downstream OFDM channel indices using SNMP via `getDocsIf31CmDsOfdmChannelIdIndex()`
        - For each channel index, fetches constellation capture configuration, modulation info,
          measurement status, and associated binary filename
        - Returns the results as a structured list of `DocsPnmCmDsConstDispMeasEntry` models

        Returns:
            List[DocsPnmCmDsConstDispMeasEntry]: A list of Constellation Display SNMP measurement entries.
        """
        entries: list[DocsPnmCmDsConstDispMeasEntry] = []

        try:
            indices = await self.getDocsIf31CmDsOfdmChannelIdIndex()

            if not indices:
                self.logger.warning("No DocsIf31CmDsOfdmChanChannelIdIndex indices found.")
                return entries

            entries = await DocsPnmCmDsConstDispMeasEntry.get(snmp=self._snmp, indices=indices)

        except Exception as e:
            self.logger.exception("Failed to retrieve DocsPnmCmDsConstDispMeasEntry entries, error: %s", e)

        return entries

    async def getDocsPnmCmUsPreEqEntry(self) -> list[DocsPnmCmUsPreEqEntry]:
        """
        Retrieves upstream OFDMA Pre-Equalization measurement entries for all upstream OFDMA channels.

        This method performs:
        - SNMP index discovery via `getDocsIf31CmDsOfdmChannelIdIndex()` (may need to be updated to upstream index discovery)
        - Per-index SNMP fetch of pre-equalization configuration and measurement metadata
        - Returns structured list of `DocsPnmCmUsPreEqEntry` models
        """
        entries: list[DocsPnmCmUsPreEqEntry] = []

        try:
            indices = await self.getDocsIf31CmUsOfdmaChanChannelIdIndex()

            if not indices:
                self.logger.warning("No DocsIf31CmUsOfdmaChannelIdIndex indices found.")
                return entries

            entries = await DocsPnmCmUsPreEqEntry.get(snmp=self._snmp, indices=indices)

        except Exception as e:
            self.logger.exception("Failed to retrieve DocsPnmCmUsPreEqEntry entries, error: %s", e)

        return entries

    async def getDocsPnmCmDsOfdmMerMarEntry(self) -> list[DocsPnmCmDsOfdmMerMarEntry]:
        """
        Retrieves DOCSIS 3.1 Downstream OFDM MER Margin entries.

        This method queries the SNMP agent to collect MER Margin data for each downstream OFDM channel
        using the ifIndex values retrieved from the modem. Each returned entry corresponds to a channel's
        MER margin metrics, including required MER, measured MER, threshold offsets, and measurement status.

        Returns:
            List[DocsPnmCmDsOfdmMerMarEntry]: A list of populated MER margin entries for each OFDM channel.
        """
        entries: list[DocsPnmCmDsOfdmMerMarEntry] = []

        try:
            indices = await self.getDocsIf31CmDsOfdmChannelIdIndex()

            if not indices:
                self.logger.warning("No DocsIf31CmDsOfdmChanChannelIdIndex indices found.")
                return entries

            entries = await DocsPnmCmDsOfdmMerMarEntry.get(snmp=self._snmp, indices=indices)
            self.logger.debug(f'Number of DocsPnmCmDsOfdmMerMarEntry Found: {len(entries)}')

        except Exception as e:
            self.logger.exception("Failed to retrieve DocsPnmCmDsOfdmMerMarEntry entries, error: %s", e)

        return entries

    async def getDocsPnmCmDsHistEntry(self) -> list[DocsPnmCmDsHistEntry]:
        """
        Retrieves DOCSIS 3.1 Downstream Histogram entries.

        This method queries the SNMP agent to collect histogram data for each downstream OFDM channel
        using the ifIndex values retrieved from the modem. Each returned entry corresponds to a channel's
        histogram configuration and status.

        """
        entries: list[DocsPnmCmDsHistEntry] = []

        try:
            indices = await self.getIfTypeIndex(DocsisIfType.docsCableMaclayer)

            if not indices:
                self.logger.error("No docsCableMaclayer indices found.")
                return entries

            self.logger.debug(f'Found docsCableDownstream Indices: {indices}')

            entries = await DocsPnmCmDsHistEntry.get(snmp=self._snmp, indices=indices)
            self.logger.debug(f'Number of DocsPnmCmDsHistEntry Found: {len(entries)}')

        except Exception as e:
            self.logger.exception("Failed to retrieve DocsPnmCmDsHistEntry entries, error: %s", e)

        return entries

    async def getDocsPnmCmDsOfdmFecEntry(self) -> list[DocsPnmCmDsOfdmFecEntry]:
        """
        Retrieve FEC Summary entries for all downstream OFDM channels.

        Returns
        -------
        List[DocsPnmCmDsOfdmFecEntry].
        """
        self.logger.debug('Entering into -> getDocsPnmCmDsOfdmFecEntry()')
        entries: list[DocsPnmCmDsOfdmFecEntry] = []
        try:
            indices = await self.getDocsIf31CmDsOfdmChannelIdIndex()

            if not indices:
                self.logger.warning("No DocsIf31CmDsOfdmChanChannelIdIndex indices found.")
                return entries

            unique_indices = sorted(set(int(i) for i in indices))
            self.logger.debug(f"`FEC Summary fetch: indices={unique_indices}")

            entries = await DocsPnmCmDsOfdmFecEntry.get(snmp=self._snmp, indices=unique_indices)

            self.logger.debug("FEC Summary fetch complete: %d entries", len(entries))
            return entries

        except Exception as e:
            self.logger.exception("Failed to retrieve DocsPnmCmDsOfdmFecEntry entries: %s", e)
            return entries

    async def getDocsPnmCmDsOfdmModProfEntry(self) -> list[DocsPnmCmDsOfdmModProfEntry]:
        """
        Retrieve Modulation Profile entries for all downstream OFDM channels.

        Returns
        -------
        List[DocsPnmCmDsOfdmModProfEntry].
        """
        self.logger.debug('Entering into -> getDocsPnmCmDsOfdmModProfEntry()')
        entries: list[DocsPnmCmDsOfdmModProfEntry] = []
        try:
            indices = await self.getDocsIf31CmDsOfdmChannelIdIndex()

            if not indices:
                self.logger.warning("No DocsIf31CmDsOfdmChanChannelIdIndex indices found.")
                return entries

            # De-dupe and sort for predictable iteration (optional but nice for logs)
            unique_indices = sorted(set(int(i) for i in indices))
            self.logger.debug(f"ModProf fetch: indices={unique_indices}")

            entries = await DocsPnmCmDsOfdmModProfEntry.get(snmp=self._snmp, indices=unique_indices)

            # Helpful summary log—count only; detailed per-field logs happen in the entry fetcher
            self.logger.debug("ModProf fetch complete: %d entries", len(entries))
            return entries

        except Exception as e:
            # Keep the exception in logs for debugging (stacktrace included)
            self.logger.exception("Failed to retrieve DocsPnmCmDsOfdmModProfEntry entries: %s", e)
            return entries

    async def getDocsIf3CmSpectrumAnalysisEntry(self, indices: list[int] = DEFAULT_SPECTRUM_ANALYZER_INDICES) -> list[DocsIf3CmSpectrumAnalysisEntry]:
        """
        Retrieves DOCSIS 3.0 Spectrum Analysis entries
        Args:
            indices: List[int] = DEFAULT_SPECTRUM_ANALYZER_INDICES
                This method queries the SNMP agent to collect spectrum analysis data for each specified index.
                Each returned entry corresponds to a spectrum analyzer's configuration and status.
                Current DOCSIS 3.0 MIB only defines index 0 for downstream spectrum analysis.
                Leaving for possible future expansion.

        """
        entries: list[DocsIf3CmSpectrumAnalysisEntry] = []

        try:
            if not indices:
                self.logger.error("No docsCableMaclayer indices found.")
                return entries

            self.logger.debug(f'Found docsCableDownstream Indices: {indices}')

            entries = await DocsIf3CmSpectrumAnalysisEntry.get(snmp=self._snmp, indices=indices)
            self.logger.debug(f'Number of DocsIf3CmSpectrumAnalysisEntry Found: {len(entries)}')

        except Exception as e:
            self.logger.exception(f"Failed to retrieve DocsIf3CmSpectrumAnalysisEntry entries: {e}")

        return entries

    async def _getDocsIf3CmSpectrumAnalysisMeasEntryIndices(self) -> list[int]:
        oid = COMPILED_OIDS.get("docsIf3CmSpectrumAnalysisMeasFrequency")
        if not oid:
            self.logger.error("OID 'docsIf3CmSpectrumAnalysisMeasFrequency' is not defined in COMPILED_OIDS.")
            return []
        try:
            results = await self._snmp.walk(oid)
        except Exception as e:
            self.logger.warning(f"SpectrumAnalysisMeas frequency walk failed for {oid}: {e}")
            return []
        if not results:
            self.logger.warning("No docsIf3CmSpectrumAnalysisMeasEntry indices found.")
            return []
        idx_freqs = Snmp_v2c.snmp_get_result_last_idx_value(results)
        return [int(idx) for idx, _ in idx_freqs]

    async def getDocsIf3CmSpectrumAnalysisMeasEntry(
        self,
        indices: list[int] | None = None,
    ) -> list[DocsIf3CmSpectrumAnalysisMeasEntry]:
        entries: list[DocsIf3CmSpectrumAnalysisMeasEntry] = []

        try:
            if not indices:
                indices = await self._getDocsIf3CmSpectrumAnalysisMeasEntryIndices()

            if not indices:
                self.logger.error("No docsIf3CmSpectrumAnalysisMeasEntry indices found.")
                return entries

            self.logger.debug(f'Found docsIf3CmSpectrumAnalysisMeasEntry Indices: {indices}')

            entries = await DocsIf3CmSpectrumAnalysisMeasEntry.get(snmp=self._snmp, indices=indices)
            self.logger.debug(f'Number of DocsIf3CmSpectrumAnalysisMeasEntry Found: {len(entries)}')

        except Exception as e:
            self.logger.exception(f"Failed to retrieve DocsIf3CmSpectrumAnalysisMeasEntry entries: {e}")

        return entries

    async def getOfdmProfiles(self) -> list[tuple[int, OfdmProfiles]]:
        """
        Retrieve provisioned OFDM profile bits for each downstream OFDM channel.

        Returns:
            List[Tuple[int, OfdmProfiles]]: A list of tuples where each tuple contains:
                - SNMP index (int)
                - Corresponding OfdmProfiles bitmask (OfdmProfiles enum)
        """
        BITS_16:int = 16

        entries: list[tuple[int, OfdmProfiles]] = []

        try:
            indices = await self.getDocsIf31CmDsOfdmChannelIdIndex()

            if not indices:
                self.logger.warning("No DocsIf31CmDsOfdmChanChannelIdIndex indices found.")
                return entries

            for index in indices:
                results = await self._snmp.get(f'docsIf31RxChStatusOfdmProfiles.{index}')
                raw = Snmp_v2c.get_result_value(results)

                if isinstance(raw, bytes):
                    value = int.from_bytes(raw, byteorder='little')
                else:
                    value = int(raw, BITS_16)

                profiles = OfdmProfiles(value)
                entries.append((index, profiles))

        except Exception as e:
            self.logger.exception("Failed to retrieve OFDM profiles, error: %s", e)

        return entries

    ####################
    # DOCSIS 4.0 - FDD #
    ####################

    async def getDocsFddCmFddSystemCfgState(self, index: int = 0) -> DocsFddCmFddSystemCfgState | None | None:
        """
        Retrieves the FDD band edge configuration state for a specific cable modem index.

        This queries the DOCSIS 4.0 MIB values for:
        - Downstream Lower Band Edge
        - Downstream Upper Band Edge
        - Upstream Upper Band Edge

        Args:
            index (int): SNMP index of the CM to query (default: 0).

        Returns:
            DocsFddCmFddSystemCfgState | None: Populated object if successful, or None on failure.
        """
        results = await self._snmp.walk('docsFddCmFddSystemCfgState')
        if not results:
            self.logger.warning(f"No results found during SNMP walk for OID {'docsFddCmFddSystemCfgState'}")
            return None

        obj = DocsFddCmFddSystemCfgState(index, self._snmp)
        success = await obj.start()

        if not success:
            self.logger.warning(f"SNMP population failed for DocsFddCmFddSystemCfgState (index={index})")
            return None

        return obj

    async def getDocsFddCmFddBandEdgeCapabilities(self, create_and_start: bool = True) -> list[DocsFddCmFddBandEdgeCapabilities] | None:
        """
        Retrieve a list of FDD band edge capability entries for a DOCSIS 4.0 modem.

        Walks the SNMP table to discover indices, and returns capability objects
        optionally populated with SNMP data.

        Args:
            create_and_start (bool): Whether to call `.start()` on each entry.

        Returns:
            A list of DocsFddCmFddBandEdgeCapabilities objects, or None if none found.
        """
        results = await self._snmp.walk('docsFddDiplexerUsUpperBandEdgeCapability')
        if not results:
            self.logger.warning("No results found during SNMP walk for OID 'docsFddDiplexerUsUpperBandEdgeCapability'")
            return None

        entries = []
        for idx in Snmp_v2c.extract_last_oid_index(results):
            obj = DocsFddCmFddBandEdgeCapabilities(idx, self._snmp)

            if create_and_start and not await obj.start():
                self.logger.warning(f"SNMP population failed for DocsFddCmFddBandEdgeCapabilities (index={idx})")
                continue

            entries.append(obj)

        return entries or None

    ######################
    # SNMP Set Operation #
    ######################

    async def setDocsDevResetNow(self) -> bool:
        """
        Triggers an immediate device reset using the SNMP `docsDevResetNow` object.

        Returns:
        - bool: True if the SNMP set operation is successful, False otherwise.
        """
        try:
            oid = f'{"docsDevResetNow"}.0'
            self.logger.debug(f'Sending device reset via SNMP SET: {oid} = 1')

            response = await self._snmp.set(oid, Snmp_v2c.TRUE, Integer32)

            if response is None:
                self.logger.error('Device reset command returned None')
                return False

            result = Snmp_v2c.snmp_set_result_value(response)

            self.logger.debug(f'Device reset command issued. SNMP response: {result}')
            return True

        except Exception as e:
            self.logger.exception(f'Failed to send device reset command: {e}')
            return False

    async def setDocsPnmBulk(self, tftp_server: str, tftp_path: str = "") -> bool:
        """
        Set Docs PNM Bulk SNMP parameters.

        Args:
            tftp_server (str): TFTP server IP address.
            tftp_path (str, optional): TFTP server path. Defaults to empty string.

        Returns:
            bool: True if all SNMP set operations succeed, False if any fail.
        """
        try:
            ip_type = Snmp_v2c.get_inet_address_type(tftp_server).value
            set_response = await self._snmp.set(f'{"docsPnmBulkDestIpAddrType"}.0', ip_type, Integer32)
            self.logger.debug(f'docsPnmBulkDestIpAddrType set: {set_response}')

            set_response = await self._snmp.set(f'{"docsPnmBulkUploadControl"}.0',
                                          DocsPnmBulkUploadControl.AUTO_UPLOAD.value, Integer32)
            self.logger.debug(f'docsPnmBulkUploadControl set: {set_response}')

            ip_binary = InetGenerate.inet_to_binary(tftp_server)
            if ip_binary is None:
                self.logger.error(f"Failed to convert IP address to binary: {tftp_server}")
                return False
            set_response = await self._snmp.set('docsPnmBulkDestIpAddr.0', ip_binary, OctetString)
            self.logger.debug(f'docsPnmBulkDestIpAddr set: {set_response}')

            tftp_path = tftp_path or ""
            set_response = await self._snmp.set(f'{"docsPnmBulkDestPath"}.0', tftp_path, OctetString)
            self.logger.debug(f'docsPnmBulkDestPath set: {set_response}')

            return True

        except Exception as e:
            self.logger.error(f"Failed to set DocsPnmBulk parameters: {e}")
            return False

    async def setDocsIf3CmSpectrumAnalysisCtrlCmd(self,
                        spec_ana_cmd: DocsIf3CmSpectrumAnalysisCtrlCmd,
                        spectrum_retrieval_type: SpectrumRetrievalType = SpectrumRetrievalType.FILE,
                        set_and_go: bool = True) -> bool:
        """
        Sets all DocsIf3CmSpectrumAnalysisCtrlCmd parameters via SNMP using index 0.

        Parameters:
        - spec_ana_cmd (DocsIf3CmSpectrumAnalysisCtrlCmd): The control command object to apply.
        - spectrum_retrieval_type (SpectrumRetrieval): Determines the method of spectrum retrieval.
            - SpectrumRetrieval.FILE: File-based retrieval, in which case `docsIf3CmSpectrumAnalysisCtrlCmdFileEnable` is set to ENABLE.
            - SpectrumRetrieval.SNMP: SNMP-based retrieval, in which case `docsIf3CmSpectrumAnalysisCtrlCmdEnable` is set to ENABLE.
        - set_and_go (bool): Whether to include the 'Enable' field in the set request.
            - If `data_retrival_opt = SpectrumRetrieval.FILE`, then `docsIf3CmSpectrumAnalysisCtrlCmdFileEnable` is set to ENABLE and `docsIf3CmSpectrumAnalysisCtrlCmdEnable` is skipped.
            - If `data_retrival_opt = SpectrumRetrieval.SNMP`, then `docsIf3CmSpectrumAnalysisCtrlCmdEnable` is set to ENABLE.

        Returns:
        - bool: True if all parameters were set successfully and confirmed, False otherwise.

        Raises:
        - Exception: If any error occurs during the SNMP set operations.
        """

        self.logger.debug(f'SpectrumAnalyzerPara: {spec_ana_cmd.to_dict()}')

        if spec_ana_cmd.precheck_spectrum_analyzer_settings():
            self.logger.debug(f'SpectrumAnalyzerPara-PreCheck-Changed: {spec_ana_cmd.to_dict()}')

        '''
            Custom SNMP SET for Spectrum Analyzer
        '''
        async def __snmp_set(field_name:str, obj_value:str | int, snmp_type:type) -> bool:
            """ Helper function to perform SNMP set and verify the result."""
            base_oid = COMPILED_OIDS.get(field_name)
            if not base_oid:
                self.logger.warning(f'OID not found for field "{field_name}", skipping.')
                return False

            oid = f"{base_oid}.0"
            logging.debug(f'Field-OID: {field_name} -> OID: {oid} -> {obj_value} -> Type: {snmp_type}')

            set_response = await self._snmp.set(oid, obj_value, snmp_type)
            logging.debug(f'Set {field_name} [{oid}] = {obj_value}: {set_response}')

            if not set_response:
                logging.error(f'Failed to set {field_name} to ({obj_value})')
                return False

            result = Snmp_v2c.snmp_set_result_value(set_response)[0]

            if not result:
                logging.error(f'Failed to set {field_name} to ({obj_value})')
                return False

            logging.debug(f"Result({result}): {type(result)} -> Value({obj_value}): {type(obj_value)}")

            if str(result) != str(obj_value):
                logging.error(f'Failed to set {field_name}. Expected ({obj_value}), got ({result})')
                return False
            return True

        # Need to get Diplex Setting to make sure that the Spec Analyzer setting are within the band
        cscs:DocsIf31CmSystemCfgDiplexState = await self.getDocsIf31CmSystemCfgDiplexState()
        cscs.to_dict()[0]

        """ TODO: Will need to validate the Spec Analyzer Settings against the Diplex Settings
        lower_edge = int(diplex_dict["docsIf31CmSystemCfgStateDiplexerCfgDsLowerBandEdge"]) * 1_000_000
        upper_edge = diplex_dict["docsIf31CmSystemCfgStateDiplexerCfgDsUpperBandEdge"] * 1_000_000
        """
        try:
            field_type_map = {
                "docsIf3CmSpectrumAnalysisCtrlCmdInactivityTimeout": Integer32,
                "docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency": Gauge32,
                "docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency": Gauge32,
                "docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan": Gauge32,
                "docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment": Gauge32,
                "docsIf3CmSpectrumAnalysisCtrlCmdEquivalentNoiseBandwidth": Gauge32,
                "docsIf3CmSpectrumAnalysisCtrlCmdWindowFunction": Integer32,
                "docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages": Gauge32,
                "docsIf3CmSpectrumAnalysisCtrlCmdEnable": Integer32,
                "docsIf3CmSpectrumAnalysisCtrlCmdFileName": OctetString,
                "docsIf3CmSpectrumAnalysisCtrlCmdFileEnable": Integer32,
            }

            '''
                Note: MUST BE THE LAST 2 AND IN THIS ORDER:
                    docsIf3CmSpectrumAnalysisCtrlCmdEnable      <- Triggers SNMP AMPLITUDE DATA RETURN
                    docsIf3CmSpectrumAnalysisCtrlCmdFileEnable  <- Trigger PNM FILE RETURN, OVERRIDES SNMP AMPLITUDE DATA RETURN
            '''

            # Iterating through the fields and setting their values via SNMP
            for field_name, snmp_type in field_type_map.items():
                obj_value = getattr(spec_ana_cmd, field_name)

                self.logger.debug(f'Field-Name: {field_name} -> SNMP-Type: {snmp_type}')

                ##############################################################
                # OVERRIDE SECTION TO MAKE SURE WE FOLLOW THE SPEC-ANA RULES #
                ##############################################################

                if field_name == "docsIf3CmSpectrumAnalysisCtrlCmdFileName":
                    file_name = getattr(spec_ana_cmd, field_name)

                    if not file_name:
                        setattr(spec_ana_cmd, field_name,f'snmp-amplitude-get-flag-{Generate.time_stamp()}')

                    await __snmp_set(field_name, getattr(spec_ana_cmd, field_name) , snmp_type)

                    continue

                #######################################################################################
                #                                                                                     #
                #                   START SPECTRUM ANALYZER MEASURING PROCESS                         #
                #                                                                                     #
                # This OID Triggers the start of the Spectrum Analysis for SNMP-AMPLITUDE-DATA RETURN #
                #######################################################################################
                elif field_name == "docsIf3CmSpectrumAnalysisCtrlCmdEnable":

                    obj_value = Snmp_v2c.TRUE
                    self.logger.debug(f'Field-Name: {field_name} -> SNMP-Type: {snmp_type}')

                    # Need to toggle ? -> FALSE -> TRUE
                    if not await __snmp_set(field_name, Snmp_v2c.FALSE, snmp_type):
                        self.logger.error(f'Fail to set {field_name} to {Snmp_v2c.FALSE}')
                        return False

                    time.sleep(1)

                    if not await __snmp_set(field_name, Snmp_v2c.TRUE, snmp_type):
                        self.logger.error(f'Fail to set {field_name} to {Snmp_v2c.TRUE}')
                        return False

                    continue

                ######################################################################################
                #
                #                   CHECK SPECTRUM ANALYZER MEASURING PROCESS
                #                           FOR PNM FILE RETRIVAL
                #
                # This OID Triggers the start of the Spectrum Analysis for PNM-FILE RETURN
                # Override SNMP-AMPLITUDE-DATA RETURN
                ######################################################################################
                elif field_name == "docsIf3CmSpectrumAnalysisCtrlCmdFileEnable":
                    obj_value = Snmp_v2c.TRUE if spectrum_retrieval_type == SpectrumRetrievalType.FILE else Snmp_v2c.FALSE
                    self.logger.debug(f'Setting File Retrival, Set-And-Go({set_and_go}) -> Value: {obj_value}')

                ###############################################
                # Set Field setting not change by above rules #
                ###############################################
                if isinstance(obj_value, Enum):
                    obj_value = str(obj_value.value)
                    self.logger.debug(f'ENUM Found: Set Value Type: {obj_value} -> {type(obj_value)}')
                else:
                    obj_value = str(obj_value)

                self.logger.debug(f'{field_name} -> Set Value Type: {obj_value} -> {type(obj_value)}')

                if not await __snmp_set(field_name, obj_value, snmp_type):
                    self.logger.error(f'Fail to set {field_name} to {obj_value}')
                    return False

            return True

        except Exception:
            logging.exception("Exception while setting DocsIf3CmSpectrumAnalysisCtrlCmd")
            return False

    async def setDocsPnmCmUsPreEq(self, ofdma_idx: int, filename:str, last_pre_eq_filename:str, set_and_go:bool=True) -> bool:
        """
        Set the upstream Pre-EQ file name and enable Pre-EQ capture for a specified OFDMA channel index.

        Args:
            ofdma_idx (int): Index in the DocsPnmCmUsPreEq SNMP table.
            file_name (str): Desired file name to use for Pre-EQ capture.

        Returns:
            bool: True if both SNMP set operations succeed and verify expected values; False otherwise.
        """
        try:
            oid = f'{"docsPnmCmUsPreEqFileName"}.{ofdma_idx}'
            self.logger.debug(f'Setting Pre-EQ filename: [{oid}] = "{filename}"')
            response = await self._snmp.set(oid, filename, OctetString)
            result = Snmp_v2c.snmp_set_result_value(response)

            if not result or str(result[0]) != filename:
                self.logger.error(f'Filename mismatch. Expected "{filename}", got "{result[0] if result else "None"}"')
                return False

            oid = f'{"docsPnmCmUsPreEqLastUpdateFileName"}.{ofdma_idx}'
            self.logger.debug(f'Setting Last-Pre-EQ filename: [{oid}] = "{last_pre_eq_filename}"')
            response = await self._snmp.set(oid, last_pre_eq_filename, OctetString)
            result = Snmp_v2c.snmp_set_result_value(response)

            if not result or str(result[0]) != last_pre_eq_filename:
                self.logger.error(f'Filename mismatch. Expected "{last_pre_eq_filename}", got "{result[0] if result else "None"}"')
                return False

            if set_and_go:
                time.sleep(1)
                enable_oid = f'{"docsPnmCmUsPreEqFileEnable"}.{ofdma_idx}'
                self.logger.debug(f'Enabling Pre-EQ capture [{enable_oid}] = {Snmp_v2c.TRUE}')
                response = await self._snmp.set(enable_oid, Snmp_v2c.TRUE, Integer32)
                result = Snmp_v2c.snmp_set_result_value(response)

                if not result or int(result[0]) != Snmp_v2c.TRUE:
                    self.logger.error(f'Failed to enable Pre-EQ capture. Expected 1, got "{result[0] if result else "None"}"')
                    return False

            return True

        except Exception as e:
            self.logger.exception(f'Exception during setDocsPnmCmUsPreEq for index {ofdma_idx}: {e}')
            return False

    async def setDocsPnmCmDsOfdmModProf(self, ofdm_idx: int, mod_prof_file_name: str, set_and_go:bool=True) -> bool:
        """
        Set the DocsPnmCmDsOfdmModProf parameters for a given OFDM index.

        Parameters:
        - ofdm_idx (int): The index of the OFDM channel.
        - mod_prof_file_name (str): The filename to set for the modulation profile.

        Returns:
        - bool: True if both SNMP sets were successful, False otherwise.
        """
        try:
            file_oid = f'{"docsPnmCmDsOfdmModProfFileName"}.{ofdm_idx}'
            enable_oid = f'{"docsPnmCmDsOfdmModProfFileEnable"}.{ofdm_idx}'

            file_response = await self._snmp.set(file_oid, mod_prof_file_name, OctetString)
            self.logger.debug(f'Set {file_oid} to {mod_prof_file_name}: {file_response}')

            if set_and_go:
                enable_response = await self._snmp.set(enable_oid, Snmp_v2c.TRUE, Integer32)
                self.logger.debug(f'Set {enable_oid} to 1 (enable): {enable_response}')

            return True

        except Exception as e:
            self.logger.error(f"Failed to set DocsPnmCmDsOfdmModProf for index {ofdm_idx}: {e}")
            return False

    async def setDocsPnmCmDsOfdmRxMer(self, ofdm_idx: int, rxmer_file_name: str, set_and_go:bool=True) -> bool:
        """
        Sets the RxMER file name and enables file capture for a specified OFDM channel index.

        Parameters:
        - ofdm_idx (str): The index in the DocsPnmCmDsOfdmRxMer SNMP table.
        - rxmer_file_name (str): Desired file name to assign for RxMER capture.

        Returns:
        - bool: True if both SNMP set operations succeed and return expected values, False otherwise.
        """
        try:
            oid_file_name = f'{"docsPnmCmDsOfdmRxMerFileName"}.{ofdm_idx}'
            set_response = await self._snmp.set(oid_file_name, rxmer_file_name, OctetString)
            self.logger.debug(f'Setting RxMER file name [{oid_file_name}] = "{rxmer_file_name}"')

            result = Snmp_v2c.snmp_set_result_value(set_response)
            if not result or str(result[0]) != rxmer_file_name:
                self.logger.error(f'File name mismatch. Expected "{rxmer_file_name}", got "{result[0] if result else "None"}"')
                return False

            if set_and_go:
                oid_file_enable = f'{"docsPnmCmDsOfdmRxMerFileEnable"}.{ofdm_idx}'
                set_response = await self._snmp.set(oid_file_enable, 1, Integer32)
                self.logger.debug(f'Enabling RxMER capture [{oid_file_enable}] = 1')

                result = Snmp_v2c.snmp_set_result_value(set_response)
                if not result or int(result[0]) != 1:
                    self.logger.error(f'Failed to enable RxMER capture. Expected 1, got "{result[0] if result else "None"}"')
                    return False

            return True

        except Exception as e:
            self.logger.exception(f'Exception during setDocsPnmCmDsOfdmRxMer for index {ofdm_idx}: {e}')
            return False

    async def setDocsPnmCmDsOfdmFecSum(self, ofdm_idx: int,
                                       fec_sum_file_name: str,
                                       fec_sum_type: FecSummaryType = FecSummaryType.TEN_MIN,
                                       set_and_go:bool=True) -> bool:
        """
        Sets SNMP parameters for FEC summary of an OFDM channel.

        Parameters:
        - ofdm_idx (str): The OFDM index.
        - fec_sum_file_name (str): The file name associated with FEC sum.
        - fec_sum_type (FecSummaryType): The type of FEC summary (default is 10 minutes).

        Returns:
        - bool: True if successful, False if any error occurs during SNMP operations.
        """
        try:
            oid_file_name = f'{"docsPnmCmDsOfdmFecFileName"}.{ofdm_idx}'
            self.logger.debug(f'Setting FEC file name [{oid_file_name}] = "{fec_sum_file_name}"')
            set_response = await self._snmp.set(oid_file_name, fec_sum_file_name, OctetString)
            result = Snmp_v2c.snmp_set_result_value(set_response)
            if not result or str(result[0]) != fec_sum_file_name:
                self.logger.error(f'File name mismatch. Expected "{fec_sum_file_name}", got "{result[0] if result else "None"}"')
                return False

            oid_sum_type = f'{"docsPnmCmDsOfdmFecSumType"}.{ofdm_idx}'
            self.logger.debug(f'Setting FEC sum type [{oid_sum_type}] = {fec_sum_type.name} -> {type(fec_sum_type.value)}')
            set_response = await self._snmp.set(oid_sum_type, fec_sum_type.value, Integer32)
            result = Snmp_v2c.snmp_set_result_value(set_response)
            if not result or int(result[0]) != fec_sum_type.value:
                self.logger.error(f'FEC sum type mismatch. Expected {fec_sum_type.value}, got "{result[0] if result else "None"}"')
                return False

            if set_and_go:
                oid_file_enable = f'{"docsPnmCmDsOfdmFecFileEnable"}.{ofdm_idx}'
                self.logger.debug(f'Enabling FEC file capture [{oid_file_enable}] = 1')
                set_response = await self._snmp.set(oid_file_enable, 1, Integer32)
                result = Snmp_v2c.snmp_set_result_value(set_response)
                if not result or int(result[0]) != 1:
                    self.logger.error(f'Failed to enable FEC capture. Expected 1, got "{result[0] if result else "None"}"')
                    return False

            self.logger.debug(f'Successfully configured FEC summary capture for OFDM index {ofdm_idx}')
            return True

        except Exception as e:
            self.logger.exception(f'Exception during setDocsPnmCmDsOfdmFecSum for index {ofdm_idx}: {e}')
            return False

    async def setDocsPnmCmOfdmChEstCoef(self, ofdm_idx: int, chan_est_file_name: str, set_and_go:bool=True) -> bool:
        """
        Sets SNMP parameters for OFDM channel estimation coefficients.

        Parameters:
        - ofdm_idx (str): The OFDM index.
        - chan_est_file_name (str): The file name associated with the OFDM Channel Estimation.

        Returns:
        - bool: True if the SNMP set operations were successful, False otherwise.
        """
        try:
            oid_file_name = f'{"docsPnmCmOfdmChEstCoefFileName"}.{ofdm_idx}'
            self.logger.debug(f'Setting OFDM Channel Estimation File Name [{oid_file_name}] = "{chan_est_file_name}"')
            set_response = await self._snmp.set(oid_file_name, chan_est_file_name, OctetString)

            result = Snmp_v2c.snmp_set_result_value(set_response)
            if not result or str(result[0]) != chan_est_file_name:
                self.logger.error(f'Failed to set channel estimation file name. Expected "{chan_est_file_name}", got "{result[0] if result else "None"}"')
                return False

            if set_and_go:
                oid_trigger_enable = f'{"docsPnmCmOfdmChEstCoefTrigEnable"}.{ofdm_idx}'
                self.logger.debug(f'Setting Channel Estimation Trigger Enable [{oid_trigger_enable}] = 1')
                set_response = await self._snmp.set(oid_trigger_enable, Snmp_v2c.TRUE, Integer32)

                result = Snmp_v2c.snmp_set_result_value(set_response)
                if not result or int(result[0]) != 1:
                    self.logger.error(f'Failed to enable channel estimation trigger. Expected 1, got "{result[0] if result else "None"}"')
                    return False

            self.logger.debug(f'Successfully configured OFDM channel estimation for index {ofdm_idx} with file name "{chan_est_file_name}"')

        except Exception as e:
            self.logger.exception(f'Exception occurred while setting OFDM Channel Estimation coefficients for index {ofdm_idx}: {e}')
            return False

        return True

    async def setDocsPnmCmDsConstDisp(
        self,
        ofdm_idx: int,
        const_disp_name: str,
        modulation_order_offset: int = CmDsConstellationDisplayConst.MODULATION_OFFSET.value,
        number_sample_symbol: int = CmDsConstellationDisplayConst.NUM_SAMPLE_SYMBOL.value,
        set_and_go: bool = True ) -> bool:
        """
        Configures SNMP parameters for the OFDM Downstream Constellation Display.

        Args:
            ofdm_idx (int): Index of the downstream OFDM channel.
            const_disp_name (str): Desired filename to store the constellation display data.
            modulation_offset (int, optional): Modulation order offset. Defaults to standard constant value.
            num_sample_symb (int, optional): Number of sample symbols. Defaults to standard constant value.
            set_and_go (bool, optional): If True, triggers immediate measurement start. Defaults to True.

        Returns:
            bool: True if all SNMP SET operations succeed; False otherwise.
        """
        try:
            # Set file name
            oid = f'{"docsPnmCmDsConstDispFileName"}.{ofdm_idx}'
            self.logger.debug(f'Setting FileName [{oid}] = "{const_disp_name}"')
            set_response = await self._snmp.set(oid, const_disp_name, OctetString)
            result = Snmp_v2c.snmp_set_result_value(set_response)
            if not result or str(result[0]) != const_disp_name:
                self.logger.error(f'Failed to set FileName. Expected "{const_disp_name}", got "{result[0] if result else "None"}"')
                return False

            # Set modulation order offset
            oid = f'{"docsPnmCmDsConstDispModOrderOffset"}.{ofdm_idx}'
            self.logger.debug(f'Setting ModOrderOffset [{oid}] = {modulation_order_offset}')
            set_response = await self._snmp.set(oid, modulation_order_offset, Gauge32)
            result = Snmp_v2c.snmp_set_result_value(set_response)
            if not result or int(result[0]) != modulation_order_offset:
                self.logger.error(f'Failed to set ModOrderOffset. Expected {modulation_order_offset}, got "{result[0] if result else "None"}"')
                return False

            # Set number of sample symbols
            oid = f'{"docsPnmCmDsConstDispNumSampleSymb"}.{ofdm_idx}'
            self.logger.debug(f'Setting NumSampleSymb [{oid}] = {number_sample_symbol}')
            set_response = await self._snmp.set(oid, number_sample_symbol, Gauge32)
            result = Snmp_v2c.snmp_set_result_value(set_response)
            if not result or int(result[0]) != number_sample_symbol:
                self.logger.error(f'Failed to set NumSampleSymb. Expected {number_sample_symbol}, got "{result[0] if result else "None"}"')
                return False

            if set_and_go:
                # Trigger measurement
                oid = f'{"docsPnmCmDsConstDispTrigEnable"}.{ofdm_idx}'
                self.logger.debug(f'Setting TrigEnable [{oid}] = 1')
                set_response = await self._snmp.set(oid, Snmp_v2c.TRUE, Integer32)
                result = Snmp_v2c.snmp_set_result_value(set_response)
                if not result or int(result[0]) != 1:
                    self.logger.error(f'Failed to trigger measurement. Expected 1, got "{result[0] if result else "None"}"')
                    return False

            self.logger.debug(
                f'Successfully configured Constellation Display for OFDM index {ofdm_idx} with file name "{const_disp_name}"'
            )
            return True

        except Exception as e:
            self.logger.exception(
                f'Exception occurred while setting Constellation Display for OFDM index {ofdm_idx}: {e}'
            )
            return False

    async def setDocsCmLatencyRptCfg(self, latency_rpt_file_name: str, num_of_reports: int = 1, set_and_go:bool=True) -> bool:
        """
        Configures the CM upstream latency reporting feature. This enables
        the creation of latency report files containing per-Service Flow
        latency measurements over a defined period of time.

        Parameters:
        - latency_rpt_file_name (str): The filename to store the latency report.
        - num_of_reports (int): Number of report files to generate.

        Returns:
        - bool: True if configuration is successful, False otherwise.
        """

        mac_idx = self.getIfTypeIndex(DocsisIfType.docsCableMaclayer)[0]

        try:
            oid_file_name = f'{"docsCmLatencyRptCfgFileName"}.{mac_idx}'
            self.logger.debug(f'Setting US Latency Report file name [{oid_file_name}] = "{latency_rpt_file_name}"')
            set_response = await self._snmp.set(oid_file_name, latency_rpt_file_name, OctetString)
            result = Snmp_v2c.snmp_set_result_value(set_response)

            if not result or str(result[0]) != latency_rpt_file_name:
                self.logger.error(f'File name mismatch. Expected "{latency_rpt_file_name}", got "{result[0] if result else "None"}"')
                return False

            if set_and_go:
                oid_num_reports = f'{"docsCmLatencyRptCfgNumFiles"}.{mac_idx}'
                self.logger.debug(f'Setting number of latency reports [{oid_num_reports}] = {num_of_reports}')
                set_response = await self._snmp.set(oid_num_reports, num_of_reports, Gauge32)
                result = Snmp_v2c.snmp_set_result_value(set_response)

                if not result or int(result[0]) != num_of_reports:
                    self.logger.error(f'Failed to enable latency report capture. Expected {num_of_reports}, got "{result[0] if result else "None"}"')
                    return False

            return True

        except Exception as e:
            self.logger.exception(f'Exception during setDocsCmLatencyRptCfg: {e}')
            return False

    async def setDocsPnmCmDsHist(self, ds_histogram_file_name: str, set_and_go:bool=True, timeout:int=10) -> bool:
        """
        Configure and enable downstream histogram capture for the CM MAC layer interface.

        This method performs the following steps:
        1. Retrieves the index for the `docsCableMaclayer` interface.
        2. Sets the histogram file name via Snmp_v2c.
        3. Enables histogram data capture via Snmp_v2c.

        Args:
            ds_histogram_file_name (str): The name of the file where the downstream histogram will be saved.

        Returns:
            bool: True if the file name was set and capture was successfully enabled, False otherwise.

        Logs:
            - debug: Index being used.
            - Debug: SNMP set operations for file name and capture enable.
            - Error: Mismatched response or SNMP failure.
            - Exception: Any exception that occurs during the SNMP operations.
        """
        idx_list = await self.getIfTypeIndex(DocsisIfType.docsCableMaclayer)

        if not idx_list:
            self.logger.error("No index found for docsCableMaclayer interface type.")
            return False

        if len(idx_list) > 1:
            self.logger.error(f"Expected a single index for docsCableMaclayer, but found multiple: {idx_list}")
            return False

        idx = idx_list[0]

        self.logger.debug(f'setDocsPnmCmDsHist -> idx: {idx}')

        try:
            # TODO: Need to make this dynamic
            set_response = await self._snmp.set(f'{"docsPnmCmDsHistTimeOut"}.{idx}', timeout, Gauge32)
            self.logger.debug(f'Setting Histogram Timeout: {timeout}')

            oid_file_name = f'{"docsPnmCmDsHistFileName"}.{idx}'
            set_response = await self._snmp.set( oid_file_name, ds_histogram_file_name, OctetString)
            self.logger.debug(f'Setting Histogram file name [{oid_file_name}] = "{ds_histogram_file_name}"')

            result = Snmp_v2c.snmp_set_result_value(set_response)
            if not result or str(result[0]) != ds_histogram_file_name:
                self.logger.error(f'File name mismatch. Expected "{ds_histogram_file_name}", got "{result[0] if result else "None"}"')
                return False

            if set_and_go:
                oid_file_enable = f'{"docsPnmCmDsHistEnable"}.{idx}'
                set_response = await self._snmp.set(oid_file_enable, Snmp_v2c.TRUE, Integer32)
                self.logger.debug(f'Enabling Histogram capture [{oid_file_enable}] = 1')

                result = Snmp_v2c.snmp_set_result_value(set_response)
                if not result or int(result[0]) != 1:
                    self.logger.error(f'Failed to enable Histogram capture. Expected 1, got "{result[0] if result else "None"}"')
                    return False

        except Exception as e:
            self.logger.exception(f'Exception during setDocsPnmCmDsHist for index {idx}: {e}')
            return False

        return True

    async def setDocsPnmCmDsOfdmSymTrig(self, ofdm_idx: int, symbol_trig_file_name: str) -> bool:
        """
        Sets SNMP parameters for OFDM Downstream Symbol Capture.

        Parameters:
        - ofdm_idx (str): The OFDM index.
        - symbol_trig_file_name (str): The file name associated with the OFDM Downstream Symbol Capture

        Returns:
        - bool: True if the SNMP set operations were successful, False otherwise.
        TODO: NOT ABLE TO TEST DUE TO CMTS DOES NOT SUPPORT
        """
        try:
            oid_file_name = f'{"docsPnmCmDsOfdmSymCaptFileName"}.{ofdm_idx}'
            self.logger.debug(f'Setting OFDM Downstream Symbol Capture File Name [{oid_file_name}] = "{symbol_trig_file_name}"')
            set_response = await self._snmp.set(oid_file_name, symbol_trig_file_name, OctetString)

            result = Snmp_v2c.snmp_set_result_value(set_response)
            if not result or str(result[0]) != symbol_trig_file_name:
                self.logger.error(f'Failed to set Downstream Symbol Capture file name. Expected "{symbol_trig_file_name}", got "{result[0] if result else "None"}"')
                return False

            oid_trigger_enable = f'{"docsPnmCmDsConstDispTrigEnable"}.{ofdm_idx}'
            self.logger.debug(f'Setting OFDM Downstream Symbol Capture Trigger Enable [{oid_trigger_enable}] = 1')
            set_response = await self._snmp.set(oid_trigger_enable, 1, Integer32)

            result = Snmp_v2c.snmp_set_result_value(set_response)
            if not result or int(result[0]) != 1:
                self.logger.error(f'Failed to enable OFDM Downstream Symbol Capture trigger. Expected 1, got "{result[0] if result else "None"}"')
                return False

            self.logger.debug(f'Successfully configured OFDM Downstream Symbol Capturey for index {ofdm_idx} with file name "{symbol_trig_file_name}"')
            return True

        except Exception as e:
            self.logger.exception(f'Exception occurred while setting OFDM Downstream Symbol Capture for index {ofdm_idx}: {e}')
            return False

    async def getDocsIf3CmStatusUsEqData(
        self,
        channel_widths: dict[int, BandwidthHz] | None = None,
    ) -> DocsEqualizerData:
        """
        Retrieve and parse DOCSIS 3.0/3.1 upstream equalizer data via Snmp_v2c.

        This method performs an SNMP walk on the OID corresponding to
        `docsIf3CmStatusUsEqData`, which contains the pre-equalization
        coefficient data for upstream channels.

        It parses the SNMP response into a structured `DocsEqualizerData` object.

        Returns:
            DocsEqualizerData: Parsed equalizer data including real/imaginary tap coefficients
            for each upstream channel index.
            Returns None if SNMP walk fails, no data is returned, or parsing fails.
        """
        oid = 'docsIf3CmStatusUsEqData'
        try:
            result = await self._snmp.walk(oid)

        except Exception as e:
            self.logger.error(f"SNMP walk failed for {oid}: {e}")
            return DocsEqualizerData()

        if not result:
            self.logger.warning(f"No data returned from SNMP walk for {oid}.")
            return DocsEqualizerData()

        ded = DocsEqualizerData()

        try:
            for varbind in result:
                us_idx = Snmp_v2c.extract_last_oid_index([varbind])[0]
                eq_bytes = Snmp_v2c.snmp_get_result_bytes([varbind])[0]
                if not eq_bytes:
                    continue
                self.logger.debug(f'idx: {us_idx} -> eq-data bytes: ({len(eq_bytes)})')
                channel_width_hz = channel_widths.get(us_idx) if channel_widths else None
                ded.add_from_bytes(us_idx, eq_bytes, channel_width_hz=channel_width_hz)

        except ValueError as e:
            self.logger.error(f"Failed to parse equalizer data. Error: {e}")
            return None

        if not ded.coefficients_found():
            self.logger.warning(
                "No upstream pre-equalization coefficients found. "
                "Ensure Pre-Equalization is enabled on the upstream interface(s).")

        return ded

# FILE: tests/test_docs_if3_cm_spectrum_analysis_meas_entry.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import pytest

from pypnm.docsis.data_type.DocsIf3CmSpectrumAnalysisMeasEntry import (
    DocsIf3CmSpectrumAnalysisMeasEntry,
)
from pypnm.snmp.snmp_v2c import Snmp_v2c


class _FakeSnmp:
    def __init__(self, idx: int, table: dict[str, object]) -> None:
        self._idx = idx
        self._table = table

    async def get(self, oid: str) -> object:
        sym, _, sfx = oid.rpartition(".")
        assert int(sfx) == self._idx
        return self._table[sym]


@pytest.mark.asyncio
async def test_from_snmp_scales_total_segment_power(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Snmp_v2c, "get_result_value", staticmethod(lambda x: x))
    monkeypatch.setattr(Snmp_v2c, "snmp_get_result_bytes", staticmethod(lambda x: x))

    idx = 3
    fake = _FakeSnmp(idx, {
        "docsIf3CmSpectrumAnalysisMeasFrequency": ["1000"],
        "docsIf3CmSpectrumAnalysisMeasAmplitudeData": [b"\x01\x02"],
        "docsIf3CmSpectrumAnalysisMeasTotalSegmentPower": ["35"],
    })

    entry = await DocsIf3CmSpectrumAnalysisMeasEntry.from_snmp(idx, fake)  # type: ignore[arg-type]

    assert entry.index == idx
    assert entry.entry.docsIf3CmSpectrumAnalysisMeasFrequency == 1000
    assert entry.entry.docsIf3CmSpectrumAnalysisMeasAmplitudeData == b"\x01\x02"
    assert entry.entry.docsIf3CmSpectrumAnalysisMeasTotalSegmentPower == pytest.approx(3.5, abs=1e-12)


@pytest.mark.asyncio
async def test_from_snmp_missing_fields_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Snmp_v2c, "get_result_value", staticmethod(lambda x: x))
    monkeypatch.setattr(Snmp_v2c, "snmp_get_result_bytes", staticmethod(lambda x: x))

    idx = 1
    fake = _FakeSnmp(idx, {
        "docsIf3CmSpectrumAnalysisMeasFrequency": ["1000"],
        "docsIf3CmSpectrumAnalysisMeasAmplitudeData": [b"\x01"],
        # Missing total segment power
    })

    with pytest.raises(ValueError) as exc:
        await DocsIf3CmSpectrumAnalysisMeasEntry.from_snmp(idx, fake)  # type: ignore[arg-type]

    assert "total_segment_power" in str(exc.value)
