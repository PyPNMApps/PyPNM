## Agent Review Bundle Summary
- Goal: Update community type hints to SnmpCommunity and fix default handling
- Changes: Swap community annotations, add SnmpCommunity casts, and refresh SPDX years
- Files: src/pypnm/api/routes/common/classes/common_endpoint_classes/schema/base_snmp.py, src/pypnm/api/routes/common/extended/common_measure_service.py, src/pypnm/api/routes/docs/pnm/ds/ofdm/mer_margin/router.py, src/pypnm/api/routes/docs/pnm/interface/router.py, src/pypnm/api/routes/docs/pnm/interface/service.py, src/pypnm/docsis/cable_modem.py, src/pypnm/docsis/cm_snmp_operation.py, src/pypnm/examples/common/cm_pnm_helpers.py, src/pypnm/examples/common/common_cli.py, src/pypnm/examples/fast_api/api-docs-dev-eventlog.py, src/pypnm/examples/fast_api/api-docs-if30-ds-scqam-chan-codewordErrorRate.py, src/pypnm/examples/fast_api/api-docs-if30-ds-scqam-chan-stats.py, src/pypnm/examples/fast_api/api-docs-if30-us-atdma-chan-preEqualization.py, src/pypnm/examples/fast_api/api-docs-if30-us-atdma-chan-stats.py, src/pypnm/examples/fast_api/api-docs-if31-docsis-baseCapability.py, src/pypnm/examples/fast_api/api-docs-if31-ds-ofdm-chan-stats.py, src/pypnm/examples/fast_api/api-docs-if31-ds-ofdm-profile-stats.py, src/pypnm/examples/fast_api/api-docs-if31-system-diplexer.py, src/pypnm/examples/fast_api/api-docs-if31-us-ofdma-channel-stats.py, src/pypnm/examples/fast_api/api-docs-pnm-ds-histogram-getCapture.py, src/pypnm/examples/fast_api/api-docs-pnm-ds-ofdm-channelEstCoeff-getCapture.py, src/pypnm/examples/fast_api/api-docs-pnm-ds-ofdm-constellationDisplay-getCapture.py, src/pypnm/examples/fast_api/api-docs-pnm-ds-ofdm-fecSummary-getCapture.py, src/pypnm/examples/fast_api/api-docs-pnm-ds-ofdm-modulationProfile-getCapture.py, src/pypnm/examples/fast_api/api-docs-pnm-ds-ofdm-rxMer-getCapture.py, src/pypnm/examples/fast_api/api-docs-pnm-interface-stats.py, src/pypnm/examples/fast_api/api-system-sysDescr.py, src/pypnm/examples/fast_api/api-system-upTime.py, src/pypnm/examples/python/py-pnm-ds-ofdm-chan-estimate.py, src/pypnm/examples/python/py-pnm-ds-ofdm-rxmer.py, src/pypnm/snmp/snmp_v2c.py
- Tests: python3 -m compileall src; ruff check src; ruff format --check . (fails pre-existing formatting); pytest -q
- Notes: Ruff format check fails due to pre-existing repo formatting drift

# FILE: src/pypnm/snmp/snmp_v2c.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
import re
from collections.abc import AsyncIterable
from datetime import datetime, timedelta, timezone
from typing import TypeVar

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    bulk_cmd,
    get_cmd,
    set_cmd,
    walk_cmd,
)
from pysnmp.proto.rfc1902 import Integer32, OctetString

from pypnm.config.pnm_config_manager import SystemConfigSettings
from pypnm.lib.constants import T
from pypnm.lib.inet import Inet
from pypnm.lib.inet_utils import InetGenerate
from pypnm.lib.types import (
    InetAddressStr,
    InterfaceIndex,
    SnmpCommunity,
    SnmpIndex,
    SnmpReadCommunity,
    SnmpWriteCommunity,
)
from pypnm.snmp.compiled_oids import COMPILED_OIDS
from pypnm.snmp.modules import InetAddressType


class Snmp_v2c:
    """
    SNMPv2c Client for asynchronous GET, SET, and WALK operations.

    Attributes:
        host (str): Hostname or IP address of the SNMP agent.
        port (int): Port number used for SNMP (default is 161).
        read_community (str): Community string for SNMP GET/WALK (default from config).
        write_community (str): Community string for SNMP SET (default from config).
        _snmp_engine (SnmpEngine): Instance of pysnmp SnmpEngine.

    Class Attributes:
        COMPILE_MIBS (bool): Whether to compile MIBs for OID resolution.
        SNMP_PORT (int): Default SNMP port.

    Example:
        >>> snmp = Snmp_v2c(Inet('192.168.1.1'), community='public')
        >>> await snmp.get('1.3.6.1.2.1.1.1.0')
        >>> await snmp.walk('1.3.6.1.2.1.2')
        >>> await snmp.set('1.3.6.1.2.1.1.5.0', 'NewHostName')
        >>> snmp.close()
    """

    DISABLE = 1
    ENABLE = 2

    TRUE = 1
    FALSE = 2

    SNMP_PORT = 161

    def __init__(
        self,
        host: Inet,
        community: SnmpCommunity | None = None,
        read_community: SnmpReadCommunity | None = None,
        write_community: SnmpWriteCommunity | None = None,
        port: int = SNMP_PORT,
        timeout: int = SystemConfigSettings.snmp_timeout(),
        retries: int = SystemConfigSettings.snmp_retries(),
    ) -> None:
        """
        Initializes the SNMPv2c client.

        Args:
            host (Inet): Host address of the SNMP device.
            community (SnmpCommunity | None): Legacy community string for SNMP access.
            read_community (SnmpReadCommunity | None): Read community string override.
            write_community (SnmpWriteCommunity | None): Write community string override.
            port (int): SNMP port (default 161).
        """
        self.logger     = logging.getLogger(self.__class__.__name__)
        self._host      = host.inet
        self._port      = port
        if read_community is not None:
            self._read_community = str(read_community)
        elif community is not None:
            self._read_community = str(community)
        else:
            self._read_community = str(SystemConfigSettings.snmp_read_community())

        if write_community is not None:
            self._write_community = str(write_community)
        elif community is not None:
            self._write_community = str(community)
        else:
            self._write_community = str(SystemConfigSettings.snmp_write_community())

        if self._write_community == "":
            self._write_community = self._read_community
        self._timeout   = timeout
        self._retries   = retries
        self._snmp_engine = SnmpEngine()

    async def get(
        self,
        oid: str | tuple[str, str, int],
        timeout: float | None = None,
        retries: int | None = None,
    ) -> list[ObjectType] | None:
        """
        Perform an SNMP GET operation.

        Notes
        -----
        `timeout` for UdpTransportTarget.create(...) is in **seconds**, not milliseconds.

        Args:
            oid: OID to fetch, either as a numeric string, symbolic name, or tuple.
            timeout: Request timeout in **seconds**. If None, uses self._timeout.
            retries: Number of retries. If None, uses self._retries.

        Returns:
            Optional[List[ObjectType]]: List of SNMP variable bindings or None if no result.

        Raises:
            RuntimeError: On SNMP errors (transport/protocol).
        """
        self.logger.debug(f"Input OID: {oid}, timeout: {timeout}, retries: {retries}")

        resolved_oid = Snmp_v2c.resolve_oid(oid)
        obj = ObjectType(self._to_object_identity(resolved_oid))

        timeout_s = float(timeout if timeout is not None else self._timeout)
        retries_n = int(retries if retries is not None else self._retries)

        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            self._snmp_engine,
            CommunityData(self._read_community, mpModel=1),
            await UdpTransportTarget.create((self._host, self._port),
                                            timeout=timeout_s,     # seconds
                                            retries=retries_n,     # count
                                            ),
            ContextData(),
            obj,
        )

        try:
            self._raise_on_snmp_error(errorIndication, errorStatus, errorIndex)
        except Exception as e:
            self.logger.error(f"Failed GET for OID {resolved_oid}: {e}")

        return varBinds

    async def walk(self, oid: str | tuple[str, str, int]) -> list[ObjectType] | None:
        """
        Perform an SNMP WALK operation.

        Args:
            oid (str | Tuple[str, str, int]): The starting OID for the walk.

        Returns:
            Optional[List[ObjectType]]: List of walked SNMP ObjectTypes, or None if no results.
        """
        self.logger.debug(f"Starting SNMP WALK with OID: {oid}")
        oid = Snmp_v2c.resolve_oid(oid)
        self.logger.debug(f"Converted: {oid}")

        identity = self._to_object_identity(oid)
        obj = ObjectType(identity)
        results: list[ObjectType] = []

        transport = await UdpTransportTarget.create((self._host, self._port),
                                                    timeout=self._timeout,
                                                    retries=self._retries)

        objects = walk_cmd(
            self._snmp_engine,
            CommunityData(self._read_community, mpModel=1),
            transport,
            ContextData(),
            obj
        )

        async for item in objects:

            errorIndication, errorStatus, errorIndex, varBinds = item

            try:
                self._raise_on_snmp_error(errorIndication, errorStatus, errorIndex)

            except Exception as e:
                self.logger.error(f"Failed walk : {e}")
                continue

            if not varBinds:
                continue

            for varBind in varBinds:
                oid_str = str(varBind[0])

                if not self._is_oid_in_subtree(oid_str, str(identity)):
                    self.logger.debug(f"End of OID subtree reached at {oid_str} -> {varBind} - List size {len(results)}")
                    return results if results else None

                results.append(varBind)

        self.logger.debug(f'List size {len(results)}')

        return results if results else None

    async def bulk_walk(
        self,
        oid: str | tuple[str, str, int],
        non_repeaters: int = 0,
        max_repetitions: int = 25,
        suppress_no_such_name: bool = True,
    ) -> list[ObjectType] | None:
        """
        Perform an SNMP GETBULK operation (faster alternative to WALK).

        GETBULK is an SNMPv2c/v3 operation that retrieves multiple variables
        in a single request, making it significantly faster than traditional
        WALK operations for large tables.

        Args:
            oid (str | Tuple[str, str, int]): The starting OID for the bulk walk.
            non_repeaters (int): Number of OIDs from the start that should not be repeated.
                                 Default is 0 (repeat all).
            max_repetitions (int): Maximum number of repetitions for repeating variables.
                                   Default is 25. Higher values = fewer requests but
                                   larger packets. Typical range: 10-50.

        Returns:
            Optional[List[ObjectType]]: List of SNMP ObjectTypes retrieved, or None if no results.

        Notes:
            - GETBULK is more efficient than WALK for large MIB tables
            - Not supported by SNMPv1 agents (will fall back to WALK)
            - max_repetitions should be tuned based on network conditions:
              * Small networks: 25-50
              * Large/slow networks: 10-25
              * Very fast networks: 50-100
        """
        oid = Snmp_v2c.resolve_oid(oid)

        identity = self._to_object_identity(oid)
        attempt_values: list[int] = []
        for value in [max_repetitions, 10, 5, 1]:
            if value > 0 and value not in attempt_values:
                attempt_values.append(value)

        last_error: str | None = None

        for attempt in attempt_values:
            self.logger.debug(
                f"Starting SNMP BULK WALK with OID: {oid}, non_repeaters={non_repeaters}, max_repetitions={attempt}"
            )
            obj = ObjectType(identity)
            results: list[ObjectType] = []
            retry = False
            hard_error = False

            transport = await UdpTransportTarget.create(
                (self._host, self._port),
                timeout=self._timeout,
                retries=self._retries
            )

            objects = await bulk_cmd(
                self._snmp_engine,
                CommunityData(self._read_community, mpModel=1),
                transport,
                ContextData(),
                non_repeaters,
                attempt,
                obj
            )

            def _process_item(
                item: tuple[object, object, object, list[ObjectType]],
                attempt_value: int,
                identity_value: object,
                results_list: list[ObjectType],
            ) -> tuple[bool, bool, bool, str | None]:
                errorIndication, errorStatus, errorIndex, varBinds = item

                if errorIndication or errorStatus:
                    status_text = ""
                    if errorStatus:
                        pretty = getattr(errorStatus, "prettyPrint", None)
                        status_text = pretty() if callable(pretty) else str(errorStatus)
                    error_message = status_text or str(errorIndication)

                    if status_text == "tooBig":
                        self.logger.warning(
                            f"Bulk walk tooBig with max_repetitions={attempt_value}; retrying with smaller value."
                        )
                        return True, True, False, error_message

                    if status_text == "noSuchName" and suppress_no_such_name:
                        self.logger.debug(f"Failed bulk walk: {error_message}")
                    else:
                        self.logger.error(f"Failed bulk walk: {error_message}")
                    return True, False, True, error_message

                if not varBinds:
                    return False, False, False, None

                for varBind in varBinds:
                    oid_str = str(varBind[0])

                    if not self._is_oid_in_subtree(oid_str, str(identity_value)):
                        self.logger.debug   (
                            f"End of OID subtree reached at {oid_str} -> {varBind} - List size {len(results_list)}"
                        )
                        return True, False, False, None

                    results_list.append(varBind)

                return False, False, False, None

            if isinstance(objects, tuple) and len(objects) == 4:
                done, retry, hard_error, error_message = _process_item(
                    objects,
                    attempt,
                    identity,
                    results,
                )
                if error_message:
                    last_error = error_message
                if done and results:
                    return results
            elif isinstance(objects, AsyncIterable):
                async for item in objects:
                    done, retry, hard_error, error_message = _process_item(
                        item,
                        attempt,
                        identity,
                        results,
                    )
                    if error_message:
                        last_error = error_message
                    if done:
                        if results:
                            return results
                        break
            else:
                last_error = f"unexpected bulk_cmd result type: {type(objects).__name__}"
                self.logger.error(f"Failed bulk walk: {last_error}")
                hard_error = True

            if hard_error:
                break
            if results:
                self.logger.debug(f'Bulk walk completed - List size {len(results)}')
                return results
            if retry:
                continue

            self.logger.debug(f"Bulk walk returned no data with max_repetitions={attempt}.")

        if last_error:
            if last_error == "noSuchName" and suppress_no_such_name:
                self.logger.debug(f"Bulk walk failed or empty ({last_error}); falling back to walk.")
            else:
                self.logger.warning(f"Bulk walk failed or empty ({last_error}); falling back to walk.")
        else:
            self.logger.warning("Bulk walk returned no data; falling back to walk.")

        return await self.walk(oid)

    async def set(self, oid: str, value: str | int, value_type: type)-> list[ObjectType] | None:
        """
        Perform an SNMP SET operation with explicit value type.

        Args:
            oid (str): The OID to set.
            value (Union[str, int]): The value to set.
            value_type (Type): pysnmp value type class (no default).

                Examples:
                    OctetString, Integer, Integer32, Counter32, Counter64, Gauge32, IpAddress.

        Returns:
            Dict[str, str]: Mapping of OID to the set value.

        Raises:
            ValueError: If value type instantiation fails.
            RuntimeError: On SNMP errors.
        """
        if value_type is None:
            raise ValueError("value_type must be explicitly specified")

        self.logger.debug(f'SNMP-SET-OID: {oid} -> {value_type} -> {value}')

        oid = Snmp_v2c.resolve_oid(oid)

        transport = await UdpTransportTarget.create((self._host, self._port),
                                                    timeout=self._timeout, retries=self._retries)

        try:
            snmp_value = value_type(value)
        except Exception as e:
            raise ValueError(f"Failed to create SNMP value of type {value_type}: {e}") from e

        errorIndication, errorStatus, errorIndex, varBinds = await set_cmd(
            self._snmp_engine,
            CommunityData(self._write_community, mpModel=1),
            transport,
            ContextData(),
            ObjectType(ObjectIdentity(oid), snmp_value),
        )
        try:
            self._raise_on_snmp_error(errorIndication, errorStatus, errorIndex)

        except Exception as e:
            self.logger.error(f"Error extracting SNMP value: {e}")
            return None

        return varBinds # type: ignore

    def close(self) -> None:
        """
        Close the SNMP engine dispatcher and release resources.
        """
        self._snmp_engine.close_dispatcher()

    @staticmethod
    def resolve_oid(oid: str | tuple[str, str, int]) -> str:
        """
        Resolves symbolic OIDs with optional numeric suffixes.

        Examples:
            'ifDescr'             → '1.3.6.1.2.1.2.2.1.2'
            'ifDescr.2'           → '1.3.6.1.2.1.2.2.1.2.2'
            '1.3.6.1.2.1.2.2.1.2' → '1.3.6.1.2.1.2.2.1.2' (unchanged)

        Returns:
            str: Fully resolved numeric OID string.
        """
        if isinstance(oid, tuple):
            # Optional support for Tuple format: (base, suffix1, suffix2)
            oid = '.'.join(map(str, oid))

        if Snmp_v2c.is_numeric_oid(oid):
            return oid

        # Split symbolic base from numeric suffix
        match = re.match(r"^([a-zA-Z0-9_:]+)(\..+)?$", oid)
        if not match:
            return oid  # fallback: invalid pattern

        base_sym, suffix = match.groups()
        base_num = COMPILED_OIDS.get(base_sym, base_sym)
        return f"{base_num}{suffix or ''}"

    @staticmethod
    def is_numeric_oid(oid: str) -> bool:
        """
        Returns True if the OID string is numeric.

        Accepted formats:
            - '1.3.6.1.2.1.2.2.1.2'
            - '.1.3.6.1.2.1.2.2.1.2'  (leading dot is allowed)

        Returns:
            bool: True if the OID is numeric, False otherwise.
        """
        return bool(re.fullmatch(r"\.?(\d+\.)+\d+", oid))

    @staticmethod
    def get_result_value(pysnmp_get_result: ObjectType | tuple[ObjectType, ...] | None) -> str | None:
        """
        Extract the value from a pysnmp GET result.

        Args:
            pysnmp_get_result: SNMP response from get().

        Returns:
            Optional[str]: The extracted value as string, or None if not found.
        """
        try:
            if isinstance(pysnmp_get_result, tuple):
                pysnmp_get_result = pysnmp_get_result[0]

            if isinstance(pysnmp_get_result, ObjectType):
                value = pysnmp_get_result[1]
                if isinstance(value, OctetString):
                    return value.prettyPrint()
                return str(value)

            return None

        except Exception as e:
            logging.debug(f"Error extracting SNMP value: {e}")
            return None

    @staticmethod
    def extract_last_oid_index(snmp_responses: list[ObjectType]) -> list[int]:
        """
        Extract the last index from a list of SNMP responses.

        Parameters:
        - snmp_responses: List of SNMP responses.

        Returns:
        - List of extracted indices.
        """
        last_oid_indexes = []
        for response in snmp_responses:
            oid = response[0]
            index = Snmp_v2c.get_oid_index(oid)
            logging.debug(f'extract_last_oid_index-IN-LOOP -> {response} -> {oid} -> {index}')
            last_oid_indexes.append(index)
        return last_oid_indexes

    @staticmethod
    def extract_oid_indices(snmp_responses: list[ObjectType],num_indices: int = 1) -> list[list[SnmpIndex]]:
        """
        Extract the last `num_indices` components from the OID index of each SNMP response.

        Parameters:
        - snmp_responses: List of SNMP responses.
        - num_indices: Number of trailing OID index components to extract.

        Returns:
        - List of lists, each containing the extracted index components.
        """
        extracted_indices:list[list[SnmpIndex]] = []

        for response in snmp_responses:
            oid = response[0]
            full_index = Snmp_v2c.get_oid_index(oid)

            if isinstance(full_index, int):
                indices = [full_index]
            elif isinstance(full_index, (list, tuple)):
                indices = list(full_index)
            else:
                logging.warning(f"Unexpected OID index format: {full_index}")
                continue

            selected = indices[-num_indices:] if len(indices) >= num_indices else indices
            logging.debug(f"extract_oid_indices -> {response} -> {oid} -> {selected}")
            extracted_indices.append(selected)

        return extracted_indices

    @staticmethod
    def snmp_get_result_value(snmp_responses: list[ObjectType]) -> list[str]:
        """
        Extract the result value from a list of SNMP responses.

        Args:
            snmp_responses (List[ObjectType]): List of SNMP ObjectType responses.

        Returns:
            List[str]: List of extracted result values as strings.
        """
        return [str(value[1]) for value in snmp_responses]

    @staticmethod
    def snmp_get_result_bytes(snmp_responses: list[ObjectType]) -> list[bytes]:
        """
        Extract raw byte values from a list of SNMP ObjectType responses.

        Args:
            snmp_responses (List[ObjectType]): List of SNMP ObjectType responses.

        Returns:
            List[bytes]: List of extracted result values as bytes.
        """
        result = []
        for varbind in snmp_responses:
            value = varbind[1]
            result.append(Snmp_v2c.snmp_octets_to_bytes(value))
        return result

    @staticmethod
    def snmp_octets_to_bytes(value: object) -> bytes:
        """
        Normalize SNMP OctetString-like values into raw bytes.

        Supports bytes/bytearray/memoryview, pysnmp objects exposing asOctets(),
        or objects that can be converted via bytes(). Returns b"" on failure.
        """
        if isinstance(value, (bytes, bytearray, memoryview)):
            return bytes(value)

        as_octets = getattr(value, "asOctets", None)
        if callable(as_octets):
            try:
                return bytes(as_octets())
            except Exception:
                return b""

        try:
            return bytes(value)
        except Exception:
            return b""

    @staticmethod
    def snmp_get_result_last_idx_value(snmp_responses: list[ObjectType]) -> list[tuple[InterfaceIndex, str]]:
        """
        Extract the last index and value from each SNMP response.

        Args:
            snmp_responses (List[ObjectType]): List of SNMP ObjectType responses.

        Returns:
            List[Tuple[InterfaceIndex, str]]: List of (last InterfaceIndex, value) pairs.
        """
        result = []
        for obj in snmp_responses:
            oid = obj[0]
            last_idx = InterfaceIndex(int(str(oid).split('.')[-1]))
            value = str(obj[1])
            result.append((last_idx, value))
        return result

    T = TypeVar("T", int, str)
    @staticmethod
    def snmp_get_result_last_idx_force_value_type(snmp_responses: list[ObjectType],
                                                  value_type: type[T] = str) -> list[tuple[int, T]]:
        """
        Extract the last index and value from each SNMP response,
        casting the value to the requested type (int or str).

        Args:
            snmp_responses: List of SNMP ObjectType responses.
            value_type: Type to cast the SNMP value to (int or str). Defaults to str.

        Returns:
            List of (last index, value) pairs, where `value` is of type `value_type`.
        """
        logger = logging.getLogger(__name__)
        result: list[tuple[int, T]] = []

        for obj in snmp_responses:
            # 1) extract index
            try:
                oid_str = str(obj[0])
                last_idx = int(oid_str.rsplit(".", 1)[-1])
            except Exception as e:
                logger.warning(f"Could not parse index from OID {obj[0]!r}: {e}")
                continue

            # 2) cast value
            raw_val = obj[1]
            try:
                if value_type is int:
                    cast_val: int | str = int(raw_val)
                else:
                    cast_val = str(raw_val)
            except Exception as e:
                logger.warning(f"Failed to cast SNMP value {raw_val!r} to {value_type}: {e}")
                # fallback: leave it in its raw form
                cast_val = raw_val  # type: ignore

            result.append((last_idx, cast_val))  # type: ignore

        return result

    @staticmethod
    def snmp_set_result_value(snmp_set_response: str) -> list[str]:
        """
        Extracts value(s) from an SNMP SET response string.

        This method parses the raw SNMP SET response string and extracts the
        returned value(s), if any, from the output. Useful for validating
        SNMP set operations.

        Parameters:
        - snmp_set_response (str): The raw SNMP SET response string, typically
        returned by an SNMP set operation.

        Returns:
        - List[str]: A list containing the parsed value(s) from the response.
                    If no value is found, returns an empty list.
        """
        if not snmp_set_response:
            return []

        logging.debug(f'snmp_set_result_value -> {snmp_set_response}')

        return  [str(value[1]) for value in snmp_set_response]

    @staticmethod
    def get_oid_index(oid: str) -> SnmpIndex | None:
        """
        Extract the index (last sub-identifier) from an OID string.

        Args:
            oid (str): The OID in dot-separated format (e.g., '1.3.6.1.2.1.2.2.1.3.2').

        Returns:
            Optional[int]: The last part of the OID interpreted as an integer, or None if extraction fails.
        """
        if not isinstance(oid, str):
            oid = str(oid)

        try:
            parts = oid.strip().split('.')
            index = SnmpIndex(int(parts[-1]))
            logging.debug(f"Extracted OID index: OID='{oid}', Parts={parts}, Index={index}")
            return index
        except (ValueError, IndexError) as e:
            logging.error(f"Failed to extract index from OID '{oid}': {e}")
            return None

    @staticmethod
    def get_inet_address_type(inet_address: InetAddressStr) -> InetAddressType:
        """
        Determine the InetAddressType of an IP address (IPv4 or IPv6).

        Args:
            inet_address (str): The IP address to check.

        Returns:
            InetAddressType: IPV4 (1) for IPv4 addresses, or IPV6 (2) for IPv6 addresses.

        Raises:
            ValueError: If the IP address is invalid.
        """
        binary = InetGenerate.inet_to_binary(inet_address)

        if not binary:
            raise ValueError(f"Invalid IP address: {inet_address}")

        return InetAddressType.IPV6 if len(binary) > 4 else InetAddressType.IPV4

    @staticmethod
    def parse_snmp_datetime(data: bytes) -> str:
        """
        Parses SNMP DateAndTime byte array and returns an ISO 8601 datetime string.

        Args:
            data (bytes): SNMP DateAndTime value as a byte array.

        Returns:
            str: ISO 8601 formatted datetime string (e.g., "2025-05-02T13:15:00").
        """
        if len(data) < 8:
            raise ValueError("Invalid SNMP DateAndTime data (too short)")

        # Convert the raw bytes into integer values
        year = data[0] << 8 | data[1]
        month = data[2]
        day = data[3]
        hour = data[4]
        minute = data[5]
        second = data[6]

        # Default: naive datetime (no timezone info)
        dt = datetime(year, month, day, hour, minute, second)

        if len(data) >= 11:
            # Timezone info exists
            direction = chr(data[8])
            tz_hours = data[9]
            tz_minutes = data[10]
            offset_minutes = tz_hours * 60 + tz_minutes
            if direction == '-':
                offset_minutes = -offset_minutes
            tz = timezone(timedelta(minutes=offset_minutes))
            dt = dt.replace(tzinfo=tz)

        return dt.isoformat()

    @staticmethod
    def truth_value(snmp_value: int | str) -> bool:
        """
        Converts SNMP TruthValue integer to a boolean.

        TruthValue ::= INTEGER { true(1), false(2) }

        Args:
            snmp_value (int or str): The raw SNMP integer value or string representation.

        Returns:
            bool: True if value is 1 (true), False if 2 (false).

        Raises:
            ValueError: If the value is not 1 or 2.
        """
        # Attempt to convert the snmp_value to an integer
        try:
            snmp_value = int(snmp_value)
        except ValueError:
            raise ValueError(f"Invalid input for TruthValue: {snmp_value}") from None

        if snmp_value == 1:
            return True
        elif snmp_value == 2:
            return False
        else:
            raise ValueError(f"Invalid TruthValue: {snmp_value}")

    @staticmethod
    def ticks_to_duration(ticks: int) -> str:
        """
        Converts SNMP sysUpTime ticks to a human-readable duration string.

        SNMP uptime ticks are measured in hundredths of a second.

        Args:
            ticks (int): The sysUpTime value in hundredths of a second.

        Returns:
            str: A formatted duration string like '3 days, 4:05:06.78'
        """
        if ticks < 0:
            raise ValueError("Ticks must be a non-negative integer")

        # Convert hundredths of a second to total seconds and microseconds
        total_seconds = ticks // 100
        remainder_hundredths = ticks % 100
        duration = timedelta(seconds=total_seconds, milliseconds=remainder_hundredths * 10)

        return str(duration)


    ###################
    # Private Methods #
    ###################

    def _to_object_identity(self, oid: str | tuple[str, str, int]) -> ObjectIdentity:
        """
        Internal helper to resolve an OID.

        Args:
            oid (Union[str, Tuple[str, str, int]]): OID to resolve.

        Returns:
            ObjectIdentity: pysnmp ObjectIdentity.
        """
        if isinstance(oid, tuple):
            self.logger.debug(f"Resolving OID tuple: {oid}")
            return ObjectIdentity(*oid)
        else:
            self.logger.debug(f"Resolving OID string: {oid}")
            return ObjectIdentity(oid)

    def _raise_on_snmp_error(self, errorIndication: Exception | str | None, errorStatus: object | None, errorIndex: Integer32 | int | None) -> None:
        """
        Raises RuntimeError if any SNMP error is detected.

        Args:
            errorIndication: General SNMP engine-level error (e.g., timeout, transport failure).
                            Typically an Exception instance or an error string, or None.
            errorStatus: SNMP protocol-level error (e.g., noSuchName, tooBig) or None.
            errorIndex: Index of the variable that caused the error (if applicable).

        Raises:
            RuntimeError: If an SNMP error or indication is present.
        """
        if errorIndication:
            raise RuntimeError(f"SNMP operation failed: {errorIndication}")
        if errorStatus:
            # errorStatus objects from pysnmp typically expose prettyPrint()
            pretty = getattr(errorStatus, "prettyPrint", None)
            status_text = pretty() if callable(pretty) else str(errorStatus)
            raise RuntimeError(
                f"SNMP error {status_text} at index {errorIndex}"
            )

    def _is_oid_in_subtree(self, oid_str: str, obj_str: str) -> bool:
        """
        Check if an OID is part of the requested subtree.

        Args:
            oid_str (str): The current OID string (e.g., '1.3.6.1.2.1.2.2.1.2.5').
            obj_str (str): The requested root OID string (e.g., '1.3.6.1.2.1.2.2.1.2').

        Returns:
            bool: True if oid_str is within the subtree of obj_str.
        """
        oid_parts = oid_str.strip('.').split('.')
        obj_parts = obj_str.strip('.').split('.')
        return oid_parts[:len(obj_parts)] == obj_parts
