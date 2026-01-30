## Agent Review Bundle Summary
- Goal: Refactor MessageResponse to Pydantic BaseModel while preserving response shape.
- Changes: Added MessagePayload/MessageResponse models with coercion/serialization, guarded empty payload processing, removed type-ignore in capture handling, added BaseModel coercion test.
- Files: src/pypnm/api/routes/common/extended/common_messaging_service.py; src/pypnm/api/routes/common/extended/common_process_service.py; src/pypnm/api/routes/advance/common/capture_service.py; tests/test_message_response_basemodel.py
- Tests: python3 -m compileall src; ruff check src; ruff format --check . (fails: would reformat many files); pytest -q
- Notes: Pytest skipped 3 hardware integration tests (PNM_CM_IT not set).

# FILE: src/pypnm/api/routes/common/extended/common_messaging_service.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
from enum import Enum
import logging

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator

from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.config.pnm_config_manager import SystemConfigSettings
from pypnm.lib.log_files import LogFile
from pypnm.lib.types import FileNameStr, TransactionId
from pypnm.lib.utils import Generate, TimeUnit


class MessageResponseType(Enum):
    """
    Enumeration of message types for categorizing responses.
    """
    PNM_FILE_TRANSACTION        = 1
    PNM_FILE_SESSION            = 2
    SNMP_DATA_RTN_SPEC_ANALYSIS = 10

class MessagePayload(BaseModel):
    """
    Typed payload entry for MessageResponse.
    """
    model_config = ConfigDict(extra="allow")

    status: str = Field(..., description="Status for this payload entry.")
    message_type: str | None = Field(None, description="Message type identifier.")
    message: object | None = Field(None, description="Message-specific content.")

    def as_dict(self) -> dict[str, object]:
        """
        Return this payload as a dictionary, preserving extra fields.
        """
        return self.model_dump()


class MessageResponse(BaseModel):
    """
    Represents a structured response with a status and optional data payload.
    """
    model_config = ConfigDict(arbitrary_types_allowed=True, validate_assignment=True)

    status: ServiceStatusCode = Field(..., description="Status of the message.")
    payload: list[MessagePayload] | None = Field(None, description="Associated payload entries.")

    def __init__(self, status: ServiceStatusCode, payload: list[MessagePayload] | list[dict[str, object]] | None = None) -> None:
        super().__init__(status=status, payload=payload)

    @field_validator("payload", mode="before")
    @classmethod
    def _coerce_payload(cls, value: object) -> list[MessagePayload] | None:
        if value is None:
            return None
        if isinstance(value, list):
            items: list[MessagePayload] = []
            for entry in value:
                if isinstance(entry, MessagePayload):
                    items.append(entry)
                    continue
                if isinstance(entry, dict):
                    items.append(MessagePayload(**entry))
                    continue
                items.append(MessagePayload(status="UNKNOWN", message=entry))
            return items
        raise ValueError("payload must be a list or None")

    @field_serializer("status")
    def _serialize_status(self, status: ServiceStatusCode) -> str:
        return status.name

    def get(self) -> dict[str, object]:
        """
        Serializes the message response to a dictionary.

        Returns:
            Dict[str, object]: Dictionary with 'status' and 'payload'.
        """
        return {
            "status": self.status.name,
            "payload": self._payload_as_dict_list(),
        }

    def __repr__(self) -> str:
        return json.dumps(self.get())

    def __str__(self) -> str:
        return self.__repr__()

    def get_payload_msg(payload_element: MessagePayload | dict[str, object]) -> tuple[str, str, object | None]:
        """
        Extracts 'status', 'message_type', and 'message' from a payload element.

        Args:
            payload_element (MessagePayload | Dict[str, object]): The payload element.

        Returns:
            Tuple[str, str, object | None]: A tuple containing the status, message type, and message content.
        """
        if isinstance(payload_element, MessagePayload):
            payload_dict = payload_element.as_dict()
        else:
            payload_dict = payload_element
        status = str(payload_dict.get("status", "UNKNOWN"))
        message_type = str(payload_dict.get("message_type", "UNKNOWN"))
        message = payload_dict.get("message", None)
        return status, message_type, message

    def payload_to_dict(self, key: int | str = "data") -> dict[int | str, object]:
        """
        Wraps the internal payload in a dictionary under the specified key.

        Args:
            key (int | str): The key under which the payload will be stored. Defaults to "data".

        Returns:
            Dict[int | str, object]: A dictionary containing the payload under the given key.
        """
        return {key: self._payload_as_dict_list()}

    def log_payload(self, filename_prefix: str = "") -> None:
        """
        Logs the payload content for debugging purposes.
        """
        prefix: str = ""
        if filename_prefix:
            prefix = f'{filename_prefix}_'

        LogFile.write(f'{prefix}payload_{Generate.time_stamp(TimeUnit.MILLISECONDS)}.msgrsp',
                      self.payload_to_dict(),
                      log_dir = SystemConfigSettings.message_response_dir())

    def _payload_as_dict_list(self) -> list[dict[str, object]] | None:
        if self.payload is None:
            return None
        payload_list: list[dict[str, object]] = []
        for entry in self.payload:
            if isinstance(entry, MessagePayload):
                payload_list.append(entry.as_dict())
                continue
            if isinstance(entry, dict):
                payload_list.append(dict(entry))
                continue
            payload_list.append({"status": "UNKNOWN", "message": entry})
        return payload_list


class CommonMessagingService:
    """
    Core service to manage multi-step messaging logic, aggregating statuses and data across tasks.

    This service tracks all status/data pairs and determines the final output status. Useful for
    batch operations, chained service calls, and aggregating results for client APIs.

    Attributes:
        _messages (List[Tuple[ServiceStatusCode, Dict[str, object]]]): Queue of messages.
        _last_non_success_status (ServiceStatusCode): Most recent non-success status seen.
    """

    def __init__(self) -> None:
        """
        Initializes an empty messaging service instance.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self._messages: list[tuple[ServiceStatusCode, dict[str, object]]] = []
        self._last_non_success_status = ServiceStatusCode.SUCCESS

    def build_msg(self, status: ServiceStatusCode, payload: dict[str, object] | None = None) -> None:
        """
        Queues a new message with status and optional data.

        Args:
            status (ServiceStatusCode): Message status.
            payload (Optional[Dict[str, object]]): Associated data for the message.

        Returns:
            bool: Always returns True after storing the message.
        """
        if status != ServiceStatusCode.SUCCESS:
            self._last_non_success_status = status

        self._messages.append((status, payload or {}))

    def send_msg(self) -> MessageResponse:
        """
        Constructs a final MessageResponse from the stored message queue.

        The returned status is either the last non-success seen or the status of the last message.

        Returns:
            MessageResponse: Aggregated response with status and list of all message data.
        """
        final_status = (
            self._last_non_success_status
            if self._last_non_success_status != ServiceStatusCode.SUCCESS
            else self._messages[-1][0]
            if self._messages
            else ServiceStatusCode.UNKNOWN
        )

        combined_data = [
            MessagePayload(
                status=status.name,
                **data,
            )
            for status, data in self._messages
        ]

        self._messages.clear()

        return MessageResponse(final_status, combined_data)

    def build_send_msg(self, status: ServiceStatusCode, data: dict[str, object] | None = None) -> MessageResponse:
        """
        Builds and immediately sends a single message.

        Args:
            status (ServiceStatusCode): Status of the message.
            data (Optional[Dict[str, Any]]): Optional data to include.

        Returns:
            MessageResponse: Final response containing the given status and data.
        """
        self.build_msg(status, data)
        return self.send_msg()

    def build_transaction_msg(self, transaction_id: TransactionId, filename: FileNameStr,
                              status: ServiceStatusCode = ServiceStatusCode.SUCCESS) -> None:
        """
        Adds a transaction message with an ID and filename to the message queue.

        Args:
            transaction_id (TransactionId): Unique transaction identifier.
            filename (FileNameStr): File name tied to the transaction.
            status (ServiceStatusCode): Message status. Defaults to SUCCESS.

        Returns:
            bool: True if message is successfully added.
        """
        self.build_msg(status, {
            "message_type": MessageResponseType.PNM_FILE_TRANSACTION.name,
            "message": {
                "transaction_id": transaction_id,
                "filename": filename
            }
        })

    def build_transaction_msg_extension(self, transaction_id: TransactionId,
                                        filename: FileNameStr,
                                        extension: dict[str, object],
                                        status: ServiceStatusCode = ServiceStatusCode.SUCCESS) -> None:
        """
        Adds a transaction message with an ID and filename to the message queue.

        Args:
            transaction_id (TransactionId): Unique transaction identifier.
            filename (FileNameStr): File name tied to the transaction.
            extension (dict[Any, Any]): Additional extension data for the transaction.
            status (ServiceStatusCode): Message status. Defaults to SUCCESS.

        Returns:
            bool: True if message is successfully added.
        """
        self.logger.debug(f"Transaction-Extension-Data: {extension}")
        self.build_msg(status, {
            "message_type": MessageResponseType.PNM_FILE_TRANSACTION.name,
            "message": {
                "transaction_id": transaction_id,
                "filename": filename,
                "extension": extension
            }
        })

    def build_session_msg( self,session_id: str,transaction_ids: list[TransactionId],
        status: ServiceStatusCode = ServiceStatusCode.SUCCESS) -> None:
        """
        Enqueue a PNM file transaction session message.

        Args:
            session_id: Unique identifier for this session.
            transaction_ids: List of transaction IDs to include in the message.
            status: Message status (defaults to SUCCESS).

        """
        self.build_msg(
            status,
            {
                "message_type": MessageResponseType.PNM_FILE_TRANSACTION.name,
                "message": {
                    "session_id": session_id,
                    "transaction_id_list": transaction_ids,
                },
            },
        )

    def get_first_of_type(self, msg_type: MessageResponseType) -> dict[str, object] | None:
        """
        Retrieves the first message of a specified type, if available.

        Args:
            msg_type (MessageResponseType): The type to look for.

        Returns:
            Optional[Dict[str, object]]: The first message of the given type, or None.
        """
        for _, data in self._messages:
            if data.get("message_type") == msg_type.name:
                return data
        return None

# FILE: src/pypnm/api/routes/common/extended/common_process_service.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging

from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.api.routes.common.extended.common_messaging_service import (
    CommonMessagingService,
    MessageResponse,
    MessageResponseType,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.file_processor import FileProcessor
from pypnm.lib.types import MacAddressStr, TransactionId, TransactionRecord
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest
from pypnm.pnm.parser.CmDsConstDispMeas import CmDsConstDispMeas
from pypnm.pnm.parser.CmDsHist import CmDsHist
from pypnm.pnm.parser.CmDsOfdmChanEstimateCoef import CmDsOfdmChanEstimateCoef
from pypnm.pnm.parser.CmDsOfdmFecSummary import CmDsOfdmFecSummary
from pypnm.pnm.parser.CmDsOfdmModulationProfile import CmDsOfdmModulationProfile
from pypnm.pnm.parser.CmDsOfdmRxMer import CmDsOfdmRxMer
from pypnm.pnm.parser.CmSpectrumAnalysis import CmSpectrumAnalysis
from pypnm.pnm.parser.CmSpectrumAnalysisSnmp import CmSpectrumAnalysisSnmp
from pypnm.pnm.parser.CmUsOfdmaPreEq import CmUsOfdmaPreEq


class CommonProcessService(CommonMessagingService):

    Message = dict

    def __init__(self, message_response: MessageResponse, **extra_options: object) -> None:
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.pnm_file_dir = self.config_mgr = SystemConfigSettings.pnm_dir()
        self._msg_rsp = message_response
        self.logger.debug(f'CommonProcessService: {self._msg_rsp}')

    def process(self) -> MessageResponse:
        """
        Processes each item in the MessageResponse payload.

        Expected payload format:
            {
                "payload": [
                    {
                        "status": "SUCCESS",
                        "message_type": "PNM_FILE_TRANSACTION",
                        "message": {
                            "transaction_id": "275de83146e904d7",
                            "filename": "ds_ofdm_rxmer_per_subcar_xx:xx:xx:xx:xx:xx_954000000_1746501260.bin",
                            "extension": dict, --Special Case: Optional extension data
                        }
                    },
                    ...
                ]
            }

        Returns:
            MessageResponse: A success message if all payloads are processed,
                            or an error message if a transaction record is missing.
        """
        if not self._msg_rsp.payload:
            self.logger.warning("Message response payload is empty.")
            return self.send_msg()

        for payload in self._msg_rsp.payload:
            status, message_type, message = MessageResponse.get_payload_msg(payload)

            self.logger.debug(f'CommonProcessService.MessageResponse: MSG-TYPE: {message_type}')

            if status != ServiceStatusCode.SUCCESS.name:
                self.logger.error(f"Status Error: {status}")
                continue

            if message_type == MessageResponseType.PNM_FILE_TRANSACTION.name:
                transaction_id:TransactionId = message.get('transaction_id')
                transaction_record = PnmFileTransaction().get_record(transaction_id)

                if not transaction_record:
                    self.build_msg(ServiceStatusCode.TRANSACTION_RECORD_GET_FAILED)
                    continue

                transaction_record["transaction_id"] = transaction_id
                self._process_pnm_measure_test(transaction_record)

            elif message_type == MessageResponseType.SNMP_DATA_RTN_SPEC_ANALYSIS.name:
                transaction_id = message.get('transaction_id')
                self.logger.debug(f'process() -> Found TransactionID: {transaction_id}')

                transaction_record = PnmFileTransaction().get_record(transaction_id)
                if not transaction_record:
                    self.build_msg(ServiceStatusCode.TRANSACTION_RECORD_GET_FAILED)
                    continue

                transaction_record["transaction_id"] = transaction_id
                self._process_pnm_measure_test(transaction_record)

        return self.send_msg()

    def _process_pnm_measure_test(self, transaction_record: TransactionRecord) -> ServiceStatusCode:
        """
        Processes the provided PNM transaction record based on its test type.

        Args:
            transaction_record (TransactionRecord): The transaction metadata including test type and filename.

        Returns:
            ServiceStatusCode: The result of the operation, indicating success or error type.
        """
        pnm_test_type = transaction_record[PnmFileTransaction().PNM_TEST_TYPE]

        if not pnm_test_type:
            self.logger.error("PNM test type is missing in the transaction record.")
            return ServiceStatusCode.MISSING_PNM_TEST_TYPE

        self.logger.debug(f"Processing PNM test type: {pnm_test_type}")
        if not transaction_record.get(PnmFileTransaction.FILE_NAME):
            self.logger.error("Filename is missing in the transaction record.")
            return ServiceStatusCode.MISSING_PNM_FILENAME

        # Check to make sure the pnm_test_type is in the DocsPnmCmCtlTest enum
        if pnm_test_type not in DocsPnmCmCtlTest.__members__:
            self.logger.error(f"Unsupported PNM test type: {pnm_test_type}")
            return ServiceStatusCode.UNSUPPORTED_TEST_TYPE

        file_name_dst = f'{self.pnm_file_dir}/{transaction_record[PnmFileTransaction.FILE_NAME]}'
        device_details:dict[str, str] = transaction_record[PnmFileTransaction.DEVICE_DETAILS]
        pnm_data = FileProcessor(file_name_dst).read_file()

        if pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR.name:
            pnm_dict = self._add_device_details(CmDsOfdmRxMer(binary_data=pnm_data).to_dict(), device_details)
            self.build_msg(ServiceStatusCode.SUCCESS, pnm_dict)

        elif pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_CODEWORD_ERROR_RATE.name:
            pnm_dict = self._add_device_details(CmDsOfdmFecSummary(binary_data=pnm_data).to_dict(), device_details)
            self.build_msg(ServiceStatusCode.SUCCESS, pnm_dict)

        elif pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_CHAN_EST_COEF.name:
            pnm_dict = self._add_device_details(CmDsOfdmChanEstimateCoef(binary_data=pnm_data).to_dict(), device_details)
            self.build_msg(ServiceStatusCode.SUCCESS, pnm_dict)

        elif pnm_test_type == DocsPnmCmCtlTest.DS_CONSTELLATION_DISP.name:
            pnm_dict = self._add_device_details(CmDsConstDispMeas(binary_data=pnm_data).to_dict(), device_details)
            self.build_msg(ServiceStatusCode.SUCCESS, pnm_dict)

        elif pnm_test_type == DocsPnmCmCtlTest.DS_HISTOGRAM.name:
            pnm_dict = self._add_device_details(CmDsHist(binary_data=pnm_data).to_dict(), device_details)
            self.build_msg(ServiceStatusCode.SUCCESS, pnm_dict)

        elif pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_MODULATION_PROFILE.name:
            pnm_dict = self._add_device_details(CmDsOfdmModulationProfile(binary_data=pnm_data).to_dict(), device_details)
            self.build_msg(ServiceStatusCode.SUCCESS, pnm_dict)

        elif pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER.name:
            self.logger.debug("Processing DS_SPECTRUM_ANALYZER PNM data")
            pnm_dict = self._add_device_details(CmSpectrumAnalysis(pnm_data).to_dict(), device_details)
            self.build_msg(ServiceStatusCode.SUCCESS, pnm_dict)

        elif pnm_test_type == DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF.name:
            self.logger.debug(f"Processing {pnm_test_type} PNM data")
            pnm_dict = self._add_device_details(CmUsOfdmaPreEq(binary_data=pnm_data).to_dict(), device_details)
            self.build_msg(ServiceStatusCode.SUCCESS, pnm_dict)

        elif pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA.name:
            self.logger.debug(f"Processing {pnm_test_type} PNM data")
            pnm_dict = self._add_device_details(CmSpectrumAnalysisSnmp(pnm_data).to_dict(), device_details)
            self._update_pnm_data_from_message_response_extension(transaction_record, pnm_dict)
            pnm_dict['mac_address'] = MacAddressStr(transaction_record[PnmFileTransaction.MAC_ADDRESS])
            self.logger.debug(f"Spectrum Analysis SNMP Data PNM Dict: {pnm_dict}")
            self.build_msg(ServiceStatusCode.SUCCESS, pnm_dict)

        else:
            self.logger.error(f"Unsupported PNM test type: {pnm_test_type}")
            return ServiceStatusCode.UNSUPPORTED_TEST_TYPE

        return ServiceStatusCode.SUCCESS


    def _add_device_details(self, pnm_data: dict, device_details: dict[str, str]) -> dict:
        """
        Adds device details to the PNM data dictionary.

        Args:
            pnm_data (dict): The PNM data dictionary.
            device_details (Dict[str, str]): Device details to be added.

        Returns:
            dict: Updated PNM data dictionary with device details.
        """
        if PnmFileTransaction.DEVICE_DETAILS not in pnm_data:
            pnm_data[PnmFileTransaction.DEVICE_DETAILS] = {}
        pnm_data[PnmFileTransaction.DEVICE_DETAILS].update(device_details)
        return pnm_data

    def  _update_pnm_data_from_message_response_extension(self,
                                                          transaction_record: TransactionRecord,
                                                          pnm_data: dict) -> dict:
        """
        Update extension data from the MessageResponse payload into the PNM data dictionary.

        Args:
            transaction_record (TransactionRecord): The transaction record containing the transaction ID.
            pnm_data (dict): The PNM data dictionary to update.

        Returns:
            dict: Updated PNM data dictionary with extension data.
        """
        transaction_id = transaction_record.get("transaction_id")
        if not transaction_id:
            self.logger.warning("Transaction record missing transaction ID.")
            return pnm_data

        if self._msg_rsp.payload is None:
            self.logger.warning("Message response payload is empty.")
            return pnm_data

        for payload in self._msg_rsp.payload:
            _status, _message_type, message = MessageResponse.get_payload_msg(payload)
            if not isinstance(message, dict):
                continue

            if message.get("transaction_id") != transaction_id:
                continue

            extension_data = message.get(PnmFileTransaction.EXTENSION)
            if not isinstance(extension_data, dict):
                self.logger.warning("No extension data found in message response.")
                return pnm_data

            self.logger.debug(f"Extension-Data: {extension_data}")
            pnm_data.update(extension_data)
            return pnm_data

        self.logger.warning("No message found for transaction record.")
        return pnm_data

# FILE: src/pypnm/api/routes/advance/common/capture_service.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from typing import Any, cast

from pypnm.api.routes.advance.common.operation_manager import OperationManager
from pypnm.api.routes.advance.common.operation_state import OperationState
from pypnm.api.routes.common.classes.file_capture.capture_group import CaptureGroup
from pypnm.api.routes.common.classes.file_capture.capture_sample import CaptureSample
from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.api.routes.common.extended.common_messaging_service import (
    MessageResponse,
    MessageResponseType,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.lib.types import GroupId, OperationId, TimeStamp
from pypnm.lib.utils import Generate


class AbstractCaptureService(ABC):
    """
    Abstract base for periodic background capture services with capture-group support.

    Responsibilities:
        - Create a new capture session (group + operation ID)
        - Periodically fetch raw MessageResponse objects (_capture_message_response)
        - Parse responses into CaptureSample objects (_process_captures)
        - Store samples in memory and persist transaction IDs via CaptureGroup
        - Provide status, results, and stop functionality

    Attributes:
        duration (float): Total runtime for captures, in seconds.
        interval (float): Delay between successive capture iterations, in seconds.
        _ops (Dict[str, Dict[str, Any]]): In-memory state for active operations.
        _cap_group (CaptureGroup): Persistence for transaction IDs across restarts.
        logger (logging.Logger): Logger for operational messages.
    """

    def __init__(self, duration: float, interval: float) -> None:
        """
        Initialize the capture service framework.

        Args:
            duration: Total duration (seconds) for which to run captures.
            interval: Interval (seconds) between capture iterations.

        Raises:
            OSError: If the capture-group database cannot be initialized.
        """
        self.duration = duration
        self.interval = interval
        self.time_remaining:int = 0
        self._ops: dict[str, dict[str, Any]] = {}
        self.logger = logging.getLogger(self.__class__.__name__)
        try:
            self._cap_group = CaptureGroup()
        except Exception as exc:
            self.logger.error(f"Failed to initialize CaptureGroup, reason={exc}", exc_info=True)
            raise

        self._capture_group_id: GroupId = GroupId("")
        self._operation_id: OperationId = OperationId("")

    async def start(self) -> tuple[GroupId, OperationId]:
        """
        Create a new capture group and operation, then schedule the background runner.

        Returns:
            A tuple of (group_id, operation_id):
            - group_id: 16-character ID for grouping transactions.
            - operation_id: 16-character unique ID for this capture run.

        Side Effects:
            - Registers a new entry in the CaptureGroup database.
            - Launches an asyncio background task that performs captures.

        Raises:
            Exception: Propagates errors from CaptureGroup creation or task scheduling.
        """
        try:
            group_id = self._cap_group.create_group()
        except Exception as exc:
            self.logger.error(f"Failed to create capture group, reason={exc}", exc_info=True)
            raise

        try:
            om = OperationManager(capture_group_id=group_id)
            operation_id:OperationId = om.register()
        except Exception as exc:
            self.logger.error(f"Failed to create operation manager, reason={exc}", exc_info=True)
            raise

        start_time = time.time()
        self._ops[operation_id] = {
            "group_id":         group_id,
            "state":            OperationState.RUNNING,
            "start_time":       start_time,
            "duration":         self.duration,
            "interval":         self.interval,
            "time_remaining":   self.time_remaining,
            "samples":          []
        }

        self.setOperationFinalInvocation(operation_id, False)

        self.logger.info(
            f"CaptureGroup={group_id} / Operation={operation_id} started "
            f"({self.duration}s @ {self.interval}s interval)")

        async def _runner() -> None:

            end_time = start_time + self.duration

            while (time.time() < end_time) and self._ops[operation_id]["state"] == OperationState.RUNNING:

                now = time.time()
                remaining = max(0, int(end_time - now))
                self._ops[operation_id]["time_remaining"] = remaining
                iteration_ts = Generate.time_stamp()

                # Add a waitup front so that it can goto the next function
                await asyncio.sleep(self.interval)

                try:
                    msg_rsp = await self._capture_message_response()
                    samples = self._process_captures(msg_rsp)
                    for sample in samples:
                        self._ops[operation_id]["samples"].append(sample)
                        self._cap_group.add_transaction(sample.transaction_id)
                        self.logger.debug(f"[{operation_id}] Captured sample txn={sample.transaction_id}")

                except Exception as exc:
                    error_msg = str(exc)
                    self.logger.error(f"[{operation_id}] Capture error: {error_msg}", exc_info=True)
                    self._ops[operation_id]["samples"].append(CaptureSample(timestamp       =   cast(TimeStamp, iteration_ts),
                                                                            transaction_id  =   "",
                                                                            filename        =   "",
                                                                            error           =   error_msg))

            # Complete if still running
            if self._ops[operation_id]["state"] == OperationState.RUNNING:

                self._ops[operation_id]["state"] = OperationState.COMPLETED
                iteration_ts = time.time()

                try:

                    self.logger.info(f'Runner ended, Final Invocation , One Last Cycle before ending'
                                    f'state={self._ops[operation_id]["state"]}'
                                    f'time-remaining={self._ops[operation_id]["time_remaining"]}')

                    self.setOperationFinalInvocation(operation_id, True)
                    msg_rsp:MessageResponse = await self._capture_message_response()

                    # This is here to before any last operation at the time of the completion of the task
                    if msg_rsp.status == ServiceStatusCode.SKIP_MESSAGE_RESPONSE:
                        self.logger.info('Skipping last _capture_message_response()')
                    else:
                        samples = self._process_captures(msg_rsp)
                        for sample in samples:
                            self._ops[operation_id]["samples"].append(sample)
                            self._cap_group.add_transaction(sample.transaction_id)
                            self.logger.info(f"[{operation_id}] Captured sample txn={sample.transaction_id}")

                except Exception as exc:
                    error_msg = str(exc)
                    self.logger.error(f"[{operation_id}] Capture error: {error_msg}", exc_info=True)
                    self._ops[operation_id]["samples"].append(
                        CaptureSample(timestamp         =   cast(TimeStamp, iteration_ts),
                                      transaction_id    =   "",
                                      filename          =   "",
                                      error             =error_msg))

            self.logger.info(f"[{operation_id}] Capture session ended with state={self._ops[operation_id]['state']}")

                                            ###############
                                            # Main RUNNER #
                                            ###############
        try:
            asyncio.create_task(_runner())
        except Exception as exc:
            self.logger.error(f"Failed to schedule capture runner task, reason={exc}", exc_info=True)
            raise

        self._capture_group_id = group_id
        self._operation_id = operation_id

        return group_id, operation_id

    def getCaptureGroupID(self) -> GroupId:
        return self._capture_group_id

    def getOperationID(self) -> OperationId:
        return self._operation_id

    def getOperation(self, operation_id:OperationId) -> dict[str, dict[str, Any]]:
        return self._ops[operation_id]

    def getOperationState(self,operation_id:OperationId) -> OperationState:
        return self._ops[operation_id]["state"]

    def setOperationFinalInvocation(self, operation_id:OperationId, state:bool) -> None:
            "Indicate that Runner is done, and invocate any final operations"
            self._ops[operation_id]["final_invocation"] = state

    def getOperationFinalInvocation(self, operation_id:OperationId) -> bool:
            return self._ops[operation_id]["final_invocation"]

    def status(self, operation_id: OperationId) -> dict[str, Any]:
        """
        Get the current state and sample count for a capture operation.

        Args:
            operation_id: The ID of the capture operation.

        Returns:
            A dict containing:
                - state (OperationState): Current operation state.
                - collected (int): Number of samples collected.
        """
        op = self._ops.get(operation_id)
        if not op:
            return {"state": OperationState.UNKNOWN, "collected": 0}

        return {
            "state": op["state"],
            "collected": len(op["samples"]),
            "time_remaining": op.get("time_remaining", 0)
        }

    def results(self, operation_id: OperationId) -> list[CaptureSample]:
        """
        Retrieve all CaptureSample objects collected for the operation.

        Args:
            operation_id: The ID of the capture operation.

        Returns:
            A list of CaptureSample. Empty if operation not found.
        """
        op = self._ops.get(operation_id)
        return op["samples"] if op else []

    def stop(self, operation_id: OperationId) -> None:
        """
        Signal the background runner to stop after the current iteration.

        Args:
            operation_id: The ID of the capture operation.

        Effects:
            Sets the operation state to STOPPED if it was RUNNING.
            Idempotent if called multiple times.
        """
        op = self._ops.get(operation_id)
        if op and op["state"] == OperationState.RUNNING:
            op["state"] = OperationState.STOPPED
            self.logger.info(f"[{operation_id}] Stopped by user")

    def _process_captures(self, msg_rsp: MessageResponse) -> list[CaptureSample]:
        """
        Parse a raw MessageResponse into a list of CaptureSample objects.

        Args:
            msg_rsp: MessageResponse from _capture_message_response.

        Returns:
            A list of CaptureSample. On payload/type/parsing errors, returns
            a list with a single CaptureSample indicating the error.
        """
        ts = cast(TimeStamp, Generate.time_stamp())
        payload = msg_rsp.payload
        if not isinstance(payload, list):
            err = f"Unexpected payload type: {type(payload).__name__}"
            self.logger.error(err)
            return [CaptureSample(timestamp         =   ts,
                                  transaction_id    =   "",
                                  filename          =   "",
                                  error             =   err)]

        samples: list[CaptureSample] = []
        for idx, entry in enumerate(payload):
            try:
                status_str, msg_type, body = MessageResponse.get_payload_msg(entry)

            except Exception as exc:
                err = f"Failed to parse payload entry {idx}: {exc}"
                self.logger.error(err, exc_info=True)
                samples.append(CaptureSample(timestamp      =   ts,
                                             transaction_id =   "",
                                             filename       =   "",
                                             error          =   err))
                continue

            if status_str != ServiceStatusCode.SUCCESS.name:
                err = f"Payload entry {idx} returned status {status_str}"
                self.logger.error(err)
                samples.append(CaptureSample(timestamp      =   ts,
                                             transaction_id =   "",
                                             filename       =   "",
                                             error          =   err))
                continue

            if msg_type != MessageResponseType.PNM_FILE_TRANSACTION.name:
                # skip non-transaction messages
                continue

            txn_id = body.get("transaction_id", "")
            filename = body.get("filename", "")
            if not txn_id or not filename:
                err = f"Missing txn_id or filename in entry {idx}"
                self.logger.warning(f"{err}: {body}")
                samples.append(CaptureSample(timestamp      =   ts,
                                             transaction_id =   txn_id,
                                             filename       =   filename,
                                             error          =   "missing-txn-or-filename"))
                continue

            try:
                rec = PnmFileTransaction().get_record(txn_id)
            except Exception as exc:
                err = f"DB fetch error for txn {txn_id}: {exc}"
                self.logger.error(err, exc_info=True)
                samples.append(CaptureSample(timestamp      =   ts,
                                             transaction_id =   txn_id,
                                             filename       =   filename,
                                             error          =   "db-fetch-error"))
                continue

            if rec is None:
                err = f"No DB record found for txn {txn_id}"
                self.logger.warning(err)
                samples.append(CaptureSample(timestamp      =   ts,
                                             transaction_id =   txn_id,
                                             filename       =   filename,
                                             error          =   "no-db-record"))
            else:
                samples.append(CaptureSample(timestamp      =   ts,
                                             transaction_id =   txn_id,
                                             filename       =   filename,
                                             error          =   None))

        if not samples:
            err = "No valid transactions found in payload"
            self.logger.warning(err)
            return [CaptureSample(timestamp         =   ts,
                                  transaction_id    =   "",
                                  filename          =   "",
                                  error             =   "no-transactions")]

        return samples

    @abstractmethod
    async def _capture_message_response(self) -> MessageResponse:
        """
        Perform one capture iteration and return its raw response.

        This method is called by the runner each cycle. Subclasses must
        implement the actual SNMP/TFTP logic and always return a
        `MessageResponse`, even on errors.

        Returns
        -------
        MessageResponse
            The raw capture response. Its `.status` field indicates success,
            failure, or a special skip code.

        Notes
        -----
        - On internal exception, catch it and return a failure response, e.g.:
          `MessageResponse(ServiceStatusCode.YOUR_ERROR_CODE)`.
        - To indicate “no PNM file needed right now” (e.g. final cleanup),
          return a `MessageResponse` with
          ``status == ServiceStatusCode.SKIP_MESSAGE_RESPONSE``.
        """
        ...

# FILE: tests/test_message_response_basemodel.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode


def test_message_response_payload_coercion() -> None:
    payload = [
        {
            "status": ServiceStatusCode.SUCCESS.name,
            "message_type": "PNM_FILE_TRANSACTION",
            "message": {
                "transaction_id": "abc123",
                "filename": "capture.bin",
            },
            "extra_field": "extra",
        },
    ]

    msg_rsp = MessageResponse(ServiceStatusCode.SUCCESS, payload=payload)

    assert msg_rsp.status == ServiceStatusCode.SUCCESS
    assert msg_rsp.payload is not None
    assert msg_rsp.payload[0].status == ServiceStatusCode.SUCCESS.name

    payload_dict = msg_rsp.payload_to_dict()
    assert payload_dict["data"][0]["message_type"] == "PNM_FILE_TRANSACTION"
    assert payload_dict["data"][0]["extra_field"] == "extra"

    msg_dict = msg_rsp.get()
    assert msg_dict["status"] == ServiceStatusCode.SUCCESS.name
