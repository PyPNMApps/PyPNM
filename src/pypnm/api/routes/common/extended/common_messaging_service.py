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
