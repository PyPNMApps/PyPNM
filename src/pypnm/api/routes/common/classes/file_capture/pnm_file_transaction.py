# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import hashlib
import logging
import time

from pypnm.api.routes.common.classes.file_capture.types import (
    DeviceDetailsModel,
    TransactionRecordModel,
)
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.sysDescr import SystemDescriptor
from pypnm.lib.db.transaction_repository import (
    DeviceDetailsRepository,
    SystemDescriptionRepository,
    TransactionRecordRow,
    TransactionRepository,
)
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import FileName, TimestampSec, TransactionId
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest


class PnmFileTransaction:
    """
    Manages persistent tracking of PNM file transactions across the PyPNM system.

    Each transaction corresponds to a PNM test result file (e.g., RxMER, Spectrum Analysis),
    whether generated through automated measurements or manually uploaded by a user.

    A transaction includes:
        - A unique transaction ID (16-char SHA-256 digest)
        - Timestamp (epoch time)
        - MAC address of the cable modem
        - PNM test type (e.g., DS_RXMER, SPECTRUM_ANALYZER)
        - Filename of the associated binary data file

    Transactions are stored in the configured database backend (SQLite/Postgres)
    using the DB schema defined under docs/design/db/.

    Usage Scenarios:
        - When a measurement test completes and produces a file.
        - When a user uploads a file manually via the REST API.
        - When retrieving metadata about previously captured test files.

    Record structure mirrors the legacy JSON layout so downstream parsers stay stable:
        {
            "timestamp": int,
            "mac_address": "<cable modem mac address>",
            "pnm_test_type": "<PNM Test Type>",
            "filename": "<FileName>",
            "device_details": {
                "system_description": { ... }
            }
        }
    """

    PNM_TEST_TYPE = "pnm_test_type"
    FILE_NAME = "filename"
    DEVICE_DETAILS = "device_details"
    MAC_ADDRESS = "mac_address"

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self._sysdescr_repo = SystemDescriptionRepository.from_system_config()
        self._device_details_repo = DeviceDetailsRepository.from_system_config()
        self._transaction_repo = TransactionRepository.from_system_config()

    async def insert(
        self, cable_modem: CableModem, pnm_test_type: DocsPnmCmCtlTest, filename: str
    ) -> TransactionId:
        """
        Record A Transaction Initiated From An Actual Cable Modem Test.

        This method is invoked by measurement services once a PNM capture has
        successfully completed and produced a result file. It pulls the current
        system description from the cable modem, generates a new transaction
        identifier, and appends a normalized record into the transaction
        database.

        Parameters
        ----------
        cable_modem:
            Live `CableModem` instance representing the device under test. Used
            to obtain the MAC address and system description snapshot.
        pnm_test_type:
            Enumeration value describing which PNM test produced the file
            (for example, DS_RXMER, DS_OFDM_HISTOGRAM, DS_CONSTELLATION).
        filename:
            Relative or absolute path to the generated PNM binary file, as
            stored by the calling measurement service.

        Returns
        -------
        str
            Newly generated transaction identifier (16-character SHA-256
            digest prefix) suitable for later lookup (download and analysis).
        """
        sd: SystemDescriptor = await cable_modem.getSysDescr()
        return self._insert_generic(
            mac_address=cable_modem.get_mac_address,
            pnm_test_type=pnm_test_type,
            filename=filename,
            system_description=sd.to_dict(),
        )

    @staticmethod
    def set_file_by_user(
        mac_address: MacAddress, pnm_test_type: DocsPnmCmCtlTest, filename: FileName
    ) -> TransactionId:
        """
        Record A Transaction For A Manually Supplied File (User Upload).

        This path is used when the file is not the result of an automated test
        initiated by PyPNM, but rather provided by the user (for example, a
        lab-captured PNM file uploaded via REST). The record is normalized into
        the same transaction database used for automated captures.

        Parameters
        ----------
        mac_address:
            MAC address of the cable modem associated with the uploaded file.
        pnm_test_type:
            Enumeration describing the semantic PNM test type for the file,
            allowing downstream analysis routing to behave consistently.
        filename:
            Filesystem path or name where the uploaded file has been stored on
            the server.

        Returns
        -------
        str
            Newly generated transaction identifier bound to the uploaded file.
        """
        txn = PnmFileTransaction()
        return txn._insert_generic(
            mac_address=mac_address,
            pnm_test_type=pnm_test_type,
            filename=filename,
        )

    def get_record(self, transaction_id: TransactionId) -> dict | None:
        """
        Fetch A Plain Dictionary Representation Of A Transaction Record.

        This method provides a minimal, schema-free view into the transaction
        database. It is intended for low-level callers that need direct access
        to the stored fields without constructing a Pydantic model.

        Parameters
        ----------
        transaction_id:
            Unique transaction identifier for the record to retrieve.

        Returns
        -------
        dict | None
            The underlying transaction record as a dictionary, or `None` when
            the identifier does not exist in the database.
        """
        record = self._transaction_repo.get_transaction_record(transaction_id)
        if record is None:
            return None
        return self._record_to_payload(record)

    def get(self, transaction_id: TransactionId) -> dict | None:
        return self.get_record(transaction_id)

    def getRecordModel(self, transaction_id: TransactionId) -> TransactionRecordModel:
        """
        Build A Canonical TransactionRecordModel For A Transaction Identifier.

        This convenience wrapper resolves the DB-backed record and constructs
        the normalized Pydantic model. If the record does not exist, a
        `null()` sentinel model is returned.

        Parameters
        ----------
        transaction_id:
            Unique transaction identifier for which a model representation is
            requested.

        Returns
        -------
        TransactionRecordModel
            Canonical, fully-normalized transaction model, or the sentinel
            `TransactionRecordModel.null()` instance for missing records.
        """
        record = self._transaction_repo.get_transaction_record(transaction_id)
        if record is None:
            return TransactionRecordModel.null()
        return self._record_to_model(record)

    def get_file_info_via_macaddress(
        self, mac_address: MacAddress
    ) -> list[TransactionRecordModel]:
        """
        Retrieve All Transaction Records Associated With A Given MAC Address.

        This method scans the transaction database and collects all entries
        whose stored `mac_address` matches the supplied cable modem MAC (case-
        insensitive). Each matching record is returned as a fully normalized
        `TransactionRecordModel`, using the same parsing logic as individual
        lookups.

        Typical usage patterns include:
        - Building a catalog of all PNM files available for a modem.
        - Populating UI tables of historical captures keyed by MAC address.
        - Providing selection lists for downstream download or analysis calls.

        Parameters
        ----------
        mac_address:
            Cable modem MAC address used as the primary lookup key. The value
            is normalized to lower-case for comparison against stored records.

        Returns
        -------
        List[TransactionRecordModel]
            List of canonical `TransactionRecordModel` instances for all
            transactions associated with the given MAC address. The list is
            empty when no matching records are found.
        """
        records = self._transaction_repo.list_transactions_for_mac(mac_address)
        models: list[TransactionRecordModel] = []
        for record in records:
            model = self._record_to_model(record)
            models.append(model)
        return models

    def get_all_record_models(self) -> list[TransactionRecordModel]:
        """
        Retrieve All Transaction Records As Canonical Models.

        This scans the transaction database and returns each record as a fully
        normalized `TransactionRecordModel`. Any per-record parse failures are
        logged and skipped so callers can still operate on partial data.

        Returns
        -------
        list[TransactionRecordModel]
            List of all transaction models currently stored in the transaction
            database. The list is empty when no records exist.
        """
        records = self._transaction_repo.list_all_transactions()
        if not records:
            return []

        models: list[TransactionRecordModel] = []
        for record in records:
            model = self._safe_record_model(record)
            if model is not None:
                models.append(model)

        return models

    def _safe_record_model(
        self, record: TransactionRecordRow
    ) -> TransactionRecordModel | None:
        try:
            return self._record_to_model(record)
        except Exception as exc:
            self.logger.warning("Skipping transaction due to parse error: %s", exc)
            return None

    # ---------------------------
    # Write helpers
    # ---------------------------

    def _insert_generic(
        self,
        mac_address: MacAddress,
        pnm_test_type: DocsPnmCmCtlTest,
        filename: str,
        system_description: dict[str, str] | None = None,
    ) -> TransactionId:
        """
        Common Logic For Creating And Persisting A Transaction Record.

        This internal helper generates a new transaction identifier, assembles
        the DB-backed record structure, and persists the transaction to the
        configured database backend.

        Parameters
        ----------
        mac_address:
            MAC address of the cable modem associated with the transaction.
        pnm_test_type:
            Enumeration describing the PNM test type that produced or owns the
            associated file.
        filename:
            Path or name of the PNM data file linked to this transaction.
        system_description:
            Optional system description snapshot dictionary, typically produced
            via `SystemDescriptor.to_dict()`. When omitted, an empty mapping is
            stored under `device_details.system_description`.

        Returns
        -------
        str
            Newly created transaction identifier associated with the record.
        """
        timestamp = int(time.time())
        hash_input = f"{filename}{timestamp}".encode()
        transaction_id = TransactionId(hashlib.sha256(hash_input).hexdigest()[:16])
        tx_id = str(transaction_id)
        if not tx_id.strip():
            self.logger.warning(
                "Skipping transaction insert for empty transaction_id (filename=%s, mac=%s)",
                filename,
                mac_address,
            )
            return TransactionId("")

        normalized_sd = self._normalize_system_description(system_description)
        device_details = {"system_description": normalized_sd}
        sysdescr_payload = normalized_sd if normalized_sd else None
        sysdescr_id = self._sysdescr_repo.get_or_create_sysdescr_id(sysdescr_payload)
        device_detail_id = self._device_details_repo.get_or_create_device_detail_id(
            device_details, sysdescr_id
        )
        self._transaction_repo.insert_transaction(
            transaction_id=transaction_id,
            timestamp_epoch=TimestampSec(timestamp),
            mac_address=mac_address,
            pnm_test_type=pnm_test_type.name,
            filename=filename,
            device_detail_id=device_detail_id,
        )
        return transaction_id

    @staticmethod
    def _normalize_system_description(
        system_description: dict[str, str] | None,
    ) -> dict[str, str]:
        if not system_description:
            return {}
        return SystemDescriptor.load_from_dict(system_description).to_dict()

    def _record_to_payload(self, record: TransactionRecordRow) -> dict:
        return {
            "timestamp": int(record.timestamp_epoch),
            "mac_address": str(record.mac_address),
            "pnm_test_type": record.pnm_test_type,
            "filename": str(record.filename),
            "device_details": {
                "system_description": record.system_description or {},
            },
        }

    def _record_to_model(self, record: TransactionRecordRow) -> TransactionRecordModel:
        sysdesc = record.system_description or {}
        system_description = SystemDescriptor.load_from_dict(sysdesc).to_model()
        return TransactionRecordModel(
            transaction_id=record.transaction_id,
            timestamp=TimestampSec(int(record.timestamp_epoch)),
            mac_address=record.mac_address,
            pnm_test_type=record.pnm_test_type,
            filename=record.filename,
            device_details=DeviceDetailsModel(system_description=system_description),
        )
