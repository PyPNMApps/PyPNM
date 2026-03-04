# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path

from pypnm.api.routes.common.classes.file_capture.transaction_record_parser import (
    TransactionRecordParser,
)
from pypnm.api.routes.common.classes.file_capture.types import TransactionRecordModel
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.sysDescr import SystemDescriptor
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import FileName, FileNameStr, TransactionId, TransactionRecord
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

    Transactions are stored in a central JSON file defined in system config at:
    `PnmFileRetrieval.transaction_db`.

    Usage Scenarios:
        - When a measurement test completes and produces a file.
        - When a user uploads a file manually via the REST API.
        - When retrieving metadata about previously captured test files.

    Attributes:
        transaction_db_path (Path): Path to the JSON file where all transactions are recorded.

    Record:
        {
            "<transaction_id>": {
                "timestamp": int,
                "mac_address": "<cable modem mac address>",
                "pnm_test_type": "<PNM Test Type>",
                "filename": "<FileName>",
                "compression": {
                    "is_compressed": bool,
                    "codec": "zstd|gzip|none",
                    "level": int,
                    "size_before": int,
                    "size_after": int
                },
                "device_details": {
                    "system_description": { ... }
                }
            }
        }
    """

    PNM_TEST_TYPE  = "pnm_test_type"
    FILE_NAME      = "filename"
    DEVICE_DETAILS = "device_details"
    MAC_ADDRESS    = "mac_address"
    EXTENSION      = "extension"
    COMPRESSION    = "compression"

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self.transaction_db_path = Path(SystemConfigSettings.transaction_db())
        self.transaction_db_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.transaction_db_path.exists():
            self.transaction_db_path.write_text(json.dumps({}))

    @staticmethod
    def _default_compression_metadata() -> dict[str, object]:
        return {
            "is_compressed": False,
            "codec": "none",
            "level": 0,
            "size_before": 0,
            "size_after": 0,
        }

    async def insert(
        self,
        cable_modem: CableModem,
        pnm_test_type: DocsPnmCmCtlTest,
        filename: str,
        system_description: dict[str, str] | None = None,
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
        if system_description is None:
            sd: SystemDescriptor = await cable_modem.getSysDescr()
            system_description = sd.to_dict()

        return self._insert_generic(
            mac_address        = cable_modem.get_mac_address,
            pnm_test_type      = pnm_test_type,
            filename           = filename,
            system_description = system_description,
        )

    @staticmethod
    def set_file_by_user(mac_address: MacAddress, pnm_test_type: DocsPnmCmCtlTest, filename: FileName) -> TransactionId:
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
            mac_address   = mac_address,
            pnm_test_type = pnm_test_type,
            filename      = filename,
        )

    # ---------------------------
    # Safe read helpers (no recursion)
    # ---------------------------

    def _load_record_dict(self, transaction_id: TransactionId) -> dict | None:
        """
        Load The Raw JSON Record For A Transaction Identifier.

        This helper reads the on-disk transaction database and returns the
        underlying dictionary for the requested transaction identifier, if
        present. It does not perform any schema normalization or conversion.

        Parameters
        ----------
        transaction_id:
            Unique transaction identifier to resolve.

        Returns
        -------
        dict | None
            Raw JSON-compatible dictionary for the transaction when present,
            or `None` if no record exists for the supplied identifier.
        """
        db = self._load_db()
        return db.get(transaction_id)

    def get_record(self, transaction_id: TransactionId) -> TransactionRecord | None:
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
        rec = self._load_record_dict(transaction_id)
        return rec if rec else None

    def get_record_by_filename(self, filename: FileNameStr) -> tuple[TransactionId, TransactionRecord] | None:
        """
        Resolve A Transaction Record By Filename.

        Matches the stored physical filename (including compression extension)
        or the raw base filename when the stored record is compressed.
        """
        safe_name = Path(str(filename)).name
        base_name = safe_name
        if base_name.endswith(".zst"):
            base_name = base_name[:-4]
        elif base_name.endswith(".gz"):
            base_name = base_name[:-3]

        db = self._load_db()
        for txn_id, record in db.items():
            rec_filename = str(record.get(self.FILE_NAME, ""))
            if not rec_filename:
                continue
            rec_safe = Path(rec_filename).name
            if rec_safe == safe_name:
                return TransactionId(str(txn_id)), record

            rec_base = rec_safe
            if rec_base.endswith(".zst"):
                rec_base = rec_base[:-4]
            elif rec_base.endswith(".gz"):
                rec_base = rec_base[:-3]
            if rec_base == base_name:
                return TransactionId(str(txn_id)), record

        return None

    def get(self, transaction_id: TransactionId) -> dict | None:
        return self.get_record(transaction_id)

    def update_record_system_description(
        self,
        transaction_id: TransactionId,
        system_description: dict[str, str],
    ) -> bool:
        """
        Update the transaction record with a normalized system description payload.
        """
        db = self._load_db()
        record = db.get(transaction_id)
        if record is None:
            self.logger.error("Transaction record not found for sysDescr update: %s", transaction_id)
            return False

        if "device_details" not in record or not isinstance(record["device_details"], dict):
            record["device_details"] = {}

        record["device_details"]["system_description"] = dict(system_description)
        self._save_db(db)
        return True

    def update_record_compression(
        self,
        transaction_id: TransactionId,
        filename: FileNameStr,
        compression: dict[str, object] | None,
    ) -> bool:
        """
        Update the filename and compression metadata for an existing transaction.

        Parameters
        ----------
        transaction_id:
            Identifier of the transaction record to update.
        filename:
            Physical filename stored in the PNM directory (includes compression extension when used).
        compression:
            Compression metadata payload or None when unavailable.

        Returns
        -------
        bool
            True when the record was updated, False when missing.
        """
        db = self._load_db()
        record = db.get(transaction_id)
        if record is None:
            self.logger.error("Transaction record not found for update: %s", transaction_id)
            return False

        record[self.FILE_NAME] = str(filename)
        record[self.COMPRESSION] = compression or self._default_compression_metadata()
        self._save_db(db)
        return True

    def getRecordModel(self, transaction_id: TransactionId) -> TransactionRecordModel:
        """
        Build A Canonical TransactionRecordModel For A Transaction Identifier.

        This convenience wrapper resolves the raw JSON record and delegates to
        `TransactionRecordParser` to construct the normalized Pydantic model.
        If the record does not exist, a `null()` sentinel model is returned.

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
        rec = self._load_record_dict(transaction_id)
        if not rec:
            return TransactionRecordModel.null()
        return TransactionRecordParser.from_id(transaction_id)

    def get_file_info_via_macaddress(self, mac_address: MacAddress) -> list[TransactionRecordModel]:
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
        db = self._load_db()
        mac_str = str(mac_address).lower()
        self.logger.info(f"Searching for files with MAC address: {mac_str}")
        records: list[TransactionRecordModel] = []

        for txn_id, record in db.items():
            if record.get(self.MAC_ADDRESS, "").lower() != mac_str:
                self.logger.info(f"Skipping file with MAC address: {record.get(self.MAC_ADDRESS, '').lower()}")
                continue
            records.append(TransactionRecordParser.from_id(txn_id))

        return records

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
        db = self._load_db()
        if not db:
            return []

        records: list[TransactionRecordModel] = []
        for txn_id in db:
            record = self._safe_parse_record(txn_id)
            if record is not None:
                records.append(record)

        return records

    def _safe_parse_record(self, txn_id: str) -> TransactionRecordModel | None:
        """
        Safely Parse A Single Transaction Record.

        Parameters
        ----------
        txn_id:
            Transaction identifier to parse.

        Returns
        -------
        TransactionRecordModel | None
            Parsed record model or None if parsing fails.
        """
        try:
            return TransactionRecordParser.from_id(TransactionId(txn_id))
        except Exception as e:
            self.logger.warning("Skipping transaction %s due to parse error: %s", txn_id, e)
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
        the JSON-serializable record structure, and writes the updated
        transaction database back to disk.

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
        timestamp       = int(time.time())
        hash_input      = f"{filename}{timestamp}".encode()
        transaction_id  = TransactionId(hashlib.sha256(hash_input).hexdigest()[:16])

        db = self._load_db()
        db[transaction_id] = {
            "timestamp":      timestamp,
            "mac_address":    str(mac_address),
            "pnm_test_type":  pnm_test_type.name,
            "filename":       filename,
            "compression":    self._default_compression_metadata(),
            "device_details": {
                "system_description": system_description or {},
            },
        }
        self._save_db(db)
        return transaction_id

    def _load_db(self) -> dict:
        """
        Load The Transaction Database From JSON Storage.

        This helper reads the transaction database file configured by
        `SystemConfigSettings.transaction_db` and returns its contents as a
        dictionary. If JSON parsing fails, an empty dictionary is returned to
        avoid propagating the error to callers.

        Returns
        -------
        dict
            Dictionary of all transaction records keyed by transaction
            identifier. An empty dictionary is returned on parse errors.
        """
        try:
            with self.transaction_db_path.open("r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}

    def _save_db(self, db: dict) -> None:
        """
        Persist The Transaction Database To Disk.

        Parameters
        ----------
        db:
            Fully realized transaction database dictionary to be serialized and
            written to the configured JSON file.
        """
        with self.transaction_db_path.open("w") as f:
            json.dump(db, f, indent=4)
