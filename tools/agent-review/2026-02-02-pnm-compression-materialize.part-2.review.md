## Agent Review Bundle Summary
- Goal: Lower SystemCall logging to debug level.
- Changes: SystemCall now logs execution at debug instead of info.
- Files: See file list below.
- Tests: `ruff check src`, `pytest -q`.
- Notes: None.
# FILE: src/pypnm/api/routes/common/classes/file_capture/pnm_file_transaction.py
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

    async def insert(self, cable_modem: CableModem, pnm_test_type: DocsPnmCmCtlTest, filename: str) -> TransactionId:
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
            mac_address        = cable_modem.get_mac_address,
            pnm_test_type      = pnm_test_type,
            filename           = filename,
            system_description = sd.to_dict(),
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
# FILE: src/pypnm/api/routes/common/classes/file_capture/transaction_record_parser.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from typing import Any

from pypnm.api.routes.common.classes.file_capture.types import (
    CompressionMetadataModel,
    DeviceDetailsModel,
    TransactionRecordModel,
)
from pypnm.docsis.cable_modem import MacAddress
from pypnm.docsis.data_type.sysDescr import SystemDescriptor
from pypnm.lib.types import FileName, MacAddressStr, TimestampSec, TransactionId


class TransactionRecordParser:
    """
    Wrapper class for a single PNM file transaction record.
    Provides easy access to core attributes like MAC, timestamp, test type, etc.
    """

    def __init__(self, transaction_id: TransactionId) -> None:
        self.transaction_id:TransactionId = transaction_id

        # TODO: Refactor to use PnmFileTransaction internally, this is causing circular imports
        from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
            PnmFileTransaction,
        )
        self.record: dict[str, Any] | None = PnmFileTransaction().get_record(transaction_id)

        if not self.record:
            raise ValueError(f"No record found for transaction ID: {transaction_id}")

    def get_timestamp(self) -> TimestampSec:
        return self.record.get("timestamp")

    def get_mac_address(self) -> MacAddressStr:
        return self.record.get("mac_address")

    def get_test_type(self) -> str:
        return self.record.get("pnm_test_type")

    def get_filename(self) -> FileName:
        return self.record.get("filename")

    def get_device_details(self) -> dict[str, Any] | None:
        return self.record.get("device_details", {}).get("system_description", {}) if self.record else None

    def get_device_model(self) -> str | None:
        device_details = self.get_device_details()
        return device_details.get("MODEL") if device_details else None

    '''
        System Descriptor
    '''

    def get_device_vendor(self) -> str | None:
        device_details = self.get_device_details()
        return device_details.get("VENDOR") if device_details else None

    def get_software_revision(self) -> str | None:
        device_details = self.get_device_details()
        return device_details.get("SW_REV") if device_details else None

    def get_hardware_revision(self) -> str | None:
        device_details = self.get_device_details()
        return device_details.get("HW_REV") if device_details else None

    def get_bootrom_version(self) -> str | None:
        device_details = self.get_device_details()
        return device_details.get("BOOTR") if device_details else None

    # ─────────────────────────────────────────────────────────────
    # New: Pydantic models and conversion helpers
    # ─────────────────────────────────────────────────────────────

    def to_model(self) -> TransactionRecordModel:
        """
        Build a Pydantic model for this transaction, normalizing device_details via:
            SystemDescriptor.load_from_dict(...).to_model()
        """
        sys_dict = self.get_device_details() or {}
        sdm = SystemDescriptor.load_from_dict(sys_dict).to_model()

        compression_payload = self.record.get("compression") if self.record else None
        compression = None
        if isinstance(compression_payload, dict):
            try:
                compression = CompressionMetadataModel(**compression_payload)
            except Exception:
                compression = None

        return TransactionRecordModel(
            transaction_id  =   self.transaction_id,
            timestamp       =   self.get_timestamp(),
            mac_address     =   self.get_mac_address() or MacAddressStr(MacAddress.null()),
            pnm_test_type   =   self.get_test_type() or "",
            filename        =   self.get_filename(),
            device_details  =   DeviceDetailsModel(system_description=sdm),
            compression     =   compression,
        )

    @classmethod
    def from_id(cls, transaction_id: TransactionId) -> TransactionRecordModel:
        """
        Convenience constructor that returns the validated model directly.
        """
        return cls(transaction_id).to_model()
# FILE: src/pypnm/api/routes/common/classes/file_capture/types.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from pypnm.docsis.cm_snmp_operation import SystemDescriptor
from pypnm.docsis.data_type.sysDescr import SystemDescriptorModel
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import FileName, MacAddressStr, TimestampSec, TransactionId

Record              = dict[str, Any]
TransactionRecord   = dict[TransactionId, Record]

class DeviceDetailsModel(BaseModel):
    system_description: SystemDescriptorModel = Field(..., description="Parsed system descriptor")

class CompressionMetadataModel(BaseModel):
    is_compressed: bool = Field(..., description="Whether the artifact is stored in compressed form.")
    codec: str = Field(..., description="Compression codec name (zstd, gzip, or none).")
    level: int = Field(..., description="Compression level used for storage.")
    size_before: int = Field(..., description="Original artifact size in bytes before compression.")
    size_after: int = Field(..., description="Compressed artifact size in bytes.")

class TransactionRecordModel(BaseModel):
    transaction_id: TransactionId       = Field(..., description="16-char transaction ID")
    timestamp: TimestampSec             = Field(..., description="Epoch seconds")
    mac_address: MacAddressStr          = Field(..., description="Cable modem MAC address")
    pnm_test_type: str                  = Field(..., description="PNM test type")
    filename: FileName                  = Field(..., description="Capture filename")
    device_details: DeviceDetailsModel  = Field(..., description="Device details container")
    compression: CompressionMetadataModel | None = Field(default=None, description="Compression metadata for stored artifacts.")

    @classmethod
    def null(cls) -> TransactionRecordModel:
        return cls(
            transaction_id  =   TransactionId(""),
            timestamp       =   TimestampSec(0),
            mac_address     =   MacAddressStr(MacAddress.null()),
            pnm_test_type   =   "",
            filename        =   FileName(""),
            device_details=DeviceDetailsModel(system_description=SystemDescriptor.empty().to_model()),
            compression     =   None,
        )
# FILE: src/pypnm/api/routes/common/extended/common_measure_service.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import asyncio
import logging
import math
import os
import shutil
import time
from enum import Enum, auto
from pathlib import Path
from typing import TypeAlias, cast

from pypnm.api.routes.common.classes.analysis.analysis import SpecAnCapturePara
from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.api.routes.common.extended.common_measure_schema import (
    DownstreamOfdmParameters,
    UpstreamOfdmaParameters,
)
from pypnm.api.routes.common.extended.common_messaging_service import (
    CommonMessagingService,
    MessageResponse,
)
from pypnm.api.routes.common.extended.types import (
    CommonMessagingServiceExtension as CMSE,
    SpectrumAnalysisSnmpSegmentPowerEntry,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.config.config_manager import ConfigManager
from pypnm.config.pnm_config_manager import PnmConfigManager
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.cm_snmp_operation import (
    DocsPnmBulkFileUploadStatus,
    DocsPnmCmCtlStatus,
    FecSummaryType,
)
from pypnm.docsis.data_type.enums import MeasStatusType
from pypnm.docsis.data_type.DocsIf3CmSpectrumAnalysisMeasEntry import (
    DocsIf3CmSpectrumAnalysisMeasEntry,
)
from pypnm.docsis.data_type.pnm.DocsIf3CmSpectrumAnalysisEntry import (
    DocsIf3CmSpectrumAnalysisEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmDsConstDispMeasEntry import (
    DocsPnmCmDsConstDispMeasEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmDsHistEntry import DocsPnmCmDsHistEntry
from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmFecEntry import DocsPnmCmDsOfdmFecEntry
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
from pypnm.lib.file_processor import FileProcessor
from pypnm.lib.ftp.ftp_connector import FTPConnector
from pypnm.lib.host_endpoint import HostEndpoint
from pypnm.lib.inet import Inet
from pypnm.lib.ping import Ping
from pypnm.lib.ssh.ssh_connector import SSHConnector
from pypnm.lib.tftp.tftp_connector import TFTPConnector
from pypnm.lib.types import (
    ChannelId,
    FileNameStr,
    FrequencyHz,
    HostNameStr,
    InterfaceIndex,
    PowerdBmV,
    SnmpCommunity,
    TransactionId,
)
from pypnm.lib.utils import Generate
from pypnm.pnm.data_type.DocsIf3CmSpectrumAnalysisCtrlCmd import (
    DocsIf3CmSpectrumAnalysisCtrlCmd,
    SpectrumRetrievalType,
    WindowFunction,
)
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest
from pypnm.pnm.lib.pnm_artifact_store import ArtifactCommitResult, PnmArtifactStore
from pypnm.snmp.modules import DocsisIfType
from pypnm.snmp.snmp_v2c import Snmp_v2c


class MeasureServiceReturnTypes(Enum):
    BASE_MODEL = auto()
    DICT = auto()

MeasurementEntry: TypeAlias =   DocsPnmCmOfdmChanEstCoefEntry   | \
                                DocsPnmCmDsConstDispMeasEntry   | \
                                DocsPnmCmDsOfdmRxMerEntry       | \
                                DocsPnmCmUsPreEqEntry           | \
                                DocsPnmCmDsHistEntry            | \
                                DocsPnmCmDsOfdmFecEntry         | \
                                DocsPnmCmDsOfdmModProfEntry     | \
                                DocsIf3CmSpectrumAnalysisEntry

class CommonMeasureService(CommonMessagingService):
    SPECTRUM_ANALYZER_AVERAGES_CAP: int = 1
    """
    Base service class for executing common Proactive Network Maintenance (PNM) measurement tests.

    Parameters:
        pnm_test_type (DocsPnmCmCtlTest): The type of PNM test to execute.
        cable_modem (CableModem): The cable modem instance used for the test.
        tftp_servers (Inet,Inet): (IPv4,IPv6)
        tftp_path (str, optional): The path on the TFTP server where test result files are stored. Default is an empty string.
        snmp_write_community (str, optional): The SNMP community string for write access. Default is "private".
        **extra_options (dict, optional): Additional keyword arguments specific to the test type, such as:
            - fec_summary_type (FecSummaryType): Required for tests involving FEC summary metrics.
            - Other parameters based on the test type.

    Notes:
        This class serves as a base for test-specific measurement operations. Subclasses should implement
        specific tests such as:
        - Downstream OFDM codeword error rate
        - RXMER per subcarrier
        - FEC statistics, etc.

        It is expected that subclasses will extend this service and provide the necessary implementations for
        executing and processing PNM measurements based on the test type and parameters.
    """
    def __init__(self, pnm_test_type:DocsPnmCmCtlTest,
                 cable_modem: CableModem,
                 tftp_servers: tuple[Inet,Inet],
                 tftp_path: str = "",
                 snmp_write_community: SnmpCommunity = "private",
                 **extra_options) -> None:
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.propagate = True

        self.pnm_filename:list[str]

        self._transactionId_pnmFile: dict[str, str] = {}
        self.pnm_test_type:DocsPnmCmCtlTest         = pnm_test_type
        self.cm:CableModem                          = cable_modem
        self.tftp_servers:tuple[Inet,Inet]          = tftp_servers
        self.tftp_path:str                          = tftp_path
        self.snmp_write_community:str               = snmp_write_community
        self.extra_options                          = extra_options
        self.config_mgr:ConfigManager               = ConfigManager()
        self.log_prefix:str                         = f"MAC: {self.cm.get_mac_address} - INET: {self.cm.get_inet_address}"
        self.pnm_dir                                = PnmConfigManager.get_save_dir()
        self.pnm_local_dir                          = SystemConfigSettings.pnm_dir
        self._capture_parameter:SpecAnCapturePara   = SpecAnCapturePara()
        self._artifact_store                        = PnmArtifactStore(pnm_dir=self.pnm_dir)

        # Initialize default spectrum capture parameters
        self._capture_parameter.spectrum_retrieval_type = SpectrumRetrievalType.UNKNOWN

        if self.extra_options:
            self.logger.debug(f"{self.log_prefix} - OPTIONS: {self.extra_options}")
            self._preload_interface_parameters()

        self._precheck()

    def _precheck(self) -> None:
        """
        Perform pre-check and ensure the save directory exists.
        """
        self.logger.debug(f'PreCheck: SaveDir: {self.pnm_dir}')
        save_path = Path(self.pnm_dir)
        save_path.mkdir(parents=True, exist_ok=True)

    def _preload_interface_parameters(self) -> None:
        """
        Load optional interface parameters from extra_options dictionary.
        If not present, sets interface_parameters to None.
        """
        self.interface_parameters = self.extra_options.get("interface_parameters", None)

    def setSpectrumCaptureParameters(self, capture_parameter:SpecAnCapturePara) -> None:
        """
        Set the spectrum capture parameters for the measurement.

        TODO: This method may be deprecated in favor of passing parameters directly during initialization.

        Args:
            capture_parameter (SpecAnCapturePara): The spectrum capture parameters.
        """
        self._capture_parameter = capture_parameter

    def getSpectrumCaptureParameters(self) -> SpecAnCapturePara:
        """
        Get the current spectrum capture parameters.

        Returns:
            SpecAnCapturePara: The current spectrum capture parameters.
        """
        return self._capture_parameter

    async def set_and_go(self, interface_parameters: DownstreamOfdmParameters | UpstreamOfdmaParameters | None = None ,
                         max_wait_count: int = 5,) -> MessageResponse:
        """
        Trigger PNM file capture and retrieval based on direction-specific parameters.

        Args:
            interface_parameters (InterfaceParameters, optional):
                The configuration specifying the direction of capture:
                - `DownstreamOfdmParameters`: For OFDM downstream channels.
                - `UpstreamOfdmaParameters`: For OFDMA upstream channels.
                If `None` (default), all channels will be captured.

            max_wait_count (int, optional):
                Maximum seconds to wait for measurement readiness. Default is 5.

        Returns:
            MessageResponse: Result indicating success or failure of the operation.
        """

        ##########################################################
        # Verify that we can connect to the CM via Ping and SNMP
        ##########################################################

        if not self.is_ping_reachable():
            self.logger.error(f"{self.log_prefix} - Unreachable via PING")
            return self.build_send_msg(ServiceStatusCode.UNREACHABLE_PING)

        if not await self.is_snmp_ready():
            self.logger.error(f"{self.log_prefix} - Unreachable via SNMP")
            return self.build_send_msg(ServiceStatusCode.UNREACHABLE_SNMP)

        #########################################################################
        #                   Spectrum Analysis SNMP Return                       #
        #########################################################################

        if self.getSpectrumCaptureParameters().spectrum_retrieval_type == SpectrumRetrievalType.SNMP:
            self.logger.debug(f"{self.log_prefix} - Performing Spectrum Analysis SNMP Amplitude Data")

            #Set Spectrum Analyzer
            __status = await self._generic_spectrum_analyzer_operation()

            if __status[0] != ServiceStatusCode.SUCCESS:
               self.logger.error(f"{self.log_prefix} - Unable to set Spectrum Analyzer Settings")
               return self.build_send_msg(ServiceStatusCode.SPEC_ANALYZER_SET_CONFIG_ERROR)

            # This is a blocking method, it will return SUCCESS or wait till timeout to return an ERROR
            status = await self._check_spectrum_amplitude_data_status()

            if status == ServiceStatusCode.SUCCESS:
                self.logger.info(f"{self.log_prefix} - Spectrum Amplitude Data is READY, collecting amplitude data, may take a while...")
                meas_entries = await self.cm.getDocsIf3CmSpectrumAnalysisMeasEntry()
                segment_power_entries: list[SpectrumAnalysisSnmpSegmentPowerEntry] = []
                if meas_entries:
                    amp_data, segment_power_entries = self._build_snmp_meas_entry_payload(meas_entries)
                else:
                    amp_data = await self.cm.getSpectrumAmplitudeData()
                    segment_power_entries = await self._build_snmp_segment_power_fallback()
                self.logger.info(f"{self.log_prefix} - Spectrum Amplitude Data collection COMPLETE, total bytes: {len(amp_data)}.")
                #################################################################################################
                # Build binary filename and save file - START
                #################################################################################################
                filename = await self._pnm_file_generator(DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA)
                tx_id = self._get_transaction_id_by_filename(filename)
                if not tx_id:
                    self.logger.error(f"{self.log_prefix} - Unable to find Transaction ID for PNM filename: {filename}")
                    return self.build_send_msg(ServiceStatusCode.PNM_FILE_TRANSACTION_ID_NOT_FOUND)

                pnm_dir = SystemConfigSettings.pnm_dir()
                fpath = f"{pnm_dir}/{filename}"
                self.logger.debug(f'SpectrumAmplitudeData: - FNAME: {filename} - Length:{len(amp_data)} - TransactionID: {tx_id}')

                FileProcessor(fpath).write_file(amp_data)
                
                #################################################################################################
                # Build binary filename and save file - END
                #################################################################################################
                capture_para:SpecAnCapturePara = self.getSpectrumCaptureParameters()
                extension_data: dict[str, object] = {
                    f'{CMSE.SPECTRUM_ANALYSIS_SNMP_CAPTURE_PARAMETER}': capture_para.model_dump(),
                    f'{CMSE.SPECTRUM_ANALYSIS_SNMP_SEGMENT_POWER}': [
                        entry.model_dump() for entry in segment_power_entries
                    ],
                }
                self.build_transaction_msg_extension(tx_id, 
                                                     filename, 
                                                     extension=extension_data)

            return self.build_send_msg(status)

        #########################################################################
        # Ensure CM Inet and TFTP server address use the same IP version
        #
        # The TFTP server address must match the IP version (IPv4 or IPv6) used
        # by the Cable Modem (CM). By default, we assume IPv4.
        #
        # If the CM's IP address is IPv6 and matches the version of the
        # secondary TFTP server entry, we switch to using the IPv6 TFTP server.
        #
        # TODO: Enhance this logic to support dual-stack (dual-home) cable modems,
        # where both IPv4 and IPv6 may be valid simultaneously.
        #########################################################################

        self.logger.info(f'{self.log_prefix} - TFTP-SERVERS: ({self.tftp_servers[0]} | {self.tftp_servers[1].inet})')

        # Default to using the IPv4 TFTP server
        tftp_server: Inet = self.tftp_servers[0]

        # Switch to IPv6 TFTP server if CM uses IPv6
        if self.cm.same_inet_version(self.tftp_servers[1]):
            tftp_server = self.tftp_servers[1]

        # Attempt to configure the CM with the selected TFTP server and path
        if not await self.cm.setDocsPnmBulk(tftp_server.inet, self.tftp_path):
            self.logger.error(
                f"{self.log_prefix} - Unable to set TFTP server {tftp_server.inet} "
                f"or TFTP path: {self.tftp_path}")
            return self.build_send_msg(ServiceStatusCode.TFTP_SERVER_PATH_SET_FAIL)

        ##############################################################################################
        # This section is determine by the direction due to which interface and type we are accessing
        ##############################################################################################

        status_index_channelId = await self._get_indexes_via_pnm_test_type(interface_parameters)
        self.logger.info(f'{self.log_prefix} - Index/ChannelID List: {status_index_channelId[1]}')
        if status_index_channelId[0] != ServiceStatusCode.SUCCESS or status_index_channelId[1] is None:
            self.logger.error(f'{self.log_prefix} - Unable to aquire index from ChannelID, reason: {status_index_channelId[0]}')
            return self.build_send_msg(status_index_channelId[0])

        ##############################################################################################
        # This section runs through all the indexes, build PNM file, run measurement and check status
        ##############################################################################################
        index_channelId: list[tuple[InterfaceIndex, ChannelId]] = status_index_channelId[1]
        return self.build_send_msg(await self._pnm_measure_status_and_pnm_file_transfer(index_channelId, max_wait_count))

    def getInterfaceParameters(self,
        interface_type: DocsisIfType) -> DownstreamOfdmParameters | UpstreamOfdmaParameters:
        """
        Instantiate and return the PNM test parameters for the specified DOCSIS interface.

        Args:
            interface_type (DocsisIfType):
                The DOCSIS interface type:
                - `DocsisIfType.docsOfdmDownstream` → returns DownstreamOfdmParameters
                - `DocsisIfType.docsOfdmaUpstream`  → returns UpstreamOfdmaParameters

        Returns:
            Union[DownstreamOfdmParameters, UpstreamOfdmaParameters]:
                A parameters object tailored to the requested interface.

        Raises:
            ValueError: If `interface_type` is not OFDM downstream or OFDMA upstream.
        """
        if interface_type == DocsisIfType.docsOfdmDownstream:
            return DownstreamOfdmParameters()
        if interface_type == DocsisIfType.docsOfdmaUpstream:
            return UpstreamOfdmaParameters()

        raise ValueError(
            f"Unsupported interface type: {interface_type!r}. "
            "Expected docsOfdmDownstream or docsOfdmaUpstream."
        )

    def is_ping_reachable(self) -> bool:
        """
        Check if the cable modem is reachable via ICMP ping.

        Returns:
            bool: True if the modem responds to ping, False otherwise.
        """
        return self.cm.is_ping_reachable()

    async def is_snmp_ready(self) -> bool:
        """
        Asynchronously check if the cable modem is accessible via SNMP.

        Returns:
            bool: True if the modem responds to SNMP queries, False otherwise.
        """
        return await self.cm.is_snmp_reachable()

    async def _filter_measurement_entries(
        self,
        entries: list[MeasurementEntry],
        channel_ids: list[ChannelId] | None,
    ) -> list[MeasurementEntry]:
        if not channel_ids:
            return entries

        channel_id_set = {int(channel_id) for channel_id in channel_ids}
        index_set: set[int] = set()

        if self.pnm_test_type in (
            DocsPnmCmCtlTest.DS_CONSTELLATION_DISP,
            DocsPnmCmCtlTest.DS_OFDM_CHAN_EST_COEF,
            DocsPnmCmCtlTest.DS_OFDM_CODEWORD_ERROR_RATE,
            DocsPnmCmCtlTest.DS_OFDM_MODULATION_PROFILE,
            DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR,
        ):
            idx_channel_id = await self.cm.getDocsIf31CmDsOfdmChannelIdIndexStack()
            index_set = {int(idx) for idx, channel_id in idx_channel_id if int(channel_id) in channel_id_set}

        elif self.pnm_test_type == DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF:
            idx_channel_id = await self.cm.getDocsIf31CmUsOfdmaChannelIdIndexStack()
            index_set = {int(idx) for idx, channel_id in idx_channel_id if int(channel_id) in channel_id_set}

        filtered: list[MeasurementEntry] = []
        for entry in entries:
            if isinstance(entry, (DocsPnmCmDsHistEntry, DocsIf3CmSpectrumAnalysisEntry)):
                continue
            if index_set:
                if int(entry.index) in index_set:
                    filtered.append(entry)
                continue
            if not hasattr(entry, "channel_id"):
                continue
            if int(entry.channel_id) in channel_id_set:
                filtered.append(entry)
        return filtered

    async def getPnmMeasurementStatistics(
        self,
        channel_ids: list[ChannelId] | None = None,
    ) -> list[MeasurementEntry]:
        """
        Retrieve PNM measurement entries for the currently configured `pnm_test_type`.

        Returns
        -------
        List[MeasurementEntry]
            A (possibly empty) list of model instances corresponding to the active
            test type:

            - DS_OFDM_CHAN_EST_COEF             → List[DocsPnmCmOfdmChanEstCoefEntry]
            - DS_CONSTELLATION_DISP             → List[DocsPnmCmDsConstDispMeasEntry]
            - DS_OFDM_RXMER_PER_SUBCAR          → List[DocsPnmCmDsOfdmRxMerEntry]
            - US_PRE_EQUALIZER_COEF             → List[DocsPnmCmUsPreEqEntry]
            - DS_HISTOGRAM                      → List[DocsPnmCmDsHistEntry]
            - DS_OFDM_FEC_SUMMARY               → List[DocsPnmCmDsOfdmFecEntry]
            - DS_OFDM_MODULATION_PROFILE        → List[DocsPnmCmDsOfdmModProfEntry]
            - SPECTRUM_ANALYZER                 → List[DocsIf3CmSpectrumAnalysisEntry]
            - SPECTRUM_ANALYZER_SNMP_AMP_DATA   → List[DocsIf3CmSpectrumAnalysisEntry]

            For other (stub/unsupported) test types, an empty list is returned.

        Notes
        -----
        - This method performs no aggregation; it returns the raw per-entry models
          fetched from the cable modem for the selected measurement type.
        - For strict typing, concrete lists are cast to `List[MeasurementEntry]`
          at return points (because `List` is invariant in the type system).
        - If `channel_ids` is provided and not empty, results are filtered to only
          include entries whose `channel_id` is in the list.
        """
        entries: list[MeasurementEntry] = []

        if self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER:
            self.logger.debug(f"{self.log_prefix} - Running SPECTRUM_ANALYZER")
            concrete = await self.cm.getDocsIf3CmSpectrumAnalysisEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_CHAN_EST_COEF:
            self.logger.debug(f"{self.log_prefix} - Running OFDM Channel Estimation Coefficient collection")
            concrete = await self.cm.getDocsPnmCmOfdmChanEstCoefEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_CONSTELLATION_DISP:
            self.logger.debug(f"{self.log_prefix} - Running OFDM Constellation Display collection")
            concrete = await self.cm.getDocsPnmCmDsConstDispMeasEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR:
            self.logger.debug(f"{self.log_prefix} - Running RXMER entry collection")
            concrete = await self.cm.getDocsPnmCmDsOfdmRxMerEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_CODEWORD_ERROR_RATE:
            self.logger.debug(f"{self.log_prefix} - Running DS_OFDM_CODEWORD_ERROR_RATE")
            concrete = await self.cm.getDocsPnmCmDsOfdmFecEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_HISTOGRAM:
            self.logger.debug(f"{self.log_prefix} - Running DS_HISTOGRAM")
            concrete = await self.cm.getDocsPnmCmDsHistEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF:
            self.logger.debug(f"{self.log_prefix} - Running Upstream Pre-Equalization entry collection")
            concrete = await self.cm.getDocsPnmCmUsPreEqEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_MODULATION_PROFILE:
            self.logger.debug(f"{self.log_prefix} - Running DS_OFDM_MODULATION_PROFILE")
            concrete = await self.cm.getDocsPnmCmDsOfdmModProfEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA:
            self.logger.debug(f"{self.log_prefix} - Running SPECTRUM_ANALYZER_SNMP_AMP_DATA")
            concrete = await self.cm.getDocsIf3CmSpectrumAnalysisEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_SYMBOL_CAPTURE:
            self.logger.warning(f"{self.log_prefix} - Stub handler: DS_OFDM_SYMBOL_CAPTURE")

        elif self.pnm_test_type == DocsPnmCmCtlTest.LATENCY_REPORT:
            self.logger.warning(f"{self.log_prefix} - Stub handler: LATENCY_REPORT")

        else:
            self.logger.warning(f"{self.log_prefix} - Unknown PNM test type: {self.pnm_test_type}")

        return entries

    ###################
    # Private Methods #
    ###################

    async def _get_and_move_pnm_file(
        self,
        pnm_file_name: FileNameStr,
    ) -> tuple[ServiceStatusCode, ArtifactCommitResult | None]:
        """
        Retrieves and moves the specified PNM file based on the configured retrieval method.

        This method delegates the file retrieval operation to a protocol-specific handler method
        depending on the configuration defined under `PnmFileRetrieval.method`. 
        Supported methods include: "local", "tftp", "sftp"
        # TODO: Need to implement, not sure if we need to: "ftp", "http", and "https".

        Configuration keys used:
            - PnmFileRetrieval.method: The file retrieval method to use (e.g., "local", "tftp", etc.).
            - PnmFileRetrieval.retries: Optional number of retries for retrieval attempts (currently unused here).

        Args:
            pnm_file_name (str): The name of the file to retrieve and move.

        Returns:
            Tuple[ServiceStatusCode, ArtifactCommitResult | None]:
                Status code plus commit metadata when the file is stored locally.
        """
        method = SystemConfigSettings.retrieval_method()
        self.logger.info(f"{self.log_prefix} - Retrieval method: {method}")
        trans_id = self._get_transaction_id_by_filename(str(pnm_file_name))
        if not trans_id:
            self.logger.warning("%s - Transaction ID not found for %s", self.log_prefix, pnm_file_name)
        ingress_path = self._artifact_store.ingress_path(pnm_file_name, trans_id)

        try:
            if method == "local":
                status = await self._handle_local_fetch(pnm_file_name, ingress_path)
            elif method == "tftp":
                status = self._handle_tftp_fetch(pnm_file_name, ingress_path)
            elif method == "ftp":
                status = self._handle_ftp_fetch(pnm_file_name, ingress_path)
            elif method == "sftp":
                status = self._handle_sftp_fetch(pnm_file_name, ingress_path)
            elif method == "http":
                status = self._handle_http_fetch(pnm_file_name)
            elif method == "https":
                status = self._handle_https_fetch(pnm_file_name)
            else:
                self.logger.error(f"{self.log_prefix} - Unsupported retrieval method: {method}")
                return ServiceStatusCode.FILE_RETRIEVAL_TYPE_INVALID, None

        except Exception as e:
            self.logger.exception(f"{self.log_prefix} - File retrieval failed: {e}")
            return ServiceStatusCode.PNM_FILE_RETRIEVAL_ERROR, None

        if status != ServiceStatusCode.SUCCESS:
            return status, None

        try:
            result = self._artifact_store.commit_ingress_file(
                pnm_type=self.pnm_test_type.name.lower(),
                ingress_path=ingress_path,
                original_filename=pnm_file_name,
            )
        except Exception as exc:
            self.logger.error("%s - Artifact commit failed: %s", self.log_prefix, exc)
            return ServiceStatusCode.COPY_PNM_FILE_TO_LOCAL_SAVE_DIR_FAILED, None

        if trans_id:
            updated = PnmFileTransaction().update_record_compression(
                trans_id,
                result.stored_filename,
                result.compression,
            )
            if not updated:
                return ServiceStatusCode.TRANSACTION_RECORD_SET_FAILED, None

        return ServiceStatusCode.SUCCESS, result

    async def _get_indexes_via_pnm_test_type(self, ifParameters: DownstreamOfdmParameters | UpstreamOfdmaParameters | None = None
                                             ) -> tuple[ServiceStatusCode, list[tuple[InterfaceIndex, ChannelId]] | None]:
        """
        Determines the appropriate interface indexes and channel IDs to target for a given PNM test type.

        Depending on the configured PNM test type, this method selects the relevant interface and filters the index/ChannelID
        tuples based on user-specified parameters.

        Args:
            interface_parameters (Optional[InterfaceParameters]): Parameters specifying interface type ("ofdm" or "ofdma")
                and optionally a list of channel IDs to filter. If not provided, default parameters are selected based on test type.

        Returns:
            Tuple[ServiceStatusCode, Optional[List[Tuple[int, int]]]]:
                A status code indicating success or reason for failure, and a list of (index, channelId) tuples.
        """

        if ifParameters is None:
            ifParameters = DownstreamOfdmParameters()

        if not ifParameters:
            ifParameters = self.getInterfaceParameters(DocsisIfType.docsOfdmDownstream)

        if self.pnm_test_type in (DocsPnmCmCtlTest.DS_HISTOGRAM, DocsPnmCmCtlTest.LATENCY_REPORT):
            idx:list[InterfaceIndex] = await self.cm.getIfTypeIndex(DocsisIfType.docsCableMaclayer)
            return ServiceStatusCode.SUCCESS, [(idx[0], ChannelId(0))]

        elif self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER:
            return ServiceStatusCode.SUCCESS, [(InterfaceIndex(0), ChannelId(0))]

        elif self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA:
            return ServiceStatusCode.SUCCESS, [(InterfaceIndex(0), ChannelId(0))]

        elif self.pnm_test_type in (DocsPnmCmCtlTest.DS_CONSTELLATION_DISP,
                                    DocsPnmCmCtlTest.DS_OFDM_CHAN_EST_COEF,
                                    DocsPnmCmCtlTest.DS_OFDM_CODEWORD_ERROR_RATE,
                                    DocsPnmCmCtlTest.DS_OFDM_MODULATION_PROFILE,
                                    DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR):

            if not ifParameters:
                ifParameters = self.getInterfaceParameters(DocsisIfType.docsOfdmDownstream)

        elif self.pnm_test_type in (DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF,):
            ifParameters = self.getInterfaceParameters(DocsisIfType.docsOfdmaUpstream)
            self.logger.debug(f'{DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF} Measurement - IfParameters: {ifParameters.model_dump()}')

        '''
        There is redundant code, but incase I may need to change due to
        change of requiments depending on Downstream vs. Upstream

        TODO: lol, I am sure I will not revisit, but OK for now.
        '''
        if ifParameters.type == "ofdm":
            channel_id_list = ifParameters.channel_id
            idx_channelId = await self.cm.getDocsIf31CmDsOfdmChannelIdIndexStack()

            if not idx_channelId:
                self.logger.warning("No OFDM channel data found.")
                return ServiceStatusCode.NO_OFDMA_CHAN_ID_INDEX_FOUND, []

            if channel_id_list:
                filtered = [tpl for tpl in idx_channelId if tpl[1] in channel_id_list]
                self.logger.debug(f'Downstream: {ifParameters.type} -> ChanID(s): {channel_id_list} -> Filtered: {filtered}')
                return ServiceStatusCode.SUCCESS, filtered

            self.logger.info(f'Downstream: {ifParameters.type} -> IDX,CHAN_ID: {idx_channelId}')

            return ServiceStatusCode.SUCCESS, idx_channelId

        elif ifParameters.type == "ofdma":
            channel_id_list = ifParameters.channel_id
            idx_channelId = await self.cm.getDocsIf31CmUsOfdmaChannelIdIndexStack()
            if not idx_channelId:
                self.logger.warning("No OFDMA channel found.")
                return ServiceStatusCode.NO_OFDMA_CHAN_ID_INDEX_FOUND, []

            if channel_id_list:
                filtered = [tpl for tpl in idx_channelId if tpl[1] in channel_id_list]
                self.logger.info(f'Upstream: {ifParameters.type} -> ChanID(s): {channel_id_list} -> Filtered: {filtered}')
                return ServiceStatusCode.SUCCESS, filtered

            self.logger.info(f'Upstream: {ifParameters.type} -> IDX,CHAN_ID: {idx_channelId}')

        return ServiceStatusCode.SUCCESS, idx_channelId

    async def _pnm_measure_status_and_pnm_file_transfer(self, idx_channelId:list[tuple[InterfaceIndex, ChannelId]], max_wait_count:int) -> ServiceStatusCode:
        """
        Set and monitor the OFDM measurement test for specified (index, PLC) tuples.

        For each (index, PLC) pair:
            - Initiates the PNM test using SNMP.
            - Waits for the test status to reach READY.
            - Monitors for the measurement status to become SAMPLE_READY.
            - Retrieves the resulting PNM file and stores it locally.

        Args:
            idx_channelId (Tuple[int, int]): A list of tuples where each tuple consists of
                the SNMP interface index and the corresponding PLC (center frequency).
            max_wait_count (int): Maximum number of seconds to wait for SAMPLE_READY status.

        Returns:
            ServiceStatusCode: SUCCESS if all steps completed successfully,
                otherwise a specific error status (e.g., if the file couldn't be retrieved
                or the measurement status did not become SAMPLE_READY).
        """
        for interface_index, channel_id in idx_channelId:

            #######################################################################
            # This sets the Measurement Table/Row for the specific PNM Measurement
            #######################################################################
            ctl_measure_status:tuple[ServiceStatusCode, list[FileNameStr]] = \
                await self._setDocsPnmCmMeasureTest(self.pnm_test_type, interface_index, channel_id)
            
            if ctl_measure_status[0] != ServiceStatusCode.SUCCESS:
                return ctl_measure_status[0]

            pnm_filenames = ctl_measure_status[1]
            self.logger.info(f'{self.log_prefix} - PNM File(s) -> {pnm_filenames}')

            count=1
            while True:
                cm_ctl_status:DocsPnmCmCtlStatus = await self.cm.getDocsPnmCmCtlStatus()
                self.logger.info(f"{self.log_prefix} - PNM status: {str(cm_ctl_status).upper()} - count: {count}")
                if cm_ctl_status == DocsPnmCmCtlStatus.TEST_IN_PROGRESS:
                    count += 1
                    await asyncio.sleep(1)
                    continue

                if cm_ctl_status == DocsPnmCmCtlStatus.READY:
                    break

                if cm_ctl_status == DocsPnmCmCtlStatus.TEMP_REJECT:
                    break

                if cm_ctl_status == DocsPnmCmCtlStatus.SNMP_ERROR:
                    break

            self.logger.debug(f"{self.log_prefix} - Checking Measurement Status for {self.pnm_test_type} @ IDX: {interface_index}")

            wait_count = 0
            def extract_idx(idx):
                return idx[0] if isinstance(idx, list) and idx else idx

            while wait_count < max_wait_count:
                meas_status = await self.cm.getPnmMeasurementStatus(self.pnm_test_type, extract_idx(interface_index))
                self.logger.info(f"{self.log_prefix} - MeasureStatus: {meas_status.name}")
                if meas_status == MeasStatusType.SAMPLE_READY:
                    break
                await asyncio.sleep(1)
                wait_count += 1

            else:
                self.logger.error(f"{self.log_prefix} - SAMPLE_READY not reached for ChannelID {channel_id}")
                return ServiceStatusCode.NOT_READY_AFTER_FILE_CAPTURE

            #Multiple PNM files for special cases
            for pnm_fname in pnm_filenames:

                status:ServiceStatusCode = await self._check_and_wait_for_tftp_upload(FileNameStr(pnm_fname))

                if status != ServiceStatusCode.SUCCESS:
                    self.logger.error(f"{self.log_prefix} - Unable to Upload PNM File to TFTP({status})")
                    return status

                # Get and copy PNM file to local data directory
                retrieval_status, commit_result = await self._get_and_move_pnm_file(FileNameStr(pnm_fname))
                if retrieval_status != ServiceStatusCode.SUCCESS or commit_result is None:
                    self.logger.error(
                        f"{self.log_prefix} - Unable to copy PNM file to local {self.pnm_dir} dir "
                        f"(status={retrieval_status})")
                    return retrieval_status

                # Find Transaction ID via filename
                trans_id = self._get_transaction_id_by_filename(pnm_fname)
                if not trans_id:
                    self.logger.error(f"{self.log_prefix} - Unable to find Transaction ID for PNM filename: {pnm_fname}")
                    return ServiceStatusCode.PNM_FILE_TRANSACTION_ID_NOT_FOUND
                
                stored_name = commit_result.stored_filename
                self.logger.debug(f'{self.log_prefix} - TransID: {trans_id} -> Filename: {stored_name}')
                self.build_transaction_msg(trans_id, stored_name)

        return ServiceStatusCode.SUCCESS

    async def _check_and_wait_for_tftp_upload(self, filename: str, max_wait_count: int = 5) -> ServiceStatusCode:
        """
        Waits for a PNM file to be uploaded via TFTP by polling the upload status.

        Args:
            filename (str): The name of the file being uploaded.
            max_wait_count (int): Maximum number of seconds to wait before timing out.

        Returns:
            ServiceStatusCode: SUCCESS if upload completed, failure code otherwise.
        """
        wait_count = 0

        while wait_count < max_wait_count:
            try:
                status = await self.cm.getBulkFileUploadStatus(filename)
            except Exception as e:
                self.logger.error(f"{self.log_prefix} - Error checking upload status for '{filename}': {e}")
                return ServiceStatusCode.TFTP_PNM_FILE_UPLOAD_FAILURE

            if status == DocsPnmBulkFileUploadStatus.UPLOAD_COMPLETED:
                self.logger.info(f"{self.log_prefix} - File '{filename}' uploaded successfully.")
                return ServiceStatusCode.SUCCESS

            if status == DocsPnmBulkFileUploadStatus.ERROR:
                self.logger.error(f"{self.log_prefix} - Device reported ERROR for file upload '{filename}'.")
                return ServiceStatusCode.TFTP_PNM_FILE_UPLOAD_FAILURE

            self.logger.debug(
                f"{self.log_prefix} - Waiting for file '{filename}' to upload "
                f"(status={status.name}, wait_count={wait_count})"
            )

            await asyncio.sleep(1)
            wait_count += 1

        self.logger.error(f"{self.log_prefix} - TFTP file '{filename}' upload timed out after {max_wait_count} seconds.")
        return ServiceStatusCode.TFTP_PNM_FILE_UPLOAD_FAILURE

    async def _setDocsPnmCmMeasureTest(self, pnm_test_type:DocsPnmCmCtlTest,
                                       interface_index:int, channel_id:ChannelId) -> tuple[ServiceStatusCode, list[FileNameStr]]:
        """
        Configure and trigger a specific PNM (Proactive Network Maintenance) measurement
        test on a cable modem based on the test type.

        Depending on the `pnm_test_type`, this method:
        - Generates appropriate output file names.
        - Uses SNMP to set the modem to collect specific diagnostic data.
        - Handles various DOCSIS downstream and upstream tests, including:
            - US Pre-Equalizer Coefficients (requires two files per interface: pre-eq and last pre-eq)
            - DS OFDM RxMER per Subcarrier
            - DS OFDM Codeword Error Rate
            - DS OFDM Channel Estimation Coefficients
            - DS Constellation Display
            - DS Histogram
            - DS OFDM Modulation Profile
            - Spectrum Analyzer Scan

        Parameters:
            pnm_test_type (DocsPnmCmCtlTest): Enum value indicating the PNM test to perform.
            interface_index (int): The SNMP index for the OFDM channel (usually the interface index).
            channel_id (int): The channel ID associated with the modem interface.

        Returns:
            Tuple[ServiceStatusCode, List[str]]: Status of the operation and list of generated file names.
        """
        pnm_files: list[FileNameStr] = []

        if pnm_test_type == DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF:

            # Pre-Eq and Last Pre-EQ (2 files)
            pre_eq_filename         = await self._pnm_file_generator(self.pnm_test_type, str(channel_id))
            last_pre_eq_filename    = await self._pnm_file_generator(self.pnm_test_type, f'last_pre-eq_{str(channel_id)}')

            self.logger.info(f'{self.log_prefix} - Setting {self.pnm_test_type} for ChannelID: {channel_id} "'
                             f'@ IDX: {interface_index} -> FN(): {pre_eq_filename}, FN(last): {last_pre_eq_filename}')

            self.logger.info(f'{self.log_prefix} - Performing US_PRE_EQUALIZER_COEF measurement on IDX: ({interface_index})')
            if not await self.cm.setDocsPnmCmUsPreEq(ofdma_idx              =   interface_index,
                                                     filename               =   pre_eq_filename,
                                                     last_pre_eq_filename   =   last_pre_eq_filename):
                self.logger.error(f"{self.log_prefix} - Upstream OFDMA Pre-Equalization is Not Avalaible")
                return ServiceStatusCode.FILE_SET_FAIL, []

            #Append files for later fetching
            pnm_files.extend([pre_eq_filename, last_pre_eq_filename])

        else:
            #The remaining PNM Measuresurement are single PNM file
            pnm_filename = await self._pnm_file_generator(self.pnm_test_type, str(channel_id))
            self.logger.debug(f'{self.log_prefix} - Setting {self.pnm_test_type} for ChannelID: {channel_id} @ IDX: {interface_index} -> FN: {pnm_filename}')
            pnm_files.append(pnm_filename)

            if pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR:

                if not await self.cm.setDocsPnmCmDsOfdmRxMer(ofdm_idx=interface_index, rxmer_file_name=pnm_filename):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_CODEWORD_ERROR_RATE:

                fst = self.extra_options.get("fec_summary_type", FecSummaryType.TEN_MIN)

                if not await self.cm.setDocsPnmCmDsOfdmFecSum(ofdm_idx=interface_index, fec_sum_file_name=pnm_filename, fec_sum_type=fst):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_CHAN_EST_COEF:

                if not await self.cm.setDocsPnmCmOfdmChEstCoef(ofdm_idx=interface_index, chan_est_file_name=pnm_filename):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.DS_CONSTELLATION_DISP:
                # OFDM Downstream Constellation Display setup
                # Extra SNMP options may include:
                #   - modulation_offset: Optional[int]
                #   - num_sample_symb: Optional[int]
                if not await self.cm.setDocsPnmCmDsConstDisp(
                    ofdm_idx                =   interface_index,
                    const_disp_name         =   pnm_filename,
                    modulation_order_offset =   self.extra_options.get('modulation_order_offset', 0),
                    number_sample_symbol    =   self.extra_options.get('number_sample_symbol', 0)
                ):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.DS_HISTOGRAM:
                sample_duration = self.extra_options.get("histogram_sample_duration", 10)
                if not await self.cm.setDocsPnmCmDsHist(ds_histogram_file_name=pnm_filename, timeout=sample_duration):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_MODULATION_PROFILE:

                if not await self.cm.setDocsPnmCmDsOfdmModProf(ofdm_idx=interface_index, mod_prof_file_name=pnm_filename):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER:
                #Created generic to be used for PNM File and SNMP Return data
                 __status = await self._generic_spectrum_analyzer_operation(filename=pnm_filename)
                 if __status[0] != ServiceStatusCode.SUCCESS:
                    return __status

        return ServiceStatusCode.SUCCESS, pnm_files

    async def _check_spectrum_amplitude_data_status(self, timeout_seconds: int = 300) -> ServiceStatusCode:
        """
        Polls the cable modem for spectrum amplitude data availability within a timeout period.

        This method repeatedly checks if `docsIf3CmSpectrumAnalysisMeasAmplitudeData` is present
        on the modem, and returns a success or timeout status accordingly.

        Args:
            timeout_seconds (int): Maximum number of seconds to wait before timing out. Default is 300.

        Returns:
            ServiceStatusCode:
                - SUCCESS if data becomes available within the timeout period.
                - SPEC_ANALYZER_AMPLITUDE_DATA_TIMEOUT if the timeout is exceeded.
        """
        t_start = time.time()

        while True:
            if await self.cm.isAmplitudeDataPresent():
                return ServiceStatusCode.SUCCESS
            now:int = math.floor(time.time() - t_start)

            if now >= timeout_seconds:
                self.logger.warning(f'{self.log_prefix} - Timeout for Amplitude Data ({now} of {timeout_seconds} seconds)')
                return ServiceStatusCode.SPEC_ANALYZER_AMPLITUDE_DATA_TIMEOUT

            self.logger.info(f'{self.log_prefix} - Waiting for Amplitude Data ({now} of {timeout_seconds})')

            await asyncio.sleep(1)

    @staticmethod
    def _build_snmp_meas_entry_payload(
        entries: list[DocsIf3CmSpectrumAnalysisMeasEntry],
    ) -> tuple[bytes, list[SpectrumAnalysisSnmpSegmentPowerEntry]]:
        """
        Build SNMP spectrum analyzer payloads from measurement entries.

        Parameters
        ----------
        entries : list[DocsIf3CmSpectrumAnalysisMeasEntry]
            Measurement entries containing amplitude data and total segment power.

        Returns
        -------
        tuple[bytes, list[SpectrumAnalysisSnmpSegmentPowerEntry]]
            Concatenated amplitude data bytes and segment power entries.
        """
        amp_chunks: list[bytes] = []
        segment_frequencies: list[FrequencyHz] = []
        segment_powers: list[PowerdBmV] = []
        for entry in entries:
            amp_chunks.append(entry.entry.docsIf3CmSpectrumAnalysisMeasAmplitudeData)
            segment_frequencies.append(entry.entry.docsIf3CmSpectrumAnalysisMeasFrequency)
            segment_powers.append(
                PowerdBmV(math.trunc(float(entry.entry.docsIf3CmSpectrumAnalysisMeasTotalSegmentPower) * 10) / 10),
            )
        segment_power = SpectrumAnalysisSnmpSegmentPowerEntry(
            segment_frequencies=segment_frequencies,
            power_dbmv=segment_powers,
        )
        return b"".join(amp_chunks), [segment_power]

    async def _build_snmp_segment_power_fallback(self) -> list[SpectrumAnalysisSnmpSegmentPowerEntry]:
        values = await self.cm.getSpectrumMeasTotalSegmentPower()
        if not values:
            return []
        self.logger.warning(
            "%s - Using total segment power fallback without frequency mapping.",
            self.log_prefix,
        )
        segment_frequencies: list[FrequencyHz] = []
        segment_powers: list[PowerdBmV] = []
        for idx, power in values:
            segment_frequencies.append(FrequencyHz(int(idx)))
            segment_powers.append(PowerdBmV(math.trunc(float(power) * 10) / 10))
        return [SpectrumAnalysisSnmpSegmentPowerEntry(
            segment_frequencies=segment_frequencies,
            power_dbmv=segment_powers,
        )]

    async def _handle_local_fetch(self, pnm_file_name: str, dest_path: Path) -> ServiceStatusCode:
        """
        Handles copying a specified PNM file from a local source directory to a configured save directory.

        This method looks up the source and destination paths from the application's system configuration
        (under the "PnmFileRetrieval" section) and attempts to copy the file named `pnm_file_name`
        from the source directory to the save directory.

        Configuration keys used:
            - PnmFileRetrieval.local.src_dir: Source directory where the PNM file resides.
            - PnmFileRetrieval.save_dir: Destination directory where the file should be saved.

        Args:
            pnm_file_name (str): The name of the file to copy.

        Returns:
            bool: True if the file was successfully copied; False otherwise.
        """

        src_dir = SystemConfigSettings.local_src_dir()

        self.logger.info(
            f'{self.log_prefix} - Local Copy - SRC: {src_dir} - SAVE: {dest_path} - FN: {pnm_file_name}'
        )

        if not os.path.isdir(src_dir) or not os.path.isdir(dest_path.parent):
            self.logger.error(f"{self.log_prefix} - Invalid source or destination directory")
            return ServiceStatusCode.LOCAL_FETCH_FAILURE

        while True:
            await asyncio.sleep(1)
            file_found = False
            for filename in os.listdir(src_dir):
                if filename == pnm_file_name:
                    file_found = True
                    src_path = os.path.join(src_dir, filename)
                    try:
                        shutil.copy2(src_path, dest_path)
                        self.logger.debug(f"{self.log_prefix} - Copied {filename} to {dest_path}")
                        return ServiceStatusCode.SUCCESS
                    except Exception as e:
                        self.logger.error(f"{self.log_prefix} - Copy failed for {filename}: {e}")
                        return ServiceStatusCode.LOCAL_FETCH_FAILURE

            if not file_found:
                self.logger.warning(f"{self.log_prefix} - File not found in source directory: {pnm_file_name}")

            return ServiceStatusCode.LOCAL_FETCH_FAILURE

    def _handle_sftp_fetch(self, pnm_file_name: FileNameStr, dest_path: Path) -> ServiceStatusCode:
        """
        Fetch a file from remote SFTP server.

        Args:
            pnm_file_name: Name of the file to fetch from remote server

        Returns:
            bool: True if file transfer successful, False otherwise
        """
        sys_config = SystemConfigSettings()

        self.logger.debug(f"{self.log_prefix} - SFTP: Connecting to: {sys_config.sftp_host()}")

        if self._ping_pnm_file_server(HostNameStr(sys_config.sftp_host())) != ServiceStatusCode.SUCCESS:
            self.logger.error(f"{self.log_prefix} - Ping failed for SFTP host: {sys_config.sftp_host()}")
            return ServiceStatusCode.SFTP_HOST_UNREACHABLE

        sftp = SSHConnector(
            hostname        =   sys_config.sftp_host(),
            username        =   sys_config.sftp_user(),
            port            =   sys_config.sftp_port())

        password_enc     = sys_config.sftp_password()
        private_key_path = sys_config.sftp_private_key_path()

        try:
            if not sftp.connect(password_enc     =   password_enc,
                                private_key_path =   private_key_path):
                self.logger.error(f'{self.log_prefix} - SFTP Connect Failure: Host: {sys_config.sftp_host()}')
                return ServiceStatusCode.SFTP_PNM_FILE_FETCH_ERROR

            remote_file_path = f'{sys_config.sftp_remote_dir()}/{pnm_file_name}'
            if not sftp.receive_file(remote_path =   remote_file_path,
                                     local_path  =   str(dest_path.parent)):
                self.logger.error(
                    f'{self.log_prefix} - SFTP Receive File Error '
                    f'(SRC:{remote_file_path} DST: {sys_config.pnm_dir()})'
                )
                return ServiceStatusCode.SFTP_PNM_FILE_FETCH_ERROR

            self.logger.info(f'{self.log_prefix} - Successfully fetched file: {pnm_file_name}')
            return ServiceStatusCode.SUCCESS

        except Exception as e:
            self.logger.error(f'{self.log_prefix} - SFTP Fetch Exception: {e}')
            return ServiceStatusCode.SFTP_PNM_FILE_FETCH_ERROR

        finally:
            sftp.disconnect()

    def _handle_tftp_fetch(self, pnm_file_name: FileNameStr, dest_path: Path) -> ServiceStatusCode:
        """
        Fetch the specified PNM file via TFTP.

        Assumes the following attributes on self:
        - self.pnm_local_dir (str)    # local directory to save the downloaded file
        - self.log_prefix (str)       # used for consistent logging

        TFTP settings are read from SystemConfigCommonSettings:
        - tftp_host (str)
        - tftp_port (int)
        - tftp_timeout (int)
        - tftp_remote_dir (str)   # remote directory where PNM files live (if applicable)
        """

        if self._ping_pnm_file_server(HostNameStr(SystemConfigSettings.tftp_host())) != ServiceStatusCode.SUCCESS:
            self.logger.error(f"{self.log_prefix} - Ping failed for TFTP host: {SystemConfigSettings.tftp_host()}")
            return ServiceStatusCode.TFTP_HOST_UNREACHABLE  

        try:
            connector = TFTPConnector(
                host    =   Inet(SystemConfigSettings.tftp_host()),
                port    =   int(str(SystemConfigSettings.tftp_port())))

        except Exception as e:
            self.logger.error(f"{self.log_prefix} - Exception during TFTP connecting: {e}")
            return ServiceStatusCode.TFTP_PNM_FILE_FETCH_ERROR

        try:

            self.logger.info(
                f"{self.log_prefix} - Starting TFTP download from "
                f"{SystemConfigSettings.tftp_host()}:{SystemConfigSettings.tftp_port()}"
            )

            # Build remote filename (some tftp servers require just the basename)
            remote_name = (
                f"{SystemConfigSettings.tftp_remote_dir().rstrip('/')}/{pnm_file_name}"
                if SystemConfigSettings.tftp_remote_dir() else
                pnm_file_name
            )
            success = connector.download_file(remote_name, str(dest_path))

            if not success:
                self.logger.error(
                    f"{self.log_prefix} - TFTP download failed for '{remote_name}'"
                )
                return ServiceStatusCode.TFTP_PNM_FILE_FETCH_ERROR

            self.logger.info(
                f"{self.log_prefix} - Successfully fetched '{pnm_file_name}' via TFTP"
            )
            return ServiceStatusCode.SUCCESS

        except Exception as e:
            self.logger.error(f"{self.log_prefix} - Exception during TFTP downloading: {e}")
            return ServiceStatusCode.TFTP_PNM_FILE_FETCH_ERROR

    def _handle_ftp_fetch(self, pnm_file_name: FileNameStr, dest_path: Path) -> ServiceStatusCode:
        """
        Fetch the specified PNM file via FTP.

        Assumes the following attributes exist on self:
        - self.pnm_local_dir (str)    # local directory to save the downloaded file
        - self.log_prefix (str)       # used for consistent logging

        All FTP-specific settings are read from SystemConfigCommonSettings:
        - ftp_host (str)
        - ftp_port (int)
        - ftp_user (str)
        - ftp_password (str)
        - ftp_use_tls (bool)
        - ftp_timeout (int)
        - ftp_remote_dir (str)   # remote directory where PNM files live
        """
        sys_config = SystemConfigSettings()

        if self._ping_pnm_file_server(HostNameStr(SystemConfigSettings.ftp_host())) != ServiceStatusCode.SUCCESS:
            self.logger.error(f"{self.log_prefix} - Ping failed for FTP host: {SystemConfigSettings.ftp_host()}")
            return ServiceStatusCode.FTP_HOST_UNREACHABLE  

        try:
            connector = FTPConnector(
                host        =   str(sys_config.ftp_host()),
                port        =   int(str(sys_config.ftp_port())),
                username    =   str(sys_config.ftp_user()),
                password    =   str(sys_config.ftp_password()),
                use_tls     =   bool(sys_config.ftp_use_tls()),
                timeout     =   int(str(sys_config.ftp_timeout()))
            )

            self.logger.debug(
                f"{self.log_prefix} - Connecting to FTP server "
                f"{sys_config.ftp_host}:{sys_config.ftp_port}"
            )
            if not connector.connect():
                self.logger.error(f"{self.log_prefix} - FTP connection failed")
                return ServiceStatusCode.FTP_PNM_FILE_FETCH_ERROR

            # Build remote and local paths
            remote_base = sys_config.ftp_remote_dir.rstrip("/") if sys_config.ftp_remote_dir else ""
            remote_path = f"{remote_base}/{pnm_file_name}" if remote_base else pnm_file_name

            self.logger.debug(
                f"{self.log_prefix} - Downloading '{remote_path}' to '{dest_path}'"
            )
            success = connector.download_file(remote_path, str(dest_path))
            connector.disconnect()

            if not success:
                self.logger.error(
                    f"{self.log_prefix} - FTP download failed for '{remote_path}'"
                )
                return ServiceStatusCode.FTP_PNM_FILE_FETCH_ERROR

            self.logger.info(
                f"{self.log_prefix} - Successfully fetched '{pnm_file_name}' via FTP"
            )
            return ServiceStatusCode.SUCCESS

        except Exception as e:
            self.logger.error(f"{self.log_prefix} - Exception during FTP fetch: {e}")
            return ServiceStatusCode.FTP_PNM_FILE_FETCH_ERROR

    def _handle_http_fetch(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        # TODO: implement HTTP file fetch logic
        self.logger.debug(f"{self.log_prefix} - HTTP fetch not yet implemented")
        return ServiceStatusCode.HTTP_PNM_FILE_FETCH_ERROR

    def _handle_https_fetch(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        # TODO: implement HTTPS file fetch logic
        self.logger.debug(f"{self.log_prefix} - HTTPS fetch not yet implemented")
        return ServiceStatusCode.SHTTP_PNM_FILE_FETCH_ERROR
    
    async def _pnm_file_generator(self, test_type: DocsPnmCmCtlTest, suffix: str = "", ext: str = ".bin") -> FileNameStr:
        """
        Generates the PNM file name based on the provided DocsPnmCmCtlTest, with optional suffix and extension.

        Args:
            test_type (DocsPnmCmCtlTest): The type of the test to generate the prefix.
            suffix (str, optional): A suffix added to the file name. Defaults to an empty string.
            ext (str, optional): The file extension. Defaults to ".bin".

        Returns:
            str: The generated PNM file name.
        """
        test_prefix = test_type.name.lower()

        if suffix:
            suffix = f'_{suffix}'

        file_name:FileNameStr = FileNameStr(f"{test_prefix}_{self.cm.get_mac_address.to_mac_format()}{suffix}_{Generate.time_stamp()}{ext}")

        transaction_id = await PnmFileTransaction().insert(self.cm, test_type, file_name)

        self.logger.debug(f"Generated PNM file name: {file_name} -> TransID: {transaction_id}")

        self._transactionId_pnmFile[transaction_id] = file_name

        return file_name

    def _get_transaction_id_by_filename(self, file_name: str) -> TransactionId | None:
        """
        Return the transaction ID associated with the given file name.
        Assumes file names are unique. Returns None if not found.
        """
        for transaction_id, name in self._transactionId_pnmFile.items():
            if name == file_name:
                return TransactionId(transaction_id)
        return None

    async def _generic_spectrum_analyzer_operation(self, filename:str="") -> tuple[ServiceStatusCode, list[str]]:
        """
        Perform a generic spectrum-analyzer operation on the cable modem, supporting two retrieval modes:
        1. SNMP-based amplitude data return (AmplitudeData textual convention)
        2. PNM file return (download via TFTP once the CM writes the file)

        The same set of control parameters (frequency range, bin count, windowing, etc.) is used
        in both cases—avoiding duplicate “control-command” logic (DRY). Downstream, a separate helper
        method is called based on `spectrum_retrieval_type`.

        Extra options (from self.extra_options):
            • inactivity_timeout             (int, default=100)
                - Maximum seconds to wait for the CM to complete the measurement
            • first_segment_center_freq      (int, default=300_000_000)
                - Starting center frequency in Hz
            • last_segment_center_freq       (int, default=900_000_000)
                - Ending center frequency in Hz
            • segment_freq_span              (int, default=7_500_000)
                - Frequency span per segment in Hz
            • num_bins_per_segment           (int, default=256)
                - Number of bins (samples) per segment
            • noise_bw                       (int, default=110)
                - Equivalent noise bandwidth in Hz
            • window_function                (WindowFunction, default=WindowFunction.HANN)
                - Window function to apply to each segment
            • num_averages                   (int, default=1)
                - Number of averages to take
            • spectrum_retrieval_type        (SpectrumRetrievalType, default=SpectrumRetrievalType.FILE)
                - FILE: write to PNM file via TFTP (requires pnm_filename)
                - SNMP: return amplitude data directly via SNMP (no file write)

        Returns:
            Tuple[ServiceStatusCode, List[str]]:
                • On success: (ServiceStatusCode.SUCCESS, [<PNM filename>]) for FILE mode,
                  or (ServiceStatusCode.SUCCESS, []) for SNMP mode.
                • On failure: (ServiceStatusCode.SPEC_ANALYZER_NOT_AVAILABLE, []).

        Raises:
            None directly—errors are mapped to a failure status code.
        """
        self.logger.info(f"{self.log_prefix} - Entering into SPECTRUM-ANALYZER Mode (filename: {filename})")

        # Default: only SNMP control-command, no file write
        ctl_cmd_filename = Snmp_v2c.TRUE

        if (self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER or \
            self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA) and \
            (not self.getSpectrumCaptureParameters()):

            self.logger.error('No Spectrum Parameters Found, did you set: setSpectrumCaptureParameters()')

            return  ServiceStatusCode.NO_SPECTRUM_CAPTURE_PARAMETERS, []

        capture_parameter = self.getSpectrumCaptureParameters()

        if not capture_parameter:

            capture_parameter = SpecAnCapturePara (
                inactivity_timeout          = self.extra_options.get("inactivity_timeout", 100),
                first_segment_center_freq   = self.extra_options.get("first_segment_center_freq", 300_000_000),
                last_segment_center_freq    = self.extra_options.get("last_segment_center_freq", 993_000_000),
                segment_freq_span           = self.extra_options.get("segment_freq_span", 1_000_000),
                num_bins_per_segment        = self.extra_options.get("num_bins_per_segment", 256),
                noise_bw                    = self.extra_options.get("noise_bw", 110),
                window_function             = self.extra_options.get("window_function", WindowFunction.HANN),
                num_averages                = self.extra_options.get("num_averages", 1),
                spectrum_retrieval_type     = self.extra_options.get("spectrum_retrieval_type",SpectrumRetrievalType.FILE),
            )

        if capture_parameter.num_averages != self.SPECTRUM_ANALYZER_AVERAGES_CAP:
            self.logger.warning(
                "%s - Capping spectrum analyzer averages from %s to %s",
                self.log_prefix,
                capture_parameter.num_averages,
                self.SPECTRUM_ANALYZER_AVERAGES_CAP,
            )
            capture_parameter.num_averages = self.SPECTRUM_ANALYZER_AVERAGES_CAP

        if capture_parameter.spectrum_retrieval_type == SpectrumRetrievalType.SNMP:
            self.logger.info(f"{self.log_prefix} - SPECTRUM-ANALYZER - SNMP-AMPLITUDE-DATA-RETURN")
            ctl_cmd_filename = Snmp_v2c.FALSE

        else:
            if not filename:
                self.logger.error(f"{self.log_prefix} - Missing 'filename' for FILE retrieval mode")
                return ServiceStatusCode.MISSING_PNM_FILENAME, []

        spectrum_cmd = DocsIf3CmSpectrumAnalysisCtrlCmd(
            docsIf3CmSpectrumAnalysisCtrlCmdInactivityTimeout           =   capture_parameter.inactivity_timeout,
            docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency =   capture_parameter.first_segment_center_freq,
            docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency  =   capture_parameter.last_segment_center_freq,
            docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan        =   capture_parameter.segment_freq_span,
            docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment           =   capture_parameter.num_bins_per_segment,
            docsIf3CmSpectrumAnalysisCtrlCmdEquivalentNoiseBandwidth    =   capture_parameter.noise_bw,
            docsIf3CmSpectrumAnalysisCtrlCmdWindowFunction              =   capture_parameter.window_function,
            docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages            =   capture_parameter.num_averages,
            docsIf3CmSpectrumAnalysisCtrlCmdEnable                      =   Snmp_v2c.TRUE,
            docsIf3CmSpectrumAnalysisCtrlCmdFileName                    =   filename,
            docsIf3CmSpectrumAnalysisCtrlCmdFileEnable                  =   ctl_cmd_filename,)

        # Issue the SNMP SET for the control-command. The downstream logic
        # (not shown here) will branch to either:
        #   • SNMP:  set FileEnable = FALSE → wait for measurement → walk AmplitudeData
        #   • FILE:  set FileEnable = TRUE  → wait for measurement status → TFTP download
        if not await self.cm.setDocsIf3CmSpectrumAnalysisCtrlCmd(spectrum_cmd,
                                                                 capture_parameter.spectrum_retrieval_type):
            self.logger.error(f"{self.log_prefix} - Spectrum Analyzer is Not Available")
            return ServiceStatusCode.SPEC_ANALYZER_NOT_AVAILABLE, []

        # On success, return the filename (if FILE mode) or an empty list (SNMP mode)
        if capture_parameter.spectrum_retrieval_type == SpectrumRetrievalType.FILE:
            return ServiceStatusCode.SUCCESS, [filename]
        else:
            return ServiceStatusCode.SUCCESS, []

    def _ping_pnm_file_server(self, host: HostNameStr) -> ServiceStatusCode:
        """
        Ping The PNM File Server To Check Its Availability.

        This helper first attempts DNS resolution of the host. If the host
        resolves only to loopback addresses (for example "127.0.0.1" or "::1"),
        ICMP ping is bypassed and the host is treated as reachable so that
        local SCP/SFTP/TFTP retrieval is not blocked by loopback
        misconfiguration.

        If DNS resolution fails entirely, the ping pre-check is skipped and the
        method returns SUCCESS while logging the condition at debug level,
        allowing the subsequent transfer step to provide a more precise error.

        For non-loopback addresses that resolve successfully, a standard ICMP
        ping is issued via HostEndpoint. If the ping fails, PING_FAILED is
        returned.
        """
        endpoint  = HostEndpoint(host)
        addresses = endpoint.resolve()

        if not addresses:
            self.logger.debug(
                f"{self.log_prefix} - DNS lookup failed for host: {host}; "
                "skipping ping pre-check"
            )
            return ServiceStatusCode.SUCCESS

        for addr in addresses:
            if addr.startswith("127.") or addr == "::1":
                self.logger.debug(
                    f"{self.log_prefix} - Host {host} resolved to loopback ({addr}); "
                    "skipping ping pre-check"
                )
                return ServiceStatusCode.SUCCESS

        if endpoint.ping():
            return ServiceStatusCode.SUCCESS

        self.logger.debug(f"{self.log_prefix} - Ping failed for host: {host}")
        return ServiceStatusCode.PING_FAILED
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
from pypnm.lib.types import FileNameStr, MacAddressStr, TransactionId, TransactionRecord
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest
from pypnm.pnm.lib.pnm_artifact_store import PnmArtifactStore
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
        self._artifact_store = PnmArtifactStore(pnm_dir=self.pnm_file_dir)
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

        filename = transaction_record[PnmFileTransaction.FILE_NAME]
        compression = transaction_record.get("compression") if isinstance(transaction_record, dict) else None
        transaction_id = transaction_record.get("transaction_id")
        if not transaction_id:
            self.logger.error("Transaction ID is missing in the transaction record.")
            return ServiceStatusCode.PNM_FILE_TRANSACTION_ID_NOT_FOUND

        txn_id = TransactionId(str(transaction_id))
        file_name_str = FileNameStr(str(filename))
        ingress_candidate = self._artifact_store.ingress_candidate_path(file_name_str, txn_id)
        if ingress_candidate.is_file():
            materialized = ingress_candidate
        else:
            ingress_fallback = self._artifact_store.find_ingress_by_filename(file_name_str)
            if ingress_fallback is not None and ingress_fallback.is_file():
                materialized = ingress_fallback
            else:
                materialized = self._artifact_store.materialize(
                    txn_id,
                    file_name_str,
                    compression,
                )
                if not materialized.is_file():
                    self.logger.error("PNM file not found on disk for transaction %s at %s", transaction_id, materialized)
                    return ServiceStatusCode.PNM_FILE_RETRIEVAL_ERROR

        device_details:dict[str, str] = transaction_record[PnmFileTransaction.DEVICE_DETAILS]
        pnm_data = FileProcessor(str(materialized)).read_file()

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
# FILE: src/pypnm/api/routes/docs/pnm/files/router.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from typing import cast

from fastapi import APIRouter, File, Path, Query, UploadFile
from fastapi.responses import FileResponse, JSONResponse

from pypnm.api.routes.common.classes.common_endpoint_classes.common.enum import (
    OutputType,
)
from pypnm.api.routes.docs.pnm.files.schemas import (
    AnalysisJsonResponse,
    FileAnalysisRequest,
    FileQueryRequest,
    FileQueryResponse,
    HexDumpResponse,
    MacAddressSystemDescriptorResponse,
    UploadFileResponse,
)
from pypnm.api.routes.docs.pnm.files.service import PnmFileService
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE
from pypnm.lib.mac_address import MacAddress, MacAddressFormat
from pypnm.lib.types import (
    FileName,
    FileNameStr,
    MacAddressStr,
    OperationId,
    TransactionId,
)


class PnmFileManager:
    """
    REST API router for managing PNM test files.

    Endpoints:
    - Search files by MAC or criteria
    - Push/upload new test file
    - Analyze an uploaded or retrieved file
    """

    DEFAULT_HEXDUMP_BYTES_PER_LINE = 16

    def __init__(self) -> None:
        self.logger = logging.getLogger(f'PnmFileManager.{self.__class__.__name__}')
        self.router = APIRouter(
            prefix="/docs/pnm/files",
            tags=["PNM File Manager"],
        )
        self._add_routes()

    def _add_routes(self) -> None:
        default_mac_address = (
            MacAddress(SystemConfigSettings.default_mac_address())
            .to_mac_format(fmt=MacAddressFormat.COLON).lower())

        @self.router.get(
            "/getMacAddresses/",
            response_model=MacAddressSystemDescriptorResponse,
            summary="Get All Registered MAC Addresses With PNM Files",
            responses=FAST_API_RESPONSE,
        )
        def get_mac_addresses() -> MacAddressSystemDescriptorResponse:  # noqa: B008
            """
            **Retrieve All Registered MAC Addresses With Uploaded PNM Files**

            Returns a list of all DOCSIS cable modem MAC addresses that have associated
            telemetry capture files stored in the PyPNM transaction database.

            Each MAC address represents a unique cable modem that has undergone
            telemetry data collection.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/file-manager/file-manager-api.md#1-get-all-registered-mac-addresses-with-pnm-files)
            """
            return PnmFileService().get_mac_addresses()

        @self.router.get(
            "/searchFiles/{mac_address}",
            response_model=FileQueryResponse,
            summary="Search For PNM Files Via Mac Address",
            responses=FAST_API_RESPONSE,
        )
        def search_files(mac_address: MacAddressStr = Path(description=(f"MAC address of the cable modem, default: **{default_mac_address}**"),)) -> FileQueryResponse:  # noqa: B008
            """
            **Search Uploaded PNM Files By MAC Address**

            Returns all registered telemetry capture files associated with a given DOCSIS cable modem.

            Each file represents a measurement such as RxMER, constellation, pre-equalization taps,
            or spectrum scan, and can be downloaded or analyzed via other endpoints.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/file-manager/file-manager-api.md#1-search-files-by-mac-address)
            """
            request = FileQueryRequest(mac_address=mac_address)
            result = PnmFileService().search_files(request)
            return result

        @self.router.get(
            "/download/transactionID/{transaction_id}",
            response_class=FileResponse,
            summary="Download A PNM File By Transaction ID",
            responses=FAST_API_RESPONSE
        )
        def download_file_via_transaction_id(transaction_id: TransactionId = Path(description="Transaction ID of the file to download"),) -> FileResponse:  # noqa: B008
            """
            **Download PNM Measurement File By Transaction ID**

            Retrieves the raw binary file generated during a telemetry capture session.
            Used for offline inspection, reprocessing, or historical archiving.

            Note:
            Depending on your browser and SwaggerUI behavior, the file may either download
            automatically or require clicking the returned link.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/file-manager/file-manager-api.md#2-download-file-by-transaction-id)
            """
            return PnmFileService().get_file_by_transaction_id(transaction_id)

        @self.router.get(
            "/download/filename/{filename}",
            response_class=FileResponse,
            summary="Download An Uncompressed PNM File By Filename",
            responses=FAST_API_RESPONSE
        )
        def download_file_via_filename(
            filename: FileNameStr = Path(description="Stored filename (raw or compressed) to download as uncompressed"),  # noqa: B008
        ) -> FileResponse:
            """
            **Download A PNM File By Filename (Uncompressed)**

            Resolves the filename against the transaction database, then materializes
            the uncompressed file from any compressed artifact before returning it.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/file-manager/file-manager-api.md#3-download-uncompressed-file-by-filename)
            """
            return PnmFileService().get_uncompressed_file_by_filename(filename)

        @self.router.get(
            "/download/macAddress/{mac_address}",
            response_class=FileResponse,
            summary="Download A PNM File By MAC Address",
            responses=FAST_API_RESPONSE
        )
        def download_file_via_mac_address(mac_address: MacAddressStr = Path(..., description="MAC address of the file to download")) -> FileResponse:  # noqa: B008
            """
            **Download PNM Measurement File By Transaction ID**

            Retrieves the raw binary file generated during a telemetry capture session.
            Used for offline inspection, reprocessing, or historical archiving.

            Note:
            Depending on your browser and SwaggerUI behavior, the file may either download
            automatically or require clicking the returned link.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/file-manager/file-manager-api.md#4-download-files-by-mac-address-zip-archive)
            """
            return PnmFileService().get_file_by_mac_address(mac_address)

        @self.router.get(
            "/download/operationID/{operation_id}",
            response_class=FileResponse,
            summary="Download A PNM File By Operation ID",
            responses=FAST_API_RESPONSE
        )
        def download_file_via_operationID(operation_id: OperationId = Path(..., description="Operation ID of the file to download")) -> FileResponse:  # noqa: B008
            """
            **Download PNM Measurement File By Operation ID**

            Retrieves the raw binary file generated during a telemetry capture session.
            Used for offline inspection, reprocessing, or historical archiving.

            Note:
            Depending on your browser and SwaggerUI behavior, the file may either download
            automatically or require clicking the returned link.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/file-manager/file-manager-api.md#5-download-files-by-operation-id-zip-archive)
            """
            return PnmFileService().get_file_by_operation_id(operation_id)

        @self.router.post(
            "/upload",
            response_model=UploadFileResponse,
            summary="Upload A PNM File",
            responses=FAST_API_RESPONSE,
        )
        async def upload_file(file: UploadFile = File(description="Raw PNM capture file (e.g., RxMER, constellation, histogram, spectrum)",),) -> JSONResponse: # noqa: B008
            """
            **Upload A PNM Binary File Into The PyPNM Transaction Database**

            This endpoint accepts a PNM capture file as multipart/form-data and stores
            it under a new transaction record.

            The server will:
            - Persist the file to the configured PNM directory.
            - Inspect the PNM header to identify the file type.
            - Map the file type to a logical PNM test (DocsPnmCmCtlTest).
            - Register a transaction entry with a placeholder null MAC address
              (to be backfilled later from the file contents).

            The response returns the generated transaction_id and echoes the stored filename.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/file-manager/file-manager-api.md#6-upload-pnm-file)

            """
            content = await file.read()
            result = PnmFileService().upload_file(filename=cast(FileName, file.filename), data=content)
            return JSONResponse(content=result.model_dump())

        @self.router.post(
            "/getAnalysis",
            response_model=AnalysisJsonResponse,
            summary="Analyze a PNM File Via Transaction ID",
            responses=FAST_API_RESPONSE,
        )
        def get_analysis_via_transaction_id(request: FileAnalysisRequest) -> AnalysisJsonResponse | FileResponse | JSONResponse:
            """
            **Analysis Of A PNM File**

            Launches an analysis routine based on the specified transactionID and requested
            analysis type. The backend will resolve the PNM file associated with the transactionID,
            inspect its header, and route it to the appropriate analysis pipeline.

            Supported Uploaded PNM File Types:
            - RxMER per subcarrier
            - Channel Estimation Coefficients
            - Constellation Diagram
            - Downstream Histogram
            - OFDMA Pre-equalization
            - Fec Summary
            - Modulation Profile

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/file-manager/file-manager-api.md#7-analyze-pnm-file-via-transaction-id)
            """
            PnmFileService().get_analysis(request)

            output_type = request.analysis.output.type

            if output_type == OutputType.JSON:
                analysis_result, file_type = PnmFileService().get_analysis(request)
                return AnalysisJsonResponse(
                        mac_address     =   analysis_result.mac_address,
                        pnm_file_type   =   file_type.name,
                        status          =   "success",
                        analysis        =   analysis_result.model_dump(),
                    )

            elif output_type == OutputType.ARCHIVE:
                return  PnmFileService().get_archive(request)

            return JSONResponse(content="Not implemented yet")

        @self.router.get(
            "/getHexdump/transactionID/{transaction_id}",
            response_model=HexDumpResponse,
            summary="Hexdump Of A PNM File By Transaction ID",
            responses=FAST_API_RESPONSE,
        )
        def get_hexdump_via_transaction_id(
            transaction_id: TransactionId = Path(..., description="Transaction ID of the PNM file to hexdump"),  # noqa: B008
            bytes_per_line: int | None    = Query(
                default=None,
                description="Optional bytes-per-line for hexdump; if omitted, the service default is used.",
            ),
        ) -> HexDumpResponse:
            """
            **Hexdump Of A PNM File**

            Generates a hexadecimal dump of the raw binary contents of a PNM file
            associated with the specified transactionID.

            This is useful for low-level inspection, debugging, or forensic analysis
            of the file structure and data.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/file-manager/file-manager-api.md#8-hexdump-of-a-pnm-file-via-transaction-id)
            """
            hexdump_result = PnmFileService().get_hexdump_by_transaction_id(
                transaction_id = transaction_id,
                bytes_per_line = bytes_per_line if bytes_per_line is not None else 0,
            )
            return hexdump_result

# Required for auto-discovery via dynamic router loading
router = PnmFileManager().router
