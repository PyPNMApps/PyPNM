## Agent Review Bundle Summary
- Goal: Restore Ruff import ordering and lock DB backend selection invariants for Postgres DSN handling.
- Changes: Normalized 2026 headers and reorganized imports in PNM file transaction and file service modules; added whitespace DSN fallback test for DatabaseManager and non-blank DSN fail-fast test for DatabaseSchemaManager; updated schema manager test header to 2026.
- Files: src/pypnm/api/routes/common/classes/file_capture/pnm_file_transaction.py, src/pypnm/api/routes/docs/pnm/files/service.py, tests/test_database_manager.py, tests/test_db_schema_manager.py.
- Tests: python3 -m compileall src; ruff check .; ruff format --check .; pytest -q.
- Notes: pytest skips include PNM_CM_IT hardware integration and PYPNM_TEST_POSTGRES-gated Postgres tests.

# FILE: src/pypnm/api/routes/common/classes/file_capture/pnm_file_transaction.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import hashlib
import logging
import time
from pathlib import Path
from typing import cast

from pypnm.api.routes.common.classes.file_capture.types import (
    DeviceDetailsModel,
    TransactionRecordModel,
)
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.sysDescr import SystemDescriptor
from pypnm.lib.db.artifact_repository import (
    ROLE_PNM_UPLOADED_RAW,
    ArtifactRepository,
)
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
        self._artifact_repo = ArtifactRepository.from_system_config()

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
        mac_address_value = cable_modem.get_mac_address
        if callable(mac_address_value):
            mac_address_value = mac_address_value()
        return self._insert_generic(
            mac_address=cast(MacAddress, mac_address_value),
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
        transaction_id = txn._insert_generic(
            mac_address=mac_address,
            pnm_test_type=pnm_test_type,
            filename=filename,
        )
        if str(transaction_id).strip():
            txn.register_pnm_artifact(transaction_id, filename, ROLE_PNM_UPLOADED_RAW)
        return transaction_id

    def register_pnm_artifact(
        self, transaction_id: TransactionId, filename: FileName | str, role: str
    ) -> None:
        """
        Register a stored PNM file artifact for a transaction.

        Parameters
        ----------
        transaction_id:
            Transaction identifier to bind to the artifact record.
        filename:
            File name or relative path of the stored PNM file under the
            configured artifact store root.
        role:
            Artifact role used for resolution (for example: pnm_raw or
            pnm_uploaded_raw).
        """
        if not str(transaction_id).strip():
            self.logger.warning(
                "Skipping artifact registration for empty transaction_id (filename=%s)",
                filename,
            )
            return
        file_path = self._resolve_pnm_path(filename)
        created_epoch = TimestampSec(int(time.time()))
        self._artifact_repo.register_transaction_artifact(
            transaction_id=transaction_id,
            file_path=file_path,
            role=role,
            created_epoch=created_epoch,
        )

    @staticmethod
    def _resolve_pnm_path(filename: FileName | str) -> Path:
        pnm_dir = SystemConfigSettings.pnm_dir()
        return Path(pnm_dir) / str(filename)

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
        hash_input = (
            f"{filename}{mac_address}{pnm_test_type.name}{time.time_ns()}"
        ).encode()
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

# FILE: src/pypnm/api/routes/docs/pnm/files/service.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import cast

from fastapi import HTTPException
from fastapi.responses import FileResponse

from pypnm.api.routes.basic.abstract.analysis_report import AnalysisRptMatplotConfig
from pypnm.api.routes.basic.channel_estimation_analysis_rpt import ChanEstimationReport
from pypnm.api.routes.basic.constellation_display_analysis_rpt import (
    ConstDisplayAnalysisRptMatplotConfig,
    ConstellationDisplayReport,
)
from pypnm.api.routes.basic.fec_summary_analysis_rpt import FecSummaryAnalysisReport
from pypnm.api.routes.basic.modulation_profile_analysis_rpt import (
    ModulationProfileReport,
)
from pypnm.api.routes.basic.rxmer_analysis_rpt import RxMerAnalysisReport
from pypnm.api.routes.basic.us_ofdma_pre_eq_analysis_rpt import CmUsOfdmaPreEqReport
from pypnm.api.routes.common.classes.analysis.model.schema import (
    ParserAnalysisModelReturn,
)
from pypnm.api.routes.common.classes.file_capture.file_type import FileType
from pypnm.api.routes.common.classes.file_capture.pnm_file_opearation import (
    OperationCaptureGroupResolver,
)
from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.api.routes.docs.pnm.files.schemas import (
    FileAnalysisRequest,
    FileEntry,
    FileQueryRequest,
    FileQueryResponse,
    HexDumpResponse,
    MacAddressSystemDescriptorEntry,
    MacAddressSystemDescriptorResponse,
    UploadFileResponse,
)
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.archive.manager import ArchiveManager
from pypnm.lib.constants import MediaType
from pypnm.lib.db.artifact_repository import (
    ROLE_PNM_RAW,
    ROLE_PNM_UPLOADED_RAW,
    ArtifactRepository,
)
from pypnm.lib.db.transaction_repository import TransactionRepository
from pypnm.lib.file_processor import FileProcessor
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import (
    FileName,
    MacAddressStr,
    OperationId,
    PathLike,
    TransactionId,
)
from pypnm.lib.utils import Generate
from pypnm.pnm.parser.model.parser_rtn_models import (
    CmDsConstDispMeasModel,
    CmDsHistModel,
    CmDsOfdmChanEstimateCoefModel,
    CmDsOfdmFecSummaryModel,
    CmDsOfdmModulationProfileModel,
    CmDsOfdmRxMerModel,
    CmUsOfdmaPreEqModel,
)
from pypnm.pnm.parser.pnm_file_type import PnmFileType
from pypnm.pnm.parser.pnm_parameter import (
    GetPnmParserAndParameters,
    PnmParserParametersModel,
    PnmParsers,
)
from pypnm.pnm.parser.pnm_type_header_mapper import PnmFileTypeMapper


class PnmFileService:
    """
    Handles file storage, metadata registration, and high-level analysis
    for PNM-related binary data pushed into the PyPNM system.

    Methods:
        - search_files: List available files by MAC.
        - get_file_by_transaction_id: Download raw PNM file by transaction ID.
        - get_file_by_operation_id: Download all files for an operation as a ZIP.
        - get_file_by_mac_address: Download all files for a MAC as a ZIP.
        - upload_file: Accepts uploaded files, saves, and registers.
        - get_analysis: Produces analysis for a stored file.
        - get_file: Serve generated CSV/JSON/ARCHIVE files.
    """

    DEFAULT_HEXDUMP_BYTES_PER_LINE: int = 16

    def __init__(self) -> None:
        self.pnm_dir: PathLike = SystemConfigSettings.pnm_dir()
        self.logger = logging.getLogger(self.__class__.__name__)
        self._artifact_repo = ArtifactRepository.from_system_config()

    def search_files(self, req: FileQueryRequest) -> FileQueryResponse:
        """
        Searches for all registered PNM files tied to a specific MAC address.
        """
        try:
            mac = MacAddress(req.mac_address)
            txn = PnmFileTransaction()
            results = txn.get_file_info_via_macaddress(mac)

            if not results:
                self.logger.warning(f"No files found for MAC: {mac}")
                return FileQueryResponse(files={str(mac): []})

            file_entries: list[FileEntry] = []

            for entry in results:
                device_details = getattr(entry, "device_details", None)

                if hasattr(device_details, "model_dump"):
                    system_description = device_details.model_dump()
                elif isinstance(device_details, dict):
                    system_description = device_details
                else:
                    system_description = None

                file_entries.append(
                    FileEntry(
                        transaction_id=entry.transaction_id,
                        filename=entry.filename,
                        pnm_test_type=entry.pnm_test_type,
                        timestamp=entry.timestamp,
                        system_description=system_description,
                    )
                )

            return FileQueryResponse(files={str(mac): file_entries})

        except Exception as e:
            self.logger.error(f"Failed to search files for MAC {req.mac_address}: {e}")
            return FileQueryResponse(files={req.mac_address: []})

    def get_file_by_transaction_id(self, transaction_id: TransactionId) -> FileResponse:
        """
        Retrieves and serves the binary file associated with the given transaction ID.
        """
        full_path = self._resolve_pnm_artifact_path(transaction_id)

        self.logger.info(
            "Retrieving file for transaction %s: %s",
            transaction_id,
            full_path,
        )

        return FileResponse(
            path=full_path,
            filename=full_path.name,
            media_type=MediaType.APPLICATION_OCTET_STREAM,
        )

    def get_file_by_operation_id(self, operation_id: OperationId) -> FileResponse:
        """
        Retrieve All PNM Files For An Operation ID As A ZIP Archive.

        Resolves the capture group associated with the supplied operation ID,
        then collects all transaction records in that group, locates their
        corresponding PNM files on disk, and packages them into a single ZIP
        archive for download.
        """
        resolver = OperationCaptureGroupResolver()
        txn_models = resolver.get_transaction_models_for_operation(operation_id)

        if not txn_models:
            raise HTTPException(
                status_code=404, detail="No transactions found for Operation ID."
            )

        files_to_archive: list[Path] = []
        for rec in txn_models:
            src_path = self._resolve_pnm_artifact_path_optional(rec.transaction_id)
            if src_path is None or not src_path.is_file():
                self.logger.warning(
                    "Skipping missing file for transaction %s at %s",
                    rec.transaction_id,
                    src_path,
                )
                continue
            files_to_archive.append(src_path)

        if not files_to_archive:
            raise HTTPException(
                status_code=404, detail="No files on disk for Operation ID."
            )

        archive_dir = Path(SystemConfigSettings.archive_dir())
        archive_dir.mkdir(parents=True, exist_ok=True)

        archive_name = f"pnm_operation_{operation_id}_{Generate.time_stamp()}.zip"
        archive_path = archive_dir / archive_name

        ArchiveManager.zip_files(
            files=files_to_archive,
            archive_path=archive_path,
            mode="w",
            compression="zipdeflated",
            preserve_tree=False,
        )

        if not archive_path.is_file():
            self.logger.error(
                "Archive creation failed for Operation ID %s at %s",
                operation_id,
                archive_path,
            )
            raise HTTPException(
                status_code=500, detail="Failed to create archive for Operation ID."
            )

        self.logger.info(
            "Returning ZIP archive for Operation ID %s: %s", operation_id, archive_path
        )

        return FileResponse(
            path=str(archive_path),
            filename=archive_name,
            media_type=MediaType.APPLICATION_ZIP,
        )

    def get_file_by_mac_address(self, mac_address: MacAddressStr) -> FileResponse:
        """
        Retrieve All PNM Files For A MAC Address As A ZIP Archive.

        Looks up all transaction records bound to the provided cable modem
        MAC address, collects their associated PNM files from the PNM
        directory, and packages them into a single ZIP archive for download.

        If no records are found, or none of the files exist on disk, a 404 is raised.
        """
        records = PnmFileTransaction().get_file_info_via_macaddress(
            MacAddress(mac_address)
        )

        if not records:
            raise HTTPException(
                status_code=404, detail="No transactions found for MAC address."
            )

        files_to_archive: list[Path] = []
        for rec in records:
            src_path = self._resolve_pnm_artifact_path_optional(rec.transaction_id)
            if src_path is None or not src_path.is_file():
                self.logger.warning(
                    "Skipping missing file for transaction %s: %s",
                    rec.transaction_id,
                    src_path,
                )
                continue
            files_to_archive.append(src_path)

        if not files_to_archive:
            raise HTTPException(
                status_code=404, detail="No files on disk for MAC address."
            )

        archive_dir = Path(SystemConfigSettings.archive_dir())
        archive_dir.mkdir(parents=True, exist_ok=True)

        safe_mac = str(MacAddress(mac_address).to_mac_format())
        archive_name = f"pnm_files_{safe_mac}_{Generate.time_stamp()}.zip"
        archive_path = archive_dir / archive_name

        ArchiveManager.zip_files(
            files=files_to_archive,
            archive_path=archive_path,
            mode="w",
            compression="zipdeflated",
            preserve_tree=False,
        )

        if not archive_path.is_file():
            self.logger.error(
                "Archive creation failed for MAC %s at %s", mac_address, archive_path
            )
            raise HTTPException(
                status_code=500, detail="Failed to create archive for MAC address."
            )

        self.logger.info(
            "Returning ZIP archive for MAC %s: %s", mac_address, archive_path
        )

        return FileResponse(
            path=str(archive_path),
            filename=archive_name,
            media_type=MediaType.APPLICATION_ZIP,
        )

    def upload_file(self, filename: FileName, data: bytes) -> UploadFileResponse:
        """
        Handle A User-Initiated Upload Of A Raw PNM Binary File.

        1. Saves the file locally to the configured directory.
        2. Inspects its header to identify the PNM file type and MAC.
        3. Maps it to a known DOCSIS test type.
        4. Registers the transaction and returns the transaction ID.
        """
        os.makedirs(self.pnm_dir, exist_ok=True)
        filepath = os.path.join(self.pnm_dir, filename)

        processor = FileProcessor(filepath)
        success = processor.write_file(data)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to write file")

        params = GetPnmParserAndParameters(processor.read_file()).to_model()
        mac_address = params.mac_address or MacAddress.null()
        pnm_file_type: PnmFileType = params.file_type

        try:
            transaction_id = PnmFileTransaction().set_file_by_user(
                mac_address=MacAddress(mac_address),
                pnm_test_type=PnmFileTypeMapper.get_test_type(pnm_file_type),
                filename=filename,
            )
        except (FileNotFoundError, RuntimeError) as exc:
            self.logger.error(
                "Failed to register uploaded file artifact for %s: %s",
                filename,
                exc,
            )
            raise HTTPException(
                status_code=500, detail="Failed to register uploaded file artifact."
            ) from exc

        return UploadFileResponse(
            mac_address=MacAddress(mac_address).mac_address,
            filename=filename,
            transaction_id=transaction_id,
        )

    def get_file(self, file_type: FileType, filename: PathLike) -> FileResponse:
        """
        Serve a generated file from its configured directory.

        Supported types:
        - CSV: returns text/csv from SystemConfigSettings.csv_dir
        - JSON: returns application/json from SystemConfigSettings.json_dir
        - ARCHIVE: returns application/zip from SystemConfigSettings.archive_dir
        """
        safe_name = Path(filename).name

        valid_extensions = [".csv", ".json", ".zip"]
        if not any(safe_name.endswith(ext) for ext in valid_extensions):
            raise HTTPException(
                status_code=400, detail=f"Invalid file extension, file: {safe_name}"
            )

        if file_type == FileType.CSV:
            base_dir = SystemConfigSettings.csv_dir()
            media_type = MediaType.TEXT_CSV

        elif file_type == FileType.JSON:
            base_dir = SystemConfigSettings.json_dir()
            media_type = MediaType.APPLICATION_JSON

        elif file_type == FileType.ARCHIVE:
            base_dir = SystemConfigSettings.archive_dir()
            media_type = MediaType.APPLICATION_ZIP

        else:
            self.logger.error(f"Unsupported file type requested: {file_type.name}")
            raise HTTPException(
                status_code=400, detail=f"Unsupported file type: {file_type.name}"
            )

        file_path = Path(base_dir) / safe_name
        if not file_path.is_file():
            self.logger.warning(f"File not found: {file_path}")
            raise HTTPException(status_code=404, detail="File not found on disk.")

        return FileResponse(
            path=str(file_path),
            filename=safe_name,
            media_type=media_type,
        )

    def get_analysis(
        self, req: FileAnalysisRequest
    ) -> tuple[ParserAnalysisModelReturn, PnmFileType]:
        """
        Returns basic analysis result for a stored PNM file identified by transaction ID.
        The analysis performed depends on the PNM file type.

        Return:
        Tuple[ParserAnalysisModelReturn, PnmFileType]
            A tuple containing the analysis model and the PNM file type.
        """
        file_path = self._resolve_pnm_artifact_path(req.search.transaction_id)
        filename = file_path.name

        self.logger.info(
            "Starting analysis for transaction ID %s on file: %s",
            req.search.transaction_id,
            file_path,
        )

        fp = FileProcessor(str(file_path)).read_file()

        # Get PnmHeader to Determine PnmFileType
        from pypnm.pnm.parser.pnm_parameter import GetPnmParserAndParameters

        parser, model = GetPnmParserAndParameters(fp).get_parser()

        self.logger.info(
            "Performing %s analysis for transaction %s on file %s",
            model.file_type.name,
            req.search.transaction_id,
            filename,
        )

        return self.__get_analysis(parser, model)

    def get_pnm_path_for_transaction(self, transaction_id: TransactionId) -> Path:
        """
        Resolve The Filesystem Path For A PNM File From A Transaction ID.

        Parameters
        ----------
        transaction_id:
            Transaction identifier associated with the PNM capture file.

        Returns
        -------
        Path
            Fully-resolved path to the PNM file on disk.

        Raises
        ------
        HTTPException
            If no artifact is linked to the transaction, or the file is not
            present on disk.
        """
        return self._resolve_pnm_artifact_path(transaction_id)

    def get_hexdump_by_transaction_id(
        self, transaction_id: TransactionId, bytes_per_line: int
    ) -> HexDumpResponse:
        """
        Generate A Structured Hexdump For A PNM File Identified By Transaction ID.

        Parameters
        ----------
        transaction_id:
            Transaction identifier associated with the PNM capture file.
        bytes_per_line:
            Number of bytes per output line in the hexdump view. Typical values
            are 8, 16, or 32. Non-positive values are coerced to the default
            configured via DEFAULT_HEXDUMP_BYTES_PER_LINE.

        Returns
        -------
        HexDumpResponse
            Structured hexdump payload including the transaction ID, the
            effective bytes-per-line setting, and formatted hexdump lines
            containing offset, hex bytes, and ASCII representation.
        """
        if bytes_per_line <= 0:
            bytes_per_line = self.DEFAULT_HEXDUMP_BYTES_PER_LINE

        file_path = self.get_pnm_path_for_transaction(transaction_id)
        processor = FileProcessor(file_path)
        lines = processor.hexdump(bytes_per_line=bytes_per_line)

        if not lines:
            self.logger.error(
                "Hexdump generation failed or produced no data for transaction %s at %s",
                transaction_id,
                file_path,
            )
            raise HTTPException(
                status_code=500, detail="Failed to generate hexdump for PNM file."
            )

        return HexDumpResponse(
            transaction_id=transaction_id,
            bytes_per_line=bytes_per_line,
            lines=lines,
        )

    def _resolve_pnm_artifact_path(self, transaction_id: TransactionId) -> Path:
        path = self._artifact_repo.resolve_transaction_artifact_path(
            transaction_id,
            roles=(ROLE_PNM_RAW, ROLE_PNM_UPLOADED_RAW),
        )
        if path is None:
            raise HTTPException(
                status_code=404,
                detail="Transaction ID not found.",
            )
        if not path.is_file():
            raise HTTPException(
                status_code=404,
                detail="File not found on disk.",
            )
        return path

    def _resolve_pnm_artifact_path_optional(
        self, transaction_id: TransactionId
    ) -> Path | None:
        try:
            return self._resolve_pnm_artifact_path(transaction_id)
        except HTTPException:
            return None

    def __get_analysis(
        self, parser: PnmParsers, model: PnmParserParametersModel
    ) -> tuple[ParserAnalysisModelReturn, PnmFileType]:
        """
        Internal method to instantiate the Analysis class with the given parser and model.
        """
        from pypnm.api.routes.common.classes.analysis.analysis import Analysis

        match model.file_type:
            case PnmFileType.RECEIVE_MODULATION_ERROR_RATIO:
                return Analysis.basic_analysis_rxmer_from_model(
                    cast(CmDsOfdmRxMerModel, parser.to_model())
                ), model.file_type

            case PnmFileType.OFDM_CHANNEL_ESTIMATE_COEFFICIENT:
                return Analysis.basic_analysis_ds_chan_est_from_model(
                    cast(CmDsOfdmChanEstimateCoefModel, parser.to_model())
                ), model.file_type

            case PnmFileType.OFDM_MODULATION_PROFILE:
                return Analysis.basic_analysis_ds_modulation_profile_from_model(
                    cast(CmDsOfdmModulationProfileModel, parser.to_model())
                ), model.file_type

            case PnmFileType.DOWNSTREAM_CONSTELLATION_DISPLAY:
                return Analysis.basic_analysis_ds_constellation_display_from_model(
                    cast(CmDsConstDispMeasModel, parser.to_model())
                ), model.file_type

            case PnmFileType.DOWNSTREAM_HISTOGRAM:
                return Analysis.basic_analysis_ds_histogram_from_model(
                    cast(CmDsHistModel, parser.to_model())
                ), model.file_type

            case PnmFileType.OFDM_FEC_SUMMARY:
                return Analysis.basic_analysis_ds_ofdm_fec_summary_from_model(
                    cast(CmDsOfdmFecSummaryModel, parser.to_model())
                ), model.file_type

            case (
                PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS
                | PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE
            ):
                return Analysis.basic_analysis_us_ofdma_pre_equalization_from_model(
                    cast(CmUsOfdmaPreEqModel, parser.to_model())
                ), model.file_type

        raise HTTPException(
            status_code=400,
            detail=f"Analysis not implemented for file type: {model.file_type.name}",
        )

    def get_archive(self, request: FileAnalysisRequest) -> FileResponse:
        rpt: Path = Path()

        theme = request.analysis.plot.ui.theme
        plot_config = AnalysisRptMatplotConfig(theme=theme)
        analysis_model, pnm_ftype = self.get_analysis(request)

        # TODO: Need to clean up circlar import at next major release
        from pypnm.api.routes.common.classes.analysis.analysis import Analysis

        analysis = Analysis.get_analysis_from_model(analysis_model)

        if pnm_ftype == PnmFileType.RECEIVE_MODULATION_ERROR_RATIO:
            analysis_rpt = RxMerAnalysisReport(analysis, plot_config)
            rpt: Path = cast(Path, analysis_rpt.build_report())

        elif pnm_ftype == PnmFileType.OFDM_CHANNEL_ESTIMATE_COEFFICIENT:
            analysis_rpt = ChanEstimationReport(analysis, plot_config)
            rpt: Path = cast(Path, analysis_rpt.build_report())

        elif pnm_ftype == PnmFileType.OFDM_MODULATION_PROFILE:
            analysis_rpt = ModulationProfileReport(analysis, plot_config)
            rpt: Path = cast(Path, analysis_rpt.build_report())

        elif pnm_ftype == PnmFileType.DOWNSTREAM_CONSTELLATION_DISPLAY:
            plot_config = ConstDisplayAnalysisRptMatplotConfig(theme=theme)
            analysis_rpt = ConstellationDisplayReport(analysis, plot_config)
            rpt: Path = cast(Path, analysis_rpt.build_report())

        elif (
            pnm_ftype == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS
            or pnm_ftype == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE
        ):
            plot_config = ConstDisplayAnalysisRptMatplotConfig(theme=theme)
            analysis_rpt = CmUsOfdmaPreEqReport(analysis)
            rpt: Path = cast(Path, analysis_rpt.build_report())

        elif pnm_ftype == PnmFileType.OFDM_FEC_SUMMARY:
            plot_config = ConstDisplayAnalysisRptMatplotConfig(theme=theme)
            analysis_rpt = FecSummaryAnalysisReport(analysis, plot_config)
            rpt: Path = cast(Path, analysis_rpt.build_report())

        return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

    def get_mac_addresses(self) -> MacAddressSystemDescriptorResponse:
        """
        Retrieve Unique MAC Addresses With Registered PNM Files.

        This scans all transaction records and returns a de-duplicated set of
        MAC addresses. When multiple records exist for the same MAC, the most
        recent record (by timestamp) is used as the source for the system
        descriptor when available.

        Parameters
        ----------
        req:
            Placeholder request model for endpoint compatibility. Currently not
            used for filtering.

        Returns
        -------
        MacAddressSystemDescriptorResponse
            Unique MAC address list with optional system descriptor per MAC.
        """
        entries = TransactionRepository.from_system_config().list_macs()
        if not entries:
            return MacAddressSystemDescriptorResponse(mac_addresses=[])

        response_entries = [
            MacAddressSystemDescriptorEntry(
                mac_address=entry.mac_address,
                system_description=entry.system_description,
            )
            for entry in entries
        ]

        return MacAddressSystemDescriptorResponse(mac_addresses=response_entries)

# FILE: tests/test_database_manager.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.db.database_manager import DatabaseManager
from pypnm.db.postgres_adapter import PostgresDatabaseAdapter
from pypnm.db.schema_version import (
    POSTGRES_SCHEMA_VERSION_INSERT,
    SCHEMA_META_ID_SEED,
    SCHEMA_VERSION_DDL,
    SCHEMA_VERSION_SEED,
)
from pypnm.db.sqlite_adapter import SQLiteDatabaseAdapter
from pypnm.lib.types import DatabaseBackend, DatabaseDsn, DatabasePath


class FakeConfigManager:
    def __init__(self, data: dict[str, object] | None = None) -> None:
        self._data: dict[str, object] = data or {}

    def get(self, *path: str) -> object | None:
        key = ".".join(path)
        return self._data.get(key)

    def reload(self) -> None:
        return None


@pytest.fixture(autouse=True)
def _reset_config(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeConfigManager()
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)
    monkeypatch.setattr(SystemConfigSettings, "_deprecated_ledger_warned", set())
    monkeypatch.setattr(DatabaseManager, "_adapter", None)
    monkeypatch.delenv("PYPNM_DB_BACKEND", raising=False)
    monkeypatch.delenv("PYPNM_DB_POSTGRES_DSN", raising=False)


def test_database_manager_defaults_to_sqlite() -> None:
    adapter = DatabaseManager.get_adapter()
    assert isinstance(adapter, SQLiteDatabaseAdapter)


def test_database_manager_env_override_postgres(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PYPNM_DB_BACKEND", "postgres")
    monkeypatch.setenv(
        "PYPNM_DB_POSTGRES_DSN", "postgresql://pypnm@localhost:5432/pypnm"
    )

    adapter = DatabaseManager.get_adapter()
    assert isinstance(adapter, PostgresDatabaseAdapter)


def test_database_manager_env_override_sqlite_wins_over_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeConfigManager({"Database.backend": "postgres"})
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)
    monkeypatch.setenv("PYPNM_DB_BACKEND", "sqlite")

    adapter = DatabaseManager.get_adapter()
    assert isinstance(adapter, SQLiteDatabaseAdapter)


def test_database_manager_handles_blank_postgres_dsn(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake = FakeConfigManager(
        {
            "Database.backend": "postgres",
            "Database.postgres.dsn": "",
        }
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    with pytest.raises(ValidationError):
        SystemConfigSettings.database_settings()

    logger_name = "DatabaseManager"
    with caplog.at_level(logging.ERROR, logger=logger_name):
        adapter = DatabaseManager.get_adapter()

    assert isinstance(adapter, SQLiteDatabaseAdapter)
    assert "Invalid Database configuration" in caplog.text


def test_database_manager_handles_env_postgres_blank_dsn(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setenv("PYPNM_DB_BACKEND", "postgres")
    monkeypatch.setenv("PYPNM_DB_POSTGRES_DSN", "")

    logger_name = "DatabaseManager"
    with caplog.at_level(logging.ERROR, logger=logger_name):
        adapter = DatabaseManager.get_adapter()

    assert isinstance(adapter, SQLiteDatabaseAdapter)
    assert "Invalid Database configuration" in caplog.text


def test_database_manager_handles_env_postgres_whitespace_dsn(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setenv("PYPNM_DB_BACKEND", "postgres")
    monkeypatch.setenv("PYPNM_DB_POSTGRES_DSN", "   ")

    logger_name = "DatabaseManager"
    with caplog.at_level(logging.ERROR, logger=logger_name):
        adapter = DatabaseManager.get_adapter()

    assert isinstance(adapter, SQLiteDatabaseAdapter)
    assert "Invalid Database configuration" in caplog.text


def test_sqlite_adapter_creates_parent_dir(tmp_path: Path) -> None:
    db_path = tmp_path / "nested" / "pypnm.sqlite3"
    adapter = SQLiteDatabaseAdapter(DatabasePath(str(db_path)))

    adapter.connect()
    try:
        assert db_path.parent.is_dir()
    finally:
        adapter.close()


def test_sqlite_adapter_apply_schema_seeds_version(tmp_path: Path) -> None:
    db_path = tmp_path / "pypnm.sqlite3"
    adapter = SQLiteDatabaseAdapter(DatabasePath(str(db_path)))

    adapter.connect()
    try:
        adapter.apply_schema()
        adapter.apply_schema()
        count, minimum = adapter.schema_meta_stats()
        assert count == 1
        assert minimum == SCHEMA_VERSION_SEED
    finally:
        adapter.close()


class FakeCursor:
    def __init__(self, fetch_queue: list[tuple[object, ...]] | None = None) -> None:
        self.executed: list[tuple[str, tuple[object, ...] | None]] = []
        self._fetch_queue: list[tuple[object, ...]] = fetch_queue or [(0,)]

    def execute(self, query: str, params: tuple[object, ...] | None = None) -> None:
        self.executed.append((query, params))

    def fetchone(self) -> tuple[object, ...] | None:
        if not self._fetch_queue:
            return None
        return self._fetch_queue.pop(0)

    def close(self) -> None:
        return None


class FakeConnection:
    def __init__(self, cursor: FakeCursor) -> None:
        self._cursor = cursor
        self.committed: bool = False

    def cursor(self) -> FakeCursor:
        return self._cursor

    def commit(self) -> None:
        self.committed = True

    def close(self) -> None:
        return None


def test_postgres_adapter_apply_schema_executes_seed() -> None:
    cursor = FakeCursor()
    connection = FakeConnection(cursor)

    def _connect(_: DatabaseDsn) -> FakeConnection:
        return connection

    adapter = PostgresDatabaseAdapter(
        DatabaseDsn("postgresql://stub"), connect_fn=_connect
    )
    adapter.connect()
    adapter.apply_schema()

    queries = [entry[0] for entry in cursor.executed]
    assert SCHEMA_VERSION_DDL in queries
    assert POSTGRES_SCHEMA_VERSION_INSERT in queries
    assert cursor.executed[-1][1] == (SCHEMA_META_ID_SEED, SCHEMA_VERSION_SEED)
    assert connection.committed is True


def test_postgres_adapter_apply_schema_skips_seed_when_present() -> None:
    cursor = FakeCursor(fetch_queue=[(1,)])
    connection = FakeConnection(cursor)

    def _connect(_: DatabaseDsn) -> FakeConnection:
        return connection

    adapter = PostgresDatabaseAdapter(
        DatabaseDsn("postgresql://stub"), connect_fn=_connect
    )
    adapter.connect()
    adapter.apply_schema()

    queries = [entry[0] for entry in cursor.executed]
    assert SCHEMA_VERSION_DDL in queries
    assert POSTGRES_SCHEMA_VERSION_INSERT not in queries
    assert connection.committed is True


def test_database_manager_initialize_and_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "pypnm.sqlite3"
    adapter = SQLiteDatabaseAdapter(DatabasePath(str(db_path)))
    monkeypatch.setattr(DatabaseManager, "_adapter", adapter)
    assert DatabaseManager.initialize() is True
    DatabaseManager.close()
    assert DatabaseManager._adapter is None


def test_database_manager_initialize_postgres_optional(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.environ.get("PYPNM_TEST_POSTGRES", "").strip() != "1":
        pytest.skip("PYPNM_TEST_POSTGRES not set")
    dsn = os.environ.get("PYPNM_DB_POSTGRES_DSN", "").strip()
    if dsn == "":
        pytest.skip("PYPNM_DB_POSTGRES_DSN not set")
    pytest.importorskip("psycopg")
    monkeypatch.setenv("PYPNM_DB_BACKEND", "postgres")
    monkeypatch.setenv("PYPNM_DB_POSTGRES_DSN", dsn)
    try:
        assert DatabaseManager.initialize() is True
    finally:
        DatabaseManager.close()


class CloseTrackingAdapter:
    def __init__(self) -> None:
        self.closed: bool = False

    def connect(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    def apply_schema(self) -> None:
        return None

    def healthcheck(self) -> bool:
        return True


def test_database_manager_close_invokes_adapter_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = CloseTrackingAdapter()
    monkeypatch.setattr(DatabaseManager, "_adapter", adapter)

    DatabaseManager.close()
    assert adapter.closed is True
    assert DatabaseManager._adapter is None


class FailingAdapter:
    def __init__(self, stage: str) -> None:
        self._stage = stage

    def connect(self) -> None:
        if self._stage == "connect":
            raise RuntimeError("connect failed")

    def close(self) -> None:
        return None

    def apply_schema(self) -> None:
        if self._stage == "apply_schema":
            raise RuntimeError("apply_schema failed")

    def healthcheck(self) -> bool:
        if self._stage == "healthcheck":
            raise RuntimeError("healthcheck failed")
        return True


def test_database_manager_initialize_connect_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = FailingAdapter("connect")
    monkeypatch.setattr(
        DatabaseManager, "get_adapter", classmethod(lambda cls: adapter)
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_backend",
        classmethod(lambda cls: DatabaseBackend.SQLITE),
    )

    assert DatabaseManager.initialize() is False


def test_database_manager_initialize_apply_schema_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = FailingAdapter("apply_schema")
    monkeypatch.setattr(
        DatabaseManager, "get_adapter", classmethod(lambda cls: adapter)
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_backend",
        classmethod(lambda cls: DatabaseBackend.SQLITE),
    )

    assert DatabaseManager.initialize() is False


def test_database_manager_initialize_healthcheck_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = FailingAdapter("healthcheck")
    monkeypatch.setattr(
        DatabaseManager, "get_adapter", classmethod(lambda cls: adapter)
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_backend",
        classmethod(lambda cls: DatabaseBackend.SQLITE),
    )

    assert DatabaseManager.initialize() is False

# FILE: tests/test_db_schema_manager.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import sqlite3
from importlib import resources
from pathlib import Path
from typing import cast

import pytest
from tests.postgres_test_utils import require_postgres

from pypnm.lib.db.db_schema_manager import (
    BEGIN_STATEMENT,
    COMMIT_STATEMENT,
    DEFAULT_ARTIFACT_STORE_NAME,
    SCHEMA_VERSION,
    SQLITE_BUSY_TIMEOUT_MS,
    SQLITE_JOURNAL_MODE,
    UNKNOWN_SYSDESCR_HASH,
    DatabaseSchemaManager,
)
from pypnm.lib.types import DatabaseBackend, DatabaseDsn, DatabasePath

SCHEMA_META_ID: int = 1
EXPECTED_UNKNOWN_COUNT: int = 1
EXPECTED_SCHEMA_STATEMENTS_MIN: int = 1
EXPECTED_SQLITE_JOURNAL_MODE: str = SQLITE_JOURNAL_MODE.lower()
UNSUPPORTED_SCHEMA_VERSION: int = SCHEMA_VERSION + 1
INVALID_DSN_VALUE: str = "   "
INDEX_CG_TX_TABLE: str = "capture_group_transactions"
INDEX_OPERATION_CAPTURES_TABLE: str = "operation_captures"
INDEX_CG_TX_CAPTURE_GROUP_POSITION: str = "idx_cg_tx_capture_group_position"
INDEX_OPERATION_CAPTURES_OPERATION_ID: str = "idx_operation_captures_operation_id"
EXPECTED_CG_TX_COLUMNS: tuple[str, str] = ("capture_group_id", "position")
EXPECTED_OPERATION_COLUMNS: tuple[str, ...] = ("operation_id",)


def _sqlite_index_columns(
    connection: sqlite3.Connection, table_name: str, index_name: str
) -> list[str]:
    cursor = connection.execute(f"PRAGMA index_list('{table_name}');")
    rows = cursor.fetchall()
    index_names = {str(row[1]) for row in rows}
    assert index_name in index_names
    cursor = connection.execute(f"PRAGMA index_info('{index_name}');")
    rows = cursor.fetchall()
    return [str(row[2]) for row in rows]


def test_sqlite_schema_init_and_health(tmp_path: Path) -> None:
    db_path = tmp_path / "pypnm_schema.sqlite3"
    sqlite_path = cast(DatabasePath, str(db_path))
    postgres_dsn = cast(DatabaseDsn, "")
    manager = DatabaseSchemaManager.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )

    manager.initialize_schema()
    manager.initialize_schema()

    health = manager.health_check()
    assert health.ok is True
    assert health.schema_version == SCHEMA_VERSION
    assert health.missing_tables == []
    assert health.unknown_sysdescr_present is True
    assert health.default_artifact_store_present is True

    connection = sqlite3.connect(db_path)
    try:
        cursor = connection.execute(
            "SELECT schema_version FROM schema_meta WHERE schema_meta_id = ?;",
            (SCHEMA_META_ID,),
        )
        row = cursor.fetchone()
        assert row is not None
        assert int(row[0]) == SCHEMA_VERSION

        cursor = connection.execute(
            "SELECT COUNT(1) FROM system_description_dim WHERE sysdescr_hash = ?;",
            (UNKNOWN_SYSDESCR_HASH,),
        )
        row = cursor.fetchone()
        assert row is not None
        assert int(row[0]) == EXPECTED_UNKNOWN_COUNT

        cursor = connection.execute(
            "SELECT root_path FROM artifact_stores WHERE store_name = ?;",
            (DEFAULT_ARTIFACT_STORE_NAME,),
        )
        row = cursor.fetchone()
        assert row is not None
        assert str(row[0]).strip() != ""
    finally:
        connection.close()


def test_sqlite_pragmas_applied(tmp_path: Path) -> None:
    db_path = tmp_path / "pypnm_schema.sqlite3"
    sqlite_path = cast(DatabasePath, str(db_path))
    postgres_dsn = cast(DatabaseDsn, "")
    manager = DatabaseSchemaManager.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )

    connection = manager.connect()
    try:
        cursor = connection.execute("PRAGMA journal_mode;")
        row = cursor.fetchone()
        assert row is not None
        assert str(row[0]).lower() == EXPECTED_SQLITE_JOURNAL_MODE

        cursor = connection.execute("PRAGMA busy_timeout;")
        row = cursor.fetchone()
        assert row is not None
        assert int(row[0]) == SQLITE_BUSY_TIMEOUT_MS
    finally:
        connection.close()


def test_sqlite_capture_group_indexes_present(tmp_path: Path) -> None:
    db_path = tmp_path / "pypnm_schema.sqlite3"
    sqlite_path = cast(DatabasePath, str(db_path))
    postgres_dsn = cast(DatabaseDsn, "")
    manager = DatabaseSchemaManager.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )

    manager.initialize_schema()

    connection = sqlite3.connect(db_path)
    try:
        columns = _sqlite_index_columns(
            connection, INDEX_CG_TX_TABLE, INDEX_CG_TX_CAPTURE_GROUP_POSITION
        )
        assert columns == list(EXPECTED_CG_TX_COLUMNS)
        columns = _sqlite_index_columns(
            connection,
            INDEX_OPERATION_CAPTURES_TABLE,
            INDEX_OPERATION_CAPTURES_OPERATION_ID,
        )
        assert columns == list(EXPECTED_OPERATION_COLUMNS)
    finally:
        connection.close()


def test_schema_version_mismatch_raises(tmp_path: Path) -> None:
    db_path = tmp_path / "pypnm_schema.sqlite3"
    sqlite_path = cast(DatabasePath, str(db_path))
    postgres_dsn = cast(DatabaseDsn, "")
    manager = DatabaseSchemaManager.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )

    manager.initialize_schema()

    connection = sqlite3.connect(db_path)
    try:
        connection.execute(
            "UPDATE schema_meta SET schema_version = ? WHERE schema_meta_id = ?;",
            (UNSUPPORTED_SCHEMA_VERSION, SCHEMA_META_ID),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(RuntimeError, match="Unsupported schema_version"):
        manager.initialize_schema()


def test_split_sql_statements_handles_quotes_and_comments() -> None:
    sql = (
        "CREATE TABLE t (v text CHECK (v ~* '^([0-9a-f]{2}:){5}[0-9a-f]{2}$'));\n"
        "-- Comment with ; should not split\n"
        "INSERT INTO t (v) VALUES ('{}'::jsonb);\n"
        "/* Block comment ; still in comment */\n"
        "SELECT $$a; b$$;\n"
    )
    statements = DatabaseSchemaManager._split_sql_statements(sql)
    assert len(statements) == 3


def test_split_sql_statements_filters_begin_commit() -> None:
    sql = "BEGIN; CREATE TABLE demo (id int); COMMIT;"
    statements = DatabaseSchemaManager._split_sql_statements(sql)
    normalized = {stmt.strip().strip(";").upper() for stmt in statements}
    assert BEGIN_STATEMENT in normalized
    assert COMMIT_STATEMENT in normalized
    assert "CREATE TABLE DEMO (ID INT)" in normalized
    assert DatabaseSchemaManager._should_skip_statement("BEGIN") is True
    assert DatabaseSchemaManager._should_skip_statement("BEGIN TRANSACTION") is True
    assert DatabaseSchemaManager._should_skip_statement("COMMIT") is True
    assert DatabaseSchemaManager._should_skip_statement("COMMIT WORK") is True
    assert DatabaseSchemaManager._should_skip_statement("ROLLBACK") is True
    assert DatabaseSchemaManager._should_skip_statement("ROLLBACK WORK") is True


def test_split_sql_statements_handles_escaped_single_quotes() -> None:
    sql = "INSERT INTO t (v) VALUES ('a''b; still string'); SELECT 1;"
    statements = DatabaseSchemaManager._split_sql_statements(sql)
    assert len(statements) == 2


def test_split_sql_statements_handles_valid_dollar_tag() -> None:
    sql = "SELECT $tag$a; b$tag$; SELECT 2;"
    statements = DatabaseSchemaManager._split_sql_statements(sql)
    assert len(statements) == 2


def test_split_sql_statements_rejects_invalid_dollar_tag() -> None:
    sql = "SELECT $a$b$; SELECT 2;"
    statements = DatabaseSchemaManager._split_sql_statements(sql)
    assert len(statements) == 2


def test_split_schema_postgres_contains_schema_meta() -> None:
    ddl_path = resources.files("pypnm.db.schema.sql").joinpath("schema_postgres.sql")
    ddl_sql = ddl_path.read_text(encoding="utf-8")
    statements = DatabaseSchemaManager._split_sql_statements(ddl_sql)
    assert len(statements) >= EXPECTED_SCHEMA_STATEMENTS_MIN
    joined = "\n".join(statements)
    assert "CREATE TABLE IF NOT EXISTS schema_meta" in joined


def test_schema_sql_assets_load_from_package() -> None:
    sqlite_sql = (
        resources.files("pypnm.db.schema.sql")
        .joinpath("schema_sqlite.sql")
        .read_text(encoding="utf-8")
    )
    postgres_sql = (
        resources.files("pypnm.db.schema.sql")
        .joinpath("schema_postgres.sql")
        .read_text(encoding="utf-8")
    )
    assert "CREATE TABLE IF NOT EXISTS schema_meta" in sqlite_sql
    assert "CREATE TABLE IF NOT EXISTS schema_meta" in postgres_sql


def test_postgres_schema_init_requires_dsn(tmp_path: Path) -> None:
    sqlite_path = cast(DatabasePath, str(tmp_path / "unused.sqlite3"))
    postgres_dsn = cast(DatabaseDsn, "")
    manager = DatabaseSchemaManager.from_overrides(
        DatabaseBackend.POSTGRES, sqlite_path, postgres_dsn
    )

    with pytest.raises(ValueError, match="Database.postgres.dsn cannot be blank"):
        manager.connect()


def test_postgres_schema_init_requires_non_blank_dsn(tmp_path: Path) -> None:
    sqlite_path = cast(DatabasePath, str(tmp_path / "unused.sqlite3"))
    postgres_dsn = cast(DatabaseDsn, INVALID_DSN_VALUE)
    manager = DatabaseSchemaManager.from_overrides(
        DatabaseBackend.POSTGRES, sqlite_path, postgres_dsn
    )

    with pytest.raises(ValueError, match="Database.postgres.dsn cannot be blank"):
        manager.connect()


def test_postgres_schema_init_optional() -> None:
    postgres_dsn, _ = require_postgres()
    sqlite_path = cast(DatabasePath, ".data/db/pypnm.sqlite3")
    manager = DatabaseSchemaManager.from_overrides(
        DatabaseBackend.POSTGRES, sqlite_path, postgres_dsn
    )
    manager.initialize_schema()
    health = manager.health_check()
    assert health.ok is True


def test_postgres_capture_group_indexes_optional() -> None:
    postgres_dsn, _ = require_postgres()
    sqlite_path = cast(DatabasePath, ".data/db/pypnm.sqlite3")
    manager = DatabaseSchemaManager.from_overrides(
        DatabaseBackend.POSTGRES, sqlite_path, postgres_dsn
    )
    manager.initialize_schema()

    connection = manager.connect()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                ""
                "SELECT indexname FROM pg_indexes "
                "WHERE schemaname = current_schema() "
                "AND tablename = %s;",
                (INDEX_CG_TX_TABLE,),
            )
            rows = cursor.fetchall()
        index_names = {str(row[0]) for row in rows}
        assert INDEX_CG_TX_CAPTURE_GROUP_POSITION in index_names

        with connection.cursor() as cursor:
            cursor.execute(
                ""
                "SELECT indexname FROM pg_indexes "
                "WHERE schemaname = current_schema() "
                "AND tablename = %s;",
                (INDEX_OPERATION_CAPTURES_TABLE,),
            )
            rows = cursor.fetchall()
        index_names = {str(row[0]) for row in rows}
        assert INDEX_OPERATION_CAPTURES_OPERATION_ID in index_names
    finally:
        connection.close()
