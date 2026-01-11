### Summary
Shifted capture-group and operation linkage persistence to DB-backed repositories with JSON fallback/backfill, aligned schema assets, and updated tests to seed DB transactions for capture group linking while keeping existing API shapes stable. Added a brief FAQ entry for the legacy operation_capture key handling, recorded a TODO to confirm the FAQ update, and documented the multi-part bundle line cap.

### Modified Files
- AGENTS.md
- docs/design/db/database-backend-burndown.md
- docs/design/db/database-backend.md
- docs/design/db/schema_postgres.sql
- docs/design/db/schema_sqlite.sql
- docs/issues/index.md
- docs/todo/todo.md
- src/pypnm/api/routes/advance/common/operation_manager.py
- src/pypnm/api/routes/common/classes/file_capture/capture_group.py
- src/pypnm/api/routes/common/classes/file_capture/pnm_file_opearation.py
- src/pypnm/api/routes/common/classes/file_capture/pnm_file_transaction.py
- src/pypnm/api/routes/docs/pnm/files/service.py
- src/pypnm/lib/db/capture_group_repository.py
- src/pypnm/lib/db/db_schema_manager.py
- src/pypnm/lib/db/transaction_repository.py
- src/pypnm/startup/startup.py
- tests/test_capture_group_empty_transaction.py
- tests/test_capture_group_persistence_normalizes_transaction_id.py
- tests/test_db_schema_manager.py
- tests/test_multi_channel_estimation_result.py
- tests/test_multi_channel_estimation_start_and_analysis.py
- tests/test_multi_rxmer_result_resolves_transactions.py
- tests/test_multi_rxmer_start_returns_operation_and_group.py
- tests/test_operation_manager_capture_group_id.py
- tests/test_operation_manager_get_capture_group.py
- tests/test_operation_workflow.py
- tests/test_transaction_id_persistence_guards.py
- tests/test_transaction_repository.py

### Commands Executed And Results
- `python3 -m compileall src` → pass
- `ruff check .` → pass
- `ruff format --check .` → pass (375 files already formatted)
- `pytest -q` → pass (585 passed, 4 skipped)

### Tests
- `pytest -q` → pass (585 passed, 4 skipped)
- `ruff check .` → pass
- `ruff format --check .` → pass

### Notes / Warnings
- pytest skips: `PNM_CM_IT` not set (3 tests), `PYPNM_DB_POSTGRES_DSN` not set (1 test)

### Remaining TODOs / Follow-Ups
- Confirm the FAQ entry for legacy operation_capture capture_group fallback is published.

# FILE: src/pypnm/api/routes/common/classes/file_capture/pnm_file_transaction.py
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

# FILE: src/pypnm/api/routes/docs/pnm/files/service.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

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

    def __init__(self) -> None:
        self.pnm_dir: PathLike = SystemConfigSettings.pnm_dir()
        self.logger = logging.getLogger(self.__class__.__name__)

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
        txn_data = PnmFileTransaction().get_record(transaction_id)

        if not txn_data:
            raise HTTPException(status_code=404, detail="Transaction ID not found.")

        filename = txn_data.get("filename")
        full_path = Path(self.pnm_dir) / str(filename)

        self.logger.info(
            f"Retrieving file for transaction {transaction_id}: {full_path}"
        )

        if not full_path.exists():
            raise HTTPException(status_code=404, detail="File not found on disk.")

        return FileResponse(
            path=full_path,
            filename=filename,
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
            src_path = Path(self.pnm_dir) / Path(rec.filename)
            if not src_path.is_file():
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
            src_path = Path(self.pnm_dir) / Path(rec.filename)
            if not src_path.is_file():
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

        transaction_id = PnmFileTransaction().set_file_by_user(
            mac_address=MacAddress(mac_address),
            pnm_test_type=PnmFileTypeMapper.get_test_type(pnm_file_type),
            filename=filename,
        )

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
        txn_rec = PnmFileTransaction().get_record(req.search.transaction_id)
        if not txn_rec:
            raise HTTPException(
                status_code=404, detail="Transaction ID not found for analysis."
            )

        filename = txn_rec.get("filename")
        if not filename:
            raise HTTPException(
                status_code=404, detail="Filename not found in transaction record."
            )

        self.logger.info(
            f"Starting analysis for transaction ID {req.search.transaction_id} on file: {self.pnm_dir}/{filename}"
        )

        # Get binary file
        file_path = f"{self.pnm_dir}/{filename}"

        if not Path(file_path).is_file():
            raise HTTPException(
                status_code=404, detail="PNM file not found on disk for analysis."
            )
        fp = FileProcessor(file_path).read_file()

        # Get PnmHeader to Determine PnmFileType
        from pypnm.pnm.parser.pnm_parameter import GetPnmParserAndParameters

        parser, model = GetPnmParserAndParameters(fp).get_parser()

        self.logger.info(
            f"Performing {model.file_type.name} analysis for transaction {req.search.transaction_id} on file {filename}"
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
            If the transaction record does not exist, the filename is missing,
            or the file is not present on disk.
        """
        txn_data = PnmFileTransaction().get_record(transaction_id)
        if not txn_data:
            raise HTTPException(status_code=404, detail="Transaction ID not found.")

        filename = txn_data.get("filename")
        if not filename:
            raise HTTPException(
                status_code=404, detail="Filename not found in transaction record."
            )

        full_path = Path(self.pnm_dir) / str(filename)

        self.logger.info(
            "Resolving PNM file for transaction %s at %s",
            transaction_id,
            full_path,
        )

        if not full_path.exists() or not full_path.is_file():
            self.logger.warning(
                "PNM file not found on disk for transaction %s at %s",
                transaction_id,
                full_path,
            )
            raise HTTPException(status_code=404, detail="PNM file not found on disk.")

        return full_path

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
        DEFAULT_HEXDUMP_BYTES_PER_LINE = 16

        if bytes_per_line <= 0:
            bytes_per_line = DEFAULT_HEXDUMP_BYTES_PER_LINE

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

    def __get_analysis(
        self, parser: PnmParsers, model: PnmParserParametersModel
    ) -> tuple[ParserAnalysisModelReturn, PnmFileType]:
        """
        Internal method to instantiate the Analysis class with the given parser and model.
        """
        from pypnm.api.routes.common.classes.analysis.analysis import Analysis

        if model.file_type == PnmFileType.RECEIVE_MODULATION_ERROR_RATIO:
            return Analysis.basic_analysis_rxmer_from_model(
                cast(CmDsOfdmRxMerModel, parser.to_model())
            ), model.file_type

        elif model.file_type == PnmFileType.OFDM_CHANNEL_ESTIMATE_COEFFICIENT:
            return Analysis.basic_analysis_ds_chan_est_from_model(
                cast(CmDsOfdmChanEstimateCoefModel, parser.to_model())
            ), model.file_type

        elif model.file_type == PnmFileType.OFDM_MODULATION_PROFILE:
            return Analysis.basic_analysis_ds_modulation_profile_from_model(
                cast(CmDsOfdmModulationProfileModel, parser.to_model())
            ), model.file_type

        elif model.file_type == PnmFileType.DOWNSTREAM_CONSTELLATION_DISPLAY:
            return Analysis.basic_analysis_ds_constellation_display_from_model(
                cast(CmDsConstDispMeasModel, parser.to_model())
            ), model.file_type

        elif model.file_type == PnmFileType.DOWNSTREAM_HISTOGRAM:
            return Analysis.basic_analysis_ds_histogram_from_model(
                cast(CmDsHistModel, parser.to_model())
            ), model.file_type

        elif model.file_type == PnmFileType.OFDM_FEC_SUMMARY:
            return Analysis.basic_analysis_ds_ofdm_fec_summary_from_model(
                cast(CmDsOfdmFecSummaryModel, parser.to_model())
            ), model.file_type

        elif (
            model.file_type == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS
            or model.file_type
            == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE
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

# FILE: src/pypnm/lib/db/capture_group_repository.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
from dataclasses import dataclass

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.db_schema_manager import (
    DatabaseSchemaManager,
    DbConnection,
)
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    GroupId,
    OperationId,
    TimestampSec,
    TransactionId,
)

_POSITION_START: int = 0
_OPERATION_ID_COLUMN: str = "operation_id"
_LEGACY_OPERATION_ID_COLUMN: str = "operation_capture_id"


@dataclass(frozen=True)
class CaptureGroupRow:
    capture_group_id: GroupId
    created_epoch: TimestampSec


class CaptureGroupRepository:
    """
    Repository for capture_groups and capture_group_transactions tables.
    """

    def __init__(
        self,
        backend: DatabaseBackend,
        sqlite_path: DatabasePath,
        postgres_dsn: DatabaseDsn,
    ) -> None:
        self._backend = backend
        self._schema_manager = DatabaseSchemaManager.from_overrides(
            backend, sqlite_path, postgres_dsn
        )
        self.logger = logging.getLogger(f"{self.__class__.__name__}")

    @classmethod
    def from_system_config(cls) -> CaptureGroupRepository:
        """
        Build a repository using SystemConfigSettings DB overrides.
        """
        return cls(
            SystemConfigSettings.database_backend(),
            SystemConfigSettings.database_sqlite_path(),
            SystemConfigSettings.database_postgres_dsn(),
        )

    @classmethod
    def from_overrides(
        cls,
        backend: DatabaseBackend,
        sqlite_path: DatabasePath,
        postgres_dsn: DatabaseDsn,
    ) -> CaptureGroupRepository:
        """
        Build a repository using explicit backend overrides.
        """
        return cls(backend, sqlite_path, postgres_dsn)

    def get_or_create_capture_group(
        self, capture_group_id: GroupId | str, created_epoch: TimestampSec
    ) -> CaptureGroupRow:
        """
        Resolve or insert a capture group row.
        """
        group_id = GroupId(str(capture_group_id))
        connection = self._connect()
        try:
            existing = self._fetch_capture_group(connection, group_id)
            if existing is not None:
                return existing
            self._insert_capture_group(connection, group_id, created_epoch)
            fetched = self._fetch_capture_group(connection, group_id)
            if fetched is None:
                raise RuntimeError("Failed to resolve capture_group after insert")
            return fetched
        finally:
            connection.close()

    def capture_group_exists(self, capture_group_id: GroupId | str) -> bool:
        """
        Check whether a capture group exists.
        """
        group_id = GroupId(str(capture_group_id))
        connection = self._connect()
        try:
            return self._fetch_capture_group(connection, group_id) is not None
        finally:
            connection.close()

    def add_transaction(
        self,
        capture_group_id: GroupId | str,
        transaction_id: TransactionId | str,
        created_epoch: TimestampSec,
    ) -> None:
        """
        Add a transaction membership row (idempotent). Assigns sequential position.
        """
        group_id = GroupId(str(capture_group_id))
        txn_id = TransactionId(str(transaction_id))
        connection = self._connect()
        try:
            existing = self._fetch_capture_group_transaction(
                connection, group_id, txn_id
            )
            if existing:
                return
            position = self._next_position(connection, group_id)
            self._insert_capture_group_transaction(
                connection, group_id, txn_id, position, created_epoch
            )
        finally:
            connection.close()

    def list_transactions(self, capture_group_id: GroupId | str) -> list[TransactionId]:
        """
        List transaction IDs for a capture group in deterministic order.
        """
        group_id = GroupId(str(capture_group_id))
        connection = self._connect()
        try:
            rows = self._fetch_capture_group_transactions(connection, group_id)
        finally:
            connection.close()
        return [TransactionId(str(row[0])) for row in rows]

    def list_capture_groups(self) -> list[GroupId]:
        """
        List all capture group identifiers.
        """
        connection = self._connect()
        try:
            rows = self._fetch_capture_groups(connection)
        finally:
            connection.close()
        return [GroupId(str(row[0])) for row in rows]

    def delete_capture_group(self, capture_group_id: GroupId | str) -> None:
        """
        Delete a capture group and its membership rows.
        """
        group_id = GroupId(str(capture_group_id))
        connection = self._connect()
        try:
            match self._backend:
                case DatabaseBackend.SQLITE:
                    connection.execute(
                        "DELETE FROM capture_groups WHERE capture_group_id = ?;",
                        (str(group_id),),
                    )
                    connection.commit()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "DELETE FROM capture_groups WHERE capture_group_id = %s;",
                            (str(group_id),),
                        )
                    connection.commit()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
        finally:
            connection.close()

    def prune_older_than(self, cutoff_epoch: TimestampSec) -> int:
        """
        Delete capture groups older than the cutoff epoch and return count.
        """
        connection = self._connect()
        try:
            match self._backend:
                case DatabaseBackend.SQLITE:
                    cursor = connection.execute(
                        "DELETE FROM capture_groups WHERE created_epoch < ?;",
                        (int(cutoff_epoch),),
                    )
                    connection.commit()
                    return int(cursor.rowcount or 0)
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "DELETE FROM capture_groups WHERE created_epoch < %s;",
                            (int(cutoff_epoch),),
                        )
                        deleted = cursor.rowcount
                    connection.commit()
                    return int(deleted or 0)
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
        finally:
            connection.close()

    def _connect(self) -> DbConnection:
        return self._schema_manager.connect()

    def _fetch_capture_group(
        self, connection: DbConnection, group_id: GroupId
    ) -> CaptureGroupRow | None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    "SELECT capture_group_id, created_epoch FROM capture_groups WHERE capture_group_id = ?;",
                    (str(group_id),),
                )
                row = cursor.fetchone()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT capture_group_id, created_epoch FROM capture_groups WHERE capture_group_id = %s;",
                        (str(group_id),),
                    )
                    row = cursor.fetchone()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")
        if row is None:
            return None
        return CaptureGroupRow(
            capture_group_id=GroupId(str(row[0])),
            created_epoch=TimestampSec(int(row[1])),
        )

    def _insert_capture_group(
        self,
        connection: DbConnection,
        group_id: GroupId,
        created_epoch: TimestampSec,
    ) -> None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO capture_groups (capture_group_id, created_epoch)
                    VALUES (?, ?);
                    """,
                    (str(group_id), int(created_epoch)),
                )
                connection.commit()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO capture_groups (capture_group_id, created_epoch)
                        VALUES (%s, %s)
                        ON CONFLICT (capture_group_id) DO NOTHING;
                        """,
                        (str(group_id), int(created_epoch)),
                    )
                connection.commit()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")

    def _fetch_capture_group_transaction(
        self, connection: DbConnection, group_id: GroupId, txn_id: TransactionId
    ) -> bool:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    """
                    SELECT 1 FROM capture_group_transactions
                    WHERE capture_group_id = ? AND transaction_id = ?;
                    """,
                    (str(group_id), str(txn_id)),
                )
                row = cursor.fetchone()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT 1 FROM capture_group_transactions
                        WHERE capture_group_id = %s AND transaction_id = %s;
                        """,
                        (str(group_id), str(txn_id)),
                    )
                    row = cursor.fetchone()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")
        return row is not None

    def _next_position(self, connection: DbConnection, group_id: GroupId) -> int:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    """
                    SELECT MAX(position) FROM capture_group_transactions
                    WHERE capture_group_id = ?;
                    """,
                    (str(group_id),),
                )
                row = cursor.fetchone()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT MAX(position) FROM capture_group_transactions
                        WHERE capture_group_id = %s;
                        """,
                        (str(group_id),),
                    )
                    row = cursor.fetchone()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")
        if row is None or row[0] is None:
            return _POSITION_START
        return int(row[0]) + 1

    def _insert_capture_group_transaction(
        self,
        connection: DbConnection,
        group_id: GroupId,
        txn_id: TransactionId,
        position: int,
        created_epoch: TimestampSec,
    ) -> None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO capture_group_transactions (
                        capture_group_id, transaction_id, position, added_epoch
                    )
                    VALUES (?, ?, ?, ?);
                    """,
                    (str(group_id), str(txn_id), int(position), int(created_epoch)),
                )
                connection.commit()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO capture_group_transactions (
                            capture_group_id, transaction_id, position, added_epoch
                        )
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (capture_group_id, transaction_id) DO NOTHING;
                        """,
                        (str(group_id), str(txn_id), int(position), int(created_epoch)),
                    )
                connection.commit()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")

    def _fetch_capture_group_transactions(
        self, connection: DbConnection, group_id: GroupId
    ) -> list[tuple[str]]:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    """
                    SELECT transaction_id FROM capture_group_transactions
                    WHERE capture_group_id = ?
                    ORDER BY position ASC, transaction_id ASC;
                    """,
                    (str(group_id),),
                )
                rows = cursor.fetchall()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT transaction_id FROM capture_group_transactions
                        WHERE capture_group_id = %s
                        ORDER BY position ASC, transaction_id ASC;
                        """,
                        (str(group_id),),
                    )
                    rows = cursor.fetchall()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")

        return [(str(row[0]),) for row in rows]

    def _fetch_capture_groups(self, connection: DbConnection) -> list[tuple[str]]:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    "SELECT capture_group_id FROM capture_groups ORDER BY created_epoch ASC;"
                )
                rows = cursor.fetchall()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT capture_group_id FROM capture_groups ORDER BY created_epoch ASC;"
                    )
                    rows = cursor.fetchall()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")

        return [(str(row[0]),) for row in rows]


class OperationCaptureRepository:
    """
    Repository for operation_captures table.
    """

    def __init__(
        self,
        backend: DatabaseBackend,
        sqlite_path: DatabasePath,
        postgres_dsn: DatabaseDsn,
    ) -> None:
        self._backend = backend
        self._schema_manager = DatabaseSchemaManager.from_overrides(
            backend, sqlite_path, postgres_dsn
        )
        self._operation_id_column: str | None = None
        self.logger = logging.getLogger(f"{self.__class__.__name__}")

    @classmethod
    def from_system_config(cls) -> OperationCaptureRepository:
        """
        Build a repository using SystemConfigSettings DB overrides.
        """
        return cls(
            SystemConfigSettings.database_backend(),
            SystemConfigSettings.database_sqlite_path(),
            SystemConfigSettings.database_postgres_dsn(),
        )

    @classmethod
    def from_overrides(
        cls,
        backend: DatabaseBackend,
        sqlite_path: DatabasePath,
        postgres_dsn: DatabaseDsn,
    ) -> OperationCaptureRepository:
        """
        Build a repository using explicit backend overrides.
        """
        return cls(backend, sqlite_path, postgres_dsn)

    def upsert_operation_capture(
        self,
        operation_id: OperationId | str,
        capture_group_id: GroupId | str,
        created_epoch: TimestampSec,
    ) -> None:
        """
        Insert or update an operation capture mapping.
        """
        op_id = OperationId(str(operation_id))
        group_id = GroupId(str(capture_group_id))
        connection = self._connect()
        try:
            column = self._resolve_operation_id_column(connection)
            match self._backend:
                case DatabaseBackend.SQLITE:
                    connection.execute(
                        f"""
                        INSERT OR REPLACE INTO operation_captures (
                            {column}, capture_group_id, created_epoch
                        )
                        VALUES (?, ?, ?);
                        """,
                        (str(op_id), str(group_id), int(created_epoch)),
                    )
                    connection.commit()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            f"""
                            INSERT INTO operation_captures (
                                {column}, capture_group_id, created_epoch
                            )
                            VALUES (%s, %s, %s)
                            ON CONFLICT ({column}) DO UPDATE SET
                                capture_group_id = EXCLUDED.capture_group_id,
                                created_epoch = EXCLUDED.created_epoch;
                            """,
                            (str(op_id), str(group_id), int(created_epoch)),
                        )
                    connection.commit()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
        finally:
            connection.close()

    def get_capture_group_id(self, operation_id: OperationId | str) -> GroupId | None:
        """
        Resolve capture_group_id for the given operation_id.
        """
        op_id = OperationId(str(operation_id))
        connection = self._connect()
        try:
            column = self._resolve_operation_id_column(connection)
            match self._backend:
                case DatabaseBackend.SQLITE:
                    cursor = connection.execute(
                        f"""
                        SELECT capture_group_id FROM operation_captures
                        WHERE {column} = ?;
                        """,
                        (str(op_id),),
                    )
                    row = cursor.fetchone()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            f"""
                            SELECT capture_group_id FROM operation_captures
                            WHERE {column} = %s;
                            """,
                            (str(op_id),),
                        )
                        row = cursor.fetchone()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
        finally:
            connection.close()

        if row is None:
            return None
        return GroupId(str(row[0]))

    def list_operation_ids(self) -> list[OperationId]:
        """
        List all operation IDs.
        """
        connection = self._connect()
        try:
            column = self._resolve_operation_id_column(connection)
            match self._backend:
                case DatabaseBackend.SQLITE:
                    cursor = connection.execute(
                        f"SELECT {column} FROM operation_captures ORDER BY created_epoch ASC;"
                    )
                    rows = cursor.fetchall()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            f"SELECT {column} FROM operation_captures ORDER BY created_epoch ASC;"
                        )
                        rows = cursor.fetchall()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
        finally:
            connection.close()

        return [OperationId(str(row[0])) for row in rows]

    def _connect(self) -> DbConnection:
        return self._schema_manager.connect()

    def _resolve_operation_id_column(self, connection: DbConnection) -> str:
        if self._operation_id_column:
            return self._operation_id_column

        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute("PRAGMA table_info('operation_captures');")
                rows = cursor.fetchall()
                column_names = {str(row[1]) for row in rows}
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT column_name
                        FROM information_schema.columns
                        WHERE table_name = 'operation_captures';
                        """
                    )
                    rows = cursor.fetchall()
                column_names = {str(row[0]) for row in rows}
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")

        if _OPERATION_ID_COLUMN in column_names:
            self._operation_id_column = _OPERATION_ID_COLUMN
        elif _LEGACY_OPERATION_ID_COLUMN in column_names:
            self._operation_id_column = _LEGACY_OPERATION_ID_COLUMN
        else:
            raise RuntimeError("operation_captures table has no operation id column")

        return self._operation_id_column

# FILE: src/pypnm/lib/db/db_schema_manager.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING, TypeAlias

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.model.db_health_model import DatabaseHealthModel
from pypnm.lib.types import DatabaseBackend, DatabaseDsn, DatabasePath

if TYPE_CHECKING:
    from psycopg import Connection as PsycopgConnection
else:
    PsycopgConnection = object

DbConnection: TypeAlias = sqlite3.Connection | PsycopgConnection

SCHEMA_VERSION: int = 1
SCHEMA_META_ID: int = 1
UNKNOWN_SYSDESCR_HASH: str = "UNKNOWN"
DEFAULT_ARTIFACT_STORE_NAME: str = "default"
DEFAULT_ARTIFACT_STORE_ROOT: str = ".data/pnm"
SQLITE_JOURNAL_MODE: str = "WAL"
SQLITE_BUSY_TIMEOUT_MS: int = 5000

BEGIN_STATEMENT: str = "BEGIN"
COMMIT_STATEMENT: str = "COMMIT"

_SQLITE_DDL_FILE: str = "schema_sqlite.sql"
_POSTGRES_DDL_FILE: str = "schema_postgres.sql"

_REQUIRED_TABLES: tuple[str, ...] = (
    "schema_meta",
    "system_description_dim",
    "device_details",
    "transaction_records",
    "capture_groups",
    "capture_group_transactions",
    "operation_captures",
    "artifact_stores",
    "file_artifacts",
    "transaction_artifacts",
)


class DatabaseSchemaManager:
    """
    Initialize and validate the DB schema for the selected backend.
    """

    def __init__(
        self,
        backend: DatabaseBackend,
        sqlite_path: DatabasePath,
        postgres_dsn: DatabaseDsn,
    ) -> None:
        self._backend = backend
        self._sqlite_path = sqlite_path
        self._postgres_dsn = postgres_dsn
        self.logger = logging.getLogger(f"{self.__class__.__name__}")

    @classmethod
    def from_system_config(cls) -> DatabaseSchemaManager:
        """
        Build a schema manager using SystemConfigSettings.
        """
        return cls(
            SystemConfigSettings.database_backend(),
            SystemConfigSettings.database_sqlite_path(),
            SystemConfigSettings.database_postgres_dsn(),
        )

    @classmethod
    def from_overrides(
        cls,
        backend: DatabaseBackend,
        sqlite_path: DatabasePath,
        postgres_dsn: DatabaseDsn,
    ) -> DatabaseSchemaManager:
        """
        Build a schema manager using explicit backend overrides.
        """
        return cls(backend, sqlite_path, postgres_dsn)

    def connect(self) -> DbConnection:
        """
        Open a DB connection for the configured backend.
        """
        match self._backend:
            case DatabaseBackend.SQLITE:
                return self._connect_sqlite()
            case DatabaseBackend.POSTGRES:
                return self._connect_postgres()
        raise ValueError(f"Unsupported Database backend: {self._backend}")

    def initialize_schema(self) -> None:
        """
        Apply schema DDL and seed required rows idempotently.
        """
        connection = self.connect()
        try:
            self._apply_schema(connection)
            self._seed_unknown_sysdescr(connection)
            self._seed_default_artifact_store(connection)
            self._ensure_schema_version(connection)
        finally:
            connection.close()

    def health_check(self) -> DatabaseHealthModel:
        """
        Run a schema health check and return a diagnostic model.
        """
        connection = self.connect()
        try:
            table_names = self._fetch_table_names(connection)
            missing_tables = [
                table for table in _REQUIRED_TABLES if table not in table_names
            ]
            schema_version = self._fetch_schema_version(connection)
            unknown_sysdescr_present = self._has_unknown_sysdescr(connection)
            default_store_present = self._has_default_artifact_store(connection)
            ok = (
                not missing_tables
                and schema_version == SCHEMA_VERSION
                and unknown_sysdescr_present
                and default_store_present
            )
            details = self._health_details(
                schema_version,
                missing_tables,
                unknown_sysdescr_present,
                default_store_present,
            )
            return DatabaseHealthModel(
                backend=self._backend,
                schema_version=schema_version,
                missing_tables=missing_tables,
                unknown_sysdescr_present=unknown_sysdescr_present,
                default_artifact_store_present=default_store_present,
                ok=ok,
                details=details,
            )
        finally:
            connection.close()

    def _connect_sqlite(self) -> sqlite3.Connection:
        db_path = self._resolve_sqlite_db_path()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(db_path)
        connection.execute(f"PRAGMA journal_mode = {SQLITE_JOURNAL_MODE};")
        connection.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS};")
        connection.execute("PRAGMA foreign_keys = ON;")
        return connection

    def _connect_postgres(self) -> PsycopgConnection:
        dsn = str(self._postgres_dsn).strip()
        if not dsn:
            raise ValueError("Database.postgres.dsn cannot be blank")
        try:
            import psycopg
        except ImportError as exc:
            raise RuntimeError(
                "psycopg is required for Postgres backend support"
            ) from exc
        return psycopg.connect(dsn)

    def _apply_schema(self, connection: DbConnection) -> None:
        ddl_sql = self._load_schema_sql()
        match self._backend:
            case DatabaseBackend.SQLITE:
                sqlite_conn = connection
                sqlite_conn.executescript(ddl_sql)
                sqlite_conn.commit()
            case DatabaseBackend.POSTGRES:
                pg_conn = connection
                statements = self._split_sql_statements(ddl_sql)
                current_idx = 0
                try:
                    with pg_conn.cursor() as cursor:
                        for idx, statement in enumerate(statements, start=1):
                            current_idx = idx
                            if self._should_skip_statement(statement):
                                continue
                            cursor.execute(statement)
                    pg_conn.commit()
                except Exception as exc:
                    pg_conn.rollback()
                    raise RuntimeError(
                        f"Failed to apply Postgres schema at statement {current_idx}"
                    ) from exc

    def _seed_unknown_sysdescr(self, connection: DbConnection) -> None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                sqlite_conn = connection
                sqlite_conn.execute(
                    """
                    INSERT OR IGNORE INTO system_description_dim (
                        hw_rev, vendor, bootr, sw_rev, model,
                        sysdescr_json, sysdescr_hash, is_unknown
                    )
                    VALUES (
                        'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN',
                        '{}', ?, 1
                    );
                    """,
                    (UNKNOWN_SYSDESCR_HASH,),
                )
                sqlite_conn.commit()
            case DatabaseBackend.POSTGRES:
                pg_conn = connection
                with pg_conn.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO system_description_dim (
                            hw_rev, vendor, bootr, sw_rev, model,
                            sysdescr_json, sysdescr_hash, is_unknown
                        )
                        VALUES (
                            'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN',
                            '{}'::jsonb, %s, TRUE
                        )
                        ON CONFLICT (sysdescr_hash) DO NOTHING;
                        """,
                        (UNKNOWN_SYSDESCR_HASH,),
                    )
                pg_conn.commit()

    def _seed_default_artifact_store(self, connection: DbConnection) -> None:
        root_path = self._normalize_root_path(SystemConfigSettings.pnm_dir())
        match self._backend:
            case DatabaseBackend.SQLITE:
                sqlite_conn = connection
                sqlite_conn.execute(
                    """
                    INSERT OR IGNORE INTO artifact_stores (store_name, root_path)
                    VALUES (?, ?);
                    """,
                    (DEFAULT_ARTIFACT_STORE_NAME, root_path),
                )
                sqlite_conn.commit()
            case DatabaseBackend.POSTGRES:
                pg_conn = connection
                with pg_conn.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO artifact_stores (store_name, root_path)
                        VALUES (%s, %s)
                        ON CONFLICT (store_name) DO NOTHING;
                        """,
                        (DEFAULT_ARTIFACT_STORE_NAME, root_path),
                    )
                pg_conn.commit()

    def _ensure_schema_version(self, connection: DbConnection) -> None:
        schema_version = self._fetch_schema_version(connection)
        if schema_version != SCHEMA_VERSION:
            raise RuntimeError(
                f"Unsupported schema_version={schema_version}; expected {SCHEMA_VERSION}"
            )

    def _fetch_table_names(self, connection: DbConnection) -> set[str]:
        match self._backend:
            case DatabaseBackend.SQLITE:
                sqlite_conn = connection
                cursor = sqlite_conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table';"
                )
                return {row[0] for row in cursor.fetchall()}
            case DatabaseBackend.POSTGRES:
                pg_conn = connection
                with pg_conn.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT table_name
                        FROM information_schema.tables
                        WHERE table_schema = 'public';
                        """
                    )
                    return {row[0] for row in cursor.fetchall()}
        return set()

    def _fetch_schema_version(self, connection: DbConnection) -> int:
        match self._backend:
            case DatabaseBackend.SQLITE:
                sqlite_conn = connection
                cursor = sqlite_conn.execute(
                    "SELECT schema_version FROM schema_meta WHERE schema_meta_id = ?;",
                    (SCHEMA_META_ID,),
                )
                row = cursor.fetchone()
                if row:
                    return int(row[0])
            case DatabaseBackend.POSTGRES:
                pg_conn = connection
                with pg_conn.cursor() as cursor:
                    cursor.execute(
                        "SELECT schema_version FROM schema_meta WHERE schema_meta_id = %s;",
                        (SCHEMA_META_ID,),
                    )
                    row = cursor.fetchone()
                    if row:
                        return int(row[0])
        return 0

    def _has_unknown_sysdescr(self, connection: DbConnection) -> bool:
        match self._backend:
            case DatabaseBackend.SQLITE:
                sqlite_conn = connection
                cursor = sqlite_conn.execute(
                    "SELECT 1 FROM system_description_dim WHERE sysdescr_hash = ?;",
                    (UNKNOWN_SYSDESCR_HASH,),
                )
                return cursor.fetchone() is not None
            case DatabaseBackend.POSTGRES:
                pg_conn = connection
                with pg_conn.cursor() as cursor:
                    cursor.execute(
                        "SELECT 1 FROM system_description_dim WHERE sysdescr_hash = %s;",
                        (UNKNOWN_SYSDESCR_HASH,),
                    )
                    return cursor.fetchone() is not None
        return False

    def _has_default_artifact_store(self, connection: DbConnection) -> bool:
        match self._backend:
            case DatabaseBackend.SQLITE:
                sqlite_conn = connection
                cursor = sqlite_conn.execute(
                    "SELECT 1 FROM artifact_stores WHERE store_name = ?;",
                    (DEFAULT_ARTIFACT_STORE_NAME,),
                )
                return cursor.fetchone() is not None
            case DatabaseBackend.POSTGRES:
                pg_conn = connection
                with pg_conn.cursor() as cursor:
                    cursor.execute(
                        "SELECT 1 FROM artifact_stores WHERE store_name = %s;",
                        (DEFAULT_ARTIFACT_STORE_NAME,),
                    )
                    return cursor.fetchone() is not None
        return False

    def _health_details(
        self,
        schema_version: int,
        missing_tables: list[str],
        unknown_sysdescr_present: bool,
        default_store_present: bool,
    ) -> str:
        if missing_tables:
            return f"Missing tables: {', '.join(missing_tables)}"
        if schema_version != SCHEMA_VERSION:
            return f"Schema version mismatch: {schema_version}"
        if not unknown_sysdescr_present:
            return "Missing UNKNOWN sysDescr seed row"
        if not default_store_present:
            return "Missing default artifact store row"
        return "Schema healthy"

    def _resolve_sqlite_db_path(self) -> Path:
        path = Path(str(self._sqlite_path))
        if path.is_absolute():
            return path
        return self._resolve_app_root() / path

    def _normalize_root_path(self, root_path: str) -> str:
        path = Path(root_path)
        if not path.is_absolute():
            return root_path
        app_root = self._resolve_app_root()
        if app_root in path.parents:
            return str(path.relative_to(app_root))
        self.logger.warning(
            "Artifact store root_path is absolute; portable paths are recommended: %s",
            root_path,
        )
        return root_path

    def _load_schema_sql(self) -> str:
        ddl_dir = self._resolve_ddl_dir()
        ddl_file = (
            _SQLITE_DDL_FILE
            if self._backend == DatabaseBackend.SQLITE
            else _POSTGRES_DDL_FILE
        )
        ddl_path = ddl_dir / ddl_file
        return ddl_path.read_text(encoding="utf-8")

    @staticmethod
    def _split_sql_statements(sql: str) -> list[str]:
        statements: list[str] = []
        buffer: list[str] = []
        in_single = False
        in_double = False
        in_line_comment = False
        in_block_comment = False
        dollar_tag: str | None = None

        idx = 0
        length = len(sql)
        while idx < length:
            ch = sql[idx]
            nxt = sql[idx + 1] if idx + 1 < length else ""

            if in_line_comment:
                buffer.append(ch)
                if ch == "\n":
                    in_line_comment = False
                idx += 1
                continue

            if in_block_comment:
                buffer.append(ch)
                if ch == "*" and nxt == "/":
                    buffer.append(nxt)
                    idx += 2
                    in_block_comment = False
                    continue
                idx += 1
                continue

            if dollar_tag is not None:
                if ch == "$" and sql.startswith(dollar_tag, idx):
                    buffer.append(dollar_tag)
                    idx += len(dollar_tag)
                    dollar_tag = None
                    continue
                buffer.append(ch)
                idx += 1
                continue

            if not in_single and not in_double:
                if ch == "-" and nxt == "-":
                    buffer.append(ch)
                    buffer.append(nxt)
                    idx += 2
                    in_line_comment = True
                    continue
                if ch == "/" and nxt == "*":
                    buffer.append(ch)
                    buffer.append(nxt)
                    idx += 2
                    in_block_comment = True
                    continue

            if not in_single and not in_double and ch == "$":
                tag_end = sql.find("$", idx + 1)
                if tag_end != -1:
                    tag = sql[idx : tag_end + 1]
                    if DatabaseSchemaManager._is_valid_dollar_tag(tag):
                        closing_idx = sql.find(tag, tag_end + 1)
                        if closing_idx == -1:
                            buffer.append(ch)
                            idx += 1
                            continue
                        dollar_tag = tag
                        buffer.append(tag)
                        idx = tag_end + 1
                        continue

            if ch == "'" and not in_double:
                if in_single and nxt == "'":
                    buffer.append(ch)
                    buffer.append(nxt)
                    idx += 2
                    continue
                in_single = not in_single
                buffer.append(ch)
                idx += 1
                continue

            if ch == '"' and not in_single:
                in_double = not in_double
                buffer.append(ch)
                idx += 1
                continue

            if ch == ";" and not in_single and not in_double and dollar_tag is None:
                statement = "".join(buffer).strip()
                if statement:
                    statements.append(statement)
                buffer = []
                idx += 1
                continue

            buffer.append(ch)
            idx += 1

        tail = "".join(buffer).strip()
        if tail:
            statements.append(tail)
        return statements

    @staticmethod
    def _should_skip_statement(statement: str) -> bool:
        normalized = " ".join(statement.strip().strip(";").split()).upper()
        return normalized in (
            BEGIN_STATEMENT,
            "BEGIN TRANSACTION",
            COMMIT_STATEMENT,
            "COMMIT WORK",
            "ROLLBACK",
            "ROLLBACK WORK",
        )

    @staticmethod
    def _is_valid_dollar_tag(tag: str) -> bool:
        if len(tag) < 2 or not tag.startswith("$") or not tag.endswith("$"):
            return False
        body = tag[1:-1]
        return all(ch_token.isalnum() or ch_token == "_" for ch_token in body)

    def _resolve_ddl_dir(self) -> Path:
        candidates = [Path(__file__).resolve(), Path.cwd().resolve()]
        for candidate in candidates:
            for parent in [candidate] + list(candidate.parents):
                ddl_dir = parent / "docs" / "design" / "db"
                if ddl_dir.is_dir():
                    return ddl_dir
        raise FileNotFoundError("Unable to locate docs/design/db for DDL assets")

    def _resolve_app_root(self) -> Path:
        cwd = Path.cwd().resolve()
        for parent in [cwd] + list(cwd.parents):
            if (parent / "pyproject.toml").is_file():
                return parent
        return cwd


def initialize_database_schema() -> None:
    """
    Initialize and validate the database schema using system configuration.
    """
    manager = DatabaseSchemaManager.from_system_config()
    manager.initialize_schema()
    health = manager.health_check()
    if not health.ok:
        raise RuntimeError(f"Database schema health check failed: {health.details}")

# FILE: src/pypnm/lib/db/transaction_repository.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.data_type.sysDescr import SystemDescriptor
from pypnm.lib.db.db_schema_manager import (
    UNKNOWN_SYSDESCR_HASH,
    DatabaseSchemaManager,
    DbConnection,
)
from pypnm.lib.mac_address import MacAddress, MacAddressFormat
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    FileName,
    HashStr,
    MacAddressStr,
    TimestampSec,
    TransactionId,
)

_UNKNOWN_FIELD_VALUE: str = "UNKNOWN"
_EMPTY_JSON_OBJECT: str = "{}"


@dataclass(frozen=True)
class MacAddressDescriptorRow:
    mac_address: MacAddressStr
    system_description: dict[str, str] | None


@dataclass(frozen=True)
class TransactionRecordRow:
    transaction_id: TransactionId
    timestamp_epoch: TimestampSec
    mac_address: MacAddressStr
    pnm_test_type: str
    filename: FileName
    system_description: dict[str, str] | None


class _RepositoryBase:
    def __init__(
        self,
        backend: DatabaseBackend,
        sqlite_path: DatabasePath,
        postgres_dsn: DatabaseDsn,
    ) -> None:
        self._backend = backend
        self._schema_manager = DatabaseSchemaManager.from_overrides(
            backend, sqlite_path, postgres_dsn
        )
        self.logger = logging.getLogger(f"{self.__class__.__name__}")

    @classmethod
    def _from_system_config(cls) -> _RepositoryBase:
        return cls(
            SystemConfigSettings.database_backend(),
            SystemConfigSettings.database_sqlite_path(),
            SystemConfigSettings.database_postgres_dsn(),
        )

    def _connect(self) -> DbConnection:
        return self._schema_manager.connect()

    @staticmethod
    def _canonical_json(data: dict[str, object]) -> str:
        return json.dumps(data, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _hash_json(data: dict[str, object]) -> HashStr:
        payload = _RepositoryBase._canonical_json(data).encode("utf-8")
        return HashStr(hashlib.sha256(payload).hexdigest())

    @staticmethod
    def _load_json_value(value: object) -> dict[str, object]:
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                return {}
            if isinstance(parsed, dict):
                return parsed
        return {}


class SystemDescriptionRepository(_RepositoryBase):
    """
    Repository for the system_description_dim dimension table.
    """

    @classmethod
    def from_system_config(cls) -> SystemDescriptionRepository:
        """
        Build a repository using SystemConfigSettings DB overrides.
        """
        return cls._from_system_config()

    @classmethod
    def from_overrides(
        cls,
        backend: DatabaseBackend,
        sqlite_path: DatabasePath,
        postgres_dsn: DatabaseDsn,
    ) -> SystemDescriptionRepository:
        """
        Build a repository using explicit backend overrides.
        """
        return cls(backend, sqlite_path, postgres_dsn)

    def get_or_create_sysdescr_id(self, sysdescr_json: dict[str, str] | None) -> int:
        """
        Resolve or insert a sysDescr row and return its primary key.
        """
        normalized = self._normalize_sysdescr_json(sysdescr_json)
        is_unknown = not normalized
        if is_unknown:
            sysdescr_hash = UNKNOWN_SYSDESCR_HASH
            hw_rev = _UNKNOWN_FIELD_VALUE
            vendor = _UNKNOWN_FIELD_VALUE
            bootr = _UNKNOWN_FIELD_VALUE
            sw_rev = _UNKNOWN_FIELD_VALUE
            model = _UNKNOWN_FIELD_VALUE
            sysdescr_payload = _EMPTY_JSON_OBJECT
        else:
            sysdescr_hash = str(self._hash_json(normalized))
            hw_rev = normalized.get("HW_REV", "")
            vendor = normalized.get("VENDOR", "")
            bootr = normalized.get("BOOTR", "")
            sw_rev = normalized.get("SW_REV", "")
            model = normalized.get("MODEL", "")
            sysdescr_payload = self._canonical_json(normalized)

        connection = self._connect()
        try:
            existing = self._fetch_sysdescr_id(connection, sysdescr_hash)
            if existing is not None:
                return existing
            self._insert_sysdescr(
                connection,
                hw_rev,
                vendor,
                bootr,
                sw_rev,
                model,
                sysdescr_payload,
                sysdescr_hash,
                is_unknown,
            )
            fetched = self._fetch_sysdescr_id(connection, sysdescr_hash)
            if fetched is None:
                raise RuntimeError("Failed to resolve sysdescr_id after insert")
            return fetched
        finally:
            connection.close()

    @staticmethod
    def _normalize_sysdescr_json(
        sysdescr_json: dict[str, str] | None,
    ) -> dict[str, str]:
        if not sysdescr_json:
            return {}
        cleaned = {key: str(value) for key, value in sysdescr_json.items()}
        normalized = SystemDescriptor.load_from_dict(cleaned).to_dict()
        if not any(value.strip() for value in normalized.values()):
            return {}
        return normalized

    def _fetch_sysdescr_id(
        self, connection: DbConnection, sysdescr_hash: str
    ) -> int | None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    "SELECT sysdescr_id FROM system_description_dim WHERE sysdescr_hash = ?;",
                    (sysdescr_hash,),
                )
                row = cursor.fetchone()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT sysdescr_id FROM system_description_dim WHERE sysdescr_hash = %s;",
                        (sysdescr_hash,),
                    )
                    row = cursor.fetchone()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")
        if not row:
            return None
        return int(row[0])

    def _insert_sysdescr(
        self,
        connection: DbConnection,
        hw_rev: str,
        vendor: str,
        bootr: str,
        sw_rev: str,
        model: str,
        sysdescr_json: str,
        sysdescr_hash: str,
        is_unknown: bool,
    ) -> None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO system_description_dim (
                        hw_rev, vendor, bootr, sw_rev, model,
                        sysdescr_json, sysdescr_hash, is_unknown
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        hw_rev,
                        vendor,
                        bootr,
                        sw_rev,
                        model,
                        sysdescr_json,
                        sysdescr_hash,
                        1 if is_unknown else 0,
                    ),
                )
                connection.commit()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO system_description_dim (
                            hw_rev, vendor, bootr, sw_rev, model,
                            sysdescr_json, sysdescr_hash, is_unknown
                        )
                        VALUES (%s, %s, %s, %s, %s, CAST(%s AS jsonb), %s, %s)
                        ON CONFLICT (sysdescr_hash) DO NOTHING;
                        """,
                        (
                            hw_rev,
                            vendor,
                            bootr,
                            sw_rev,
                            model,
                            sysdescr_json,
                            sysdescr_hash,
                            is_unknown,
                        ),
                    )
                connection.commit()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")


class DeviceDetailsRepository(_RepositoryBase):
    """
    Repository for the device_details dimension table.
    """

    @classmethod
    def from_system_config(cls) -> DeviceDetailsRepository:
        """
        Build a repository using SystemConfigSettings DB overrides.
        """
        return cls._from_system_config()

    @classmethod
    def from_overrides(
        cls,
        backend: DatabaseBackend,
        sqlite_path: DatabasePath,
        postgres_dsn: DatabaseDsn,
    ) -> DeviceDetailsRepository:
        """
        Build a repository using explicit backend overrides.
        """
        return cls(backend, sqlite_path, postgres_dsn)

    def get_or_create_device_detail_id(
        self, device_details_json: dict[str, object], sysdescr_id: int
    ) -> int:
        """
        Resolve or insert a device_details row and return its primary key.
        """
        payload = device_details_json or {}
        device_details_hash = str(self._hash_json(payload))
        payload_json = self._canonical_json(payload)

        connection = self._connect()
        try:
            existing = self._fetch_device_detail_id(connection, device_details_hash)
            if existing is not None:
                return existing
            self._insert_device_details(
                connection, sysdescr_id, payload_json, device_details_hash
            )
            fetched = self._fetch_device_detail_id(connection, device_details_hash)
            if fetched is None:
                raise RuntimeError("Failed to resolve device_detail_id after insert")
            return fetched
        finally:
            connection.close()

    def _fetch_device_detail_id(
        self, connection: DbConnection, device_details_hash: str
    ) -> int | None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    "SELECT device_detail_id FROM device_details WHERE device_details_hash = ?;",
                    (device_details_hash,),
                )
                row = cursor.fetchone()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT device_detail_id FROM device_details WHERE device_details_hash = %s;",
                        (device_details_hash,),
                    )
                    row = cursor.fetchone()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")
        if not row:
            return None
        return int(row[0])

    def _insert_device_details(
        self,
        connection: DbConnection,
        sysdescr_id: int,
        device_details_json: str,
        device_details_hash: str,
    ) -> None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO device_details (
                        sysdescr_id, device_details_json, device_details_hash
                    )
                    VALUES (?, ?, ?);
                    """,
                    (sysdescr_id, device_details_json, device_details_hash),
                )
                connection.commit()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO device_details (
                            sysdescr_id, device_details_json, device_details_hash
                        )
                        VALUES (%s, CAST(%s AS jsonb), %s)
                        ON CONFLICT (device_details_hash) DO NOTHING;
                        """,
                        (sysdescr_id, device_details_json, device_details_hash),
                    )
                connection.commit()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")


class TransactionRepository(_RepositoryBase):
    """
    Repository for transaction_records and related queries.
    """

    @classmethod
    def from_system_config(cls) -> TransactionRepository:
        """
        Build a repository using SystemConfigSettings DB overrides.
        """
        return cls._from_system_config()

    @classmethod
    def from_overrides(
        cls,
        backend: DatabaseBackend,
        sqlite_path: DatabasePath,
        postgres_dsn: DatabaseDsn,
    ) -> TransactionRepository:
        """
        Build a repository using explicit backend overrides.
        """
        return cls(backend, sqlite_path, postgres_dsn)

    def insert_transaction(
        self,
        transaction_id: TransactionId,
        timestamp_epoch: TimestampSec,
        mac_address: MacAddress | MacAddressStr | str,
        pnm_test_type: str,
        filename: FileName | str,
        device_detail_id: int,
    ) -> None:
        """
        Insert a transaction record (idempotent on transaction_id).
        """
        mac_str = self._normalize_mac(mac_address)
        connection = self._connect()
        try:
            match self._backend:
                case DatabaseBackend.SQLITE:
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO transaction_records (
                            transaction_id, timestamp_epoch, mac_address,
                            pnm_test_type, filename, device_detail_id
                        )
                        VALUES (?, ?, ?, ?, ?, ?);
                        """,
                        (
                            str(transaction_id),
                            int(timestamp_epoch),
                            mac_str,
                            pnm_test_type,
                            str(filename),
                            device_detail_id,
                        ),
                    )
                    connection.commit()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            """
                            INSERT INTO transaction_records (
                                transaction_id, timestamp_epoch, mac_address,
                                pnm_test_type, filename, device_detail_id
                            )
                            VALUES (%s, %s, %s, %s, %s, %s)
                            ON CONFLICT (transaction_id) DO NOTHING;
                            """,
                            (
                                str(transaction_id),
                                int(timestamp_epoch),
                                mac_str,
                                pnm_test_type,
                                str(filename),
                                device_detail_id,
                            ),
                        )
                    connection.commit()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
        finally:
            connection.close()

    def list_macs(self) -> list[MacAddressDescriptorRow]:
        """
        List distinct MAC addresses with best-effort system_description metadata.
        """
        connection = self._connect()
        try:
            rows = self._fetch_mac_rows(connection)
        finally:
            connection.close()

        latest_by_mac: dict[str, tuple[int, dict[str, str] | None]] = {}
        for mac_str, timestamp_epoch, device_details_json in rows:
            normalized_mac = str(mac_str).lower().strip()
            if not normalized_mac:
                continue
            system_description = self._extract_system_description(device_details_json)
            existing = latest_by_mac.get(normalized_mac)
            if existing is None:
                latest_by_mac[normalized_mac] = (timestamp_epoch, system_description)
                continue
            existing_ts, _existing_sd = existing
            if timestamp_epoch >= existing_ts:
                latest_by_mac[normalized_mac] = (timestamp_epoch, system_description)

        results: list[MacAddressDescriptorRow] = []
        for mac_str, (_ts, system_description) in sorted(
            latest_by_mac.items(), key=lambda item: item[0]
        ):
            results.append(
                MacAddressDescriptorRow(
                    mac_address=MacAddressStr(mac_str),
                    system_description=system_description,
                )
            )

        return results

    def list_transactions_for_mac(
        self, mac_address: MacAddress | MacAddressStr | str
    ) -> list[TransactionRecordRow]:
        """
        List all transactions for a MAC address ordered by timestamp.
        """
        mac_str = self._normalize_mac(mac_address)
        connection = self._connect()
        try:
            rows = self._fetch_transaction_rows_for_mac(connection, mac_str)
        finally:
            connection.close()
        return self._transaction_rows_from_query(rows)

    def list_all_transactions(self) -> list[TransactionRecordRow]:
        """
        List all transactions ordered by timestamp.
        """
        connection = self._connect()
        try:
            rows = self._fetch_all_transaction_rows(connection)
        finally:
            connection.close()
        return self._transaction_rows_from_query(rows)

    def get_transaction_record(
        self, transaction_id: TransactionId
    ) -> TransactionRecordRow | None:
        """
        Fetch a transaction record by identifier.
        """
        connection = self._connect()
        try:
            row = self._fetch_transaction_row_by_id(connection, str(transaction_id))
        finally:
            connection.close()

        if row is None:
            return None
        return self._transaction_row_from_tuple(row)

    def _fetch_mac_rows(
        self, connection: DbConnection
    ) -> list[tuple[str, int, object]]:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    """
                    SELECT t.mac_address, t.timestamp_epoch, d.device_details_json
                    FROM transaction_records t
                    JOIN device_details d ON t.device_detail_id = d.device_detail_id
                    ORDER BY t.timestamp_epoch DESC;
                    """
                )
                rows = cursor.fetchall()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT t.mac_address, t.timestamp_epoch, d.device_details_json
                        FROM transaction_records t
                        JOIN device_details d ON t.device_detail_id = d.device_detail_id
                        ORDER BY t.timestamp_epoch DESC;
                        """
                    )
                    rows = cursor.fetchall()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")

        return [(str(row[0]), int(row[1]), row[2]) for row in rows]

    def _fetch_transaction_rows_for_mac(
        self, connection: DbConnection, mac_address: str
    ) -> list[tuple[str, int, str, str, str, object]]:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    """
                    SELECT t.transaction_id, t.timestamp_epoch, t.mac_address,
                           t.pnm_test_type, t.filename, d.device_details_json
                    FROM transaction_records t
                    JOIN device_details d ON t.device_detail_id = d.device_detail_id
                    WHERE t.mac_address = ?
                    ORDER BY t.timestamp_epoch ASC, t.transaction_id ASC;
                    """,
                    (mac_address,),
                )
                rows = cursor.fetchall()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT t.transaction_id, t.timestamp_epoch, t.mac_address,
                               t.pnm_test_type, t.filename, d.device_details_json
                        FROM transaction_records t
                        JOIN device_details d ON t.device_detail_id = d.device_detail_id
                        WHERE t.mac_address = %s
                        ORDER BY t.timestamp_epoch ASC, t.transaction_id ASC;
                        """,
                        (mac_address,),
                    )
                    rows = cursor.fetchall()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")

        return [
            (
                str(row[0]),
                int(row[1]),
                str(row[2]),
                str(row[3]),
                str(row[4]),
                row[5],
            )
            for row in rows
        ]

    def _fetch_all_transaction_rows(
        self, connection: DbConnection
    ) -> list[tuple[str, int, str, str, str, object]]:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    """
                    SELECT t.transaction_id, t.timestamp_epoch, t.mac_address,
                           t.pnm_test_type, t.filename, d.device_details_json
                    FROM transaction_records t
                    JOIN device_details d ON t.device_detail_id = d.device_detail_id
                    ORDER BY t.timestamp_epoch ASC, t.transaction_id ASC;
                    """
                )
                rows = cursor.fetchall()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT t.transaction_id, t.timestamp_epoch, t.mac_address,
                               t.pnm_test_type, t.filename, d.device_details_json
                        FROM transaction_records t
                        JOIN device_details d ON t.device_detail_id = d.device_detail_id
                        ORDER BY t.timestamp_epoch ASC, t.transaction_id ASC;
                        """
                    )
                    rows = cursor.fetchall()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")

        return [
            (
                str(row[0]),
                int(row[1]),
                str(row[2]),
                str(row[3]),
                str(row[4]),
                row[5],
            )
            for row in rows
        ]

    def _fetch_transaction_row_by_id(
        self, connection: DbConnection, transaction_id: str
    ) -> tuple[str, int, str, str, str, object] | None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    """
                    SELECT t.transaction_id, t.timestamp_epoch, t.mac_address,
                           t.pnm_test_type, t.filename, d.device_details_json
                    FROM transaction_records t
                    JOIN device_details d ON t.device_detail_id = d.device_detail_id
                    WHERE t.transaction_id = ?;
                    """,
                    (transaction_id,),
                )
                row = cursor.fetchone()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT t.transaction_id, t.timestamp_epoch, t.mac_address,
                               t.pnm_test_type, t.filename, d.device_details_json
                        FROM transaction_records t
                        JOIN device_details d ON t.device_detail_id = d.device_detail_id
                        WHERE t.transaction_id = %s;
                        """,
                        (transaction_id,),
                    )
                    row = cursor.fetchone()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")

        if row is None:
            return None
        return (
            str(row[0]),
            int(row[1]),
            str(row[2]),
            str(row[3]),
            str(row[4]),
            row[5],
        )

    @staticmethod
    def _normalize_mac(mac_address: MacAddress | MacAddressStr | str) -> str:
        if isinstance(mac_address, MacAddress):
            return mac_address.to_mac_format(MacAddressFormat.COLON).lower()
        normalized = MacAddress(mac_address).to_mac_format(MacAddressFormat.COLON)
        return str(normalized).lower()

    def _transaction_rows_from_query(
        self, rows: list[tuple[str, int, str, str, str, object]]
    ) -> list[TransactionRecordRow]:
        records: list[TransactionRecordRow] = []
        for row in rows:
            record = self._transaction_row_from_tuple(row)
            records.append(record)
        return records

    def _transaction_row_from_tuple(
        self, row: tuple[str, int, str, str, str, object]
    ) -> TransactionRecordRow:
        system_description = self._extract_system_description(row[5])
        return TransactionRecordRow(
            transaction_id=TransactionId(row[0]),
            timestamp_epoch=TimestampSec(int(row[1])),
            mac_address=MacAddressStr(row[2]),
            pnm_test_type=row[3],
            filename=FileName(row[4]),
            system_description=system_description,
        )

    def _extract_system_description(
        self, device_details_json: object
    ) -> dict[str, str] | None:
        payload = self._load_json_value(device_details_json)
        if not payload:
            return None
        sysdesc = payload.get("system_description")
        if not isinstance(sysdesc, dict):
            return None
        cleaned: dict[str, str] = {}
        for key, value in sysdesc.items():
            cleaned[str(key)] = str(value)
        return cleaned or None

# FILE: src/pypnm/startup/startup.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pypnm.api.routes.common.extended.common_process_service import SystemConfigSettings
from pypnm.config.log_config import LoggerConfigurator
from pypnm.lib.db.db_schema_manager import initialize_database_schema


class StartUp:
    """
    Class to handle the startup process of the PyPNM application.
    It initializes the system configuration settings and prepares the environment.
    """

    @classmethod
    def initialize(cls) -> None:
        """
        Initialize the system configuration settings and set up logging.
        This method should be called at the start of the application.
        """
        SystemConfigSettings.initialize_directories()
        initialize_database_schema()

        LoggerConfigurator(
            SystemConfigSettings.log_dir(),
            SystemConfigSettings.log_filename(),
            SystemConfigSettings.log_level(),
        )
