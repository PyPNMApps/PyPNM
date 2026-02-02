## Agent Review Bundle Summary
- Goal: Lower SystemCall logging to debug level.
- Changes: SystemCall now logs execution at debug instead of info.
- Files: See file list below.
- Tests: `ruff check src`, `pytest -q`.
- Notes: None.
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
from pypnm.lib.file_processor import FileProcessor
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import (
    FileName,
    FileNameStr,
    MacAddressStr,
    OperationId,
    PathLike,
    TransactionId,
)
from pypnm.lib.utils import Generate
from pypnm.pnm.lib.pnm_artifact_store import PnmArtifactStore
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
        self._artifact_store = PnmArtifactStore(pnm_dir=self.pnm_dir)

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
                        transaction_id      = entry.transaction_id,
                        filename            = entry.filename,
                        pnm_test_type       = entry.pnm_test_type,
                        timestamp           = entry.timestamp,
                        system_description  = system_description,
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
        compression = txn_data.get("compression") if isinstance(txn_data, dict) else None
        full_path = self._artifact_store.resolve_physical_path(FileNameStr(str(filename)), compression)

        self.logger.info(f"Retrieving file for transaction {transaction_id}: {full_path}")

        if not full_path.exists():
            raise HTTPException(status_code=404, detail="File not found on disk.")

        return FileResponse(
            path        =   full_path,
            filename    =   Path(full_path).name,
            media_type  =   MediaType.APPLICATION_OCTET_STREAM,
        )

    def get_uncompressed_file_by_filename(self, filename: FileNameStr) -> FileResponse:
        """
        Retrieve an uncompressed PNM file by filename.

        The filename is resolved against the transaction database, then the
        artifact store materializes the raw file if it is stored compressed.
        """
        safe_name = FileNameStr(Path(str(filename)).name)
        record_match = PnmFileTransaction().get_record_by_filename(safe_name)
        if not record_match:
            raise HTTPException(status_code=404, detail="Filename not found in transaction records.")

        transaction_id, record = record_match
        record_filename = record.get("filename")
        if not record_filename:
            raise HTTPException(status_code=404, detail="Filename not found in transaction record.")

        compression = record.get("compression") if isinstance(record, dict) else None
        materialized = self._artifact_store.materialize(
            transaction_id,
            FileNameStr(str(record_filename)),
            compression,
        )

        self.logger.info("Retrieving uncompressed file for %s at %s", safe_name, materialized)

        if not materialized.exists():
            raise HTTPException(status_code=404, detail="PNM file not found on disk.")

        return FileResponse(
            path        =   materialized,
            filename    =   materialized.name,
            media_type  =   MediaType.APPLICATION_OCTET_STREAM,
        )

    def get_file_by_operation_id(self, operation_id: OperationId) -> FileResponse:
        """
        Retrieve All PNM Files For An Operation ID As A ZIP Archive.

        Resolves the capture group associated with the supplied operation ID,
        then collects all transaction records in that group, locates their
        corresponding PNM files on disk, and packages them into a single ZIP
        archive for download.
        """
        resolver    = OperationCaptureGroupResolver()
        txn_models  = resolver.get_transaction_models_for_operation(operation_id)

        if not txn_models:
            raise HTTPException(status_code=404, detail="No transactions found for Operation ID.")

        files_to_archive: list[Path] = []
        for rec in txn_models:
            compression = rec.compression.model_dump() if rec.compression else None
            src_path = self._artifact_store.resolve_physical_path(FileNameStr(str(rec.filename)), compression)
            if not src_path.is_file():
                self.logger.warning(
                    "Skipping missing file for transaction %s at %s",
                    rec.transaction_id,
                    src_path,
                )
                continue
            files_to_archive.append(src_path)

        if not files_to_archive:
            raise HTTPException(status_code=404, detail="No files on disk for Operation ID.")

        archive_dir = Path(SystemConfigSettings.archive_dir())
        archive_dir.mkdir(parents=True, exist_ok=True)

        archive_name = f"pnm_operation_{operation_id}_{Generate.time_stamp()}.zip"
        archive_path = archive_dir / archive_name

        ArchiveManager.zip_files(
            files         = files_to_archive,
            archive_path  = archive_path,
            mode          = "w",
            compression   = "zipdeflated",
            preserve_tree = False,
        )

        if not archive_path.is_file():
            self.logger.error("Archive creation failed for Operation ID %s at %s", operation_id, archive_path)
            raise HTTPException(status_code=500, detail="Failed to create archive for Operation ID.")

        self.logger.info("Returning ZIP archive for Operation ID %s: %s", operation_id, archive_path)

        return FileResponse(
            path        = str(archive_path),
            filename    = archive_name,
            media_type  = MediaType.APPLICATION_ZIP,
        )

    def get_file_by_mac_address(self, mac_address: MacAddressStr) -> FileResponse:
        """
        Retrieve All PNM Files For A MAC Address As A ZIP Archive.

        Looks up all transaction records bound to the provided cable modem
        MAC address, collects their associated PNM files from the PNM
        directory, and packages them into a single ZIP archive for download.

        If no records are found, or none of the files exist on disk, a 404 is raised.
        """
        records = PnmFileTransaction().get_file_info_via_macaddress(MacAddress(mac_address))

        if not records:
            raise HTTPException(status_code=404, detail="No transactions found for MAC address.")

        files_to_archive: list[Path] = []
        for rec in records:
            compression = rec.compression.model_dump() if rec.compression else None
            src_path = self._artifact_store.resolve_physical_path(FileNameStr(str(rec.filename)), compression)
            if not src_path.is_file():
                self.logger.warning(
                    "Skipping missing file for transaction %s: %s",
                    rec.transaction_id,
                    src_path,
                )
                continue
            files_to_archive.append(src_path)

        if not files_to_archive:
            raise HTTPException(status_code=404, detail="No files on disk for MAC address.")

        archive_dir = Path(SystemConfigSettings.archive_dir())
        archive_dir.mkdir(parents=True, exist_ok=True)

        safe_mac = str(MacAddress(mac_address).to_mac_format())
        archive_name = f"pnm_files_{safe_mac}_{Generate.time_stamp()}.zip"
        archive_path = archive_dir / archive_name

        ArchiveManager.zip_files(
            files           = files_to_archive,
            archive_path    = archive_path,
            mode            = "w",
            compression     = "zipdeflated",
            preserve_tree   = False,
        )

        if not archive_path.is_file():
            self.logger.error("Archive creation failed for MAC %s at %s", mac_address, archive_path)
            raise HTTPException(status_code=500, detail="Failed to create archive for MAC address.")

        self.logger.info("Returning ZIP archive for MAC %s: %s", mac_address, archive_path)

        return FileResponse(
            path        =   str(archive_path),
            filename    =   archive_name,
            media_type  =   MediaType.APPLICATION_ZIP,
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
        ingress_path = self._artifact_store.ingress_path(FileNameStr(str(filename)))
        filepath = str(ingress_path)

        processor = FileProcessor(filepath)
        success = processor.write_file(data)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to write file")

        params = GetPnmParserAndParameters(processor.read_file()).to_model()
        mac_address = params.mac_address or MacAddress.null()
        pnm_file_type: PnmFileType = params.file_type

        transaction_id = PnmFileTransaction().set_file_by_user(
            mac_address   = MacAddress(mac_address),
            pnm_test_type = PnmFileTypeMapper.get_test_type(pnm_file_type),
            filename      = filename,
        )

        commit_result = self._artifact_store.commit_ingress_file(
            pnm_type=pnm_file_type.name.lower(),
            ingress_path=Path(filepath),
            original_filename=FileNameStr(str(filename)),
        )
        PnmFileTransaction().update_record_compression(
            transaction_id,
            commit_result.stored_filename,
            commit_result.compression,
        )

        return UploadFileResponse(
            mac_address     = MacAddress(mac_address).mac_address,
            filename        = commit_result.stored_filename,
            transaction_id  = transaction_id,
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
            raise HTTPException(status_code=400, detail=f"Invalid file extension, file: {safe_name}")

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
            raise HTTPException(status_code=400, detail=f"Unsupported file type: {file_type.name}")

        file_path = Path(base_dir) / safe_name
        if not file_path.is_file():
            self.logger.warning(f"File not found: {file_path}")
            raise HTTPException(status_code=404, detail="File not found on disk.")

        return FileResponse(
            path        =   str(file_path),
            filename    =   safe_name,
            media_type  =   media_type,
        )

    def get_analysis(self, req: FileAnalysisRequest) -> tuple[ParserAnalysisModelReturn, PnmFileType]:
        """
        Returns basic analysis result for a stored PNM file identified by transaction ID.
        The analysis performed depends on the PNM file type.

        Return:
        Tuple[ParserAnalysisModelReturn, PnmFileType]
            A tuple containing the analysis model and the PNM file type.
        """
        txn_rec = PnmFileTransaction().get_record(req.search.transaction_id)
        if not txn_rec:
            raise HTTPException(status_code=404, detail="Transaction ID not found for analysis.")

        filename = txn_rec.get("filename")
        if not filename:
            raise HTTPException(status_code=404, detail="Filename not found in transaction record.")

        self.logger.info(f"Starting analysis for transaction ID {req.search.transaction_id} on file: {self.pnm_dir}/{filename}")

        compression = txn_rec.get("compression") if isinstance(txn_rec, dict) else None
        materialized = self._artifact_store.materialize(
            req.search.transaction_id,
            FileNameStr(str(filename)),
            compression,
        )

        if not Path(materialized).is_file():
            raise HTTPException(status_code=404, detail="PNM file not found on disk for analysis.")
        fp = FileProcessor(str(materialized)).read_file()

        # Get PnmHeader to Determine PnmFileType
        from pypnm.pnm.parser.pnm_parameter import GetPnmParserAndParameters
        parser, model  = GetPnmParserAndParameters(fp).get_parser()

        self.logger.info(f"Performing {model.file_type.name} analysis for transaction {req.search.transaction_id} on file {filename}")

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
            raise HTTPException(status_code=404, detail="Filename not found in transaction record.")

        compression = txn_data.get("compression") if isinstance(txn_data, dict) else None
        materialized = self._artifact_store.materialize(
            transaction_id,
            FileNameStr(str(filename)),
            compression,
        )

        self.logger.info(
            "Resolving PNM file for transaction %s at %s",
            transaction_id,
            materialized,
        )

        if not materialized.exists() or not materialized.is_file():
            self.logger.warning(
                "PNM file not found on disk for transaction %s at %s",
                transaction_id,
                materialized,
            )
            raise HTTPException(status_code=404, detail="PNM file not found on disk.")

        return materialized

    def get_hexdump_by_transaction_id(self, transaction_id: TransactionId, bytes_per_line: int) -> HexDumpResponse:
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

        file_path  = self.get_pnm_path_for_transaction(transaction_id)
        processor  = FileProcessor(file_path)
        lines      = processor.hexdump(bytes_per_line=bytes_per_line)

        if not lines:
            self.logger.error(
                "Hexdump generation failed or produced no data for transaction %s at %s",
                transaction_id,
                file_path,
            )
            raise HTTPException(status_code=500, detail="Failed to generate hexdump for PNM file.")

        return HexDumpResponse(
            transaction_id = transaction_id,
            bytes_per_line = bytes_per_line,
            lines          = lines,
        )

    def __get_analysis(self, parser: PnmParsers, model:PnmParserParametersModel) -> tuple[ParserAnalysisModelReturn, PnmFileType]:
        """
        Internal method to instantiate the Analysis class with the given parser and model.
        """
        from pypnm.api.routes.common.classes.analysis.analysis import Analysis
        if model.file_type == PnmFileType.RECEIVE_MODULATION_ERROR_RATIO:
            return Analysis.basic_analysis_rxmer_from_model(cast(CmDsOfdmRxMerModel, parser.to_model())), model.file_type

        elif model.file_type == PnmFileType.OFDM_CHANNEL_ESTIMATE_COEFFICIENT:
            return Analysis.basic_analysis_ds_chan_est_from_model(cast(CmDsOfdmChanEstimateCoefModel, parser.to_model())), model.file_type

        elif model.file_type == PnmFileType.OFDM_MODULATION_PROFILE:
            return Analysis.basic_analysis_ds_modulation_profile_from_model(cast(CmDsOfdmModulationProfileModel, parser.to_model())), model.file_type

        elif model.file_type == PnmFileType.DOWNSTREAM_CONSTELLATION_DISPLAY:
            return Analysis.basic_analysis_ds_constellation_display_from_model(cast(CmDsConstDispMeasModel, parser.to_model())), model.file_type

        elif model.file_type == PnmFileType.DOWNSTREAM_HISTOGRAM:
            return Analysis.basic_analysis_ds_histogram_from_model(cast(CmDsHistModel, parser.to_model())), model.file_type

        elif model.file_type == PnmFileType.OFDM_FEC_SUMMARY:
            return Analysis.basic_analysis_ds_ofdm_fec_summary_from_model(cast(CmDsOfdmFecSummaryModel, parser.to_model())), model.file_type

        elif model.file_type == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS or model.file_type == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE:
            return Analysis.basic_analysis_us_ofdma_pre_equalization_from_model(cast(CmUsOfdmaPreEqModel, parser.to_model())), model.file_type

        raise HTTPException(
            status_code=400,
            detail=f"Analysis not implemented for file type: {model.file_type.name}"
        )

    def get_archive(self, request: FileAnalysisRequest) -> FileResponse:
        rpt: Path = Path()

        theme = request.analysis.plot.ui.theme
        plot_config = AnalysisRptMatplotConfig(theme = theme)
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
            plot_config = ConstDisplayAnalysisRptMatplotConfig(theme = theme)
            analysis_rpt = ConstellationDisplayReport(analysis, plot_config)
            rpt: Path = cast(Path, analysis_rpt.build_report())

        elif pnm_ftype == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS or pnm_ftype == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE:
            plot_config = ConstDisplayAnalysisRptMatplotConfig(theme = theme)
            analysis_rpt = CmUsOfdmaPreEqReport(analysis)
            rpt: Path = cast(Path, analysis_rpt.build_report())

        elif pnm_ftype == PnmFileType.OFDM_FEC_SUMMARY:
            plot_config = ConstDisplayAnalysisRptMatplotConfig(theme = theme)
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
        records = PnmFileTransaction().get_all_record_models()
        if not records:
            return MacAddressSystemDescriptorResponse(mac_addresses=[])

        latest_by_mac: dict[str, tuple[int, dict[str, str] | None]] = {}

        for rec in records:
            mac_value = getattr(rec, "mac_address", "")
            mac_str   = str(mac_value).lower().strip()
            if not mac_str:
                continue

            ts_value = getattr(rec, "timestamp", 0)
            try:
                ts_int = int(ts_value)
            except Exception:
                ts_int = 0

            system_description: dict[str, str] | None = None

            device_details = getattr(rec, "device_details", None)
            if device_details is not None:
                if hasattr(device_details, "system_description"):
                    sd_value = getattr(device_details, "system_description", None)
                    if sd_value is not None:
                        if hasattr(sd_value, "model_dump"):
                            system_description = sd_value.model_dump()
                        elif isinstance(sd_value, dict):
                            system_description = sd_value

                elif hasattr(device_details, "model_dump"):
                    dd_dump = device_details.model_dump()
                    if isinstance(dd_dump, dict):
                        sd_value = dd_dump.get("system_description")
                        if isinstance(sd_value, dict):
                            system_description = sd_value

                elif isinstance(device_details, dict):
                    sd_value = device_details.get("system_description")
                    if isinstance(sd_value, dict):
                        system_description = sd_value

            existing = latest_by_mac.get(mac_str)
            if existing is None:
                latest_by_mac[mac_str] = (ts_int, system_description)
                continue

            existing_ts, _existing_sd = existing
            if ts_int >= existing_ts:
                latest_by_mac[mac_str] = (ts_int, system_description)

        entries: list[MacAddressSystemDescriptorEntry] = []
        for mac_str, (_ts, sd) in sorted(latest_by_mac.items(), key=lambda x: x[0]):
            entries.append(
                MacAddressSystemDescriptorEntry(
                    mac_address         = mac_str,
                    system_description  = sd,
                )
            )

        return MacAddressSystemDescriptorResponse(mac_addresses=entries)
# FILE: src/pypnm/api/routes/pypnm/system/log/schemas.py

from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
from pydantic import BaseModel

from pypnm.config.pnm_artifact_storage import PnmArtifactStorageConfig


class SystemConfigModel(BaseModel):
    FastApiRequestDefault: dict[str, object]
    SNMP: dict[str, object]
    PnmBulkDataTransfer: dict[str, object]
    PnmFileRetrieval: dict[str, object]
    PnmArtifactStorage: PnmArtifactStorageConfig
    logging: dict[str, object]
# FILE: src/pypnm/api/routes/pypnm/system/web_service/schemas.py

from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
from pydantic import BaseModel

from pypnm.config.pnm_artifact_storage import PnmArtifactStorageConfig


class SystemConfigModel(BaseModel):
    FastApiRequestDefault: dict[str, object]
    SNMP: dict[str, object]
    PnmBulkDataTransfer: dict[str, object]
    PnmFileRetrieval: dict[str, object]
    PnmArtifactStorage: PnmArtifactStorageConfig
    logging: dict[str, object]
# FILE: src/pypnm/config/pnm_artifact_storage.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pydantic import BaseModel, Field


class ArtifactCompressionPolicyConfig(BaseModel):
    enabled: bool = Field(..., description="Enable policy-driven compression for PNM artifacts.")
    min_bytes: int = Field(..., description="Skip compression for artifacts smaller than this size in bytes.")
    conditional_max_ratio: float = Field(..., description="Maximum compressed/original ratio to allow conditional compression.")
    conditional_min_savings_bytes: int = Field(..., description="Minimum byte savings required for conditional compression.")
    deny: list[str] = Field(default_factory=list, description="PNM types that never compress.")
    always: list[str] = Field(default_factory=list, description="PNM types that always compress.")
    conditional: list[str] = Field(default_factory=list, description="PNM types that compress if thresholds are met.")
    primary_codec: str = Field(..., description="Primary compression codec (zstd).")
    gzip_fallback: bool = Field(..., description="Allow gzip when zstd is unavailable.")
    zstd_level: int = Field(..., description="Zstd compression level.")
    gzip_level: int = Field(..., description="Gzip compression level.")


class ArtifactCacheConfig(BaseModel):
    tmp_root: str = Field(..., description="Root directory for ephemeral artifact caches.")
    ingress_dir: str = Field(..., description="Ingress cache directory name under tmp_root.")
    materialized_dir: str = Field(..., description="Materialized cache directory name under tmp_root.")
    ingress_ttl_seconds: int = Field(..., description="Ingress cache TTL in seconds.")
    materialized_ttl_seconds: int = Field(..., description="Materialized cache TTL in seconds.")
    cleanup_interval_seconds: int = Field(..., description="Minimum seconds between opportunistic cleanups.")


class PnmArtifactStorageConfig(BaseModel):
    compression: ArtifactCompressionPolicyConfig = Field(..., description="Artifact compression policy configuration.")
    cache: ArtifactCacheConfig = Field(..., description="Artifact cache configuration.")

    @classmethod
    def defaults(cls) -> PnmArtifactStorageConfig:
        return cls(
            compression=ArtifactCompressionPolicyConfig(
                enabled=True,
                min_bytes=4096,
                conditional_max_ratio=0.92,
                conditional_min_savings_bytes=8192,
                deny=["ds_ofdm_chan_est_coef"],
                always=["ds_ofdm_codeword_error_rate", "ds_ofdm_modulation_profile"],
                conditional=["ds_ofdm_rxmer_per_subcar", "us_pre_equalizer_coef"],
                primary_codec="zstd",
                gzip_fallback=True,
                zstd_level=3,
                gzip_level=6,
            ),
            cache=ArtifactCacheConfig(
                tmp_root="/tmp/pypnm",
                ingress_dir="ingress",
                materialized_dir="materialized",
                ingress_ttl_seconds=900,
                materialized_ttl_seconds=86400,
                cleanup_interval_seconds=3600,
            ),
        )

    @classmethod
    def from_config(cls, config: dict[str, object] | None) -> PnmArtifactStorageConfig:
        if not isinstance(config, dict):
            return cls.defaults()
        try:
            return cls(**config)
        except Exception:
            return cls.defaults()
# FILE: src/pypnm/config/system_config_settings.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from pathlib import Path
from typing import cast

from pypnm.config.config_manager import ConfigManager
from pypnm.config.pnm_artifact_storage import PnmArtifactStorageConfig
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.secret.crypto_manager import SecretCryptoError, SecretCryptoManager
from pypnm.lib.types import (
    FileNameStr,
    InetAddressStr,
    IPv4Str,
    IPv6Str,
    MacAddressStr,
    SnmpReadCommunity,
    SnmpWriteCommunity,
)


class SystemConfigSettings:
    """Provides dynamically reloaded system configuration via class properties."""
    _cfg        = ConfigManager()
    _logger     = logging.getLogger("SystemConfigSettings")

    _DEFAULT_IP_ADDRESS: InetAddressStr      = cast(InetAddressStr, "192.168.0.100")
    _DEFAULT_SNMP_RETRIES: int              = 5
    _DEFAULT_SNMP_TIMEOUT: int              = 2
    _DEFAULT_FILE_RETRIEVAL_RETRIES: int    = 5
    _DEFAULT_HTTP_PORT: int                 = 80
    _DEFAULT_HTTPS_PORT: int                = 443
    _DEFAULT_TFTP_PORT: int                 = 69
    _DEFAULT_FTP_PORT: int                  = 21
    _DEFAULT_SFTP_PORT: int                 = 22
    _DEFAULT_SCP_PORT: int                  = 22
    _DEFAULT_LOG_LEVEL: str                 = "INFO"
    _DEFAULT_LOG_DIR: str                   = "logs"
    _DEFAULT_LOG_FILENAME: str              = "pypnm.log"
    _DEFAULT_SNMP_READ_COMMUNITY: str       = "public"
    _DEFAULT_SNMP_WRITE_COMMUNITY: str      = ""
    _DEFAULT_PNM_DIR: str                   = ".data/pnm"
    _DEFAULT_CSV_DIR: str                   = ".data/csv"
    _DEFAULT_JSON_DIR: str                  = ".data/json"
    _DEFAULT_XLSX_DIR: str                  = ".data/xlsx"
    _DEFAULT_PNG_DIR: str                   = ".data/png"
    _DEFAULT_ARCHIVE_DIR: str               = ".data/archive"
    _DEFAULT_MSG_RSP_DIR: str               = ".data/msg_rsp"

    _ENCRYPTED_TOKEN_PREFIX: str            = "ENC["

    _PRIMARY_RETRIEVAL_METHOD_KEY: str      = "retrieval_method"
    _LEGACY_RETRIEVAL_METHOD_KEY: str       = "retrival_method"

    @classmethod
    def _config_path(cls, *path: str) -> str:
        """Return dotted path for logging."""
        return ".".join(path)

    @classmethod
    def _peek_str(cls, *path: str) -> str:
        value = cls._cfg.get(*path)
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        return str(value)

    @classmethod
    def _peek_str_fallback(cls, primary: tuple[str, ...], legacy: tuple[str, ...]) -> str:
        value = cls._cfg.get(*primary)
        if value is not None:
            if isinstance(value, str):
                return value
            return str(value)
        return cls._peek_str(*legacy)

    @classmethod
    def _maybe_decrypt(cls, value: str, *path: str) -> str:
        text = value.strip()
        if text == "":
            return ""
        if not text.startswith(cls._ENCRYPTED_TOKEN_PREFIX):
            return text
        try:
            return SecretCryptoManager.decrypt_password(text)
        except SecretCryptoError as exc:
            cls._logger.error(
                "Failed to decrypt configuration value for '%s': %s",
                cls._config_path(*path),
                exc,
            )
            return ""

    @classmethod
    def _get_password_value(cls, require: bool, *method_path: str) -> str:
        password_enc = cls._peek_str(*method_path, "password_enc")
        if password_enc.strip() != "":
            decrypted = cls._maybe_decrypt(password_enc, *method_path, "password_enc")
            if decrypted != "":
                return decrypted
            if require:
                return ""

        password = cls._peek_str(*method_path, "password")
        if password.strip() == "":
            if require:
                cls._logger.error(
                    "Missing configuration value for '%s'; expected password or password_enc",
                    cls._config_path(*method_path, "password"),
                )
            return ""

        return cls._maybe_decrypt(password, *method_path, "password")

    @classmethod
    def _get_password_value_fallback(cls, require: bool, primary: tuple[str, ...], legacy: tuple[str, ...]) -> str:
        password_enc = cls._peek_str_fallback(primary + ("password_enc",), legacy + ("password_enc",))
        if password_enc.strip() != "":
            decrypted = cls._maybe_decrypt(password_enc, *(primary + ("password_enc",)))
            if decrypted != "":
                return decrypted
            if require:
                return ""

        password = cls._peek_str_fallback(primary + ("password",), legacy + ("password",))
        if password.strip() == "":
            if require:
                cls._logger.error(
                    "Missing configuration value for '%s'; expected password or password_enc",
                    cls._config_path(*(primary + ("password",))),
                )
            return ""

        return cls._maybe_decrypt(password, *(primary + ("password",)))

    @classmethod
    def _get_str(cls, default: str, *path: str) -> str:
        value = cls._cfg.get(*path)
        if value is None:
            cls._logger.error(
                "Missing configuration value for '%s'; using default '%s'",
                cls._config_path(*path),
                default,
            )
            return default
        if not isinstance(value, str):
            coerced = str(value)
            cls._logger.error(
                "Non-string configuration value for '%s': %r; using coerced '%s'",
                cls._config_path(*path),
                value,
                coerced,
            )
            return coerced
        if value == "":
            cls._logger.error(
                "Empty configuration value for '%s'; using default '%s'",
                cls._config_path(*path),
                default,
            )
            return default
        return value

    @classmethod
    def _get_str_fallback(cls, default: str, primary: tuple[str, ...], legacy: tuple[str, ...]) -> str:
        value = cls._cfg.get(*primary)
        if value is not None:
            if isinstance(value, str) and value != "":
                return value
            if not isinstance(value, str):
                coerced = str(value)
                cls._logger.error(
                    "Non-string configuration value for '%s': %r; using coerced '%s'",
                    cls._config_path(*primary),
                    value,
                    coerced,
                )
                return coerced
            if value == "":
                legacy_value = cls._cfg.get(*legacy)
                if legacy_value is not None:
                    if not isinstance(legacy_value, str):
                        coerced = str(legacy_value)
                        cls._logger.error(
                            "Non-string configuration value for '%s': %r; using coerced '%s'",
                            cls._config_path(*primary),
                            legacy_value,
                            coerced,
                        )
                        return coerced
                    if legacy_value != "":
                        return legacy_value
                cls._logger.error(
                    "Empty configuration value for '%s'; using default '%s'",
                    cls._config_path(*primary),
                    default,
                )
                return default

        legacy_value = cls._cfg.get(*legacy)
        if legacy_value is None:
            cls._logger.error(
                "Missing configuration value for '%s'; using default '%s'",
                cls._config_path(*primary),
                default,
            )
            return default
        if not isinstance(legacy_value, str):
            coerced = str(legacy_value)
            cls._logger.error(
                "Non-string configuration value for '%s': %r; using coerced '%s'",
                cls._config_path(*primary),
                legacy_value,
                coerced,
            )
            return coerced
        if legacy_value == "":
            cls._logger.error(
                "Empty configuration value for '%s'; using default '%s'",
                cls._config_path(*primary),
                default,
            )
            return default
        return legacy_value

    @classmethod
    def _get_str_allow_empty(cls, default: str, *path: str) -> str:
        value = cls._cfg.get(*path)
        if value is None:
            return default
        if not isinstance(value, str):
            coerced = str(value)
            cls._logger.error(
                "Non-string configuration value for '%s': %r; using coerced '%s'",
                cls._config_path(*path),
                value,
                coerced,
            )
            return coerced
        return value

    @classmethod
    def _get_str_fallback_allow_empty(cls, default: str, primary: tuple[str, ...], legacy: tuple[str, ...]) -> str:
        value = cls._cfg.get(*primary)
        if value is not None:
            if isinstance(value, str):
                return value
            coerced = str(value)
            cls._logger.error(
                "Non-string configuration value for '%s': %r; using coerced '%s'",
                cls._config_path(*primary),
                value,
                coerced,
            )
            return coerced

        legacy_value = cls._cfg.get(*legacy)
        if legacy_value is None:
            return default
        if not isinstance(legacy_value, str):
            coerced = str(legacy_value)
            cls._logger.error(
                "Non-string configuration value for '%s': %r; using coerced '%s'",
                cls._config_path(*primary),
                legacy_value,
                coerced,
            )
            return coerced
        return legacy_value

    @classmethod
    def _get_int(cls, default: int, *path: str) -> int:
        value = cls._cfg.get(*path)
        if value is None:
            cls._logger.error(
                "Missing configuration value for '%s'; using default %d",
                cls._config_path(*path),
                default,
            )
            return default
        try:
            return int(value)
        except (TypeError, ValueError):
            cls._logger.error(
                "Invalid integer configuration value for '%s': %r; using default %d",
                cls._config_path(*path),
                value,
                default,
            )
            return default

    @classmethod
    def _get_int_fallback(cls, default: int, primary: tuple[str, ...], legacy: tuple[str, ...]) -> int:
        value = cls._cfg.get(*primary)
        if value is not None:
            try:
                return int(value)
            except (TypeError, ValueError):
                cls._logger.error(
                    "Invalid integer configuration value for '%s': %r; using default %d",
                    cls._config_path(*primary),
                    value,
                    default,
                )
                return default

        legacy_value = cls._cfg.get(*legacy)
        if legacy_value is None:
            cls._logger.error(
                "Missing configuration value for '%s'; using default %d",
                cls._config_path(*primary),
                default,
            )
            return default
        try:
            return int(legacy_value)
        except (TypeError, ValueError):
            cls._logger.error(
                "Invalid integer configuration value for '%s': %r; using default %d",
                cls._config_path(*primary),
                legacy_value,
                default,
            )
            return default

    @classmethod
    def _get_bool(cls, default: bool, *path: str) -> bool:
        value = cls._cfg.get(*path)
        if isinstance(value, bool):
            return value
        if value is None:
            cls._logger.error(
                "Missing configuration value for '%s'; using default %s",
                cls._config_path(*path),
                default,
            )
            return default

        text = str(value).strip().lower()
        if text in ("1", "true", "yes", "on"):
            return True
        if text in ("0", "false", "no", "off"):
            return False

        cls._logger.error(
            "Invalid boolean configuration value for '%s': %r; using default %s",
            cls._config_path(*path),
            value,
            default,
        )
        return default

    @classmethod
    def _get_bool_fallback(cls, default: bool, primary: tuple[str, ...], legacy: tuple[str, ...]) -> bool:
        value = cls._cfg.get(*primary)
        if isinstance(value, bool):
            return value
        if value is None:
            legacy_value = cls._cfg.get(*legacy)
            if isinstance(legacy_value, bool):
                return legacy_value
            if legacy_value is None:
                cls._logger.error(
                    "Missing configuration value for '%s'; using default %s",
                    cls._config_path(*primary),
                    default,
                )
                return default
            text = str(legacy_value).strip().lower()
            if text in ("1", "true", "yes", "on"):
                return True
            if text in ("0", "false", "no", "off"):
                return False
            cls._logger.error(
                "Invalid boolean configuration value for '%s': %r; using default %s",
                cls._config_path(*primary),
                legacy_value,
                default,
            )
            return default

        text = str(value).strip().lower()
        if text in ("1", "true", "yes", "on"):
            return True
        if text in ("0", "false", "no", "off"):
            return False

        cls._logger.error(
            "Invalid boolean configuration value for '%s': %r; using default %s",
            cls._config_path(*primary),
            value,
            default,
        )
        return default

    @classmethod
    def get_config_path(cls) -> str:
        return cls._cfg.get_config_path()

    @classmethod
    def default_mac_address(cls) -> MacAddressStr:
        mac = cls._cfg.get("FastApiRequestDefault", "mac_address")
        if not mac:
            cls._logger.error(
                "Missing configuration value for '%s'; using MacAddress.null()",
                cls._config_path("FastApiRequestDefault", "mac_address"),
            )
            return cast(MacAddressStr, MacAddress.null())
        return cast(MacAddressStr, mac)

    @classmethod
    def default_ip_address(cls) -> InetAddressStr:
        return cast(
            InetAddressStr,
            cls._get_str(cls._DEFAULT_IP_ADDRESS, "FastApiRequestDefault", "ip_address"),
        )

    # SNMP v2 settings
    @classmethod
    def snmp_enable(cls) -> bool:
        return cls._get_bool(True, "SNMP", "version", "2c", "enable")

    @classmethod
    def snmp_retries(cls) -> int:
        return cls._get_int(cls._DEFAULT_SNMP_RETRIES, "SNMP", "version", "2c", "retries")



    @classmethod
    def snmp_read_community(cls) -> SnmpReadCommunity:
        value = cls._cfg.get("SNMP", "version", "2c", "read_community")
        if value is not None:
            if isinstance(value, str) and value.strip() != "":
                return cast(SnmpReadCommunity, value)
            if not isinstance(value, str):
                coerced = str(value)
                cls._logger.error(
                    "Non-string configuration value for '%s': %r; using coerced '%s'",
                    cls._config_path("SNMP", "version", "2c", "read_community"),
                    value,
                    coerced,
                )
                return cast(SnmpReadCommunity, coerced)
        legacy = cls._cfg.get("SNMP", "version", "2c", "community")
        if legacy is not None:
            if isinstance(legacy, str) and legacy.strip() != "":
                return cast(SnmpReadCommunity, legacy)
            if not isinstance(legacy, str):
                coerced = str(legacy)
                cls._logger.error(
                    "Non-string configuration value for '%s': %r; using coerced '%s'",
                    cls._config_path("SNMP", "version", "2c", "community"),
                    legacy,
                    coerced,
                )
                return cast(SnmpReadCommunity, coerced)
        return cast(
            SnmpReadCommunity,
            cls._get_str(cls._DEFAULT_SNMP_READ_COMMUNITY, "SNMP", "version", "2c", "read_community"),
        )

    @classmethod
    def snmp_write_community(cls) -> SnmpWriteCommunity:
        value = cls._cfg.get("SNMP", "version", "2c", "write_community")
        if value is not None:
            if isinstance(value, str) and value.strip() != "":
                return cast(SnmpWriteCommunity, value)
            if not isinstance(value, str):
                coerced = str(value)
                cls._logger.error(
                    "Non-string configuration value for '%s': %r; using coerced '%s'",
                    cls._config_path("SNMP", "version", "2c", "write_community"),
                    value,
                    coerced,
                )
                return cast(SnmpWriteCommunity, coerced)
        return cast(
            SnmpWriteCommunity,
            cls._get_str(cls._DEFAULT_SNMP_WRITE_COMMUNITY, "SNMP", "version", "2c", "write_community"),
        )

    # SNMP v3 settings

    @classmethod
    def snmp_v3_enable(cls) -> bool:
        return cls._get_bool(False, "SNMP", "version", "3", "enable")

    @classmethod
    def snmp_v3_username(cls) -> str:
        if not cls.snmp_v3_enable():
            return ""
        return cls._get_str("", "SNMP", "version", "3", "username")

    @classmethod
    def snmp_v3_security_level(cls) -> str:
        if not cls.snmp_v3_enable():
            return ""
        return cls._get_str("", "SNMP", "version", "3", "securityLevel")

    @classmethod
    def snmp_v3_auth_protocol(cls) -> str:
        if not cls.snmp_v3_enable():
            return ""
        return cls._get_str("", "SNMP", "version", "3", "authProtocol")

    @classmethod
    def snmp_v3_auth_password(cls) -> str:
        if not cls.snmp_v3_enable():
            return ""
        value = cls._get_str("", "SNMP", "version", "3", "authPassword")
        return cls._maybe_decrypt(value, "SNMP", "version", "3", "authPassword")

    @classmethod
    def snmp_v3_priv_protocol(cls) -> str:
        if not cls.snmp_v3_enable():
            return ""
        return cls._get_str("", "SNMP", "version", "3", "privProtocol")

    @classmethod
    def snmp_v3_priv_password(cls) -> str:
        if not cls.snmp_v3_enable():
            return ""
        value = cls._get_str("", "SNMP", "version", "3", "privPassword")
        return cls._maybe_decrypt(value, "SNMP", "version", "3", "privPassword")

    # SNMP general settings
    @classmethod
    def snmp_timeout(cls) -> int:
        return cls._get_int(cls._DEFAULT_SNMP_TIMEOUT, "SNMP", "timeout")

    # Bulk data transfer settings
    @classmethod
    def bulk_transfer_method(cls) -> str:
        return cls._get_str("", "PnmBulkDataTransfer", "method")

    @classmethod
    def bulk_tftp_ip_v4(cls) -> IPv4Str:
        return cast(
            IPv4Str,
            cls._get_str("", "PnmBulkDataTransfer", "tftp", "ip_v4"),
        )

    @classmethod
    def bulk_tftp_ip_v6(cls) -> IPv6Str:
        return cast(
            IPv6Str,
            cls._get_str("", "PnmBulkDataTransfer", "tftp", "ip_v6"),
        )

    @classmethod
    def bulk_tftp_remote_dir(cls) -> str:
        return cls._get_str_allow_empty("", "PnmBulkDataTransfer", "tftp", "remote_dir")

    @classmethod
    def bulk_http_base_url(cls) -> str:
        return cls._get_str("", "PnmBulkDataTransfer", "http", "base_url")

    @classmethod
    def bulk_http_port(cls) -> int:
        return cls._get_int(cls._DEFAULT_HTTP_PORT, "PnmBulkDataTransfer", "http", "port")

    @classmethod
    def bulk_https_base_url(cls) -> str:
        return cls._get_str("", "PnmBulkDataTransfer", "https", "base_url")

    @classmethod
    def bulk_https_port(cls) -> int:
        return cls._get_int(cls._DEFAULT_HTTPS_PORT, "PnmBulkDataTransfer", "https", "port")

    # PNM file retrieval/storage settings
    @classmethod
    def save_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_PNM_DIR, "PnmFileRetrieval", "pnm_dir")

    @classmethod
    def pnm_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_PNM_DIR, "PnmFileRetrieval", "pnm_dir")

    @classmethod
    def csv_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_CSV_DIR, "PnmFileRetrieval", "csv_dir")

    @classmethod
    def json_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_JSON_DIR, "PnmFileRetrieval", "json_dir")

    @classmethod
    def xlsx_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_XLSX_DIR, "PnmFileRetrieval", "xlsx_dir")

    @classmethod
    def png_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_PNG_DIR, "PnmFileRetrieval", "png_dir")

    @classmethod
    def archive_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_ARCHIVE_DIR, "PnmFileRetrieval", "archive_dir")

    @classmethod
    def message_response_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_MSG_RSP_DIR, "PnmFileRetrieval", "msg_rsp_dir")

    @classmethod
    def transaction_db(cls) -> str:
        return cls._get_str("", "PnmFileRetrieval", "transaction_db")

    @classmethod
    def capture_group_db(cls) -> str:
        return cls._get_str("", "PnmFileRetrieval", "capture_group_db")

    @classmethod
    def session_group_db(cls) -> str:
        return cls._get_str("", "PnmFileRetrieval", "session_group_db")

    @classmethod
    def operation_db(cls) -> str:
        return cls._get_str("", "PnmFileRetrieval", "operation_db")

    @classmethod
    def json_db(cls) -> str:
        return cls._get_str("", "PnmFileRetrieval", "json_transaction_db")

    @classmethod
    def pnm_artifact_storage(cls) -> PnmArtifactStorageConfig:
        """
        Load PNM artifact storage configuration from system config.
        """
        config = cls._cfg.get("PnmArtifactStorage")
        return PnmArtifactStorageConfig.from_config(config if isinstance(config, dict) else None)

    @classmethod
    def file_retrieval_retries(cls) -> int:
        return cls._get_int(cls._DEFAULT_FILE_RETRIEVAL_RETRIES, "PnmFileRetrieval", "retries")

    @classmethod
    def retrieval_method(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "method")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "method")

        return cls._get_str_fallback("", primary, legacy)

    # Local method
    @classmethod
    def local_src_dir(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "local", "src_dir")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "local", "src_dir")
        return cls._get_str_fallback("", primary, legacy)

    # TFTP method
    @classmethod
    def tftp_host(cls) -> InetAddressStr:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "tftp", "host")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "tftp", "host")
        return InetAddressStr(cls._get_str_fallback("", primary, legacy))

    @classmethod
    def tftp_port(cls) -> int:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "tftp", "port")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "tftp", "port")
        return cls._get_int_fallback(cls._DEFAULT_TFTP_PORT, primary, legacy)

    @classmethod
    def tftp_timeout(cls) -> int:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "tftp", "timeout")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "tftp", "timeout")
        return cls._get_int_fallback(cls._DEFAULT_SNMP_TIMEOUT, primary, legacy)

    @classmethod
    def tftp_remote_dir(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "tftp", "remote_dir")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "tftp", "remote_dir")
        return cls._get_str_fallback_allow_empty("", primary, legacy)

    # FTP method
    @classmethod
    def ftp_host(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "host")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "host")
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def ftp_port(cls) -> int:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "port")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "port")
        return cls._get_int_fallback(cls._DEFAULT_FTP_PORT, primary, legacy)

    @classmethod
    def ftp_use_tls(cls) -> bool:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "tls")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "tls")
        return cls._get_bool_fallback(False, primary, legacy)

    @classmethod
    def ftp_timeout(cls) -> int:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "timeout")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "timeout")
        return cls._get_int_fallback(cls._DEFAULT_SNMP_TIMEOUT, primary, legacy)

    @classmethod
    def ftp_user(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "user")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "user")
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def ftp_password(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "ftp")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "ftp")
        return cls._get_password_value_fallback(
            True,
            primary,
            legacy,
        )

    @classmethod
    def ftp_remote_dir(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "remote_dir")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "remote_dir")
        return cls._get_str_fallback_allow_empty("", primary, legacy)

    # SCP method
    @classmethod
    def scp_host(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "scp", "host")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "scp", "host")
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def scp_port(cls) -> int:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "scp", "port")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "scp", "port")
        return cls._get_int_fallback(cls._DEFAULT_SCP_PORT, primary, legacy)

    @classmethod
    def scp_user(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "scp", "user")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "scp", "user")
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def scp_password(cls) -> str:
        private_key_path_primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "scp", "private_key_path")
        private_key_path_legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "scp", "private_key_path")
        private_key_path         = cls._peek_str_fallback(private_key_path_primary, private_key_path_legacy).strip()
        require                  = private_key_path == ""

        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "scp")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "scp")

        return cls._get_password_value_fallback(
            require,
            primary,
            legacy,
        )

    @classmethod
    def scp_private_key_path(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "scp", "private_key_path")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "scp", "private_key_path")
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def scp_remote_dir(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "scp", "remote_dir")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "scp", "remote_dir")
        return cls._get_str_fallback_allow_empty("", primary, legacy)

    # SFTP method
    @classmethod
    def sftp_host(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "host")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "host")
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def sftp_port(cls) -> int:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "port")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "port")
        return cls._get_int_fallback(cls._DEFAULT_SFTP_PORT, primary, legacy)

    @classmethod
    def sftp_user(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "user")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "user")
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def sftp_password(cls) -> str:
        private_key_path_primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "private_key_path")
        private_key_path_legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "private_key_path")
        private_key_path         = cls._peek_str_fallback(private_key_path_primary, private_key_path_legacy).strip()
        require                  = private_key_path == ""

        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "sftp")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "sftp")

        return cls._get_password_value_fallback(
            require,
            primary,
            legacy,
        )

    @classmethod
    def sftp_private_key_path(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "private_key_path")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "private_key_path")
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def sftp_remote_dir(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "remote_dir")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "remote_dir")
        return cls._get_str_fallback_allow_empty("", primary, legacy)

    # HTTP method
    @classmethod
    def http_base_url(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "http", "base_url")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "http", "base_url")
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def http_port(cls) -> int:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "http", "port")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "http", "port")
        return cls._get_int_fallback(cls._DEFAULT_HTTP_PORT, primary, legacy)

    # HTTPS method
    @classmethod
    def https_base_url(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "https", "base_url")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "https", "base_url")
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def https_port(cls) -> int:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "https", "port")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "https", "port")
        return cls._get_int_fallback(cls._DEFAULT_HTTPS_PORT, primary, legacy)

    # Logging
    @classmethod
    def log_level(cls) -> str:
        return cls._get_str(cls._DEFAULT_LOG_LEVEL, "logging", "log_level")

    @classmethod
    def log_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_LOG_DIR, "logging", "log_dir")

    @classmethod
    def log_filename(cls) -> FileNameStr:
        return cls._get_str(cls._DEFAULT_LOG_FILENAME, "logging", "log_filename")

    @classmethod
    def initialize_directories(cls) -> None:
        """
        Create necessary directories if they do not exist.
        """
        directories = [
            cls.pnm_dir(),
            cls.csv_dir(),
            cls.json_dir(),
            cls.xlsx_dir(),
            cls.png_dir(),
            cls.archive_dir(),
            cls.message_response_dir(),
            cls.log_dir(),
        ]
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)

    @classmethod
    def reload(cls) -> None:
        """
        Reload the configuration settings.
        """
        cls._cfg.reload()
        cls.initialize_directories()
# FILE: src/pypnm/lib/compression/__init__.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from pypnm.lib.compression.manager import CompressionManager

__all__ = ["CompressionManager"]
# FILE: src/pypnm/lib/compression/__pycache__/__init__.cpython-310.pyc
o

    ý
iª   ã                   @   s   d dl mZ dgZdS )é    )ÚCompressionManagerr   N)Ú
pypnm.lib.compression.managerr   Ú__all__© r   r   ú@/home/dev01/Projects/PyPNM/src/pypnm/lib/compression/__init__.pyÚ<module>   s   


# FILE: src/pypnm/lib/compression/__pycache__/manager.cpython-310.pyc
o

    
i^	  ã                   @  sN   d dl mZ d dlZd dlZd dlZd dlmZ d dlmZ G dd dZ	dS )é    )Ú
annotationsN)ÚPath)Ú
SystemCallc                   @  sx   e Zd ZdZd$d%ddZd&ddZd'ddZd(ddZed)ddZ	d*d
d
Z
ed*d
dZ
d+d d!Z
ed+d"d#Z
dS ),ÚCompressionManagerzB
    Provide gzip and zstd compression/decompression helpers.
    NÚ
system_callúSystemCall | NoneÚreturnÚNonec                 C  s"   t  | jj ¡| _|p
t | _d S ©N)ÚloggingÚ	getLoggerÚ	__class__Ú__name__Úloggerr   Ú
_system_call)Úselfr   © r   ú?/home/dev01/Projects/PyPNM/src/pypnm/lib/compression/manager.pyÚ__init__   s   zCompressionManager.__init__ÚprimaryÚstrÚ
gzip_fallbackÚboolú
str | Nonec                 C  s0   |dkr|   ¡ r
dS |rdS d S |dkrdS d S )NÚzstdÚzstÚgzÚgzip)Ú_is_zstd_available)r   r   r   r   r   r   Ú
select_codec   s   zCompressionManager.select_codecÚcodecÚsrcr   ÚdestÚlevelÚintc                 C  sB   |dkr
|   |||¡ d S |dkr|  |||¡ d S td| ©Nr   r
   zUnsupported compression codec: )Ú_compress_zstdÚ_compress_gzipÚ
ValueError)r   r    r!   r"   r#   r   r   r   Úcompress"   s   zCompressionManager.compressc                 C  s>   |dkr
|   ||¡ d S |dkr|  ||¡ d S td| r%   )Ú_decompress_zstdÚ_decompress_gzipr(   )r   r    r!   r"   r   r   r   Ú
decompress+   s   

z
CompressionManager.decompressc                   C  s   t  d¡d uS )Nr   )ÚshutilÚwhichr   r   r   r   r
   4   s   z%CompressionManager._is_zstd_availablec                 C  s4   dd| dddt |t |g}| jj|dd d S )Nr   Ú-ú-qú-fú-oT©Úcheck©r   r   Úrun)r   r!   r"   r#   Úcmdr   r   r   r&   8   s    z!CompressionManager._compress_zstdc              	   C  sz   |   d¡.}tj |d|d
}| |¡ W d    n1 s
w   Y  W d    d S W d    d S 1 s6w   Y  d S )NÚrbÚwb)Ú
compresslevel)Úopenr
   Ú
writelines)r!   r"   r#   Úf_inÚf_outr   r   r   r'   <   s   

Pÿz!CompressionManager._compress_gzipc                 C  s.   dddddt |t |g}| jj|dd d S )Nr   z-dr0   r1   r2   Tr3   r5   )r   r!   r"   r7   r   r   r   r*   A   s   z#CompressionManager._decompress_zstdc              	   C  sv   t  | d¡+}| d¡
}| |¡ W d    n1 s
w   Y  W d    d S W d    d S 1 s4w   Y  d S )Nr8   r9   )r
   r;   r<   )r!   r"   r=   r>   r   r   r   r+   E   s   
Pÿz#CompressionManager._decompress_gzipr
   )r   r   r   r	   )r   r   r   r   r   r   )
r    r   r!   r   r"   r   r#   r$   r   r	   )r    r   r!   r   r"   r   r   r	   )r   r   )r!   r   r"   r   r#   r$   r   r	   )r!   r   r"   r   r   r	   )r   Ú
__module__Ú
__qualname__Ú__doc__r   r   r)   r,   Ú
staticmethodr
   r&   r'   r*   r+   r   r   r   r   r      s
    




		



r   )
Ú
__future__r   r
   r
   r-   Úpathlibr   Ú
pypnm.lib.system_call.managerr   r   r   r   r   r   Ú<module>   s   



# FILE: src/pypnm/lib/compression/manager.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import gzip
import logging
import shutil
from pathlib import Path

from pypnm.lib.system_call.manager import SystemCall


class CompressionManager:
    """
    Provide gzip and zstd compression/decompression helpers.
    """

    def __init__(self, system_call: SystemCall | None = None) -> None:
        self.logger = logging.getLogger(f"{self.__class__.__name__}")
        self._system_call = system_call or SystemCall()

    def select_codec(self, primary: str, gzip_fallback: bool) -> str | None:
        if primary == "zstd":
            if self._is_zstd_available():
                return "zst"
            if gzip_fallback:
                return "gz"
            return None
        if primary == "gzip":
            return "gz"
        return None

    def compress(self, codec: str, src: Path, dest: Path, level: int) -> None:
        if codec == "zst":
            self._compress_zstd(src, dest, level)
            return
        if codec == "gz":
            self._compress_gzip(src, dest, level)
            return
        raise ValueError(f"Unsupported compression codec: {codec}")

    def decompress(self, codec: str, src: Path, dest: Path) -> None:
        if codec == "zst":
            self._decompress_zstd(src, dest)
            return
        if codec == "gz":
            self._decompress_gzip(src, dest)
            return
        raise ValueError(f"Unsupported compression codec: {codec}")

    @staticmethod
    def _is_zstd_available() -> bool:
        return shutil.which("zstd") is not None

    def _compress_zstd(self, src: Path, dest: Path, level: int) -> None:
        cmd = ["zstd", f"-{level}", "-q", "-f", "-o", str(dest), str(src)]
        self._system_call.run(cmd, check=True)

    @staticmethod
    def _compress_gzip(src: Path, dest: Path, level: int) -> None:
        with src.open("rb") as f_in, gzip.open(dest, "wb", compresslevel=level) as f_out:
            f_out.writelines(f_in)

    def _decompress_zstd(self, src: Path, dest: Path) -> None:
        cmd = ["zstd", "-d", "-q", "-f", "-o", str(dest), str(src)]
        self._system_call.run(cmd, check=True)

    @staticmethod
    def _decompress_gzip(src: Path, dest: Path) -> None:
        with gzip.open(src, "rb") as f_in, dest.open("wb") as f_out:
            f_out.writelines(f_in)
# FILE: src/pypnm/lib/system_call/__init__.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from pypnm.lib.system_call.manager import SystemCall

__all__ = ["SystemCall"]
# FILE: src/pypnm/lib/system_call/__pycache__/__init__.cpython-310.pyc
o

    ï
i   ã                   @   s   d dl mZ dgZdS )é    )Ú
SystemCallr   N)Ú
pypnm.lib.system_call.managerr   Ú__all__© r   r   ú@/home/dev01/Projects/PyPNM/src/pypnm/lib/system_call/__init__.pyÚ<module>   s   


# FILE: src/pypnm/lib/system_call/__pycache__/manager.cpython-310.pyc
o

    ò#i-  ã                   @  s.   d dl mZ d dlZd dlZG dd dZdS )é    )Ú
annotationsNc                   @  s&   e Zd ZdZdddZddd
d
ZdS )Ú
SystemCallzP
    Unified subprocess wrapper with logging and consistent error handling.
    ÚreturnÚNonec                 C  s   t  | jj ¡| _d S )N)ÚloggingÚ	getLoggerÚ	__class__Ú__name__Úlogger)Úself© r
   ú?/home/dev01/Projects/PyPNM/src/pypnm/lib/system_call/manager.pyÚ__init__   s   zSystemCall.__init__TÚargsú	list[str]ÚcheckÚboolú subprocess.CompletedProcess[str]c              
   C  sº   | j  dd |¡¡ z
tj||ddd}W n% tjy: } z|jr&|j ¡ nd}| j  dd |¡|j	|¡  d}~ww |j	dkr[|d	u r[|jrL|j ¡ nd}| j  
d
|j	d |¡|¡ |S )
zû
        Execute a system command and return the completed process result.

        Parameters
        ----------
        args:
            Command argument list to execute.
        check:
            When True, raise on non-zero return code.
        zSystem call: %sÚ T)r   Úcapture_outputÚtextz	no stderrz)System call failed: %s (rc=%s, stderr=%s)Nr   Fz6System call returned non-zero rc=%s for %s (stderr=%s))
r
   ÚdebugÚjoinÚ
subprocessÚrunÚCalledProcessErrorÚstderrÚstripÚerrorÚ
returncodeÚwarning)r
   r   r   ÚresultÚexcr
   r
   r
   r
   r      s.   

üýüzSystemCall.runN)r   r   )T)r   r   r   r   r   r   )r	   Ú
__module__Ú
__qualname__Ú__doc__r   r   r
   r
   r
   r
   r   
   s    
r   )Ú
__future__r   r   r   r   r
   r
   r
   r
   Ú<module>   s   

# FILE: src/pypnm/lib/system_call/manager.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
import subprocess


class SystemCall:
    """
    Unified subprocess wrapper with logging and consistent error handling.
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger(f"{self.__class__.__name__}")

    def run(self, args: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
        """
        Execute a system command and return the completed process result.

        Parameters
        ----------
        args:
            Command argument list to execute.
        check:
            When True, raise on non-zero return code.
        """
        self.logger.debug("System call: %s", " ".join(args))
        try:
            result = subprocess.run(
                args,
                check=check,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.strip() if exc.stderr else "no stderr"
            self.logger.error("System call failed: %s (rc=%s, stderr=%s)", " ".join(args), exc.returncode, stderr)
            raise

        if result.returncode != 0 and check is False:
            stderr = result.stderr.strip() if result.stderr else "no stderr"
            self.logger.warning(
                "System call returned non-zero rc=%s for %s (stderr=%s)",
                result.returncode,
                " ".join(args),
                stderr,
            )

        return result
# FILE: src/pypnm/pnm/lib/pnm_artifact_store.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from pypnm.api.routes.common.classes.file_capture.types import CompressionMetadataModel
from pypnm.config.config_manager import ConfigManager
from pypnm.config.pnm_artifact_storage import PnmArtifactStorageConfig
from pypnm.lib.compression.manager import CompressionManager
from pypnm.lib.system_call.manager import SystemCall
from pypnm.lib.types import FileNameStr, PathLike, TransactionId


@dataclass(frozen=True)
class ArtifactCommitResult:
    stored_filename: FileNameStr
    stored_path: Path
    compression: dict[str, object] | None
    size_before: int
    size_after: int


class PnmArtifactStore:
    """
    Manage at-rest compression and materialized caches for PNM artifacts.
    """

    _STAMP_SUFFIX = ".stamp.json"

    def __init__(self, config: PnmArtifactStorageConfig | None = None, pnm_dir: PathLike | None = None) -> None:
        """
        Initialize artifact storage with compression and cache configuration.

        Parameters
        ----------
        config:
            Optional explicit artifact storage configuration. When omitted,
            the config is loaded from the system configuration.
        pnm_dir:
            Optional override for the durable PNM storage root.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self._config = config or self._load_config()
        self._pnm_dir = Path(pnm_dir) if pnm_dir is not None else Path(self._load_pnm_dir())
        self._compression_manager = CompressionManager(SystemCall())
        self._tmp_root = Path(self._config.cache.tmp_root)
        self._ingress_dir = self._tmp_root / self._config.cache.ingress_dir
        self._materialized_dir = self._tmp_root / self._config.cache.materialized_dir
        self._last_cleanup = 0.0

        self._pnm_dir.mkdir(parents=True, exist_ok=True)
        self._ingress_dir.mkdir(parents=True, exist_ok=True)
        self._materialized_dir.mkdir(parents=True, exist_ok=True)

    def ingress_path(self, filename: FileNameStr, transaction_id: TransactionId | None = None) -> Path:
        """
        Return a writable ingress path for a capture file.

        Parameters
        ----------
        filename:
            Target filename for the ingress copy (normalized to raw filename).
        transaction_id:
            Optional transaction ID to place the file in a scoped ingress folder.

        Returns
        -------
        Path
            Filesystem path where callers can write the ingress artifact.
        """
        if transaction_id:
            dest_dir = self._ingress_dir / str(transaction_id)
        else:
            dest_dir = self._ingress_dir / "untracked"
        dest_dir.mkdir(parents=True, exist_ok=True)
        return dest_dir / self._normalize_ingress_name(filename)

    def ingress_candidate_path(self, filename: FileNameStr, transaction_id: TransactionId | None = None) -> Path:
        """
        Return the expected ingress path without creating directories.

        Parameters
        ----------
        filename:
            Target filename for the ingress copy (normalized to raw filename).
        transaction_id:
            Optional transaction ID to place the file in a scoped ingress folder.

        Returns
        -------
        Path
            Expected ingress location for the artifact.
        """
        if transaction_id:
            dest_dir = self._ingress_dir / str(transaction_id)
        else:
            dest_dir = self._ingress_dir / "untracked"
        return dest_dir / self._normalize_ingress_name(filename)

    def find_ingress_by_filename(self, filename: FileNameStr) -> Path | None:
        """
        Search ingress cache for a filename, returning a unique match.

        Parameters
        ----------
        filename:
            Filename to search for (normalized to raw filename).

        Returns
        -------
        Path | None
            Matching ingress path when exactly one file is found; otherwise None.
        """
        target = self._normalize_ingress_name(filename)
        matches = list(self._ingress_dir.rglob(target))
        if len(matches) == 1:
            return matches[0]
        return None

    @staticmethod
    def _normalize_ingress_name(filename: FileNameStr) -> str:
        name = Path(str(filename)).name
        if name.endswith(".zst"):
            return name[:-4]
        if name.endswith(".gz"):
            return name[:-3]
        return name

    def commit_ingress_file(
        self,
        pnm_type: str,
        ingress_path: Path,
        original_filename: FileNameStr,
    ) -> ArtifactCommitResult:
        """
        Commit an ingress file into the durable store with compression policy.

        Parameters
        ----------
        pnm_type:
            PNM type string used to evaluate compression policy.
        ingress_path:
            Filesystem path of the ingress artifact to commit.
        original_filename:
            Original filename used to derive the stored filename.

        Returns
        -------
        ArtifactCommitResult
            Commit metadata including stored filename, sizes, and compression info.
        """
        self._maybe_cleanup()

        if not ingress_path.is_file():
            raise FileNotFoundError(f"Ingress file not found: {ingress_path}")

        size_before = ingress_path.stat().st_size
        if not self._config.compression.enabled:
            return self._commit_raw(ingress_path, original_filename, size_before)

        if size_before < self._config.compression.min_bytes:
            return self._commit_raw(ingress_path, original_filename, size_before)

        policy = self._config.compression
        action = self._compression_action(pnm_type)

        if action == "deny":
            return self._commit_raw(ingress_path, original_filename, size_before)

        codec = self._compression_manager.select_codec(policy.primary_codec, policy.gzip_fallback)
        if codec is None:
            return self._commit_raw(ingress_path, original_filename, size_before)

        compressed_path = self._pnm_dir / f"{Path(str(original_filename)).name}.{codec}"
        tmp_path = self._pnm_dir / f".{compressed_path.name}.tmp"

        level = policy.zstd_level if codec == "zst" else policy.gzip_level
        self._compression_manager.compress(codec, ingress_path, tmp_path, level)

        size_after = tmp_path.stat().st_size
        ratio = size_after / size_before if size_before else 1.0
        savings = size_before - size_after

        if (
            action == "conditional"
            and ratio > policy.conditional_max_ratio
            and savings < policy.conditional_min_savings_bytes
        ):
            tmp_path.unlink(missing_ok=True)
            return self._commit_raw(ingress_path, original_filename, size_before)

        os.replace(tmp_path, compressed_path)

        compression = CompressionMetadataModel(
            is_compressed=True,
            codec="zstd" if codec == "zst" else "gzip",
            level=policy.zstd_level if codec == "zst" else policy.gzip_level,
            size_before=size_before,
            size_after=size_after,
        )
        return ArtifactCommitResult(
            stored_filename=FileNameStr(compressed_path.name),
            stored_path=compressed_path,
            compression=compression.model_dump(),
            size_before=size_before,
            size_after=size_after,
        )

    def resolve_physical_path(self, filename: FileNameStr, compression: dict[str, object] | None) -> Path:
        """
        Resolve the on-disk artifact path using filename and compression metadata.

        Parameters
        ----------
        filename:
            Stored filename as recorded in the transaction record.
        compression:
            Compression metadata dict, when available.

        Returns
        -------
        Path
            Best-effort resolved physical path on disk.
        """
        base = Path(str(filename)).name
        if compression and compression.get("is_compressed") is True:
            codec = self._codec_from_filename(base, compression)
            if codec == "zst":
                name = base if base.endswith(".zst") else f"{base}.zst"
                candidate = self._pnm_dir / name
                if candidate.is_file():
                    return candidate
            if codec == "gz":
                name = base if base.endswith(".gz") else f"{base}.gz"
                candidate = self._pnm_dir / name
                if candidate.is_file():
                    return candidate
            candidate = self._pnm_dir / base
            if candidate.is_file():
                return candidate

        raw_path = self._pnm_dir / base
        if raw_path.is_file():
            return raw_path

        zstd_path = self._pnm_dir / f"{base}.zst"
        if zstd_path.is_file():
            return zstd_path

        gzip_path = self._pnm_dir / f"{base}.gz"
        if gzip_path.is_file():
            return gzip_path

        return raw_path

    def materialize(
        self,
        transaction_id: TransactionId,
        filename: FileNameStr,
        compression: dict[str, object] | None,
    ) -> Path:
        """
        Provide a raw file path, materializing compressed artifacts into cache.

        Parameters
        ----------
        transaction_id:
            Transaction identifier for scoping the materialized cache path.
        filename:
            Stored filename as recorded in the transaction record.
        compression:
            Compression metadata dict, when available.

        Returns
        -------
        Path
            Path to a raw artifact, either the durable store or materialized cache.
        """
        self._maybe_cleanup()

        physical_path = self.resolve_physical_path(filename, compression)
        codec = self._codec_from_filename(physical_path.name, compression)
        if codec is None:
            return physical_path

        materialized_path = self._materialized_path(transaction_id, physical_path)
        stamp_path = Path(f"{materialized_path}{self._STAMP_SUFFIX}")

        if self._stamp_valid(stamp_path, physical_path, codec, materialized_path):
            return materialized_path

        self.logger.warning(
            "Uncompressed cache miss for transaction %s; raw file not cached, decompressing %s",
            transaction_id,
            physical_path,
        )
        materialized_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = materialized_path.with_name(f".{materialized_path.name}.tmp")

        self._compression_manager.decompress(codec, physical_path, tmp_path)

        os.replace(tmp_path, materialized_path)
        self._write_stamp(stamp_path, physical_path, codec)
        return materialized_path

    def read_bytes(
        self,
        transaction_id: TransactionId,
        filename: FileNameStr,
        compression: dict[str, object] | None,
    ) -> bytes:
        """
        Read artifact bytes, materializing into cache as needed.

        Parameters
        ----------
        transaction_id:
            Transaction identifier for cache scoping.
        filename:
            Stored filename as recorded in the transaction record.
        compression:
            Compression metadata dict, when available.

        Returns
        -------
        bytes
            Raw artifact bytes.
        """
        materialized = self.materialize(transaction_id, filename, compression)
        return materialized.read_bytes()

    def _load_config(self) -> PnmArtifactStorageConfig:
        """
        Load artifact storage configuration from system config.
        """
        config = ConfigManager().get("PnmArtifactStorage")
        return PnmArtifactStorageConfig.from_config(config if isinstance(config, dict) else None)

    def _load_pnm_dir(self) -> PathLike:
        """
        Load the configured PNM storage directory.
        """
        config = ConfigManager().get("PnmFileRetrieval", "pnm_dir")
        if isinstance(config, str) and config.strip():
            return config
        return ".data/pnm"

    def _compression_action(self, pnm_type: str) -> str:
        """
        Resolve the compression policy action for a PNM type.
        """
        policy = self._config.compression
        if pnm_type in policy.deny:
            return "deny"
        if pnm_type in policy.always:
            return "always"
        if pnm_type in policy.conditional:
            return "conditional"
        return "deny"

    @staticmethod
    def _raw_compression_metadata(size: int) -> CompressionMetadataModel:
        """
        Build compression metadata for uncompressed artifacts.
        """
        return CompressionMetadataModel(
            is_compressed=False,
            codec="none",
            level=0,
            size_before=size,
            size_after=size,
        )

    def _commit_raw(
        self,
        ingress_path: Path,
        original_filename: FileNameStr,
        size_before: int,
    ) -> ArtifactCommitResult:
        """
        Persist an uncompressed artifact into the durable store.
        """
        dest_path = self._pnm_dir / Path(str(original_filename)).name
        tmp_path = self._pnm_dir / f".{dest_path.name}.tmp"
        shutil.copy2(ingress_path, tmp_path)
        os.replace(tmp_path, dest_path)
        compression = self._raw_compression_metadata(size_before)
        return ArtifactCommitResult(
            stored_filename=FileNameStr(dest_path.name),
            stored_path=dest_path,
            compression=compression.model_dump(),
            size_before=size_before,
            size_after=size_before,
        )

    def _codec_from_filename(self, filename: str, compression: dict[str, object] | None) -> str | None:
        """
        Detect codec from metadata and filename extension.
        """
        if compression and compression.get("is_compressed") is True:
            codec = compression.get("codec")
            if isinstance(codec, str):
                if filename.endswith(".zst") and codec != "zstd":
                    self.logger.warning("Compression metadata codec '%s' conflicts with .zst extension", codec)
                if filename.endswith(".gz") and codec != "gzip":
                    self.logger.warning("Compression metadata codec '%s' conflicts with .gz extension", codec)
                return "zst" if codec == "zstd" else "gz" if codec == "gzip" else None
        if filename.endswith(".zst"):
            return "zst"
        if filename.endswith(".gz"):
            return "gz"
        return None

    def _is_compressed(self, compression: dict[str, object] | None, filename: str) -> bool:
        """
        Determine whether a file is compressed based on metadata or extension.
        """
        if compression and compression.get("is_compressed") is True:
            return True
        return filename.endswith(".zst") or filename.endswith(".gz")

    def _materialized_path(self, transaction_id: TransactionId, source_path: Path) -> Path:
        """
        Build the cache path for a materialized artifact copy.
        """
        digest = hashlib.sha256(str(source_path).encode()).hexdigest()[:12]
        name = source_path.name
        if name.endswith(".zst"):
            name = name[:-4]
        elif name.endswith(".gz"):
            name = name[:-3]
        return self._materialized_dir / str(transaction_id) / digest / name

    def _write_stamp(self, stamp_path: Path, source_path: Path, codec: str) -> None:
        """
        Write a cache stamp describing the source artifact.
        """
        payload = {
            "source_path": str(source_path),
            "source_mtime": source_path.stat().st_mtime,
            "source_size": source_path.stat().st_size,
            "codec": codec,
        }
        stamp_path.write_text(json.dumps(payload))

    def _stamp_valid(self, stamp_path: Path, source_path: Path, codec: str, materialized_path: Path) -> bool:
        """
        Validate a materialized cache stamp against the source artifact.
        """
        if not stamp_path.is_file() or not materialized_path.is_file():
            return False
        try:
            data = json.loads(stamp_path.read_text())
        except Exception:
            return False
        if data.get("source_path") != str(source_path):
            return False
        if data.get("source_mtime") != source_path.stat().st_mtime:
            return False
        if data.get("source_size") != source_path.stat().st_size:
            return False
        return data.get("codec") == codec

    def _maybe_cleanup(self) -> None:
        """
        Run cache cleanup on a configured cadence.
        """
        now = time.time()
        interval = self._config.cache.cleanup_interval_seconds
        if now - self._last_cleanup < interval:
            return
        self._cleanup_dir(self._ingress_dir, self._config.cache.ingress_ttl_seconds)
        self._cleanup_dir(self._materialized_dir, self._config.cache.materialized_ttl_seconds)
        self._last_cleanup = now

    def _cleanup_dir(self, root: Path, ttl_seconds: int) -> None:
        """
        Remove expired files and empty directories under a cache root.
        """
        if ttl_seconds <= 0:
            return
        now = time.time()
        for path in root.rglob("*"):
            if path.is_file():
                age = now - path.stat().st_mtime
                if age >= ttl_seconds:
                    path.unlink(missing_ok=True)
        for path in sorted(root.rglob("*"), reverse=True):
            if path.is_dir():
                try:
                    path.rmdir()
                except OSError:
                    continue
# FILE: src/pypnm/tools/tmp_cache_cleanup.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
import time
from pathlib import Path

from pypnm.config.config_manager import ConfigManager
from pypnm.config.pnm_artifact_storage import PnmArtifactStorageConfig


class TmpCacheCleaner:
    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        config = ConfigManager().get("PnmArtifactStorage")
        self._config = PnmArtifactStorageConfig.from_config(config if isinstance(config, dict) else None)
        self._tmp_root = Path(self._config.cache.tmp_root)

    def run(self) -> int:
        ingress_dir = self._tmp_root / "ingress"
        materialized_dir = self._tmp_root / "materialized"

        self._cleanup_dir(ingress_dir, self._config.cache.ingress_ttl_seconds)
        self._cleanup_dir(materialized_dir, self._config.cache.materialized_ttl_seconds)
        return 0

    def _cleanup_dir(self, root: Path, ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            return
        if not root.exists():
            return
        now = time.time()
        for path in root.rglob("*"):
            if path.is_file():
                age = now - path.stat().st_mtime
                if age >= ttl_seconds:
                    path.unlink(missing_ok=True)
        for path in sorted(root.rglob("*"), reverse=True):
            if path.is_dir():
                try:
                    path.rmdir()
                except OSError:
                    continue


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    return TmpCacheCleaner().run()


if __name__ == "__main__":
    raise SystemExit(main())
# FILE: tests/test_common_process_service.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
from pathlib import Path
import pytest

from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.extended.common_process_service import CommonProcessService
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.lib.types import TransactionId, TransactionRecord
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest


def _service_stub(payload: list[dict[str, object]] | None = None) -> CommonProcessService:
    service = CommonProcessService.__new__(CommonProcessService)
    service.logger = logging.getLogger("CommonProcessService")
    service._msg_rsp = MessageResponse(ServiceStatusCode.SUCCESS, payload=payload or [])
    return service


def test_update_pnm_data_from_message_response_extension_merges() -> None:
    service = _service_stub()
    transaction_id = TransactionId("abc123")
    service._msg_rsp.payload = [
        {
            "status": ServiceStatusCode.SUCCESS.name,
            "message_type": "PNM_FILE_TRANSACTION",
            "message": {
                "transaction_id": transaction_id,
                "extension": {"key": "value"},
            },
        },
    ]
    transaction_record: TransactionRecord = {"transaction_id": transaction_id}
    pnm_data = {"existing": "data"}

    updated = service._update_pnm_data_from_message_response_extension(transaction_record, pnm_data)

    assert updated == {"existing": "data", "key": "value"}
    assert transaction_record["transaction_id"] == transaction_id


def test_update_pnm_data_from_message_response_extension_missing_extension() -> None:
    service = _service_stub()
    transaction_id = TransactionId("abc123")
    service._msg_rsp.payload = [
        {
            "status": ServiceStatusCode.SUCCESS.name,
            "message_type": "PNM_FILE_TRANSACTION",
            "message": {
                "transaction_id": transaction_id,
            },
        },
    ]
    transaction_record: TransactionRecord = {"transaction_id": transaction_id}
    pnm_data = {"existing": "data"}

    updated = service._update_pnm_data_from_message_response_extension(transaction_record, pnm_data)

    assert updated == {"existing": "data"}


def test_process_prefers_ingress_file_when_present(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ingress_file = tmp_path / "ingress.bin"
    ingress_file.write_bytes(b"test")

    class _FakeArtifactStore:
        def ingress_candidate_path(self, filename: object, transaction_id: object) -> Path:
            return ingress_file

        def materialize(self, transaction_id: object, filename: object, compression: object) -> Path:
            raise AssertionError("materialize should not be called when ingress file exists")

    class _FakeParser:
        def __init__(self, binary_data: bytes) -> None:
            self.binary_data = binary_data

        def to_dict(self) -> dict[str, object]:
            return {"data": "ok"}

    service = CommonProcessService.__new__(CommonProcessService)
    service.logger = logging.getLogger("CommonProcessService")
    service._artifact_store = _FakeArtifactStore()
    service._msg_rsp = MessageResponse(ServiceStatusCode.SUCCESS, payload=[])
    service._messages = []

    transaction_record: TransactionRecord = {
        "transaction_id": TransactionId("tx-ingress"),
        "filename": "ingress.bin",
        "pnm_test_type": DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR.name,
        "device_details": {},
    }

    monkeypatch.setattr(
        "pypnm.api.routes.common.extended.common_process_service.CmDsOfdmRxMer",
        _FakeParser,
    )

    status = service._process_pnm_measure_test(transaction_record)

    assert status == ServiceStatusCode.SUCCESS


def test_process_uses_ingress_fallback_when_transaction_dir_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ingress_dir = tmp_path / "ingress" / "other-tx"
    ingress_dir.mkdir(parents=True)
    ingress_file = ingress_dir / "fallback.bin"
    ingress_file.write_bytes(b"fallback")

    class _FakeArtifactStore:
        def ingress_candidate_path(self, filename: object, transaction_id: object) -> Path:
            return tmp_path / "ingress" / "missing" / "fallback.bin"

        def find_ingress_by_filename(self, filename: object) -> Path | None:
            return ingress_file

        def materialize(self, transaction_id: object, filename: object, compression: object) -> Path:
            raise AssertionError("materialize should not be called when ingress fallback exists")

    class _FakeParser:
        def __init__(self, binary_data: bytes) -> None:
            self.binary_data = binary_data

        def to_dict(self) -> dict[str, object]:
            return {"data": "ok"}

    service = CommonProcessService.__new__(CommonProcessService)
    service.logger = logging.getLogger("CommonProcessService")
    service._artifact_store = _FakeArtifactStore()
    service._msg_rsp = MessageResponse(ServiceStatusCode.SUCCESS, payload=[])
    service._messages = []

    transaction_record: TransactionRecord = {
        "transaction_id": TransactionId("tx-fallback"),
        "filename": "fallback.bin",
        "pnm_test_type": DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR.name,
        "device_details": {},
    }

    monkeypatch.setattr(
        "pypnm.api.routes.common.extended.common_process_service.CmDsOfdmRxMer",
        _FakeParser,
    )

    status = service._process_pnm_measure_test(transaction_record)

    assert status == ServiceStatusCode.SUCCESS
# FILE: tests/test_pnm_artifact_store.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

from pypnm.config.pnm_artifact_storage import (
    ArtifactCacheConfig,
    ArtifactCompressionPolicyConfig,
    PnmArtifactStorageConfig,
)
from pypnm.lib.types import FileNameStr, TransactionId
from pypnm.pnm.lib.pnm_artifact_store import PnmArtifactStore


def _build_config(tmp_root: Path, min_bytes: int) -> PnmArtifactStorageConfig:
    return PnmArtifactStorageConfig(
        compression=ArtifactCompressionPolicyConfig(
            enabled=True,
            min_bytes=min_bytes,
            conditional_max_ratio=0.92,
            conditional_min_savings_bytes=8192,
            deny=[],
            always=["test_type"],
            conditional=[],
            primary_codec="gzip",
            gzip_fallback=False,
            zstd_level=3,
            gzip_level=6,
        ),
        cache=ArtifactCacheConfig(
            tmp_root=str(tmp_root),
            ingress_dir="ingress",
            materialized_dir="materialized",
            ingress_ttl_seconds=900,
            materialized_ttl_seconds=86400,
            cleanup_interval_seconds=0,
        ),
    )


def test_commit_ingress_file_gzip_compresses(tmp_path: Path) -> None:
    cfg = _build_config(tmp_path / "tmp", min_bytes=0)
    pnm_dir = tmp_path / "pnm"
    store = PnmArtifactStore(config=cfg, pnm_dir=pnm_dir)

    txn_id = TransactionId("tx1")
    ingress = store.ingress_path(FileNameStr("test.bin"), txn_id)
    ingress.write_bytes(b"0" * 10000)

    result = store.commit_ingress_file("test_type", ingress, FileNameStr("test.bin"))
    assert str(result.stored_filename).endswith(".gz")
    assert result.compression is not None
    assert result.compression.get("is_compressed") is True
    assert result.size_after < result.size_before


def test_commit_ingress_file_min_bytes_skips_compression(tmp_path: Path) -> None:
    cfg = _build_config(tmp_path / "tmp", min_bytes=20000)
    pnm_dir = tmp_path / "pnm"
    store = PnmArtifactStore(config=cfg, pnm_dir=pnm_dir)

    ingress = store.ingress_path(FileNameStr("test.bin"), TransactionId("tx2"))
    ingress.write_bytes(b"1" * 10000)

    result = store.commit_ingress_file("test_type", ingress, FileNameStr("test.bin"))
    assert str(result.stored_filename).endswith("test.bin")
    assert result.compression is not None
    assert result.compression.get("is_compressed") is False


def test_materialize_decompresses_gzip(tmp_path: Path) -> None:
    cfg = _build_config(tmp_path / "tmp", min_bytes=0)
    pnm_dir = tmp_path / "pnm"
    store = PnmArtifactStore(config=cfg, pnm_dir=pnm_dir)

    txn_id = TransactionId("tx3")
    ingress = store.ingress_path(FileNameStr("test.bin"), txn_id)
    payload = b"abc" * 5000
    ingress.write_bytes(payload)

    result = store.commit_ingress_file("test_type", ingress, FileNameStr("test.bin"))
    materialized = store.materialize(txn_id, result.stored_filename, result.compression)

    assert materialized.read_bytes() == payload


def test_resolve_physical_path_prefers_raw_when_missing_compressed(tmp_path: Path) -> None:
    cfg = _build_config(tmp_path / "tmp", min_bytes=0)
    pnm_dir = tmp_path / "pnm"
    store = PnmArtifactStore(config=cfg, pnm_dir=pnm_dir)

    raw_path = pnm_dir / "raw.bin"
    raw_path.write_bytes(b"raw")

    compression = {
        "is_compressed": True,
        "codec": "zstd",
        "level": 3,
        "size_before": 3,
        "size_after": 2,
    }
    resolved = store.resolve_physical_path(FileNameStr("raw.bin"), compression)
    assert resolved == raw_path
# FILE: tests/test_pnm_file_transaction_filename.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.types import FileNameStr, TransactionId


def _patch_transaction_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    db_path = tmp_path / "transactions.json"

    def _fake_transaction_db(cls: type[SystemConfigSettings]) -> str:
        return str(db_path)

    monkeypatch.setattr(
        SystemConfigSettings,
        "transaction_db",
        classmethod(_fake_transaction_db),
        raising=False,
    )

    return db_path


def test_get_record_by_filename_matches_raw(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = _patch_transaction_db(tmp_path, monkeypatch)
    records = {
        "tx-raw": {
            "filename": "raw.bin",
        },
    }
    db_path.write_text(json.dumps(records))

    txn = PnmFileTransaction()
    result = txn.get_record_by_filename(FileNameStr("raw.bin"))

    assert result is not None
    transaction_id, record = result
    assert transaction_id == TransactionId("tx-raw")
    assert record.get("filename") == "raw.bin"


def test_get_record_by_filename_matches_compressed_base(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = _patch_transaction_db(tmp_path, monkeypatch)
    records = {
        "tx-comp": {
            "filename": "capture.bin.zst",
            "compression": {
                "is_compressed": True,
                "codec": "zstd",
                "level": 3,
                "size_before": 10,
                "size_after": 5,
            },
        },
    }
    db_path.write_text(json.dumps(records))

    txn = PnmFileTransaction()
    result = txn.get_record_by_filename(FileNameStr("capture.bin"))

    assert result is not None
    transaction_id, record = result
    assert transaction_id == TransactionId("tx-comp")
    assert record.get("filename") == "capture.bin.zst"
