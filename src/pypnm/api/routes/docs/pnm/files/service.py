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
        full_path = Path(self.pnm_dir) / str(filename)

        self.logger.info(f"Retrieving file for transaction {transaction_id}: {full_path}")

        if not full_path.exists():
            raise HTTPException(status_code=404, detail="File not found on disk.")

        return FileResponse(
            path        =   full_path,
            filename    =   filename,
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
        filepath = os.path.join(self.pnm_dir, filename)

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

        return UploadFileResponse(
            mac_address     = MacAddress(mac_address).mac_address,
            filename        = filename,
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

        # Get binary file
        file_path = f'{self.pnm_dir}/{filename}'

        if not Path(file_path).is_file():
            raise HTTPException(status_code=404, detail="PNM file not found on disk for analysis.")
        fp = FileProcessor(file_path).read_file()

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
