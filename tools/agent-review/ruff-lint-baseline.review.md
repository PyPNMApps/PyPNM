## Agent Review Bundle Summary Template (Standard)

### Summary
Resolved ruff check blockers by importing PnmParsers, fixing a legacy retrieval fallback assignment, and adding missing annotations/strict zip usage across tests. Updated SPDX years in touched files to 2025-2026 where applicable.

### Modified Files
- src/pypnm/api/routes/docs/pnm/files/service.py
- src/pypnm/lib/secret/crypto_manager.py
- tests/test_complex_array_ops.py
- tests/test_docs_pnm_chan_est_entry_casts.py
- tests/test_docs_pnm_rxmer_entry_casts.py
- tests/test_echo_detector.py
- tests/test_fixed_point_decoder.py
- tests/test_ftp_connector.py
- tests/test_group_delay_calculator.py
- tests/test_heatmap_anomaly_detector.py
- tests/test_host_endpoint.py
- tests/test_ifft_echo_detector.py
- tests/test_ping.py
- tests/test_pnm_channel_estimation_parse.py
- tests/test_pnm_constellation_parse.py
- tests/test_pnm_factory_fetcher.py
- tests/test_pnm_fec_summary_parse.py
- tests/test_pnm_header_each_file.py
- tests/test_pnm_histogram_parse.py
- tests/test_pnm_modulation_profile_parse.py
- tests/test_pnm_parser_and_parameters.py
- tests/test_pnm_rxmer_parse.py
- tests/test_pnm_spectrum_analysis_parse.py
- tests/test_scalar_value_converters.py
- tests/test_shannon.py
- tests/test_shannon_series.py
- tests/test_signal_statistics.py
- tests/test_utils_time_stamp.py
- tests/test_pnm_file_type_mapper.py

### Commands Executed And Results
- `ruff check src test --fix` → failed (E902: no such file or directory: test; 1 remaining)
- `ruff check src test` → failed (E902: no such file or directory: test)
- `ruff check src tests --fix` → failed (123 errors remaining)
- `ruff check src tests` → passed
- `ruff check . --fix` → passed
- `ruff check .` → passed

### Tests
- `pytest` → not run (not requested)
- `ruff` → passed

### Notes / Warnings
- Initial ruff invocations failed due to the `test` path typo; reran with `tests`.

### Remaining TODOs / Follow-Ups
- None.


# FILE: /home/dev01/Projects/PyPNM/src/pypnm/api/routes/docs/pnm/files/service.py
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


# FILE: /home/dev01/Projects/PyPNM/src/pypnm/lib/secret/crypto_manager.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import base64
import contextlib
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken


class SecretCryptoError(Exception):
    """
    Secret Encryption/Decryption Failure.

    Raised when a secret cannot be encrypted or decrypted due to missing keys,
    invalid token formats, permission problems, or cryptographic validation
    failures.
    """


@dataclass(frozen=True, slots=True)
class SecretToken:
    """
    Versioned Encrypted Secret Token.

    Attributes
    ----------
    version:
        Token version string (example: "v1").
    payload:
        The encrypted payload (Fernet token string).
    """

    version: str
    payload: str


class SecretCryptoManager:
    """
    Secret Encryption Manager For Config-Stored Passwords.

    This class supports storing encrypted passwords inside JSON configuration
    (example: system.json) while keeping the decryption key outside the repo,
    typically in the user's ~/.ssh directory.

    Security Model
    --------------
    - The encrypted password may safely live in the config file.
    - The decrypt key MUST NOT live in the config file or repo.
    - The decrypt key is loaded from one of:
      1) A key file (default: ~/.ssh/pypnm_secrets.key)
      2) An environment variable (default: PYPNM_SECRET_KEY)

    Token Format
    ------------
    Tokens are stored as:

        ENC[v1]:<fernet-token>

    Where <fernet-token> is a URL-safe base64 encoded token produced by Fernet.

    Notes
    -----
    Fernet provides authenticated encryption (confidentiality + integrity). If a
    token is altered, decryption will fail with an integrity error.
    """

    DEFAULT_ENV_VAR_NAME            = "PYPNM_SECRET_KEY"
    DEFAULT_KEY_FILE_NAME           = "pypnm_secrets.key"
    DEFAULT_TOKEN_VERSION           = "v1"
    DEFAULT_TOKEN_PREFIX            = "ENC"
    SSH_DIR_NAME                    = ".ssh"

    FERNET_KEY_SIZE_BYTES           = 32

    KEY_FILE_PERMISSIONS            = 0o600
    SSH_DIR_PERMISSIONS             = 0o700

    def __init__(self) -> None:
        self.logger = logging.getLogger(f"{self.__class__.__name__}")

    @staticmethod
    def default_key_path() -> Path:
        """
        Return The Default Key File Path Under ~/.ssh.

        Returns
        -------
        Path
            The default key file path: ~/.ssh/pypnm_secrets.key
        """
        home_dir = Path.home()
        return home_dir / SecretCryptoManager.SSH_DIR_NAME / SecretCryptoManager.DEFAULT_KEY_FILE_NAME

    @staticmethod
    def build_token(payload: str, version: str = DEFAULT_TOKEN_VERSION) -> str:
        """
        Build A Versioned Token String.

        Parameters
        ----------
        payload:
            Fernet token string (URL-safe base64).
        version:
            Token version (default: "v1").

        Returns
        -------
        str
            Versioned token string in format: ENC[vX]:<payload>
        """
        return f"{SecretCryptoManager.DEFAULT_TOKEN_PREFIX}[{version}]:{payload}"

    @staticmethod
    def parse_token(token: str) -> SecretToken:
        """
        Parse A Versioned Token String.

        Parameters
        ----------
        token:
            Token string in format: ENC[vX]:<payload>

        Returns
        -------
        SecretToken
            Parsed token components.

        Raises
        ------
        SecretCryptoError
            If the token is malformed or missing required parts.
        """
        prefix = f"{SecretCryptoManager.DEFAULT_TOKEN_PREFIX}["
        if not token.startswith(prefix):
            raise SecretCryptoError("Encrypted token missing expected 'ENC[...]:...' prefix.")

        end_bracket_index = token.find("]:")
        if end_bracket_index < 0:
            raise SecretCryptoError("Encrypted token missing closing ']:' delimiter.")

        version = token[len(prefix):end_bracket_index].strip()
        if version == "":
            raise SecretCryptoError("Encrypted token version is empty.")

        payload = token[end_bracket_index + 2:].strip()
        if payload == "":
            raise SecretCryptoError("Encrypted token payload is empty.")

        return SecretToken(version=version, payload=payload)

    @staticmethod
    def generate_key_b64() -> str:
        """
        Generate A New Fernet Key As A Base64 String.

        Returns
        -------
        str
            URL-safe base64 encoded key string.
        """
        key_bytes = Fernet.generate_key()
        return key_bytes.decode("utf-8")

    @staticmethod
    def write_key_file(key_path: Path, key_b64: str) -> Path:
        """
        Write A Fernet Key To Disk With Tight Permissions.

        Parameters
        ----------
        key_path:
            Path to write the key file (example: ~/.ssh/pypnm_secrets.key).
        key_b64:
            Fernet key (URL-safe base64 string).

        Returns
        -------
        Path
            The key_path written.

        Raises
        ------
        SecretCryptoError
            If the key is invalid or cannot be written securely.
        """
        SecretCryptoManager.validate_key_b64(key_b64)
        ssh_dir = key_path.parent
        ssh_dir.mkdir(parents=True, exist_ok=True)

        with contextlib.suppress(OSError):
            os.chmod(ssh_dir, SecretCryptoManager.SSH_DIR_PERMISSIONS)

        key_path.write_text(key_b64.strip() + "\n", encoding="utf-8")

        with contextlib.suppress(OSError):
            os.chmod(key_path, SecretCryptoManager.KEY_FILE_PERMISSIONS)

        return key_path

    @staticmethod
    def validate_key_b64(key_b64: str) -> None:
        """
        Validate A Fernet Key String.

        Parameters
        ----------
        key_b64:
            Fernet key as a URL-safe base64 string.

        Raises
        ------
        SecretCryptoError
            If the key is invalid.
        """
        key_str = key_b64.strip()
        if key_str == "":
            raise SecretCryptoError("Secret key is empty.")

        try:
            raw = base64.urlsafe_b64decode(key_str.encode("utf-8"))
        except Exception as exc:
            raise SecretCryptoError(f"Secret key is not valid base64: {exc}") from exc

        if len(raw) != SecretCryptoManager.FERNET_KEY_SIZE_BYTES:
            raise SecretCryptoError(
                f"Secret key decoded size is invalid: {len(raw)} bytes (expected {SecretCryptoManager.FERNET_KEY_SIZE_BYTES})."
            )

        try:
            Fernet(key_str.encode("utf-8"))
        except Exception as exc:
            raise SecretCryptoError(f"Secret key is not a valid Fernet key: {exc}") from exc

    @staticmethod
    def load_key_bytes(key_path: Path, env_var_name: str = DEFAULT_ENV_VAR_NAME) -> bytes:
        """
        Load Secret Key Bytes From Key File Or Environment Variable.

        Resolution Order
        ----------------
        1) key_path file
        2) env var env_var_name

        Parameters
        ----------
        key_path:
            Path to the key file (example: ~/.ssh/pypnm_secrets.key).
        env_var_name:
            Environment variable name to use as fallback (default: PYPNM_SECRET_KEY).

        Returns
        -------
        bytes
            Fernet key bytes.

        Raises
        ------
        SecretCryptoError
            If no key source is available or if the key is invalid.
        """
        if key_path.exists() and key_path.is_file():
            key_b64 = key_path.read_text(encoding="utf-8").strip()
            SecretCryptoManager.validate_key_b64(key_b64)
            return key_b64.encode("utf-8")

        env_value = os.environ.get(env_var_name, "").strip()
        if env_value != "":
            SecretCryptoManager.validate_key_b64(env_value)
            return env_value.encode("utf-8")

        raise SecretCryptoError(
            f"Missing secret key. Provide key file '{key_path}' or set environment variable '{env_var_name}'."
        )

    @staticmethod
    def encrypt_password(
        password: str,
        key_path: Path | None = None,
        env_var_name: str = DEFAULT_ENV_VAR_NAME,
        version: str = DEFAULT_TOKEN_VERSION,
    ) -> str:
        """
        Encrypt A Password For Storage In system.json.

        Parameters
        ----------
        password:
            Plaintext password to encrypt.
        key_path:
            Key file path. If empty, defaults to ~/.ssh/pypnm_secrets.key
        env_var_name:
            Environment variable for key fallback (default: PYPNM_SECRET_KEY).
        version:
            Token version label (default: "v1").

        Returns
        -------
        str
            Versioned token string in format: ENC[vX]:<payload>

        Raises
        ------
        SecretCryptoError
            If encryption fails due to missing/invalid key or invalid input.
        """
        password_str = password.strip()
        if password_str == "":
            raise SecretCryptoError("Password is empty; refusing to encrypt empty value.")

        actual_key_path = key_path if key_path is not None else SecretCryptoManager.default_key_path()
        key_bytes       = SecretCryptoManager.load_key_bytes(actual_key_path, env_var_name=env_var_name)
        fernet          = Fernet(key_bytes)

        token_bytes = fernet.encrypt(password_str.encode("utf-8"))
        token_str   = token_bytes.decode("utf-8")

        return SecretCryptoManager.build_token(payload=token_str, version=version)

    @staticmethod
    def decrypt_password(
        token: str,
        key_path: Path | None = None,
        env_var_name: str = DEFAULT_ENV_VAR_NAME,
        accepted_versions: tuple[str, ...] = (DEFAULT_TOKEN_VERSION,),
    ) -> str:
        """
        Decrypt A Password Token From system.json.

        Parameters
        ----------
        token:
            Versioned token string in format: ENC[vX]:<payload>
        key_path:
            Key file path. If empty, defaults to ~/.ssh/pypnm_secrets.key
        env_var_name:
            Environment variable for key fallback (default: PYPNM_SECRET_KEY).
        accepted_versions:
            Allowed token versions (default: ("v1",)).

        Returns
        -------
        str
            Decrypted plaintext password.

        Raises
        ------
        SecretCryptoError
            If decryption fails due to invalid token, missing key, wrong key,
            unsupported token version, or integrity/authentication failure.
        """
        token_str         = token.strip()
        parsed            = SecretCryptoManager.parse_token(token_str)
        version_supported = parsed.version in accepted_versions

        if not version_supported:
            raise SecretCryptoError(
                f"Unsupported encrypted token version '{parsed.version}'. Allowed: {', '.join(accepted_versions)}"
            )

        actual_key_path = key_path if key_path is not None else SecretCryptoManager.default_key_path()
        key_bytes       = SecretCryptoManager.load_key_bytes(actual_key_path, env_var_name=env_var_name)
        fernet          = Fernet(key_bytes)

        try:
            clear_bytes = fernet.decrypt(parsed.payload.encode("utf-8"))
        except InvalidToken as exc:
            raise SecretCryptoError("Failed to decrypt password: invalid token or wrong secret key.") from exc

        clear_str = clear_bytes.decode("utf-8").strip()
        if clear_str == "":
            raise SecretCryptoError("Decrypted password is empty; token or key may be invalid.")

        return clear_str

    @staticmethod
    def encrypt_system_config_secrets(config: dict[str, Any]) -> dict[str, Any]:
        """
        Encrypt System Config Secrets In-Place Semantics (Returns Updated Copy).

        Contract
        --------
        - Never persist a 'password' key.
        - If a password exists (from 'password' or 'password_enc'), store it as
          encrypted token in 'password_enc' (ENC[...]).
        - If password is empty, keep 'password_enc' as "" and still remove 'password'.
        - SCP is not handled here (removed as an option); this function only enforces
          secret storage semantics for configured methods.
        """
        pnm = config.get("PnmFileRetrieval", {})
        retrieval = pnm.get("retrieval_method")
        if not isinstance(retrieval, dict):
            legacy = pnm.get("retrival_method")
            retrieval = legacy if isinstance(legacy, dict) else {}
        methods = retrieval.get("methods", {})

        if not isinstance(methods, dict):
            return config

        for method_cfg in methods.values():
            if not isinstance(method_cfg, dict):
                continue

            password_enc = str(method_cfg.get("password_enc", "") or "").strip()
            password     = str(method_cfg.get("password", "") or "").strip()

            token_source = password_enc if password_enc != "" else password

            if token_source == "":
                method_cfg.pop("password", None)
                method_cfg["password_enc"] = ""
                continue

            if token_source.startswith("ENC["):
                method_cfg["password_enc"] = token_source
            else:
                method_cfg["password_enc"] = SecretCryptoManager.encrypt_password(token_source)

            method_cfg.pop("password", None)

        return config


# FILE: /home/dev01/Projects/PyPNM/tests/test_complex_array_ops.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

# tests/test_complex_array_ops.py
from __future__ import annotations

import math

import numpy as np
import pytest

from pypnm.lib.signal_processing.complex_array_ops import ComplexArrayOps


def pairs(*vals: float) -> list[tuple[float, float]]:
    """Build (re, im) pairs from flat numbers: r1,i1,r2,i2,..."""
    assert len(vals) % 2 == 0
    it = iter(vals)
    return [(float(r), float(i)) for r, i in zip(it, it, strict=False)]


def test_init_and_len_and_repr() -> None:
    x = pairs(1, 0, 0, 1, -1, 0)
    ops = ComplexArrayOps(x)
    assert len(ops) == 3
    r = repr(ops)
    assert "ComplexArrayOps" in r
    assert "RMS=" in r and "MeanPwr=" in r


def test_invalid_shape_raises() -> None:
    with pytest.raises(ValueError):
        ComplexArrayOps([(1.0,)] * 2)
    with pytest.raises(ValueError):
        ComplexArrayOps([])


def test_as_array_and_to_pairs_roundtrip() -> None:
    x = pairs(1, 2, 3, 4, -5, 0)
    ops = ComplexArrayOps(x)
    arr = ops.as_array()
    assert arr.dtype == np.complex128
    assert np.allclose(arr.real, [1, 3, -5])
    assert np.allclose(arr.imag, [2, 4, 0])

    back = ops.to_pairs()
    assert back == x


def test_magnitude_power_and_db() -> None:
    x = pairs(3, 4, 0, 0)
    ops = ComplexArrayOps(x)

    mag = ops.magnitude()
    pwr = ops.power()
    pwr_db = ops.power_db()

    assert np.allclose(mag, [5.0, 0.0])
    assert np.allclose(pwr, [25.0, 0.0])

    assert np.isfinite(pwr_db[1])
    assert pwr_db[0] > pwr_db[1]


def test_phase_and_unwrap() -> None:
    # With default discont=π, unwrap does NOT add 2π for jump exactly π
    x = pairs(1, 0, -1, 0, 1, 0)
    ops = ComplexArrayOps(x)
    ph = ops.phase()
    ph_u = ops.phase(unwrap=True)

    assert np.allclose(ph, [0.0, np.pi, 0.0])
    assert np.allclose(ph_u, [0.0, np.pi, 0.0])


def test_rms_and_mean_power_with_mask() -> None:
    x = pairs(1, 0, 0, 2, 0, 0)  # powers: 1, 4, 0 → mean=5/3
    ops = ComplexArrayOps(x)

    assert ops.mean_power() == pytest.approx(5.0 / 3.0, abs=1e-12)
    assert ops.rms() == pytest.approx(math.sqrt(5.0 / 3.0), abs=1e-12)

    mask = np.array([True, False, True])
    assert ops.mean_power(mask=mask) == pytest.approx(0.5, abs=1e-12)
    assert ops.rms(mask=mask) == pytest.approx(math.sqrt(0.5), abs=1e-12)

    with pytest.raises(ValueError):
        ops.mean_power(mask=[True])


def test_conjugate_and_scale() -> None:
    x = pairs(1, -2, -3, 4)
    ops = ComplexArrayOps(x)

    conj = ops.conj()
    assert np.allclose(conj.as_array(), np.conjugate(ops.as_array()))
    assert not np.shares_memory(conj.as_array(), ops.as_array())

    scaled = ops.scale(2.0 - 1.0j)
    assert np.allclose(scaled.as_array(), (2.0 - 1.0j) * ops.as_array())

    def test_reciprocal_exact_and_eps() -> None:
        x = pairs(1, 0, 0, 1, 0, 0)
        ops = ComplexArrayOps(x)

        inv = ops.reciprocal()

        # Silence intentional divide-by-zero for the zero sample
        with np.errstate(divide="ignore", invalid="ignore"):
            target = 1.0 / ops.as_array()  # inf+nanj for the last zero sample

        assert np.allclose(inv.as_array(), target, equal_nan=True)

        inv_eps = ops.reciprocal(eps=1e-9)
        assert np.isfinite(inv_eps.as_array()[-1])
        assert np.allclose(inv_eps.as_array()[:-1], target[:-1], rtol=1e-12, atol=1e-12)

def test_normalize_rms_global_and_masked() -> None:
    x = pairs(3, 4, 0, 0)  # RMS = 5/sqrt(2)
    ops = ComplexArrayOps(x)

    target = 1.0
    norm = ops.normalize_rms(target=target)
    assert norm.rms() == pytest.approx(target, abs=1e-12)

    mask = np.array([True, False])
    norm_m = ops.normalize_rms(target=2.0, mask=mask)
    assert norm_m.rms(mask=mask) == pytest.approx(2.0, abs=1e-12)


def test_fft_ifft_roundtrip() -> None:
    x = np.zeros((8, 2), dtype=float)
    x[0] = (1.0, 0.0)
    ops = ComplexArrayOps([tuple(row) for row in x])

    X = ops.fft()
    x_rt = X.ifft()
    assert np.allclose(x_rt.as_array(), ops.as_array(), atol=1e-12)


def test_real_imag_accessors() -> None:
    x = pairs(1.2, -3.4, 5.6, 7.8)
    ops = ComplexArrayOps(x)
    assert np.allclose(ops.real(), [1.2, 5.6])
    assert np.allclose(ops.imag(), [-3.4, 7.8])


def test_copy_is_independent() -> None:
    x = pairs(1, 2, 3, 4)
    ops = ComplexArrayOps(x)
    cpy = ops.copy()
    assert np.allclose(cpy.as_array(), ops.as_array())
    cpy_scaled = cpy.scale(2.0)
    assert np.allclose(ops.as_array(), np.array([1 + 2j, 3 + 4j], dtype=np.complex128))
    assert np.allclose(cpy_scaled.as_array(), 2.0 * cpy.as_array())


# FILE: /home/dev01/Projects/PyPNM/tests/test_docs_pnm_chan_est_entry_casts.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import pytest

from pypnm.docsis.cm_snmp_operation import MeasStatusType
from pypnm.docsis.data_type.pnm.DocsPnmCmOfdmChanEstCoefEntry import (
    DocsPnmCmOfdmChanEstCoefEntry,
    DocsPnmCmOfdmChanEstCoefFields,
)
from pypnm.snmp.snmp_v2c import Snmp_v2c


class _FakeSnmp:
    def __init__(self, idx: int, table: dict[str, object]) -> None:
        self._idx, self._t = idx, table

    async def get(self, oq: str) -> object | None:
        sym, _, sfx = oq.rpartition(".")
        assert int(sfx) == self._idx
        # return None if the OID isn't present (simulate missing field)
        return self._t.get(sym)


@pytest.mark.asyncio
async def test_chan_est_from_snmp_scaling_and_types(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Snmp_v2c, "get_result_value", staticmethod(lambda x: x))

    idx = 11
    fake = _FakeSnmp(idx, {
        "docsPnmCmOfdmChEstCoefTrigEnable": 1,               # -> True
        "docsPnmCmOfdmChEstCoefAmpRipplePkToPk": 3323,       # -> 33.23
        "docsPnmCmOfdmChEstCoefAmpRippleRms": 631,           # -> 6.31
        "docsPnmCmOfdmChEstCoefAmpSlope": 92,                # -> 0.92
        "docsPnmCmOfdmChEstCoefGrpDelayRipplePkToPk": 7,     # int
        "docsPnmCmOfdmChEstCoefGrpDelayRippleRms": 5,        # int
        "docsPnmCmOfdmChEstCoefMeasStatus": 4,               # -> "sample_ready"
        "docsPnmCmOfdmChEstCoefFileName": "chan_est.bin",
        "docsPnmCmOfdmChEstCoefAmpMean": 4288,               # -> 42.88
        "docsPnmCmOfdmChEstCoefGrpDelaySlope": 3,            # int
        "docsPnmCmOfdmChEstCoefGrpDelayMean": 12,            # int
    })

    e = await DocsPnmCmOfdmChanEstCoefEntry.from_snmp(idx, fake)  # type: ignore[arg-type]
    assert e.index == idx and e.channel_id == idx
    f: DocsPnmCmOfdmChanEstCoefFields = e.entry

    assert f.docsPnmCmOfdmChEstCoefTrigEnable is True
    assert f.docsPnmCmOfdmChEstCoefMeasStatus == str(MeasStatusType(4))  # "sample_ready"
    assert f.docsPnmCmOfdmChEstCoefFileName == "chan_est.bin"

    assert f.docsPnmCmOfdmChEstCoefAmpRipplePkToPk == pytest.approx(33.23, abs=0.0)
    assert f.docsPnmCmOfdmChEstCoefAmpRippleRms == pytest.approx(6.31, abs=0.0)
    assert f.docsPnmCmOfdmChEstCoefAmpSlope == pytest.approx(0.92, abs=0.0)
    assert f.docsPnmCmOfdmChEstCoefAmpMean == pytest.approx(42.88, abs=0.0)

    assert f.docsPnmCmOfdmChEstCoefGrpDelayRipplePkToPk == 7
    assert f.docsPnmCmOfdmChEstCoefGrpDelayRippleRms == 5
    assert f.docsPnmCmOfdmChEstCoefGrpDelaySlope == 3
    assert f.docsPnmCmOfdmChEstCoefGrpDelayMean == 12


@pytest.mark.asyncio
async def test_chan_est_missing_field_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Snmp_v2c, "get_result_value", staticmethod(lambda x: x))
    idx = 2
    fake = _FakeSnmp(idx, {
        "docsPnmCmOfdmChEstCoefTrigEnable": 1,
        "docsPnmCmOfdmChEstCoefAmpRipplePkToPk": 100,       # 1.00
        "docsPnmCmOfdmChEstCoefAmpRippleRms": 200,          # 2.00
        "docsPnmCmOfdmChEstCoefAmpSlope": 50,               # 0.50
        "docsPnmCmOfdmChEstCoefGrpDelayRipplePkToPk": 1,
        "docsPnmCmOfdmChEstCoefGrpDelayRippleRms": 1,
        "docsPnmCmOfdmChEstCoefMeasStatus": 3,
        "docsPnmCmOfdmChEstCoefFileName": "x.bin",
        # "docsPnmCmOfdmChEstCoefAmpMean": MISSING -> should raise
        "docsPnmCmOfdmChEstCoefGrpDelaySlope": 1,
        "docsPnmCmOfdmChEstCoefGrpDelayMean": 1,
    })
    with pytest.raises(ValueError):
        await DocsPnmCmOfdmChanEstCoefEntry.from_snmp(idx, fake)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_chan_est_get_empty_indices_returns_empty_list() -> None:
    out = await DocsPnmCmOfdmChanEstCoefEntry.get(snmp=None, indices=[])  # type: ignore[arg-type]
    assert out == []


# FILE: /home/dev01/Projects/PyPNM/tests/test_docs_pnm_rxmer_entry_casts.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

# tests/test_docs_pnm_rxmer_entry_casts.py
from __future__ import annotations

import pytest

from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmRxMerEntry import (
    DocsPnmCmDsOfdmRxMerEntry,
    DocsPnmCmDsOfdmRxMerFields,
    MeasStatusType,  # enum whose str() returns the lowercase name
)
from pypnm.snmp.snmp_v2c import Snmp_v2c


class _FakeSnmp:
    def __init__(self, idx: int, table: dict[str, object]) -> None:
        self._idx = idx
        self._t = table

    async def get(self, oq: str) -> object:
        sym, _, sfx = oq.rpartition(".")
        assert int(sfx) == self._idx
        return self._t[sym]


@pytest.mark.asyncio
async def test_from_snmp_scaling_and_types(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Happy-path test:
      • get_result_value is pass-through
      • integer fixed-point fields scale by /100.0
      • status is mapped to its lowercase string name
      • frequency is left as plain integer-ish Hz
    """
    monkeypatch.setattr(Snmp_v2c, "get_result_value", staticmethod(lambda x: x))

    idx = 7
    fake = _FakeSnmp(idx, {
        "docsPnmCmDsOfdmRxMerFileEnable": 1,
        "docsPnmCmDsOfdmRxMerMeasStatus": 4,                     # -> "sample_ready"
        "docsPnmCmDsOfdmRxMerFileName": "ds_ofdm_rxmer.bin",
        "docsPnmCmDsOfdmRxMerPercentile": 2,                     # -> 0.02
        "docsPnmCmDsOfdmRxMerMean": 3323,                        # -> 33.23
        "docsPnmCmDsOfdmRxMerStdDev": 631,                       # -> 6.31
        "docsPnmCmDsOfdmRxMerThrVal": 92,                        # -> 0.92
        "docsPnmCmDsOfdmRxMerThrHighestFreq": 314_800_000,       # -> 314800000
    })

    e = await DocsPnmCmDsOfdmRxMerEntry.from_snmp(idx, fake)  # type: ignore[arg-type]
    assert e.index == idx and e.channel_id == idx
    f: DocsPnmCmDsOfdmRxMerFields = e.entry

    assert f.docsPnmCmDsOfdmRxMerFileEnable is True
    assert f.docsPnmCmDsOfdmRxMerMeasStatus == "sample_ready"   # string name now
    assert f.docsPnmCmDsOfdmRxMerFileName == "ds_ofdm_rxmer.bin"

    assert f.docsPnmCmDsOfdmRxMerPercentile == pytest.approx(0.02, abs=0.0)
    assert f.docsPnmCmDsOfdmRxMerMean == pytest.approx(33.23, abs=0.0)
    assert f.docsPnmCmDsOfdmRxMerStdDev == pytest.approx(6.31, abs=0.0)
    assert f.docsPnmCmDsOfdmRxMerThrVal == pytest.approx(0.92, abs=0.0)

    # Frequency Hz remains an integer-ish value (typed alias), compare numerically
    assert f.docsPnmCmDsOfdmRxMerThrHighestFreq == pytest.approx(314_800_000, abs=0.0)


@pytest.mark.asyncio
async def test_from_snmp_missing_required_fields_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Since the entry class enforces non-optional fields, missing any of them should raise ValueError.
    Here we omit several fields and verify the error message lists them.
    """
    monkeypatch.setattr(Snmp_v2c, "get_result_value", staticmethod(lambda x: x))

    idx = 1
    # Missing file_name + all float fields → should raise
    fake = _FakeSnmp(idx, {
        "docsPnmCmDsOfdmRxMerFileEnable": 0,
        "docsPnmCmDsOfdmRxMerMeasStatus": 3,            # "busy"
        # "docsPnmCmDsOfdmRxMerFileName": ... MISSING ...
        # float-ish fields MISSING:
        # "docsPnmCmDsOfdmRxMerPercentile"
        # "docsPnmCmDsOfdmRxMerMean"
        # "docsPnmCmDsOfdmRxMerStdDev"
        # "docsPnmCmDsOfdmRxMerThrVal"
        "docsPnmCmDsOfdmRxMerThrHighestFreq": 100_000_000,
    })

    with pytest.raises(ValueError) as exc:
        await DocsPnmCmDsOfdmRxMerEntry.from_snmp(idx, fake)  # type: ignore[arg-type]

    msg = str(exc.value)
    # Ensure the expected keys are called out
    for missing_key in ("file_name", "perc", "mean", "stddev", "thr_val"):
        assert missing_key in msg


@pytest.mark.asyncio
async def test_get_empty_indices_returns_empty_list() -> None:
    out = await DocsPnmCmDsOfdmRxMerEntry.get(snmp=None, indices=[])  # type: ignore[arg-type]
    assert out == []


@pytest.mark.parametrize("code, expected", [
    (1, "other"),
    (2, "inactive"),
    (3, "busy"),
    (4, "sample_ready"),
    (5, "error"),
    (6, "resource_unavailable"),
    (7, "sample_truncated"),
    (8, "interface_modification"),
])
def test_status_enum_string_names(code: int, expected: str) -> None:
    # Sanity-check the enum-to-string behavior used by the entry class
    assert str(MeasStatusType(code)) == expected


@pytest.mark.asyncio
async def test_debug_toggle_does_not_break(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Flip the ClassVar DEBUG flag to True and run a fetch to ensure no exceptions are thrown
    (we're not asserting logs here, just that it still works).
    """
    monkeypatch.setattr(Snmp_v2c, "get_result_value", staticmethod(lambda x: x))

    idx = 2
    fake = _FakeSnmp(idx, {
        "docsPnmCmDsOfdmRxMerFileEnable": 1,
        "docsPnmCmDsOfdmRxMerMeasStatus": 2,                     # "inactive"
        "docsPnmCmDsOfdmRxMerFileName": "foo.bin",
        "docsPnmCmDsOfdmRxMerPercentile": 10,                    # -> 0.10
        "docsPnmCmDsOfdmRxMerMean": 1234,                        # -> 12.34
        "docsPnmCmDsOfdmRxMerStdDev": 5,                         # -> 0.05
        "docsPnmCmDsOfdmRxMerThrVal": 200,                       # -> 2.00
        "docsPnmCmDsOfdmRxMerThrHighestFreq": 765_000_000,
    })

    # flip DEBUG on for the class during this test
    prev = DocsPnmCmDsOfdmRxMerEntry.DEBUG
    DocsPnmCmDsOfdmRxMerEntry.DEBUG = True
    try:
        e = await DocsPnmCmDsOfdmRxMerEntry.from_snmp(idx, fake)  # type: ignore[arg-type]
        f = e.entry
        assert f.docsPnmCmDsOfdmRxMerMeasStatus == "inactive"
        assert f.docsPnmCmDsOfdmRxMerPercentile == pytest.approx(0.10, abs=0.0)
        assert f.docsPnmCmDsOfdmRxMerMean == pytest.approx(12.34, abs=0.0)
        assert f.docsPnmCmDsOfdmRxMerStdDev == pytest.approx(0.05, abs=0.0)
        assert f.docsPnmCmDsOfdmRxMerThrVal == pytest.approx(2.00, abs=0.0)
        assert f.docsPnmCmDsOfdmRxMerThrHighestFreq == 765_000_000
    finally:
        DocsPnmCmDsOfdmRxMerEntry.DEBUG = prev


# FILE: /home/dev01/Projects/PyPNM/tests/test_echo_detector.py
# test_echo_detector.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import numpy as np
import pytest

# Import your detector from its project path
from pypnm.api.routes.advance.analysis.signal_analysis.detection.echo.echo_detector import (
    EchoDetector,
)
from pypnm.lib.types import ChannelId

# Fixed PHY/Test parameters
DF_HZ = 50_000.0               # subcarrier spacing (Hz)
NFFT = 4096                    # IFFT length
FS = NFFT * DF_HZ              # sample rate (Hz) = 204.8 MHz
VF = 0.87                      # RG6 default
C0 = 299_792_458.0             # m/s
V = C0 * VF                    # propagation speed in the cable
FEET_PER_METER = 3.280839895013123


def _bins_for_distance_ft(distance_ft: float, fs: float = FS, v: float = V) -> int:
    """
    Convert a one-way distance (ft) to the echo bin index after the direct path
    using round-trip time t = 2d / v and bin = t * fs.
    """
    d_m = distance_ft / FEET_PER_METER
    t = (2.0 * d_m) / v
    return int(round(t * fs))


def _make_freq_response_from_impulses(pulses: list[tuple[int, float]], nfft: int = NFFT) -> np.ndarray:
    """
    Build H(f) by FFT of h[n] with time-domain impulses:
    pulses = [(bin_index, amplitude), ...]
    """
    h = np.zeros(nfft, dtype=np.complex128)
    for idx, amp in pulses:
        h[idx % nfft] += complex(float(amp), 0.0)
    H = np.fft.fft(h, n=nfft)
    return H.astype(np.complex128)


def test_direct_plus_known_echo_bin_and_distance() -> None:
    """
    Create a direct path at bin 0 and a single echo at ~20 ft.
    Validate that the detector finds the echo near the expected bin and that
    echo distances increase (monotonic) relative to the direct path.
    """
    distance_ft = 20.0
    echo_bin = _bins_for_distance_ft(distance_ft)
    # A modest echo amplitude (linear)
    echo_amp = 0.25

    H = _make_freq_response_from_impulses([(0, 1.0), (echo_bin, echo_amp)], nfft=NFFT)
    det = EchoDetector(
        freq_data=H,
        subcarrier_spacing_hz=DF_HZ,
        n_fft=NFFT,
        cable_type="RG6",
        channel_id=ChannelId(197),
    )

    rep = det.multi_echo(
        threshold_mode="fractional",
        threshold_frac=0.05,            # 5% of direct amplitude
        guard_bins=0,                   # allow immediate search; detector also has 10-ft guard by default
        min_separation_s=8.0 / det.fs,  # ~8 bins
        max_delay_s=3.5e-6,
        max_peaks=3,
        include_time_response=False,
        direct_at_zero=True,
        window="hann",
        normalize_power=True,
        edge_guard_bins=8,
        # keep default min_detect_distance_ft=10.0
    )

    # Must have at least one echo
    assert len(rep.echoes) >= 1, "Expected at least one echo to be detected."

    first = rep.echoes[0]
    # Bin check: within ±1 bin of expected
    assert first.bin_index == pytest.approx(echo_bin, abs=1), (
        f"First echo bin {first.bin_index} not close to expected {echo_bin}"
    )

    # Time/Distance sanity: > 0
    assert first.time_s > 0.0
    assert first.distance_m > 0.0
    # Distance close to 20 ft (±1 ft tolerance)
    assert first.distance_ft == pytest.approx(distance_ft, abs=1.0)

    # If more echoes somehow cross threshold, ensure distances are non-decreasing
    dists = [e.distance_m for e in rep.echoes]
    assert dists == sorted(dists), "Echo distances should be non-decreasing."


def test_snapshot_average_with_guard_and_min_separation() -> None:
    """
    Two-snapshot average case:
      - A strong artifact at 2 bins (inside the 10-ft guard → should be ignored)
      - A valid echo beyond the guard (e.g., ~15 ft) that should be detected
    Also enforces min-separation (~8 bins).
    """
    # Near artifact within ~10 ft guard
    near_ft = 5.0
    near_bin = _bins_for_distance_ft(near_ft)

    # Valid echo beyond guard
    valid_ft = 15.0
    valid_bin = _bins_for_distance_ft(valid_ft)

    # Build two snapshots with slight amplitude variation
    H1 = _make_freq_response_from_impulses([(0, 1.0), (near_bin, 0.5), (valid_bin, 0.25)], nfft=NFFT)
    H2 = _make_freq_response_from_impulses([(0, 1.0), (near_bin, 0.45), (valid_bin, 0.3)], nfft=NFFT)
    H_snapshots = np.vstack([H1, H2])  # shape (2, NFFT), complex

    det = EchoDetector(
        freq_data=H_snapshots,          # (M, N) complex → averaged internally
        subcarrier_spacing_hz=DF_HZ,
        n_fft=NFFT,
        cable_type="RG6",
        channel_id=194,
    )

    rep = det.multi_echo(
        threshold_mode="fractional",
        threshold_frac=0.05,
        guard_bins=0,                    # leave explicit guard at 0; detector uses 10-ft min distance guard
        min_separation_s=8.0 / det.fs,   # ~8 bins
        max_delay_s=3.5e-6,
        max_peaks=3,
        include_time_response=False,
        direct_at_zero=True,
        window="hann",
        normalize_power=True,
        edge_guard_bins=8,
        # keep default min_detect_distance_ft=10.0
    )

    # We expect the near artifact to be rejected by min_detect_distance_ft (~5 bins)
    # and the valid echo beyond ~10 ft to be included.
    bins = [e.bin_index for e in rep.echoes]

    # Valid echo must be present (±1 bin)
    assert any(abs(b - valid_bin) <= 1 for b in bins), (
        f"Valid echo near bin {valid_bin} not detected; got bins {bins}"
    )

    # Near artifact must be absent
    assert all(abs(b - near_bin) > 1 for b in bins), (
        f"Near artifact within guard (bin {near_bin}) should have been rejected; got bins {bins}"
    )

    # Min separation: all selected bins spaced by ≥ ~8 bins
    bins_sorted = sorted(bins)
    for i in range(1, len(bins_sorted)):
        assert (bins_sorted[i] - bins_sorted[i - 1]) >= 8 - 1, "Echo picks violate min separation constraint"


# FILE: /home/dev01/Projects/PyPNM/tests/test_fixed_point_decoder.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import math

import pytest

from pypnm.pnm.lib.fixed_point_decoder import (
    FixedPointDecoder,
    FractionalBits,
    IntegerBits,
)

# ───────────────────────── helpers ─────────────────────────

def _q(a: int, b: int) -> tuple[IntegerBits, FractionalBits]:
    return (IntegerBits(a), FractionalBits(b))

def _bits_per_component(q: tuple[IntegerBits, FractionalBits]) -> int:
    a, b = int(q[0]), int(q[1])
    return a + b + 1  # +1 sign bit

def _bytes_per_component(q: tuple[IntegerBits, FractionalBits]) -> int:
    tbits = _bits_per_component(q)
    assert tbits % 8 == 0, "Test helper expects byte-aligned Q formats"
    return tbits // 8

def _scale(q: tuple[IntegerBits, FractionalBits]) -> int:
    return 1 << int(q[1])

def _twos_wrap(n: int, total_bits: int) -> int:
    mask = (1 << total_bits) - 1
    return n & mask

def _pack_component(value: float, q: tuple[IntegerBits, FractionalBits], *, signed: bool, byteorder: str) -> bytes:
    """Pack one fixed-point component into bytes, respecting endianness."""
    frac = int(q[1])
    total_bits = _bits_per_component(q)
    byte_len = _bytes_per_component(q)
    scale = 1 << frac

    # Convert float to fixed
    raw = int(round(value * scale))

    if signed:
        raw = _twos_wrap(raw, total_bits)
        return raw.to_bytes(byte_len, byteorder=byteorder, signed=False)

    # unsigned path (clamp)
    max_u = (1 << total_bits) - 1
    raw_u = max(0, min(max_u, raw))
    return raw_u.to_bytes(byte_len, byteorder=byteorder, signed=False)

def _pack_q_pair(re: float, im: float, q: tuple[IntegerBits, FractionalBits], *, signed: bool = True, endian: str = "little") -> bytes:
    """Encode one complex sample for generic Q(a,b), honoring endianness."""
    return (
        _pack_component(re, q, signed=signed, byteorder=endian) +
        _pack_component(im, q, signed=signed, byteorder=endian)
    )

# ───────────────────────── unit tests ─────────────────────────

@pytest.mark.parametrize("q", [_q(1, 14), _q(2, 13)])
def test_decode_fixed_point_signed_basic(q: tuple[IntegerBits, FractionalBits]) -> None:
    frac = int(q[1])
    # +1.0
    assert FixedPointDecoder.decode_fixed_point(1 << frac, q, signed=True) == pytest.approx(1.0)
    # +0.25
    assert FixedPointDecoder.decode_fixed_point(1 << (frac - 2), q, signed=True) == pytest.approx(0.25)
    # -1.0 (two's complement of +1.0)
    total_bits = _bits_per_component(q)
    neg_one_tc = _twos_wrap(-(1 << frac), total_bits)
    assert FixedPointDecoder.decode_fixed_point(neg_one_tc, q, signed=True) == pytest.approx(-1.0)

def test_decode_fixed_point_unsigned_q1_14() -> None:
    q = _q(1, 14)
    val = FixedPointDecoder.decode_fixed_point(0x7FFF, q, signed=False)
    assert val == pytest.approx(0x7FFF / (2 ** 14))

def test_decode_fixed_point_non_byte_aligned_allowed_single_value() -> None:
    # Single-value decoder does not enforce byte alignment (only complex decoder does).
    q_bad = _q(1, 15)  # 17 total bits
    val = FixedPointDecoder.decode_fixed_point(0x1, q_bad, signed=True)
    assert val == pytest.approx(1 / (2 ** 15))

def test_decode_complex_rejects_non_byte_aligned() -> None:
    q_bad = _q(1, 15)  # 17 total bits → not byte aligned
    with pytest.raises(ValueError, match="must be a multiple of 8"):
        FixedPointDecoder.decode_complex_data(b"\x00" * 8, q_bad, signed=True)

@pytest.mark.parametrize("q", [_q(1, 14), _q(2, 13)])
@pytest.mark.parametrize("endian", ["little", "big"])
def test_decode_complex_two_samples_signed_roundtrip(
    q: tuple[IntegerBits, FractionalBits],
    endian: str,
) -> None:
    # Two samples: (1.0, -0.5) and (0.25, 0.0)
    blob = b"".join([
        _pack_q_pair(1.0, -0.5, q, signed=True, endian=endian),
        _pack_q_pair(0.25, 0.0, q, signed=True, endian=endian),
    ])
    out = FixedPointDecoder.decode_complex_data(blob, q, signed=True, endian=endian)
    assert isinstance(out, list)
    assert len(out) == 2
    assert out[0].real == pytest.approx(1.0)
    assert out[0].imag == pytest.approx(-0.5)
    assert out[1].real == pytest.approx(0.25)
    assert out[1].imag == pytest.approx(0.0)

def test_decode_complex_invalid_length() -> None:
    q = _q(1, 14)
    with pytest.raises(ValueError, match="data length must be a multiple of the complex number size"):
        FixedPointDecoder.decode_complex_data(b"\x00\x01\x02", q, signed=True)

def test_decode_complex_unsigned_mode() -> None:
    q = _q(1, 14)
    # Pack using unsigned semantics:
    blob = _pack_q_pair(0x7FFF / (2 ** 14), 0.5, q, signed=False, endian="little")
    vals = FixedPointDecoder.decode_complex_data(blob, q, signed=False, endian="little")
    assert len(vals) == 1
    assert vals[0].real == pytest.approx(0x7FFF / (2 ** 14))
    assert vals[0].imag == pytest.approx(0.5)

def test_decode_complex_empty_ok() -> None:
    q = _q(2, 13)
    out = FixedPointDecoder.decode_complex_data(b"", q, signed=True, endian="big")
    assert isinstance(out, list)
    assert len(out) == 0

@pytest.mark.parametrize("q", [_q(1, 14), _q(2, 13)])
def test_decode_complex_wrong_endian_changes_values(q: tuple[IntegerBits, FractionalBits]) -> None:
    # Build little-endian blob but decode as big-endian: values should not match expected
    expected = [(0.5, -0.25), (-0.75, 0.125)]
    blob_le = b"".join(_pack_q_pair(r, i, q, signed=True, endian="little") for (r, i) in expected)

    out_be = FixedPointDecoder.decode_complex_data(blob_le, q, signed=True, endian="big")
    assert len(out_be) == len(expected)

    # At least one component must differ significantly if endian is wrong.
    mismatches = 0
    for got, (er, ei) in zip(out_be, expected, strict=False):
        if not math.isclose(got.real, er, rel_tol=1e-6, abs_tol=1e-6) or \
           not math.isclose(got.imag, ei, rel_tol=1e-6, abs_tol=1e-6):
            mismatches += 1
    assert mismatches >= 1

@pytest.mark.parametrize("q", [_q(1, 14), _q(2, 13)])
def test_decode_complex_data_multiple_samples_roundtrip_like(
    q: tuple[IntegerBits, FractionalBits],
) -> None:
    samples = [(0.0, 0.0), (0.5, 0.5), (-0.75, 0.25), (1.0, -1.0)]
    blob = b"".join(_pack_q_pair(r, i, q, signed=True, endian="little") for (r, i) in samples)
    out = FixedPointDecoder.decode_complex_data(blob, q, signed=True, endian="little")
    assert len(out) == len(samples)
    for got, (er, ei) in zip(out, samples, strict=False):
        assert got.real == pytest.approx(er, abs=1e-4)
        assert got.imag == pytest.approx(ei,  abs=1e-4)


# FILE: /home/dev01/Projects/PyPNM/tests/test_ftp_connector.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import ftplib
from collections.abc import Callable
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pypnm.lib.ftp.ftp_connector import FTPConnector


@pytest.fixture
def mock_ftp() -> MagicMock:
    m = MagicMock(spec=ftplib.FTP)
    m.nlst.return_value = ["file1.txt", "dir"]
    m.size.return_value = 1234
    m.pwd.return_value = "/"
    return m


def test_connect_plain_success(mock_ftp: MagicMock) -> None:
    # Plain FTP should connect/login; don't assert prot_p on a non-TLS client.
    with patch("ftplib.FTP", return_value=mock_ftp) as cls:
        c = FTPConnector("example.com", username="u", password="p", use_tls=False)
        assert c.connect() is True
        cls.assert_called_once()
        mock_ftp.connect.assert_called_once_with("example.com", 21, timeout=30)
        mock_ftp.login.assert_called_once_with("u", "p")


def test_connect_tls_calls_prot_p() -> None:
    m = MagicMock(spec=ftplib.FTP_TLS)
    with patch("ftplib.FTP_TLS", return_value=m):
        c = FTPConnector("host", use_tls=True)
        assert c.connect() is True
        m.prot_p.assert_called_once()


def test_connect_failure_returns_false() -> None:
    with patch("ftplib.FTP", side_effect=RuntimeError("boom")):
        c = FTPConnector("host")
        assert c.connect() is False


def test_disconnect_quit_no_raise(mock_ftp: MagicMock) -> None:
    with patch("ftplib.FTP", return_value=mock_ftp):
        c = FTPConnector("h")
        assert c.connect()
        c.disconnect()
        mock_ftp.quit.assert_called_once()
        assert c.ftp is None


def test_list_dir_returns_names(mock_ftp: MagicMock) -> None:
    with patch("ftplib.FTP", return_value=mock_ftp):
        c = FTPConnector("h")
        c.connect()
        out = c.list_dir("/some")
        mock_ftp.nlst.assert_called_once_with("/some")
        assert out == ["file1.txt", "dir"]


def test_make_dirs_creates_nested_when_missing(mock_ftp: MagicMock) -> None:
    # Let cwd fail for any subdir to force mkd; root is fine
    def cwd_side_effect(path: str) -> None:
        if path != "/":
            raise ftplib.error_perm("nope")

    mock_ftp.cwd.side_effect = cwd_side_effect
    with patch("ftplib.FTP", return_value=mock_ftp):
        c = FTPConnector("h")
        c.connect()
        c.make_dirs("/a/b/c")
        # mkd should be called for each missing component
        assert mock_ftp.mkd.call_count == 3
        mock_ftp.cwd.assert_any_call("/")  # returned to root at end


def test_upload_file_success(tmp_path: Path) -> None:
    ftp = MagicMock(spec=ftplib.FTP)

    # Track created directories so subsequent cwd to them succeeds
    created: set[str] = set()

    def cwd_side_effect(path: str) -> None:
        # Root always ok
        if path == "/":
            return
        # Accept cwd if previously "created"
        if path.lstrip("/") in created:
            return
        # Otherwise pretend it doesn't exist (trigger mkd)
        raise ftplib.error_perm("missing")

    def mkd_side_effect(path: str) -> None:
        created.add(path.lstrip("/"))

    ftp.cwd.side_effect = cwd_side_effect
    ftp.mkd.side_effect = mkd_side_effect

    local = tmp_path / "in.bin"
    local.write_bytes(b"payload")

    with patch("ftplib.FTP", return_value=ftp):
        c = FTPConnector("h")
        assert c.connect()
        ok = c.upload_file(str(local), "/x/y/out.bin")
        assert ok is True
        # ensure it tried to create both levels
        assert "x" in created and "x/y" in created
        ftp.storbinary.assert_called_once()
        args, _ = ftp.storbinary.call_args
        assert args[0].startswith("STOR ")


def test_upload_file_missing_local_returns_false() -> None:
    ftp = MagicMock(spec=ftplib.FTP)
    with patch("ftplib.FTP", return_value=ftp):
        c = FTPConnector("h")
        c.connect()
        assert c.upload_file("no_such_file.bin", "/remote.bin") is False
        ftp.storbinary.assert_not_called()


def test_download_file_to_dir_and_to_file(tmp_path: Path) -> None:
    ftp = MagicMock(spec=ftplib.FTP)

    def retr_side_effect(cmd: str, writer_cb: Callable[[bytes], object]) -> None:
        writer_cb(b"abc123")

    ftp.retrbinary.side_effect = retr_side_effect

    with patch("ftplib.FTP", return_value=ftp):
        c = FTPConnector("h")
        c.connect()

        # Download to directory path (auto-append filename)
        out_dir = tmp_path / "dl"
        out_dir.mkdir()
        ok = c.download_file("/r/file.txt", str(out_dir))
        assert ok is True
        data = (out_dir / "file.txt").read_bytes()
        assert data == b"abc123"

        # Download to explicit file path
        out_file = tmp_path / "explicit.bin"
        ok = c.download_file("/remote.bin", str(out_file))
        assert ok is True
        assert out_file.read_bytes() == b"abc123"


def test_delete_get_size_cwd_pwd(mock_ftp: MagicMock) -> None:
    with patch("ftplib.FTP", return_value=mock_ftp):
        c = FTPConnector("h")
        c.connect()

        assert c.delete_file("/a.txt") is True
        mock_ftp.delete.assert_called_once_with("/a.txt")

        assert c.get_size("/a.txt") == 1234
        mock_ftp.size.assert_called_once_with("/a.txt")

        assert c.cwd("/some") is True
        mock_ftp.cwd.assert_called_with("/some")

        assert c.pwd() == "/"
        mock_ftp.pwd.assert_called_once()


def test_get_size_failure_returns_none(mock_ftp: MagicMock) -> None:
    mock_ftp.size.side_effect = RuntimeError("oops")
    with patch("ftplib.FTP", return_value=mock_ftp):
        c = FTPConnector("h")
        c.connect()
        assert c.get_size("/bad") is None


def test_methods_raise_without_connection() -> None:
    c = FTPConnector("h")
    with pytest.raises(ConnectionError):
        c.list_dir("/")
    with pytest.raises(ConnectionError):
        c.make_dirs("/a")
    with pytest.raises(ConnectionError):
        c.upload_file(__file__, "/r")
    with pytest.raises(ConnectionError):
        c.download_file("/r", ".")
    with pytest.raises(ConnectionError):
        c.delete_file("/r")
    with pytest.raises(ConnectionError):
        c.get_size("/r")
    with pytest.raises(ConnectionError):
        c.cwd("/")
    with pytest.raises(ConnectionError):
        c.pwd()


# FILE: /home/dev01/Projects/PyPNM/tests/test_group_delay_calculator.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import numpy as np
import pytest

from pypnm.api.routes.advance.analysis.signal_analysis.group_delay_calculator import (
    GroupDelayCalculator,
    GroupDelayCalculatorModel,
)

RTOL = 1e-6
ATOL = 1e-9


def _mk_linear_phase(freqs_hz: np.ndarray, tau_s: float) -> np.ndarray:
    """
    Build H(f) = exp(-j*2π f τ). Group delay should be constant τ.
    """
    return np.exp(-1j * 2.0 * np.pi * freqs_hz * tau_s)


@pytest.mark.pnm
def test_group_delay_constant_for_linear_phase_single_snapshot() -> None:
    K = 256
    tau_true = 5e-6
    f0 = 100e6
    df = 25e3
    freqs = f0 + df * np.arange(K)

    H = _mk_linear_phase(freqs, tau_true)
    calc = GroupDelayCalculator(H, freqs)
    f_out, tau_g = calc.compute_group_delay_full()

    assert f_out.shape == (K,)
    assert tau_g.shape == (K,)
    assert np.allclose(tau_g, tau_true, rtol=RTOL, atol=ATOL)


@pytest.mark.pnm
def test_group_delay_median_across_snapshots_with_noise() -> None:
    K = 128
    M = 5
    tau_true = 2.5e-6
    f0 = 90e6
    df = 50e3
    freqs = f0 + df * np.arange(K)

    rng = np.random.default_rng(123)
    Hs = []
    for _ in range(M):
        H_clean = _mk_linear_phase(freqs, tau_true)
        phase_jitter = rng.normal(scale=1e-2, size=K)
        H_noisy = H_clean * np.exp(1j * phase_jitter)
        Hs.append(H_noisy)
    H = np.stack(Hs, axis=0)

    calc = GroupDelayCalculator(H, freqs)
    f_med, tau_med = calc.median_group_delay()

    assert f_med.shape == (K,)
    assert tau_med.shape == (K,)
    assert np.allclose(tau_med, tau_true, rtol=5e-3, atol=1e-7)


@pytest.mark.pnm
def test_input_encodings_pairs_and_mk2() -> None:
    K = 64
    tau_true = 1e-6
    f0 = 200e6
    df = 25e3
    freqs = f0 + df * np.arange(K)

    H_complex = _mk_linear_phase(freqs, tau_true)

    pairs_K2 = np.stack([np.real(H_complex), np.imag(H_complex)], axis=1)
    calc_pairs = GroupDelayCalculator(pairs_K2, freqs)
    _, tau_pairs = calc_pairs.compute_group_delay_full()

    pairs_MK2 = pairs_K2[np.newaxis, ...]
    calc_pairs_batched = GroupDelayCalculator(pairs_MK2, freqs)
    _, tau_pairs_batched = calc_pairs_batched.compute_group_delay_full()

    calc_c = GroupDelayCalculator(H_complex, freqs)
    _, tau_c = calc_c.compute_group_delay_full()

    assert np.allclose(tau_pairs, tau_c, rtol=RTOL, atol=ATOL)
    assert np.allclose(tau_pairs_batched, tau_c, rtol=RTOL, atol=ATOL)


@pytest.mark.pnm
def test_snapshot_group_delay_shape() -> None:
    K = 33
    M = 3
    tau_true = 4e-6
    f0, df = 50e6, 25e3
    freqs = f0 + df * np.arange(K)
    H = np.stack([_mk_linear_phase(freqs, tau_true) for _ in range(M)], axis=0)

    calc = GroupDelayCalculator(H, freqs)
    taus = calc.snapshot_group_delay()
    assert taus.shape == (M, K)
    assert np.allclose(taus, tau_true, rtol=RTOL, atol=ATOL)


@pytest.mark.pnm
def test_model_build_and_alias_fields() -> None:
    K = 40
    tau_true = 3e-6
    f0, df = 70e6, 25e3
    freqs = f0 + df * np.arange(K)
    H = _mk_linear_phase(freqs, tau_true)

    mdl: GroupDelayCalculatorModel = GroupDelayCalculator(H, freqs).to_model()

    assert mdl.dataset_info.subcarriers == K
    assert mdl.dataset_info.snapshots == 1
    assert mdl.complex_unit == "[Real, Imaginary]"
    assert len(mdl.freqs) == K
    assert len(mdl.H_avg) == K
    assert len(mdl.group_delay_full.freqs) == K
    assert len(mdl.group_delay_full.tau_g) == K
    assert len(mdl.snapshot_group_delay.taus) == 1
    assert len(mdl.snapshot_group_delay.taus[0]) == K
    assert len(mdl.median_group_delay.freqs) == K
    assert len(mdl.median_group_delay.tau_med) == K
    assert np.allclose(mdl.group_delay_full.tau_g, tau_true, rtol=RTOL, atol=ATOL)
    assert np.allclose(mdl.median_group_delay.tau_med, tau_true, rtol=RTOL, atol=ATOL)


@pytest.mark.pnm
def test_to_dict_uses_alias_and_is_serializable() -> None:
    K = 16
    tau_true = 1e-6
    f0, df = 10e6, 25e3
    freqs = f0 + df * np.arange(K)
    H = _mk_linear_phase(freqs, tau_true)

    dct = GroupDelayCalculator(H, freqs).to_dict()

    assert "H_avg" in dct
    assert isinstance(dct["H_avg"], list)
    assert all(isinstance(x, tuple) and len(x) == 2 for x in dct["H_avg"])
    assert "complex_unit" in dct
    assert dct["complex_unit"] == "[Real, Imaginary]"
    assert "H_raw" in dct
    assert "group_delay_full" in dct


@pytest.mark.pnm
def test_validation_duplicate_freqs_and_mismatched_lengths() -> None:
    freqs = np.array([100.0, 100.0, 200.0])
    H = np.array([1+0j, 1+0j, 1+0j])
    calc = GroupDelayCalculator(H, freqs)
    with pytest.raises(ValueError):
        _ = calc.compute_group_delay_full()

    freqs2 = np.array([1.0, 2.0, 3.0, 4.0])
    H2 = np.array([1+0j, 1+0j, 1+0j])
    with pytest.raises(ValueError):
        _ = GroupDelayCalculator(H2, freqs2)

    with pytest.raises(ValueError):
        _ = GroupDelayCalculator(np.zeros((2, 3, 3)), np.array([1.0, 2.0, 3.0]))


# FILE: /home/dev01/Projects/PyPNM/tests/test_heatmap_anomaly_detector.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import numpy as np
import pytest

from pypnm.api.routes.advance.analysis.signal_analysis.detection.anolamaly.heatmap_anomaly_detection import (
    HeatmapAnomalyDetector,
)


@pytest.mark.pnm
def test_compute_zmap_basic_stats() -> None:
    # simple 2D ramp
    a = np.arange(20, dtype=float).reshape(4, 5)
    det = HeatmapAnomalyDetector(a, threshold=2.0)
    z = det.compute_zmap()

    assert z.shape == a.shape
    # zmap should be zero-mean, unit-variance (up to numerical tolerance)
    assert abs(z.mean()) < 1e-12
    assert abs(z.std() - 1.0) < 1e-12


@pytest.mark.pnm
def test_compute_zmap_zero_sigma() -> None:
    # constant matrix -> std == 0 -> zmap should be all zeros
    a = np.full((3, 4), 7.0)
    det = HeatmapAnomalyDetector(a, threshold=3.0)
    z = det.compute_zmap()
    assert np.all(z == 0.0)

    mask = det.detect()
    assert mask.shape == a.shape
    # no anomalies because z == 0 everywhere
    assert not mask.any()


@pytest.mark.pnm
def test_detect_thresholding_and_boxes_single_blob() -> None:
    # Create a small grid with one obvious high anomaly block
    a = np.zeros((6, 6), dtype=float)
    a[2:4, 3:5] = 100.0  # 2x2 bright blob

    det = HeatmapAnomalyDetector(a, threshold=2.0)
    mask = det.detect()

    # Blob region should be True; outside False
    assert mask[2:4, 3:5].all()
    assert not mask[:2, :].any()
    assert not mask[4:, :].any()

    boxes = det.find_boxes()
    # exactly one box, spanning the 2x2 region
    assert len(boxes) == 1
    r0, c0, r1, c1 = boxes[0]
    assert (r0, c0, r1, c1) == (2, 3, 3, 4)


@pytest.mark.pnm
def test_find_boxes_multiple_disjoint_blobs() -> None:
    a = np.zeros((8, 8), dtype=float)
    a[1:3, 1:3] = 10.0     # blob A
    a[5:7, 5:7] = -10.0    # blob B (negative should also be flagged via |z|)

    det = HeatmapAnomalyDetector(a, threshold=1.0)
    det.detect()
    boxes = det.find_boxes()

    # We expect two disjoint boxes
    assert len(boxes) == 2
    assert (1, 1, 2, 2) in boxes
    assert (5, 5, 6, 6) in boxes


@pytest.mark.pnm
def test_four_connectivity_not_diagonal_connected() -> None:
    # Two pixels touching diagonally should be separate components.
    a = np.zeros((3, 3), dtype=float)
    a[0, 0] = 100.0
    a[1, 1] = 100.0

    det = HeatmapAnomalyDetector(a, threshold=1.0)
    det.detect()
    boxes = det.find_boxes()

    assert len(boxes) == 2
    assert (0, 0, 0, 0) in boxes
    assert (1, 1, 1, 1) in boxes


@pytest.mark.pnm
def test_to_json_structure_after_detection() -> None:
    a = np.zeros((5, 5), dtype=float)
    a[2, 2] = 50.0

    det = HeatmapAnomalyDetector(a, threshold=1.5)
    det.detect()
    det.find_boxes()
    payload = det.to_json()

    assert "threshold" in payload and payload["threshold"] == 1.5
    assert "boxes" in payload and isinstance(payload["boxes"], list)
    # one 1x1 box expected
    assert payload["boxes"] == [{"row_min": 2, "col_min": 2, "row_max": 2, "col_max": 2}]


# FILE: /home/dev01/Projects/PyPNM/tests/test_host_endpoint.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
import socket

import pytest

from pypnm.lib.host_endpoint import HostEndpoint
from pypnm.lib.ping import Ping
from pypnm.lib.types import HostNameStr


def test_ping_delegates_to_ping_is_reachable(monkeypatch: pytest.MonkeyPatch) -> None:
    called: dict[str, object] = {}

    def fake_is_reachable(host: str, timeout: int, count: int) -> bool:
        called["host"] = host
        called["timeout"] = timeout
        called["count"] = count
        return True

    monkeypatch.setattr(Ping, "is_reachable", fake_is_reachable)

    endpoint = HostEndpoint(HostNameStr("example.com"))
    result = endpoint.ping(timeout = 2, count = 3)

    assert result is True
    assert called["host"] == "example.com"
    assert called["timeout"] == 2
    assert called["count"] == 3


def test_resolve_returns_unique_addresses_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(host: str, _service: object) -> list[tuple[object, ...]]:
        assert host == "example.com"
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 0, 0, 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    endpoint  = HostEndpoint(HostNameStr("example.com"))
    addresses = endpoint.resolve()

    assert "192.0.2.1" in addresses
    assert "2001:db8::1" in addresses
    assert len(addresses) == 2


def test_resolve_logs_error_and_returns_empty_on_dns_failure(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    def fake_getaddrinfo(host: str, _service: int | str | None) -> list[tuple[object, ...]]:
        raise OSError("temporary failure in name resolution")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    endpoint = HostEndpoint(HostNameStr("bad-hostname.invalid"))

    logger_name = "HostEndpoint"
    with caplog.at_level(logging.ERROR, logger = logger_name):
        addresses = endpoint.resolve()

    assert addresses == []
    assert "DNS lookup failed for bad-hostname.invalid" in caplog.text


def test_resolve_google_dns_smoke() -> None:
    """
    Smoke-Test Real DNS Resolution For www.google.com.

    This test exercises the HostEndpoint.resolve() method against a well-known
    public hostname. If DNS resolution fails (for example, due to an offline
    or sandboxed environment), the test is skipped instead of treated as a
    hard failure.
    """
    endpoint  = HostEndpoint(HostNameStr("www.google.com"))
    addresses = endpoint.resolve()

    if not addresses:
        pytest.skip("DNS resolution failed for www.google.com; skipping smoke test")

    for addr in addresses:
        assert isinstance(addr, str)
        assert len(addr) > 0


def test_ping_localhost_reachable() -> None:
    """
    Verify That Localhost Is Reachable Via HostEndpoint.ping.

    This is an integration-style smoke test using the real Ping.is_reachable()
    implementation. It will fail if ICMP ping to 'localhost' is not functioning
    correctly in the current environment.
    """
    endpoint = HostEndpoint(HostNameStr("localhost"))
    assert endpoint.ping(timeout = 1, count = 1) is True


# FILE: /home/dev01/Projects/PyPNM/tests/test_ifft_echo_detector.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import numpy as np
import pytest

from pypnm.api.routes.advance.analysis.signal_analysis.detection.echo.ifft import (
    IfftEchoDetector,
)
from pypnm.lib.constants import SPEED_OF_LIGHT as C0


@pytest.mark.pnm
def test_to_model_detects_single_echo_basic() -> None:
    # Build a simple time response: impulse at 0 and smaller echo at bin d
    N = 256
    d = 10                       # echo at 10 samples
    fs = 1_000_000.0             # 1 MHz sample rate -> 1 us per sample
    vf = 0.87                    # velocity factor for to_model() (used in detector ctor)

    h = np.zeros(N, dtype=np.complex128)
    h[0] = 1.0 + 0j
    h[d] = 0.4 + 0j

    H = np.fft.fft(h)            # detector expects frequency-domain data
    det = IfftEchoDetector(H, sample_rate=fs, prop_speed_frac=vf)

    m = det.to_model(threshold_frac=0.2, guard_bins=1, max_delay_s=None, n_fft=None)

    # Indices
    assert m.reflection.direct_index == 0
    assert m.reflection.echo_index == d

    # Delay and distance
    expected_delay = d / fs
    expected_dist_m = expected_delay * (C0 * vf) / 2.0
    assert m.reflection.reflection_delay_s == pytest.approx(expected_delay, rel=1e-6)
    assert m.reflection.reflection_distance_m == pytest.approx(expected_dist_m, rel=1e-6)

    # Amplitude ratio ~ 0.4
    assert m.reflection.amp_ratio == pytest.approx(0.4, rel=1e-3)

    # Model shape fields
    assert m.dataset_info.subcarriers == N
    assert m.dataset_info.snapshots == 1
    assert m.sample_rate_hz == fs
    assert m.prop_speed_mps == pytest.approx(C0 * vf, rel=1e-12)

    # Optional time block present by default
    assert m.time_response is not None
    assert m.time_response.n_fft == N
    assert len(m.time_response.time_axis_s) == N
    assert len(m.time_response.time_response) == N


@pytest.mark.pnm
def test_detect_multiple_reflections_with_spacing_and_padding() -> None:
    N = 512
    fs = 2_000_000.0
    vf = 0.82

    h = np.zeros(N, dtype=np.complex128)
    h[0] = 1.0
    h[15] = 0.6
    h[40] = 0.5
    H = np.fft.fft(h)

    det = IfftEchoDetector(H, sample_rate=fs, prop_speed_frac=vf)

    nfft = 1024
    rpt = det.detect_multiple_reflections(
        cable_type="RG59",
        velocity_factor=None,
        threshold_frac=0.2,
        guard_bins=1,
        min_separation_s=0.0,
        max_delay_s=None,
        max_peaks=5,
        n_fft=nfft,
        include_time_response=True,
    )

    scale = nfft // N  # 2
    expected_bins = [15 * scale, 40 * scale]
    assert [e.bin_index for e in rpt.echoes[:2]] == expected_bins

    # distance sanity remains the same
    dists = [e.distance_m for e in rpt.echoes]
    assert all(d > 0 for d in dists)
    assert dists[0] < dists[1]

    assert rpt.time_response is not None
    assert rpt.time_response.n_fft == nfft
    assert len(rpt.time_response.time_axis_s) == nfft
    assert len(rpt.time_response.time_response) == nfft


@pytest.mark.pnm
def test_accepts_real_imag_pair_inputs_shapes() -> None:
    N = 128
    fs = 500_000.0

    # Build simple time response and FFT to get H
    h = np.zeros(N, dtype=np.complex128)
    h[0] = 1.0
    h[8] = 0.25
    H = np.fft.fft(h)

    # (N,2) real/imag input (single snapshot)
    H_pairs = np.column_stack((H.real, H.imag))
    det_single = IfftEchoDetector(H_pairs, sample_rate=fs)
    m_single = det_single.to_model()
    assert m_single.dataset_info.snapshots == 1
    assert m_single.dataset_info.subcarriers == N

    # (M,N,2) real/imag input (two snapshots, identical)
    H_pairs2 = np.stack([H_pairs, H_pairs], axis=0)
    det_multi = IfftEchoDetector(H_pairs2, sample_rate=fs)
    m_multi = det_multi.to_model()
    assert m_multi.dataset_info.snapshots == 2
    assert m_multi.dataset_info.subcarriers == N


@pytest.mark.pnm
def test_compute_time_response_raises_when_nfft_too_small() -> None:
    N = 64
    fs = 1e6
    h = np.zeros(N, dtype=np.complex128)
    h[0] = 1.0
    H = np.fft.fft(h)

    det = IfftEchoDetector(H, sample_rate=fs)
    with pytest.raises(ValueError):
        det.compute_time_response(n_fft=N - 1)  # must be >= N


@pytest.mark.pnm
def test_no_echo_found_when_threshold_too_high() -> None:
    N = 128
    fs = 1e6
    h = np.zeros(N, dtype=np.complex128)
    h[0] = 1.0
    h[20] = 0.05  # small echo

    H = np.fft.fft(h)
    det = IfftEchoDetector(H, sample_rate=fs)

    # Threshold above 5% echo → expect failure
    with pytest.raises(RuntimeError):
        det.to_model(threshold_frac=0.2)  # 20% > 5%, so no echo should be found


# FILE: /home/dev01/Projects/PyPNM/tests/test_ping.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
import subprocess
from collections.abc import Callable
from typing import NoReturn

import pytest

from pypnm.lib.ping import Ping


class DummyCompleted:
    def __init__(self, returncode: int) -> None:
        self.returncode = returncode


def _mock_run_factory(expected_cmd_out: list[str], rc: int = 0) -> Callable[..., DummyCompleted]:
    captured: dict[str, object] = {}

    def _mock_run(cmd: list[str], *args: object, **kwargs: object) -> DummyCompleted:
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs

        if "stdout" in kwargs:
            assert kwargs["stdout"] is subprocess.DEVNULL
        if "stderr" in kwargs:
            assert kwargs["stderr"] is subprocess.DEVNULL

        return DummyCompleted(rc)

    _mock_run.captured = captured  # type: ignore[attr-defined]
    _mock_run.expected = expected_cmd_out  # type: ignore[attr-defined]
    return _mock_run


def test_linux_mac_builds_correct_command_and_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("platform.system", lambda: "Linux")

    expected_cmd = ["ping", "-c", "3", "-W", "2", "host.example"]
    mock_run = _mock_run_factory(expected_cmd, rc=0)
    monkeypatch.setattr("subprocess.run", mock_run)

    ok = Ping.is_reachable("host.example", timeout=2, count=3)
    assert ok is True
    assert mock_run.captured["cmd"] == expected_cmd


def test_linux_mac_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("platform.system", lambda: "Darwin")

    expected_cmd = ["ping", "-c", "1", "-W", "1", "8.8.8.8"]
    mock_run = _mock_run_factory(expected_cmd, rc=1)
    monkeypatch.setattr("subprocess.run", mock_run)

    ok = Ping.is_reachable("8.8.8.8")
    assert ok is False
    assert mock_run.captured["cmd"] == expected_cmd


def test_windows_builds_correct_command_and_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("platform.system", lambda: "Windows")

    expected_cmd = ["ping", "-n", "4", "-w", "3000", "10.0.0.1"]
    mock_run = _mock_run_factory(expected_cmd, rc=0)
    monkeypatch.setattr("subprocess.run", mock_run)

    ok = Ping.is_reachable("10.0.0.1", timeout=3, count=4)
    assert ok is True
    assert mock_run.captured["cmd"] == expected_cmd


def test_subprocess_exception_returns_false(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr("platform.system", lambda: "Linux")

    def boom(*args: object, **kwargs: object) -> NoReturn:
        raise OSError("no ping here")

    monkeypatch.setattr("subprocess.run", boom)

    with caplog.at_level(logging.ERROR):
        ok = Ping.is_reachable("nowhere.invalid", timeout=1, count=1)

    assert ok is False
    # Optional: assert we actually logged the error
    assert "[Ping Error] no ping here" in caplog.text


# FILE: /home/dev01/Projects/PyPNM/tests/test_pnm_channel_estimation_parse.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typing_extensions import assert_type

from pypnm.lib.types import ComplexArray, ComplexSeries
from pypnm.pnm.parser.CmDsOfdmChanEstimateCoef import CmDsOfdmChanEstimateCoef

DATA_DIR = Path(__file__).parent / "files"
CE_PATH = DATA_DIR / "channel_estimation.bin"
NON_CE_PATH = DATA_DIR / "rxmer.bin"  # negative test: valid PNM but wrong type

MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")


def _is_pair_seq(x: object) -> bool:
    """Return True for [re, im] where both are number-like."""
    return (
        isinstance(x, (list, tuple))
        and len(x) == 2
        and all(isinstance(v, (int, float)) for v in x)
    )


@pytest.fixture(scope="session")
def ce_bytes() -> bytes:
    return CE_PATH.read_bytes()


@pytest.mark.pnm
def test_ce_parses_and_model_shape(ce_bytes: bytes) -> None:
    ce_model = CmDsOfdmChanEstimateCoef(ce_bytes).to_model()

    # Basic header fields
    assert isinstance(ce_model.channel_id, int)
    assert MAC_RE.match(ce_model.mac_address)

    # Subcarrier metadata sane
    assert isinstance(ce_model.subcarrier_spacing, int) and ce_model.subcarrier_spacing > 0
    assert isinstance(ce_model.first_active_subcarrier_index, int)
    assert ce_model.first_active_subcarrier_index >= 0

    # Data length is raw bytes; must be multiple of 4 (2B real + 2B imag per complex)
    assert ce_model.data_length % 4 == 0

    # Number of complex points = data_length / 4
    num_points = ce_model.data_length // 4
    assert isinstance(ce_model.values, list) and len(ce_model.values) == num_points
    assert all(_is_pair_seq(p) for p in ce_model.values)

    # Units
    assert ce_model.value_units == "complex"

    # OBW equals (#points) * spacing
    assert ce_model.occupied_channel_bandwidth == num_points * ce_model.subcarrier_spacing


@pytest.mark.pnm
def test_ce_coeff_rounding_and_raw_access(ce_bytes: bytes) -> None:
    parser = CmDsOfdmChanEstimateCoef(ce_bytes)

    # Rounded → ComplexArray: list[[re, im], ...]
    rounded = parser.get_coefficients("rounded")
    assert isinstance(rounded, list)
    assert all(_is_pair_seq(v) for v in rounded)

    # Raw → ComplexSeries: list[complex]
    raw = parser.get_coefficients("raw")
    assert isinstance(raw, list)
    assert all(isinstance(v, complex) for v in raw)

    # Same length views
    assert len(raw) == len(rounded)

    # ---- Static typing assertions (validate overloads) ----
    assert_type(parser.get_coefficients("rounded"), ComplexArray)   # Literal["rounded"] → ComplexArray
    assert_type(parser.get_coefficients("raw"), ComplexSeries)      # Literal["raw"] → ComplexSeries
    assert_type(parser.get_coefficients(), ComplexArray)            # default → ComplexArray


@pytest.mark.pnm
def test_ce_serialization_roundtrip(ce_bytes: bytes) -> None:
    parser = CmDsOfdmChanEstimateCoef(ce_bytes)

    d = parser.to_dict()
    j = parser.to_json()

    parsed = json.loads(j)
    # Top-level keys must match dict export
    assert set(parsed.keys()) == set(d.keys())


@pytest.mark.pnm
def test_non_ce_file_rejected() -> None:
    with pytest.raises(ValueError):
        _ = CmDsOfdmChanEstimateCoef(NON_CE_PATH.read_bytes())


# FILE: /home/dev01/Projects/PyPNM/tests/test_pnm_constellation_parse.py
# tests/test_pnm_constellation_parse.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia


from __future__ import annotations

import math
from pathlib import Path

import pytest

from pypnm.pnm.parser.CmDsConstDispMeas import CmDsConstDispMeas

DATA_DIR = Path(__file__).parent / "files"
CONST_PATH = DATA_DIR / "const_display.bin"
NON_CONST_PATH = DATA_DIR / "fec_summary.bin"  # negative test sample


@pytest.fixture(scope="session")
def const_bytes() -> bytes:
    return CONST_PATH.read_bytes()


@pytest.mark.pnm
def test_constellation_file_parses_and_model_shape(const_bytes: bytes) -> None:
    cm = CmDsConstDispMeas(const_bytes)
    m = cm.to_model()

    # basic header presence
    assert m.pnm_header is not None
    # required top-level fields
    assert isinstance(m.channel_id, int)
    assert isinstance(m.mac_address, str) and len(m.mac_address) >= 11  # "aa:bb:cc:dd:ee:ff"
    assert isinstance(m.subcarrier_zero_frequency, int)
    assert isinstance(m.subcarrier_spacing, int) and m.subcarrier_spacing > 0

    # model semantics
    assert m.sample_units == "[Real(I), Imaginary(Q)]"
    assert isinstance(m.actual_modulation_order, int) and m.actual_modulation_order >= 0
    assert isinstance(m.num_sample_symbols, int) and m.num_sample_symbols >= 0
    assert isinstance(m.sample_length, int) and m.sample_length >= 0

    # samples shape: list of [I, Q] float pairs
    assert isinstance(m.samples, list)
    assert all(isinstance(pair, (list, tuple)) and len(pair) == 2 for pair in m.samples)
    assert all(all(isinstance(v, (int, float)) and math.isfinite(v) for v in pair) for pair in m.samples)


    # length consistency: payload bytes / 4 => number of complex pairs
    assert len(m.samples) == m.sample_length // 4


@pytest.mark.pnm
def test_constellation_samples_decoded_nonempty_and_reasonable_range() -> None:
    cm = CmDsConstDispMeas(CONST_PATH.read_bytes())
    m = cm.to_model()

    # Must have some content
    assert len(m.samples) > 0

    # Values should be small (fixed-point 2.13 typical ranges); don't over-constrain:
    # just ensure not absurd. (Avoid strict bounds—device-dependent.)
    flat = [v for pair in m.samples for v in pair]
    assert all(math.isfinite(v) for v in flat)
    # Very loose sanity: within a few standard units
    assert all(-10.0 <= v <= 10.0 for v in flat)


@pytest.mark.pnm
def test_constellation_serialization_roundtrip() -> None:
    cm = CmDsConstDispMeas(CONST_PATH.read_bytes())

    d = cm.to_dict()
    j = cm.to_json()

    # Ensure core keys exist and JSON serializes without error
    for key in ("pnm_header", "channel_id", "mac_address", "samples", "sample_length"):
        assert key in d

    import json
    parsed = json.loads(j)
    assert set(parsed.keys()) == set(d.keys())


@pytest.mark.pnm
def test_non_constellation_file_is_rejected() -> None:
    with pytest.raises(ValueError):
        _ = CmDsConstDispMeas(NON_CONST_PATH.read_bytes())


# FILE: /home/dev01/Projects/PyPNM/tests/test_pnm_factory_fetcher.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path
from struct import pack

import pytest

from pypnm.pnm.parser.CmDsConstDispMeas import CmDsConstDispMeas
from pypnm.pnm.parser.CmDsHist import CmDsHist
from pypnm.pnm.parser.CmDsOfdmChanEstimateCoef import CmDsOfdmChanEstimateCoef
from pypnm.pnm.parser.CmDsOfdmFecSummary import CmDsOfdmFecSummary
from pypnm.pnm.parser.CmDsOfdmModulationProfile import CmDsOfdmModulationProfile
from pypnm.pnm.parser.CmDsOfdmRxMer import CmDsOfdmRxMer
from pypnm.pnm.parser.CmSpectrumAnalysis import CmSpectrumAnalysis
from pypnm.pnm.parser.fetch_pnm_process import PnmFileTypeObjectFetcher

DATA_DIR = Path(__file__).parent / "files"

@pytest.mark.pnm
@pytest.mark.parametrize(
    "filename, expected_cls",
    [
        ("rxmer.bin", CmDsOfdmRxMer),
        ("channel_estimation.bin", CmDsOfdmChanEstimateCoef),
        ("const_display.bin", CmDsConstDispMeas),
        ("histogram.bin", CmDsHist),
        ("fec_summary.bin", CmDsOfdmFecSummary),
        ("modulation_profile.bin", CmDsOfdmModulationProfile),
        ("spectrum_analyzer.bin", CmSpectrumAnalysis),
    ],
)
def test_factory_returns_correct_parser(filename: str, expected_cls: type[object]) -> None:
    blob = (DATA_DIR / filename).read_bytes()
    parser = PnmFileTypeObjectFetcher(blob).get_parser()
    assert isinstance(parser, expected_cls)
    # Smoketest that the parser can materialize a model/dict without exceptions
    assert hasattr(parser, "to_model") or hasattr(parser, "to_dict")
    _ = parser.to_model() if hasattr(parser, "to_model") else parser.to_dict()


@pytest.mark.pnm
def test_factory_unknown_type_raises_value_error() -> None:
    """
    Build a minimal, valid-looking PNM header with an unknown 3-char type ("PNX")
    so the factory cannot map it to a known parser.
    Header format (standard): '!3sBBBI'
    """
    # file_type="PNX", file_type_num=5, major=1, minor=0, capture_time=0
    header = pack("!3sBBBI", b"PNX", 5, 1, 0, 0)
    with pytest.raises(ValueError):
        PnmFileTypeObjectFetcher(header)


# FILE: /home/dev01/Projects/PyPNM/tests/test_pnm_fec_summary_parse.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pypnm.pnm.parser.CmDsOfdmFecSummary import CmDsOfdmFecSummary
from pypnm.pnm.parser.model.parser_rtn_models import CmDsOfdmFecSummaryModel

DATA_DIR = Path(__file__).parent / "files"
FEC_PATH = DATA_DIR / "fec_summary.bin"


@pytest.fixture(scope="session")
def fec_bytes() -> bytes:
    return FEC_PATH.read_bytes()


@pytest.mark.pnm
def test_fec_summary_parses_and_model_shape(fec_bytes: bytes) -> None:
    """Basic parse + model shape."""
    fec = CmDsOfdmFecSummary(fec_bytes).to_model()
    assert isinstance(fec, CmDsOfdmFecSummaryModel)

    # top-level fields exist
    assert fec.channel_id >= 0
    assert isinstance(fec.mac_address, str) and len(fec.mac_address) >= 11  # "aa:bb:cc:dd:ee:ff"
    assert fec.num_profiles >= 0
    assert len(fec.fec_summary_data) == fec.num_profiles


@pytest.mark.pnm
def test_profiles_and_sets_are_consistent(fec_bytes: bytes) -> None:
    """Each profile has number_of_sets matching entry arrays, and values are sane."""
    model = CmDsOfdmFecSummary(fec_bytes).to_model()

    for p in model.fec_summary_data:
        assert p.number_of_sets == len(p.codeword_entries.timestamp)
        assert len(p.codeword_entries.timestamp) == len(p.codeword_entries.total_codewords) == \
               len(p.codeword_entries.corrected) == len(p.codeword_entries.uncorrectable)

        # timestamps monotonic non-decreasing
        ts = p.codeword_entries.timestamp
        assert all(ts[i] <= ts[i + 1] for i in range(len(ts) - 1))

        # counts are non-negative and totals >= corrected + uncorrectable (best-effort sanity)
        tot = p.codeword_entries.total_codewords
        cor = p.codeword_entries.corrected
        unc = p.codeword_entries.uncorrectable
        assert all(x >= 0 for x in tot)
        assert all(x >= 0 for x in cor)
        assert all(x >= 0 for x in unc)
        assert all(t >= c + u for t, c, u in zip(tot, cor, unc, strict=False))


@pytest.mark.pnm
def test_capture_time_overridden_from_first_timestamp(fec_bytes: bytes) -> None:
    """
    FEC Summary PNN8 omits header capture_time; the parser should override it
    from the first timestamp in the first profile.
    """
    obj = CmDsOfdmFecSummary(fec_bytes)
    model = obj.to_model()

    # pull first timestamp actually parsed
    first_ts = model.fec_summary_data[0].codeword_entries.timestamp[0]
    assert model.pnm_header.capture_time == first_ts


@pytest.mark.pnm
def test_summary_type_label_is_readable(fec_bytes: bytes) -> None:
    model = CmDsOfdmFecSummary(fec_bytes).to_model()
    # label should be a non-empty string; known mapping currently has "24-hour interval" for type 2
    assert isinstance(model.summary_type_label, str) and model.summary_type_label


@pytest.mark.pnm
def test_serialization_roundtrip(fec_bytes: bytes) -> None:
    obj = CmDsOfdmFecSummary(fec_bytes)

    d = obj.to_dict()
    j = obj.to_model().model_dump_json()
    parsed = json.loads(j)

    # top-level keys should match
    assert set(parsed.keys()) == set(d.keys())


@pytest.mark.pnm
def test_wrong_type_rejected() -> None:
    """Smoke check: feeding a non-FEC file should raise ValueError."""
    # Use another PNM sample as a negative test if present; fallback to rxmer.bin
    alt_path = DATA_DIR / "rxmer.bin"
    raw = alt_path.read_bytes()
    with pytest.raises(ValueError):
        _ = CmDsOfdmFecSummary(raw)


# FILE: /home/dev01/Projects/PyPNM/tests/test_pnm_header_each_file.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import time
from pathlib import Path

import pytest

from pypnm.lib.constants import DEFAULT_CAPTURE_TIME
from pypnm.lib.types import CaptureTime
from pypnm.pnm.parser.pnm_file_type import PnmFileType
from pypnm.pnm.parser.pnm_header import PnmHeader

DATA_DIR = Path(__file__).parent / "files"

ALL_FILES = [
    "channel_estimation.bin",
    "const_display.bin",
    "fec_summary.bin",
    "histogram.bin",
    "modulation_profile.bin",
    "rxmer.bin",
    "spectrum_analyzer.bin",
]

MISSING_CAPTURE = {"fec_summary.bin"}  # PNN8 → no capture_time in header


def _p(name: str) -> Path:
    return DATA_DIR / name


@pytest.mark.pnm
def test_data_files_present() -> None:
    assert DATA_DIR.is_dir()
    for f in ALL_FILES:
        assert _p(f).is_file(), f"Missing test file: {f}"


@pytest.mark.pnm
@pytest.mark.parametrize("fname", ALL_FILES)
def test_pnm_header_per_file(fname: str) -> None:
    """Exercise PnmHeader parsing for each file and validate invariants."""
    data = _p(fname).read_bytes()
    hdr = PnmHeader.from_bytes(data)
    params = hdr.getPnmHeaderParameterModel()

    # Basic invariants for every file
    assert params.file_type is not None and len(params.file_type) == 3
    assert params.file_type_version >= 0
    assert params.major_version >= 0
    assert params.minor_version >= 0
    # payload is captured
    assert isinstance(hdr.pnm_data, (bytes, bytearray))

    # Header dict behavior
    d_full = hdr.getPnmHeader(header_only=False)
    d_hdr = hdr.getPnmHeader(header_only=True)
    assert "pnm_header" in d_full and "pnm_header" in d_hdr
    assert "data" in d_full and "data" not in d_hdr

    # File-type resolution should produce something (may be None if unknown)
    # This doesn’t force a specific enum—just tries to resolve it.
    _ = hdr.get_pnm_file_type()

    # capture_time semantics:
    if fname in MISSING_CAPTURE:
        # FEC summary omits capture_time → override must succeed
        ts = int(time.time())
        changed = hdr.override_capture_time(CaptureTime(ts))
        assert changed is True
        assert hdr.getPnmHeaderParameterModel().capture_time == ts
        assert hdr.getPnmHeaderParameterModel().capture_time != DEFAULT_CAPTURE_TIME
        # Sanity: if enum resolves, it must be the FEC summary type
        et = hdr.get_pnm_file_type()
        if et is not None:
            assert et == PnmFileType.OFDM_FEC_SUMMARY
    else:
        # Others should keep their original capture_time; override should be rejected
        before = hdr.getPnmHeaderParameterModel().capture_time
        changed = hdr.override_capture_time(CaptureTime(int(time.time())))
        after = hdr.getPnmHeaderParameterModel().capture_time
        assert changed is False
        assert after == before


# FILE: /home/dev01/Projects/PyPNM/tests/test_pnm_histogram_parse.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia


from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from pypnm.pnm.parser.CmDsHist import CmDsHist

DATA_DIR = Path(__file__).parent / "files"
HIST_PATH = DATA_DIR / "histogram.bin"
NON_HIST_PATH = DATA_DIR / "rxmer.bin"  # valid PNM but wrong type -> negative test

MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


@pytest.fixture(scope="session")
def hist_bytes() -> bytes:
    return HIST_PATH.read_bytes()


@pytest.mark.pnm
def test_hist_parses_and_model_shape(hist_bytes: bytes) -> None:
    m = CmDsHist(hist_bytes).to_model()

    # Header present
    assert m.pnm_header is not None

    # MAC format from parser is hex with colons
    assert isinstance(m.mac_address, str) and MAC_RE.match(m.mac_address)

    # Symmetry is a single byte -> int
    assert isinstance(m.symmetry, int)
    assert m.symmetry >= 0  # don’t assume meaning, just non-negative

    # Length fields are consistent with arrays
    assert m.dwell_count_values_length == len(m.dwell_count_values) * 4
    assert m.hit_count_values_length == len(m.hit_count_values) * 4

    # Non-empty arrays expected for a real capture
    assert len(m.dwell_count_values) > 0
    assert len(m.hit_count_values) > 0

    # Values are non-negative integers (stored as 32-bit big-endian)
    assert all(isinstance(v, (int, float)) and v >= 0 for v in m.dwell_count_values)
    assert all(isinstance(v, (int, float)) and v >= 0 for v in m.hit_count_values)


@pytest.mark.pnm
def test_hist_serialization_roundtrip(hist_bytes: bytes) -> None:
    h = CmDsHist(hist_bytes)
    d = h.to_dict()
    j = h.to_json()

    parsed = json.loads(j)
    # Top-level keys should match
    assert set(parsed.keys()) == set(d.keys())

    # Spot-check nested keys exist
    for k in (
        "pnm_header",
        "mac_address",
        "symmetry",
        "dwell_count_values_length",
        "dwell_count_values",
        "hit_count_values_length",
        "hit_count_values",
    ):
        assert k in d and k in parsed


@pytest.mark.pnm
def test_non_hist_file_rejected() -> None:
    with pytest.raises(ValueError):
        _ = CmDsHist(NON_HIST_PATH.read_bytes())


# FILE: /home/dev01/Projects/PyPNM/tests/test_pnm_modulation_profile_parse.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pypnm.pnm.parser.CmDsOfdmModulationProfile import CmDsOfdmModulationProfile
from pypnm.pnm.parser.model.parser_rtn_models import CmDsOfdmModulationProfileModel

DATA_DIR = Path(__file__).parent / "files"
MODPROF_PATH = DATA_DIR / "modulation_profile.bin"
NON_MODPROF_PATH = DATA_DIR / "rxmer.bin"  # negative test sample


@pytest.fixture(scope="session")
def modprof_bytes() -> bytes:
    return MODPROF_PATH.read_bytes()


@pytest.mark.pnm
def test_modprof_parses_and_model_shape(modprof_bytes: bytes) -> None:
    mp = CmDsOfdmModulationProfile(modprof_bytes).to_model()
    assert isinstance(mp, CmDsOfdmModulationProfileModel)

    # Header & core fields
    assert mp.num_profiles >= 0
    assert mp.profile_data_length_bytes >= 0
    assert isinstance(mp.mac_address, str) and len(mp.mac_address) >= 11  # "aa:bb:cc:dd:ee:ff"
    assert mp.subcarrier_spacing > 0
    assert mp.first_active_subcarrier_index >= 0
    assert mp.subcarrier_zero_frequency >= 0

    # Profiles container aligns with count
    assert len(mp.profiles) == mp.num_profiles


@pytest.mark.pnm
def test_profile_schemes_valid_and_decoded(modprof_bytes: bytes) -> None:
    mp = CmDsOfdmModulationProfile(modprof_bytes).to_model()

    for profile in mp.profiles:
        # profile ids are non-negative
        assert profile.profile_id >= 0

        # schemes should be a list; if present, each has required fields
        assert isinstance(profile.schemes, list)
        for sch in profile.schemes:
            # Discriminated union: schema_type is 0 (range) or 1 (skip)
            assert sch.schema_type in (0, 1)
            if sch.schema_type == 0:
                # Range schema
                assert hasattr(sch, "modulation_order")
                assert isinstance(sch.modulation_order, str) and sch.modulation_order
                assert sch.num_subcarriers >= 0
            else:
                # Skip schema
                assert hasattr(sch, "main_modulation_order")
                assert hasattr(sch, "skip_modulation_order")
                assert isinstance(sch.main_modulation_order, str) and sch.main_modulation_order
                assert isinstance(sch.skip_modulation_order, str) and sch.skip_modulation_order
                assert sch.num_subcarriers >= 0


@pytest.mark.pnm
def test_serialization_roundtrip(modprof_bytes: bytes) -> None:
    obj = CmDsOfdmModulationProfile(modprof_bytes)

    d = obj.to_dict()
    j = obj.to_model().model_dump_json()
    parsed = json.loads(j)

    # Top-level keys parity
    assert set(parsed.keys()) == set(d.keys())


@pytest.mark.pnm
def test_get_frequencies_current_behavior_is_empty(modprof_bytes: bytes) -> None:
    """
    get_frequencies currently returns [] (TODO noted in implementation).
    Keep this as a behavioral check until the TODO is implemented.
    """
    obj = CmDsOfdmModulationProfile(modprof_bytes)
    freqs = obj.get_frequencies()
    assert isinstance(freqs, list)
    assert len(freqs) == 0


@pytest.mark.pnm
def test_wrong_type_rejected() -> None:
    """Feeding a non-modulation-profile file should raise ValueError."""
    raw = NON_MODPROF_PATH.read_bytes()
    with pytest.raises(ValueError):
        _ = CmDsOfdmModulationProfile(raw)


# FILE: /home/dev01/Projects/PyPNM/tests/test_pnm_parser_and_parameters.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest

from pypnm.lib.mac_address import MacAddress
from pypnm.pnm.parser.CmDsConstDispMeas import CmDsConstDispMeas
from pypnm.pnm.parser.CmDsHist import CmDsHist
from pypnm.pnm.parser.CmDsOfdmChanEstimateCoef import CmDsOfdmChanEstimateCoef
from pypnm.pnm.parser.CmDsOfdmFecSummary import CmDsOfdmFecSummary
from pypnm.pnm.parser.CmDsOfdmModulationProfile import CmDsOfdmModulationProfile
from pypnm.pnm.parser.CmDsOfdmRxMer import CmDsOfdmRxMer
from pypnm.pnm.parser.pnm_file_type import PnmFileType
from pypnm.pnm.parser.pnm_parameter import GetPnmParserAndParameters

DATA_DIR = Path(__file__).parent / "files"

# fname, supported, expected parser class (or None when unsupported)
CASES = [
    ("channel_estimation.bin", True,  CmDsOfdmChanEstimateCoef),
    ("const_display.bin",      True,  CmDsConstDispMeas),
    ("fec_summary.bin",        True,  CmDsOfdmFecSummary),
    ("modulation_profile.bin", True,  CmDsOfdmModulationProfile),
    ("rxmer.bin",              True,  CmDsOfdmRxMer),
    ("histogram.bin",          True,  CmDsHist),
    ("spectrum_analyzer.bin",  False, None),
]


@pytest.mark.pnm
@pytest.mark.parametrize("fname,supported,parser_cls", CASES)
def test_get_pnm_parser_and_parameters_and_models(
    fname: str,
    supported: bool,
    parser_cls: type[object] | None,
) -> None:
    blob = (DATA_DIR / fname).read_bytes()
    wrapper = GetPnmParserAndParameters(blob)

    if not supported:
        with pytest.raises(NotImplementedError):
            _ = wrapper.to_model()
        with pytest.raises(NotImplementedError):
            _ = wrapper.get_parser()
        return

    # 1) High-level parameter model
    params = wrapper.to_model()
    assert isinstance(params.file_type, PnmFileType)
    assert isinstance(params.mac_address, str)

    params_dict = wrapper.to_dict()

    # file_type should be a PnmFileType enum in the dict as well
    assert "file_type" in params_dict
    ft = params_dict["file_type"]
    assert isinstance(ft, PnmFileType)
    assert ft is params.file_type

    # Canonical string like "PNN2", "PNN4", etc.
    ft_str = ft.value
    assert isinstance(ft_str, str)
    assert len(ft_str) >= 3

    # mac_address must be present and a string
    assert "mac_address" in params_dict
    assert isinstance(params_dict["mac_address"], str)

    # MAC sanity when formatted as aa:bb:...
    mac = params_dict["mac_address"]
    if mac:
        parts = mac.split(":")
        if all(len(p) == 2 for p in parts):
            assert all(0 <= int(p, 16) <= 0xFF for p in parts)

    # 2) Concrete parser + its own model
    parser, params_again = wrapper.get_parser()

    # Wrapper must return the same params instance/data
    assert params_again.file_type == params.file_type
    assert params_again.mac_address == params.mac_address

    # Concrete parser type must match the expected parser for this file
    assert isinstance(parser, parser_cls)

    # All concrete parsers must expose .to_model()
    model = parser.to_model()

    # Every measurement model should have mac_address and pnm_header
    assert hasattr(model, "mac_address")
    assert hasattr(model, "pnm_header")

    assert isinstance(model.mac_address, str)

    # If the top-level params has a non-null MAC, it must match the model MAC.
    # For file types where we intentionally don't propagate MAC (e.g. some headers),
    # params.mac_address will be the null MAC and we don't enforce equality.
    if params.mac_address != MacAddress.null():
        assert model.mac_address == params.mac_address

    # pnm_header should have file_type and file_type_version so we can reconstruct the PNM code
    header = model.pnm_header
    assert hasattr(header, "file_type")
    assert hasattr(header, "file_type_version")

    header_code = f"{header.file_type}{header.file_type_version}"
    assert header_code == ft_str


# FILE: /home/dev01/Projects/PyPNM/tests/test_pnm_rxmer_parse.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pypnm.pnm.parser.CmDsOfdmRxMer import CmDsOfdmRxMer

DATA_DIR = Path(__file__).parent / "files"
RXMER_PATH = DATA_DIR / "rxmer.bin"
NON_RXMER_PATH = DATA_DIR / "fec_summary.bin"  # negative test sample

@pytest.fixture(scope="session")
def rxmer_bytes() -> bytes:
    return RXMER_PATH.read_bytes()

@pytest.mark.pnm
def test_rxmer_file_loads_and_models_ok(rxmer_bytes: bytes) -> None:
    rx = CmDsOfdmRxMer(rxmer_bytes).to_model()

    # basic shape
    assert rx.data_length == len(rx.values)
    assert rx.value_units == "dB"
    assert rx.occupied_channel_bandwidth == rx.data_length * rx.subcarrier_spacing

    # stats: Pydantic -> dict for key checks
    stats = rx.signal_statistics.model_dump()
    assert "mean" in stats
    mean = stats["mean"]

    # Some implementations expose min/max directly; others via quantiles; fall back to computed.
    if "min" in stats and "max" in stats:
        smin, smax = stats["min"], stats["max"]
    elif "quantiles" in stats and isinstance(stats["quantiles"], dict):
        q = stats["quantiles"]
        # try common keys, else fallback to computed
        smin = q.get("min", min(rx.values))
        smax = q.get("max", max(rx.values))
    else:
        smin, smax = min(rx.values), max(rx.values)

    assert smin <= mean <= smax

    # modulation stats is already a dict
    mod = rx.modulation_statistics
    assert isinstance(mod, dict) and mod

@pytest.mark.pnm
def test_rxmer_values_in_range_and_cached() -> None:
    raw = RXMER_PATH.read_bytes()
    rxmer = CmDsOfdmRxMer(raw)

    vals1 = rxmer.get_rxmer_values()
    # Quarter-dB decoded and clamped [0.0, 63.5]
    assert all((0.0 <= v <= 63.5) for v in vals1)

    # Cached behavior: second call returns identical content
    vals2 = rxmer.get_rxmer_values()
    assert vals1 is vals2 or vals1 == vals2  # either same object or same content

@pytest.mark.pnm
def test_rxmer_frequencies_monotonic_and_sized() -> None:
    raw = RXMER_PATH.read_bytes()
    rxmer = CmDsOfdmRxMer(raw)
    model = rxmer.to_model()

    freqs = rxmer.get_frequencies()
    assert len(freqs) == model.data_length

    # Monotonic ascending with step == subcarrier spacing
    if len(freqs) >= 2:
        step = freqs[1] - freqs[0]
        assert step == model.subcarrier_spacing
        assert all(freqs[i] < freqs[i + 1] for i in range(len(freqs) - 1))

@pytest.mark.pnm
def test_rxmer_serialization_roundtrip() -> None:
    raw = RXMER_PATH.read_bytes()
    rxmer = CmDsOfdmRxMer(raw)

    d = rxmer.to_dict()
    j = rxmer.to_json()

    # JSON should be valid and represent same keys as dict (at least top-level)
    parsed = json.loads(j)
    assert set(parsed.keys()) == set(d.keys())

@pytest.mark.pnm
def test_non_rxmer_file_rejected() -> None:
    raw = NON_RXMER_PATH.read_bytes()
    with pytest.raises(ValueError):
        _ = CmDsOfdmRxMer(raw)


# FILE: /home/dev01/Projects/PyPNM/tests/test_pnm_spectrum_analysis_parse.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pypnm.pnm.parser.CmSpectrumAnalysis import CmSpectrumAnalysis

DATA_DIR = Path(__file__).parent / "files"
SPEC_PATH = DATA_DIR / "spectrum_analyzer.bin"


@pytest.fixture(scope="session")
def spectrum_bytes() -> bytes:
    return SPEC_PATH.read_bytes()


@pytest.mark.pnm
def test_spectrum_analyzer_parses_and_model_shape(spectrum_bytes: bytes) -> None:
    sa = CmSpectrumAnalysis(spectrum_bytes)
    m = sa.to_model()

    # header basics
    assert m.num_bins_per_segment >= 1
    assert m.segment_frequency_span > 0
    assert m.bin_frequency_spacing > 0

    # numeric types can be int or float depending on decode
    assert isinstance(m.first_segment_center_frequency, (int, float))
    assert isinstance(m.last_segment_center_frequency, (int, float))
    assert isinstance(m.spectrum_analysis_data_length, int)

    # serialized in dict/json via field_serializer
    assert isinstance(m.spectrum_analysis_data, (bytes, str))

    # segments present & each segment is a list[float]
    assert len(m.amplitude_bin_segments_float) >= 1
    for seg in m.amplitude_bin_segments_float:
        assert isinstance(seg, list)
        assert all(isinstance(v, float) for v in seg)
        assert len(seg) <= m.num_bins_per_segment

    if len(m.amplitude_bin_segments_float) > 1:
        for seg in m.amplitude_bin_segments_float[:-1]:
            assert len(seg) == m.num_bins_per_segment


@pytest.mark.pnm
def test_spectrum_analyzer_json_and_dict_roundtrip(spectrum_bytes: bytes) -> None:
    sa = CmSpectrumAnalysis(spectrum_bytes)

    d = sa.to_dict()
    j = sa.to_json()
    parsed = json.loads(j)

    # top-level keys align
    assert set(parsed.keys()) == set(d.keys())

    # In both dict and JSON, spectrum_analysis_data is hex string (due to field_serializer)
    assert isinstance(d["spectrum_analysis_data"], str)
    assert isinstance(parsed["spectrum_analysis_data"], str)
    assert parsed["spectrum_analysis_data"] == d["spectrum_analysis_data"]


@pytest.mark.pnm
def test_bin_frequency_spacing_consistency(spectrum_bytes: bytes) -> None:
    sa = CmSpectrumAnalysis(spectrum_bytes)
    m = sa.to_model()

    expect = int(m.segment_frequency_span / m.num_bins_per_segment)
    assert m.bin_frequency_spacing == expect


# FILE: /home/dev01/Projects/PyPNM/tests/test_scalar_value_converters.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import pytest

from pypnm.docsis.data_type.enums import MeasStatusType
from pypnm.lib.types import ScalarValue
from pypnm.snmp.casts import (
    as_bool,
    as_float0,
    as_float2,
    as_int,
    as_str,
    measurement_status,
    per_hundred,
    per_thousand,
    scale,
)


@pytest.mark.parametrize("value", [0, 1, "0", "1", 2, "2"])
def test_measurement_status_valid_enum_values(value: ScalarValue) -> None:
    """
    measurement_status should map numeric codes to MeasStatusType string form.
    We use the first enum member as a reference to avoid hard-coding values.
    """
    first_member = list(MeasStatusType)[0]
    # Only run a strict check when the value matches the first_member.value,
    # otherwise we just verify that valid ints do not raise and produce a string.
    if int(value) == int(first_member.value):
        assert measurement_status(value) == str(first_member)
    else:
        out = measurement_status(value)
        assert isinstance(out, str)
        assert out != ""


@pytest.mark.parametrize("value", ["not-an-int", "abc", "", object()])
def test_measurement_status_invalid_returns_other(value: object) -> None:
    assert measurement_status(value) == "other"


@pytest.mark.parametrize(
    "value, expected",
    [
        (0, False),
        (1, True),
        ("0", False),
        ("1", True),
        ("2", True),      # bool(2) is True
        ("", False),      # fallback to bool("") -> False
        ("false", True),  # int() fails, so bool("false") -> True
    ],
)
def test_as_bool_behaviour(value: ScalarValue, expected: bool) -> None:
    assert as_bool(value) is expected


@pytest.mark.parametrize(
    "value, expected",
    [
        (0, 0),
        (1, 1),
        (-5, -5),
        ("10", 10),
        ("-3", -3),
    ],
)
def test_as_int_converts_numeric_strings_and_ints(value: ScalarValue, expected: int) -> None:
    assert as_int(value) == expected


@pytest.mark.parametrize(
    "value, expected",
    [
        (0, "0"),
        (1, "1"),
        (-3, "-3"),
        (1.5, "1.5"),
        ("abc", "abc"),
    ],
)
def test_as_str_round_trips_to_string(value: ScalarValue, expected: str) -> None:
    assert as_str(value) == expected


@pytest.mark.parametrize(
    "value, expected",
    [
        (0, 0.0),
        (1, 1.0),
        (-3, -3.0),
        ("2.5", 2.5),
        ("0", 0.0),
    ],
)
def test_as_float0_basic_conversion(value: ScalarValue, expected: float) -> None:
    assert as_float0(value) == pytest.approx(expected)


@pytest.mark.parametrize(
    "value, expected",
    [
        (0, 0.0),
        (1, 0.01),
        (123, 1.23),
        ("250", 2.50),
        (-100, -1.00),
    ],
)
def test_as_float2_fixed_point_two_decimals(value: ScalarValue, expected: float) -> None:
    assert as_float2(value) == pytest.approx(expected, rel=1e-9, abs=1e-9)


@pytest.mark.parametrize(
    "value, factor, ndigits, expected",
    [
        (100, 0.01, None, 1.0),
        (100, 0.01, 2, 1.00),
        ("250", 0.1, 1, 25.0),
        (5, 2.0, 0, 10.0),
    ],
)
def test_scale_with_and_without_rounding(
    value: ScalarValue,
    factor: float,
    ndigits: int | None,
    expected: float,
) -> None:
    out = scale(value, factor=factor, ndigits=ndigits)
    assert out == pytest.approx(expected, rel=1e-9, abs=1e-9)


@pytest.mark.parametrize(
    "value, ndigits, expected",
    [
        (0, 2, 0.0),
        (100, 2, 1.0),
        ("250", 2, 2.5),
        (123, 1, 1.2),
    ],
)
def test_per_hundred_normalization(value: ScalarValue, ndigits: int, expected: float) -> None:
    assert per_hundred(value, ndigits=ndigits) == pytest.approx(expected, rel=1e-9, abs=1e-9)


@pytest.mark.parametrize(
    "value, ndigits, expected",
    [
        (0, 3, 0.0),
        (1000, 3, 1.0),
        ("2500", 3, 2.5),
        (1234, 3, 1.234),
        (1234, 2, 1.23),
    ],
)
def test_per_thousand_normalization(value: ScalarValue, ndigits: int, expected: float) -> None:
    assert per_thousand(value, ndigits=ndigits) == pytest.approx(expected, rel=1e-9, abs=1e-9)


# FILE: /home/dev01/Projects/PyPNM/tests/test_shannon.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

# tests/test_shannon.py
from __future__ import annotations

import math

import numpy as np
import pytest

from pypnm.lib.signal_processing.shan.shannon import Shannon
from pypnm.pnm.parser.CmDsOfdmModulationProfile import ModulationOrderType


def test_snr_to_bits_examples() -> None:
    assert Shannon._snr_to_bits(0.0) == 1
    assert Shannon._snr_to_bits(3.0) == 1
    assert Shannon._snr_to_bits(10.0) == 3
    assert Shannon._snr_to_bits(30.0) == 9


def test_bits_to_snr_and_inverse_relations() -> None:
    expected_db = 10.0 * math.log10((2**8) - 1)
    assert Shannon.bits_to_snr(8) == pytest.approx(expected_db, rel=1e-12)
    with pytest.raises(ValueError):
        Shannon.bits_to_snr(0)


def test_bits_from_symbol_count() -> None:
    assert Shannon.bits_from_symbol_count(1) == 0
    assert Shannon.bits_from_symbol_count(2) == 1
    assert Shannon.bits_from_symbol_count(256) == 8
    with pytest.raises(ValueError):
        Shannon.bits_from_symbol_count(0)


def test_from_modulation_and_getters() -> None:
    sh = Shannon.from_modulation("qam_256")
    target_bits = 8
    # Allow one-bit drop due to FP rounding of 10*log10(2**bits - 1)
    assert sh.bits in (target_bits, target_bits - 1)
    # SNR should match theoretical for target_bits
    assert sh.get_snr_db() == pytest.approx(Shannon.bits_to_snr(target_bits), rel=1e-12)


def test_from_modulation_type_enum() -> None:
    sh = Shannon.from_modulation_type(ModulationOrderType.qam_256)
    target_bits = 8
    assert sh.bits in (target_bits, target_bits - 1)
    assert sh.get_snr_db() == pytest.approx(Shannon.bits_to_snr(target_bits), rel=1e-12)


def test_snr_from_modulation_matches_bits_to_snr() -> None:
    by_name = Shannon.snr_from_modulation("qam_256")
    by_bits = Shannon.bits_to_snr(8)
    assert by_name == pytest.approx(by_bits, rel=1e-12)
    with pytest.raises(ValueError):
        Shannon.snr_from_modulation("qam_999")


def test_snr_to_limit_vectorized_and_scalar() -> None:
    snrs = [0.0, 3.0, 10.0, 30.0]
    expected = [Shannon._snr_to_bits(s) for s in snrs]
    assert Shannon.snr_to_limit(snrs) == expected
    arr = np.array(snrs, dtype=float)
    assert Shannon.snr_to_limit(arr) == expected
    assert Shannon.snr_to_limit(10.0) == [Shannon._snr_to_bits(10.0)]


def test_snr_to_snr_limit_roundtrip() -> None:
    snrs = [0.0, 10.0, 24.0, 30.0]
    bits_limits = Shannon.snr_to_limit(snrs)
    expected_db_limits = [Shannon.bits_to_snr(b) for b in bits_limits]
    got = Shannon.snr_to_snr_limit(snrs)
    assert len(got) == len(expected_db_limits)
    for g, e in zip(got, expected_db_limits, strict=False):
        assert g == pytest.approx(e, rel=1e-12)


# FILE: /home/dev01/Projects/PyPNM/tests/test_shannon_series.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

# tests/test_shannon_series.py
from __future__ import annotations

import json
import math

import pytest

from pypnm.lib.signal_processing.shan.series import ShannonSeries
from pypnm.lib.signal_processing.shan.shannon import Shannon


def test_invalid_inputs_raise() -> None:
    with pytest.raises(ValueError):
        ShannonSeries([-1.0])
    with pytest.raises(ValueError):
        ShannonSeries([float("nan")])
    with pytest.raises(ValueError):
        ShannonSeries([float("inf")])


def test_basic_series_outputs() -> None:
    snrs = [0.0, 3.0, 10.0, 30.0]
    series = ShannonSeries(snrs)

    # lengths
    assert len(series.snr_db_values) == len(snrs)
    assert len(series.bits_list) == len(snrs)
    assert len(series.modulations) == len(snrs)
    assert len(series.limit()) == len(snrs)

    # per-element expectations via Shannon
    exp_bits = [Shannon(s).bits for s in snrs]
    exp_mods = [Shannon(s).get_modulation() for s in snrs]
    assert series.bits_list == exp_bits
    assert series.modulations == exp_mods

    # average bits within bounds
    avg = series.average_bits()
    assert isinstance(avg, float)
    assert min(exp_bits) <= avg <= max(exp_bits)

    # max modulation matches the highest bits entry
    assert series.max_modulation() == exp_mods[exp_bits.index(max(exp_bits))]


def test_supported_modulation_counts_and_model() -> None:
    snrs = [0.0, 6.0, 12.0, 18.0, 24.0, 30.0]
    series = ShannonSeries(snrs)

    # counts should include all known modulations from Shannon.QAM_MODULATIONS
    known_mods = set(Shannon.QAM_MODULATIONS.values())
    counts = series.supported_modulation_counts()
    assert set(counts.keys()) == known_mods

    # monotonic: higher-order modulations cannot have higher counts than lower-order ones
    # build a list sorted by bits (ascending)
    bits_sorted = sorted(Shannon.QAM_MODULATIONS.items(), key=lambda kv: kv[0])
    prev = math.inf
    for _bits, name in bits_sorted:
        c = counts[name]
        assert isinstance(c, int) and 0 <= c <= len(snrs)
        assert c <= prev
        prev = c

    # model / dict / json shapes
    model = series.to_model()
    d = series.to_dict()
    j = series.to_json()
    j_obj = json.loads(j)

    assert model.bits_per_symbol == series.bits_list
    assert model.modulations == series.modulations
    assert model.snr_db_values == series.snr_db_values
    assert set(model.supported_modulation_counts.keys()) == known_mods
    assert d["bits_per_symbol"] == series.bits_list
    assert set(d["supported_modulation_counts"].keys()) == known_mods
    assert j_obj.get("avg", True)  # tolerate additional fields if present


def test_repr_and_str() -> None:
    snrs = [0.0, 10.0]
    series = ShannonSeries(snrs)
    r = repr(series)
    s = str(series)
    assert "ShannonSeries" in r
    assert "SNR values" in s


# FILE: /home/dev01/Projects/PyPNM/tests/test_signal_statistics.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
import math

import numpy as np
import pytest

from pypnm.pnm.lib.signal_statistics import SignalStatistics, SignalStatisticsModel


def _isclose(a: float, b: float, rtol: float = 1e-12, atol: float = 1e-12) -> float:
    return float(np.isclose(a, b, rtol=rtol, atol=atol))


def _allclose(a: float, b: float, rtol: float = 1e-12, atol: float = 1e-12) -> bool:
    return bool(np.allclose(a, b, rtol=rtol, atol=atol))


def test_rejects_empty_input() -> None:
    with pytest.raises(ValueError):
        SignalStatistics([]).compute()  # type: ignore[arg-type]


def test_basic_stats_on_simple_vector() -> None:
    x = np.array([1.0, 2.0, 3.0, 4.0])
    s = SignalStatistics(x).compute()

    # mean / median
    assert _isclose(s.mean, np.mean(x))
    assert _isclose(s.median, np.median(x))

    # std/variance (population)
    assert _isclose(s.std, np.std(x))
    assert _isclose(s.variance, np.var(x))
    assert _isclose(s.std**2, s.variance)

    # power = mean(x^2)
    assert _isclose(s.power, np.mean(x**2))

    # peak-to-peak
    assert _isclose(s.peak_to_peak, np.ptp(x))

    # mean absolute deviation around mean
    mad = np.mean(np.abs(x - x.mean()))
    assert _isclose(s.mean_abs_deviation, mad)

    # crest factor = max(|x|)/sqrt(power)
    peak = np.abs(x).max()
    expect_cf = peak / math.sqrt(np.mean(x**2))
    assert _isclose(s.crest_factor, expect_cf)

    # zero crossing rate / count
    crossings = int(np.sum(x[:-1] * x[1:] < 0))
    expect_zcr = crossings / (len(x) - 1)
    assert s.zero_crossings == crossings
    assert _isclose(s.zero_crossing_rate, expect_zcr)


def test_handles_single_sample() -> None:
    x = np.array([3.5])
    s = SignalStatistics(x).compute()

    # With one sample:
    assert _isclose(s.mean, 3.5)
    assert _isclose(s.median, 3.5)
    assert _isclose(s.std, 0.0)
    assert _isclose(s.variance, 0.0)
    assert _isclose(s.power, 3.5**2)
    assert _isclose(s.peak_to_peak, 0.0)
    assert _isclose(s.mean_abs_deviation, 0.0)
    # zero-crossing metrics defined this way in implementation:
    assert s.zero_crossings == 0
    assert _isclose(s.zero_crossing_rate, 0.0)

    # skewness/kurtosis are NaN when std == 0
    assert math.isnan(s.skewness)
    assert math.isnan(s.kurtosis)

    # crest factor with one nonzero value equals 1.0
    assert _isclose(s.crest_factor, 1.0)


def test_constant_signal_properties() -> None:
    x = np.ones(256) * -7.0
    s = SignalStatistics(x).compute()

    assert _isclose(s.mean, -7.0)
    assert _isclose(s.median, -7.0)
    assert _isclose(s.std, 0.0)
    assert _isclose(s.variance, 0.0)
    assert _isclose(s.power, 49.0)
    assert _isclose(s.peak_to_peak, 0.0)
    assert _isclose(s.mean_abs_deviation, 0.0)
    assert s.zero_crossings == 0
    assert _isclose(s.zero_crossing_rate, 0.0)
    assert math.isnan(s.skewness)
    assert math.isnan(s.kurtosis)
    # crest factor = |peak|/sqrt(power) = 7 / 7 = 1
    assert _isclose(s.crest_factor, 1.0)


def test_random_signal_matches_numpy() -> None:
    rng = np.random.default_rng(12345)
    x = rng.normal(loc=0.0, scale=2.0, size=10_000)
    s = SignalStatistics(x).compute()

    # basic alignment with numpy (population stats)
    assert _isclose(s.mean, np.mean(x), rtol=1e-9, atol=1e-9)
    assert _isclose(s.std, np.std(x), rtol=1e-9, atol=1e-9)
    assert _isclose(s.variance, np.var(x), rtol=1e-9, atol=1e-9)
    assert _isclose(s.power, np.mean(x**2), rtol=1e-9, atol=1e-9)

    # zero-crossings sanity: for zero-mean Gaussian, ZCR ~ 0.5
    assert 0.45 <= s.zero_crossing_rate <= 0.55


def test_nd_shapes_are_flattened() -> None:
    x2d = np.array([[1.0, -2.0, 3.0], [4.0, -5.0, 6.0]])
    s = SignalStatistics(x2d).compute()
    x1d = x2d.flatten()
    s_ref = SignalStatistics(x1d).compute()

    # Every numeric field should match after flatten
    for field in SignalStatisticsModel.model_fields:
        v = getattr(s, field)
        v_ref = getattr(s_ref, field)
        if isinstance(v, float) and math.isnan(v):
            assert isinstance(v_ref, float) and math.isnan(v_ref)
        else:
            assert _isclose(v, v_ref)


def test_model_serialization_roundtrip() -> None:
    x = np.array([0.0, 1.0, -1.0, 2.0, -2.0])
    s = SignalStatistics(x).compute()

    # dict keys present
    d = s.model_dump()
    for key in SignalStatisticsModel.model_fields:
        assert key in d

    # JSON round-trip
    j = s.model_dump_json()
    parsed = json.loads(j)
    assert set(parsed.keys()) == set(d.keys())


# FILE: /home/dev01/Projects/PyPNM/tests/test_utils_time_stamp.py
# tests/test_utils_time_stamp.py
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
import time

import pytest

from pypnm.lib.utils import Generate, TimeUnit


def test_time_unit_values() -> None:
    """
    Verify that TimeUnit enum members have the expected string values.
    """
    assert TimeUnit.SECONDS.value      == "s"
    assert TimeUnit.MILLISECONDS.value == "ms"
    assert TimeUnit.NANOSECONDS.value  == "ns"


def test_time_stamp_default_is_seconds(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Ensure the default time_stamp() call uses seconds and int(time.time()).
    """
    calls = {"time": 0, "time_ns": 0}

    def fake_time() -> float:
        calls["time"] += 1
        return 1_234.567

    def fake_time_ns() -> int:
        calls["time_ns"] += 1
        return 999_999_999

    monkeypatch.setattr(time, "time", fake_time)
    monkeypatch.setattr(time, "time_ns", fake_time_ns)

    ts = Generate.time_stamp()
    assert ts == 1_234
    assert calls["time"] == 1
    assert calls["time_ns"] == 0


def test_time_stamp_seconds(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Verify explicit TimeUnit.SECONDS returns truncated seconds from time.time().
    """
    calls = {"time": 0, "time_ns": 0}

    def fake_time() -> float:
        calls["time"] += 1
        return 2_000.999

    def fake_time_ns() -> int:
        calls["time_ns"] += 1
        return 0

    monkeypatch.setattr(time, "time", fake_time)
    monkeypatch.setattr(time, "time_ns", fake_time_ns)

    ts = Generate.time_stamp(TimeUnit.SECONDS)
    assert ts == 2_000
    assert calls["time"] == 1
    assert calls["time_ns"] == 0


def test_time_stamp_milliseconds(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Verify TimeUnit.MILLISECONDS uses time.time_ns() and converts to ms.
    """
    calls = {"time": 0, "time_ns": 0}

    def fake_time() -> float:
        calls["time"] += 1
        return 0.0

    def fake_time_ns() -> int:
        calls["time_ns"] += 1
        return 1_234_567_890  # ns

    monkeypatch.setattr(time, "time", fake_time)
    monkeypatch.setattr(time, "time_ns", fake_time_ns)

    ts = Generate.time_stamp(TimeUnit.MILLISECONDS)
    assert ts == 1_234_567_890 // 1_000_000
    assert calls["time_ns"] == 1
    # time() is never used in this branch
    assert calls["time"] == 0


def test_time_stamp_nanoseconds(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Verify TimeUnit.NANOSECONDS returns the raw value from time.time_ns().
    """
    calls = {"time": 0, "time_ns": 0}

    def fake_time() -> float:
        calls["time"] += 1
        return 0.0

    def fake_time_ns() -> int:
        calls["time_ns"] += 1
        return 987_654_321

    monkeypatch.setattr(time, "time", fake_time)
    monkeypatch.setattr(time, "time_ns", fake_time_ns)

    ts = Generate.time_stamp(TimeUnit.NANOSECONDS)
    assert ts == 987_654_321
    assert calls["time_ns"] == 1
    # time() is never used in this branch
    assert calls["time"] == 0


# FILE: /home/dev01/Projects/PyPNM/tests/test_pnm_file_type_mapper.py
# tests/test_pnm_file_type_mapper.py
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
import pytest

from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest
from pypnm.pnm.parser.pnm_file_type import PnmFileType
from pypnm.pnm.parser.pnm_type_header_mapper import PnmFileTypeMapper


def test_test_to_file_type_mapping_round_trip() -> None:
    """
    Verify that every DocsPnmCmCtlTest → PnmFileType mapping works in both directions.
    """
    for test_type, file_type in PnmFileTypeMapper._test_to_file_type.items():
        assert PnmFileTypeMapper.get_file_type(test_type) is file_type
        assert PnmFileTypeMapper.get_test_type(file_type) is test_type


def test_all_mapped_tests_are_known_enums() -> None:
    """
    Ensure that all keys in the mapping are valid DocsPnmCmCtlTest members.
    """
    for test_type in PnmFileTypeMapper._test_to_file_type:
        assert isinstance(test_type, DocsPnmCmCtlTest)


def test_all_mapped_file_types_are_known_enums() -> None:
    """
    Ensure that all values in the mapping are valid PnmFileType members.
    """
    for file_type in PnmFileTypeMapper._test_to_file_type.values():
        assert isinstance(file_type, PnmFileType)


def test_unmapped_test_type_returns_none_if_any_exist() -> None:
    """
    If there are DocsPnmCmCtlTest members not present in the mapping,
    verify that get_file_type returns None for at least one of them.
    """
    unmapped_tests = [t for t in DocsPnmCmCtlTest if t not in PnmFileTypeMapper._test_to_file_type]
    if not unmapped_tests:
        pytest.skip("All DocsPnmCmCtlTest values are mapped; no unmapped test type to validate.")
    assert PnmFileTypeMapper.get_file_type(unmapped_tests[0]) is None


def test_unmapped_file_type_returns_none_if_any_exist() -> None:
    """
    If there are PnmFileType members not present in the mapping values,
    verify that get_test_type returns None for at least one of them.
    """
    mapped_file_types = set(PnmFileTypeMapper._test_to_file_type.values())
    unmapped_file_types = [ft for ft in PnmFileType if ft not in mapped_file_types]
    if not unmapped_file_types:
        pytest.skip("All PnmFileType values are mapped; no unmapped file type to validate.")
    assert PnmFileTypeMapper.get_test_type(unmapped_file_types[0]) is None
