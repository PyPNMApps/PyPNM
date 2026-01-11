# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

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
from pypnm.lib.types import FileName, MacAddressStr, OperationId, TransactionId


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
        self.logger = logging.getLogger(f"PnmFileManager.{self.__class__.__name__}")
        self.router = APIRouter(
            prefix="/docs/pnm/files",
            tags=["PNM File Manager"],
        )
        self._add_routes()

    def _add_routes(self) -> None:
        default_mac_address = (
            MacAddress(SystemConfigSettings.default_mac_address())
            .to_mac_format(fmt=MacAddressFormat.COLON)
            .lower()
        )

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
        def search_files(
            mac_address: MacAddressStr = Path(
                description=(
                    f"MAC address of the cable modem, default: **{default_mac_address}**"
                ),
            ),
        ) -> FileQueryResponse:  # noqa: B008
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
            responses=FAST_API_RESPONSE,
        )
        def download_file_via_transaction_id(
            transaction_id: TransactionId = Path(
                description="Transaction ID of the file to download"
            ),
        ) -> FileResponse:  # noqa: B008
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
            "/download/macAddress/{mac_address}",
            response_class=FileResponse,
            summary="Download A PNM File By MAC Address",
            responses=FAST_API_RESPONSE,
        )
        def download_file_via_mac_address(
            mac_address: MacAddressStr = Path(
                ..., description="MAC address of the file to download"
            ),
        ) -> FileResponse:  # noqa: B008
            """
            **Download PNM Measurement File By Transaction ID**

            Retrieves the raw binary file generated during a telemetry capture session.
            Used for offline inspection, reprocessing, or historical archiving.

            Note:
            Depending on your browser and SwaggerUI behavior, the file may either download
            automatically or require clicking the returned link.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/file-manager/file-manager-api.md#3-download-files-by-mac-address-zip-archive)
            """
            return PnmFileService().get_file_by_mac_address(mac_address)

        @self.router.get(
            "/download/operationID/{operation_id}",
            response_class=FileResponse,
            summary="Download A PNM File By Operation ID",
            responses=FAST_API_RESPONSE,
        )
        def download_file_via_operationID(
            operation_id: OperationId = Path(
                ..., description="Operation ID of the file to download"
            ),
        ) -> FileResponse:  # noqa: B008
            """
            **Download PNM Measurement File By Operation ID**

            Retrieves the raw binary file generated during a telemetry capture session.
            Used for offline inspection, reprocessing, or historical archiving.

            Note:
            Depending on your browser and SwaggerUI behavior, the file may either download
            automatically or require clicking the returned link.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/file-manager/file-manager-api.md#4-download-files-by-operation-id-zip-archive)
            """
            return PnmFileService().get_file_by_operation_id(operation_id)

        @self.router.post(
            "/upload",
            response_model=UploadFileResponse,
            summary="Upload A PNM File",
            responses=FAST_API_RESPONSE,
        )
        async def upload_file(
            file: UploadFile = File(
                description="Raw PNM capture file (e.g., RxMER, constellation, histogram, spectrum)",
            ),
        ) -> JSONResponse:  # noqa: B008
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

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/file-manager/file-manager-api.md#5-upload-pnm-file)

            """
            content = await file.read()
            result = PnmFileService().upload_file(
                filename=cast(FileName, file.filename), data=content
            )
            return JSONResponse(content=result.model_dump())

        @self.router.post(
            "/getAnalysis",
            response_model=AnalysisJsonResponse,
            summary="Analyze a PNM File Via Transaction ID",
            responses=FAST_API_RESPONSE,
        )
        def get_analysis_via_transaction_id(
            request: FileAnalysisRequest,
        ) -> AnalysisJsonResponse | FileResponse | JSONResponse:
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

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/file-manager/file-manager-api.md#6-analyze-pnm-file-via-transaction-id)
            """
            PnmFileService().get_analysis(request)

            output_type = request.analysis.output.type

            if output_type == OutputType.JSON:
                analysis_result, file_type = PnmFileService().get_analysis(request)
                return AnalysisJsonResponse(
                    mac_address=analysis_result.mac_address,
                    pnm_file_type=file_type.name,
                    status="success",
                    analysis=analysis_result.model_dump(),
                )

            elif output_type == OutputType.ARCHIVE:
                return PnmFileService().get_archive(request)

            return JSONResponse(content="Not implemented yet")

        @self.router.get(
            "/getHexdump/transactionID/{transaction_id}",
            response_model=HexDumpResponse,
            summary="Hexdump Of A PNM File By Transaction ID",
            responses=FAST_API_RESPONSE,
        )
        def get_hexdump_via_transaction_id(
            transaction_id: TransactionId = Path(
                ..., description="Transaction ID of the PNM file to hexdump"
            ),  # noqa: B008
            bytes_per_line: int | None = Query(
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

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/file-manager/file-manager-api.md#7-hexdump-of-a-pnm-file-via-transaction-id)
            """
            hexdump_result = PnmFileService().get_hexdump_by_transaction_id(
                transaction_id=transaction_id,
                bytes_per_line=bytes_per_line if bytes_per_line is not None else 0,
            )
            return hexdump_result


# Required for auto-discovery via dynamic router loading
router = PnmFileManager().router
