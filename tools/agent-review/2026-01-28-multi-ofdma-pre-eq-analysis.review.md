## Agent Review Bundle Summary
- Goal: Split OFDMA analysis types from channel-estimation types and wire the new OFDMA enum into the endpoint.
- Changes: Added MultiOfdmaPreEqAnalysisType; updated OFDMA analysis parsing to be per-file resilient; switched endpoint and schema to OFDMA enum; updated agent testing rules.
- Files: src/pypnm/api/routes/advance/analysis/signal_analysis/multi_ofdma_pre_eq_signal_analysis.py; src/pypnm/api/routes/advance/multi_us_ofdma_pre_eq/router.py; src/pypnm/api/routes/advance/multi_us_ofdma_pre_eq/schemas.py; src/pypnm/api/routes/advance/analysis/signal_analysis/multi_chan_est_singnal_analysis.py; tests/test_multi_ofdma_pre_eq_analysis_data.py; AGENTS.md; CODING_AGENTS.md.
- Tests: python3 -m compileall src; ruff check src; ruff check src --fix; pytest -q; mkdocs build -s (docs-only change).
- Notes: pytest skips due to PNM_CM_IT not set; ruff format check still fails due to repo drift.

# FILE: src/pypnm/api/routes/advance/analysis/signal_analysis/multi_ofdma_pre_eq_signal_analysis.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pypnm.api.routes.advance.analysis.signal_analysis.multi_ofdm_chan_signal_analysis import (
    ChannelComplexMap,
    ChannelFrequencyMap,
    ChannelOccupiedBwMap,
    MultiOfdmChanSignalAnalysis,
)
from pypnm.api.routes.advance.common.transactionsCollection import (
    TransactionCollectionModel,
)
from pypnm.api.routes.common.classes.analysis.analysis import Analysis
from pypnm.api.routes.common.classes.analysis.model.schema import (
    UsOfdmaUsPreEqAnalysisModel,
)
from pypnm.lib.types import (
    ChannelId,
    ComplexArray,
    FrequencyHz,
    FrequencySeriesHz,
    StringEnum,
)
from pypnm.pnm.parser.CmUsOfdmaPreEq import CmUsOfdmaPreEq


class MultiOfdmaPreEqAnalysisType(StringEnum):
    """Enumeration Of Supported Multi-OFDMA-Pre-EQ Analysis Types."""
    MIN_AVG_MAX         = "min-avg-max"
    GROUP_DELAY         = "group-delay"
    ECHO_DETECTION_IFFT = "echo-detection-ifft"


class MultiOfdmaPreEqSignalAnalysis(MultiOfdmChanSignalAnalysis):
    """Performs signal-quality analyses on grouped OFDMA Pre-EQ captures."""

    def _parse_capture(self, tcm: TransactionCollectionModel) -> tuple[ChannelId, ComplexArray, FrequencySeriesHz, FrequencyHz] | None:
        try:
            model = CmUsOfdmaPreEq(tcm.data).to_model()
            result: UsOfdmaUsPreEqAnalysisModel = Analysis.basic_analysis_us_ofdma_pre_equalization_from_model(model)

        except Exception as e:
            self.logger.error(f"OFDMA pre-eq analysis parse failed: {e}")
            return None

        return (
            ChannelId(result.channel_id),
            result.carrier_values.complex,
            result.carrier_values.frequency,
            result.carrier_values.occupied_channel_bandwidth,
        )

    def _extract_channel_data(self) -> tuple[ChannelComplexMap, ChannelFrequencyMap, ChannelOccupiedBwMap]:
        """Collect OFDMA Pre-EQ capture data into analysis-ready maps."""
        channel_data: ChannelComplexMap = {}
        freqs: ChannelFrequencyMap = {}
        obw: ChannelOccupiedBwMap = {}

        for tcm in self._trans_collect.getTransactionCollectionModel():
            parsed = self._parse_capture(tcm)
            if parsed is None:
                continue

            ch, complex_values, frequency, bandwidth = parsed
            if complex_values:
                channel_data.setdefault(ch, []).append(complex_values)
            freqs[ch] = frequency
            obw[ch] = bandwidth

        return channel_data, freqs, obw

# FILE: src/pypnm/api/routes/advance/multi_us_ofdma_pre_eq/router.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import io
import logging
import os
import zipfile
from collections.abc import Callable
from typing import cast

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, StreamingResponse

from pypnm.api.routes.advance.analysis.signal_analysis.multi_ofdma_pre_eq_signal_analysis import (
    MultiOfdmaPreEqAnalysisType,
    MultiOfdmaPreEqSignalAnalysis,
)
from pypnm.api.routes.advance.common.abstract.service import AbstractService
from pypnm.api.routes.advance.common.capture_data_aggregator import (
    CaptureDataAggregator,
)
from pypnm.api.routes.advance.common.operation_manager import OperationManager
from pypnm.api.routes.advance.common.operation_state import OperationState
from pypnm.api.routes.advance.multi_us_ofdma_pre_eq.schemas import (
    AnalysisDataModel,
    MultiUsOfdmaPreEqAnalysisRequest,
    MultiUsOfdmaPreEqAnalysisResponse,
    MultiUsOfdmaPreEqRequest,
    MultiUsOfdmaPreEqResponseStatus,
    MultiUsOfdmaPreEqStartResponse,
    MultiUsOfdmaPreEqStatusResponse,
)
from pypnm.api.routes.advance.multi_us_ofdma_pre_eq.service import (
    MultiUsOfdmaPreEqService,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.common.enum import (
    OutputType,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.request_defaults import (
    RequestDefaultsResolver,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.snmp.schemas import (
    SnmpResponse,
)
from pypnm.api.routes.common.classes.file_capture.file_type import FileType
from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.extended.common_measure_schema import (
    UpstreamOfdmaParameters,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.files.service import PnmFileService
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cable_modem import CableModem
from pypnm.lib.inet import Inet, InetAddressStr
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import ChannelId, GroupId, MacAddressStr, OperationId


class MultiUsOfdmaPreEqRouter(AbstractService):
    """Router for handling Multi-US-OFDMA-Pre-Equalization operations."""

    def __init__(self) -> None:
        super().__init__()
        self.router = APIRouter(prefix="/advance/multiUsOfdmaPreEqualization",
                                tags=["PNM Operations - Multi-US-OFDMA-Pre-Equalization"])
        self.logger = logging.getLogger(self.__class__.__name__)
        self._add_routes()

    # ──────────────────────────────────────────────────────────
    # Routes
    # ──────────────────────────────────────────────────────────
    def _add_routes(self) -> None:

        @self.router.post("/start",
            response_model=MultiUsOfdmaPreEqStartResponse | SnmpResponse,
            summary="Start a multi-sample US OFDMA Pre-Equalization capture")
        async def start_multi_chan_estimation(request: MultiUsOfdmaPreEqRequest) -> MultiUsOfdmaPreEqStartResponse | SnmpResponse:

            duration, interval = request.capture.parameters.measurement_duration, request.capture.parameters.sample_interval
            mac_address: MacAddressStr = request.cable_modem.mac_address
            ip_address: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(request.cable_modem.snmp)
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(request.cable_modem.pnm_parameters.tftp)
            channel_ids = request.cable_modem.pnm_parameters.capture.channel_ids
            interface_parameters = self._resolve_interface_parameters(channel_ids)


            self.logger.info(f"[start] Multi-US OFDMA Pre-Equalization for MAC={mac_address}, duration={duration}s interval={interval}s")

            cm = CableModem(mac_address=MacAddress(mac_address), inet=Inet(ip_address), write_community=community)

             # Pre-checks
            status, msg = await CableModemServicePreCheck(cable_modem=cm, validate_ofdma_exist=True).run_precheck()
            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(f"[start] Precheck failed for MAC={mac_address}: {msg}")
                return SnmpResponse(mac_address=mac_address, status=status, message=msg)

            group_id, operation_id = await self.loadService(MultiUsOfdmaPreEqService,
                                                            cm,
                                                            tftp_servers,
                                                            duration=duration,
                                                            interval=interval,
                                                            interface_parameters=interface_parameters,)
            return MultiUsOfdmaPreEqStartResponse(mac_address     =   mac_address,
                                                    status          =   OperationState.RUNNING,
                                                    message         =   None,
                                                    group_id        =   group_id,
                                                    operation_id    =   operation_id)


        @self.router.get("/status/{operation_id}",
            response_model=MultiUsOfdmaPreEqStatusResponse,
            summary="Get status of a multi-sample US OFDMA Pre-Equalization capture")
        def get_status(operation_id: OperationId) -> MultiUsOfdmaPreEqStatusResponse:
            try:
                service: MultiUsOfdmaPreEqService = cast(MultiUsOfdmaPreEqService, self.getService(operation_id))

            except KeyError as err:
                raise HTTPException(status_code=404, detail="Operation not found") from err

            status = service.status(operation_id)
            return MultiUsOfdmaPreEqStatusResponse(
                mac_address     =   service.cm.get_mac_address.mac_address,
                status          =   "success",
                message         =   None,
                operation       =   MultiUsOfdmaPreEqResponseStatus(
                    operation_id    =   operation_id,
                    state           =   status["state"],
                    collected       =   status["collected"],
                    time_remaining  =   status["time_remaining"],
                    message         =   None))

        @self.router.get("/results/{operation_id}",
            summary="Download a ZIP archive of all UsOfdmaPreEqualization capture files",
            responses={200: {"content": {"application/zip": {}},
                             "description": "ZIP archive of capture files"}})
        def download_results_zip(operation_id: OperationId) -> StreamingResponse:

            svc: MultiUsOfdmaPreEqService = cast(MultiUsOfdmaPreEqService, self.getService(operation_id))
            samples = svc.results(operation_id)
            pnm_dir, mac = str(SystemConfigSettings.pnm_dir()), svc.cm.get_mac_address.mac_address
            buf = io.BytesIO()

            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                for s in samples:
                    path = os.path.join(pnm_dir, s.filename)

                    try:
                        zf.write(path, arcname=os.path.basename(s.filename))

                    except FileNotFoundError:
                        self.logger.warning(f"[zip] Missing: {path}")

                    except Exception as e:
                        self.logger.warning(f"[zip] Skip {path}: {e}")

            buf.seek(0)
            headers = {"Content-Disposition": f"attachment; filename=multiUsOfdmaPreEqualization_{mac}_{operation_id}.zip"}
            return StreamingResponse(buf, media_type="application/zip", headers=headers)


        @self.router.delete("/stop/{operation_id}",
            response_model=MultiUsOfdmaPreEqStatusResponse,
            summary="Stop a running multi-sample US OFDMA Pre-Equalization capture early")
        def stop_capture(operation_id: OperationId) -> MultiUsOfdmaPreEqStatusResponse:
            """


            """
            try:
                service: MultiUsOfdmaPreEqService = cast(MultiUsOfdmaPreEqService, self.getService(operation_id))

            except KeyError as err:
                raise HTTPException(status_code=404, detail="Operation not found") from err

            service.stop(operation_id)
            status = service.status(operation_id)
            return MultiUsOfdmaPreEqStatusResponse(
                mac_address =   service.cm.get_mac_address.mac_address,
                status      =   OperationState.STOPPED,
                message     =   None,
                operation   =   MultiUsOfdmaPreEqResponseStatus(
                    operation_id    =   operation_id,
                    state           =   status["state"],
                    collected       =   status["collected"],
                    time_remaining  =   status["time_remaining"],
                    message         =   None)
            )


        @self.router.post("/analysis",
            response_model=MultiUsOfdmaPreEqAnalysisResponse,
            summary="Perform signal analysis on a previously executed Multi-US OFDMA Pre-Equalization")
        def analysis(request: MultiUsOfdmaPreEqAnalysisRequest) -> MultiUsOfdmaPreEqAnalysisResponse | FileResponse:
            """
            Perform post-capture analysis on Multi-US OFDMA Pre-Equalization measurement data.

            Supports:
            - MIN_AVG_MAX
            - GROUP_DELAY
            - ECHO_DETECTION_PHASE_SLOPE
            - ECHO_DETECTION_IFFT
            """
            try:
                capture_group_id: GroupId = OperationManager.get_capture_group(request.operation_id)
                self.logger.info(f"[analysis] operation_id={request.operation_id} capture_group={capture_group_id}")
            except KeyError:
                msg = f"No capture group found for operation {request.operation_id}"
                self.logger.error(msg)
                return MultiUsOfdmaPreEqAnalysisResponse(
                    mac_address     =   MacAddress.null(),
                    status          =   ServiceStatusCode.CAPTURE_GROUP_NOT_FOUND,
                    message         =   msg,
                    data            =   AnalysisDataModel(analysis_type="UNKNOWN", results=[]))

            # Prepare data aggregator
            cda = CaptureDataAggregator(capture_group_id)

            # Parse analysis type
            try:
                atype = MultiOfdmaPreEqAnalysisType(request.analysis.type)

            except ValueError:
                msg = f"Invalid analysis type: {request.analysis.type}"
                self.logger.error(msg)
                return MultiUsOfdmaPreEqAnalysisResponse(
                    mac_address =   MacAddress.null(),
                    status      =   ServiceStatusCode.US_OFDMA_PRE_EQ_INVALID_ANALYSIS_TYPE,
                    message     =   msg,
                    data        =   AnalysisDataModel(analysis_type="UNKNOWN", results=[]))

            # Dispatch map for type → analysis engine
            analysis_map: dict[MultiOfdmaPreEqAnalysisType, Callable[[CaptureDataAggregator], MultiOfdmaPreEqSignalAnalysis]] = {
                MultiOfdmaPreEqAnalysisType.MIN_AVG_MAX:         lambda agg: MultiOfdmaPreEqSignalAnalysis(agg, MultiOfdmaPreEqAnalysisType.MIN_AVG_MAX),
                MultiOfdmaPreEqAnalysisType.GROUP_DELAY:         lambda agg: MultiOfdmaPreEqSignalAnalysis(agg, MultiOfdmaPreEqAnalysisType.GROUP_DELAY),
                MultiOfdmaPreEqAnalysisType.ECHO_DETECTION_IFFT: lambda agg: MultiOfdmaPreEqSignalAnalysis(agg, MultiOfdmaPreEqAnalysisType.ECHO_DETECTION_IFFT),
            }

            if atype not in analysis_map:
                msg = f"Unsupported analysis type: {atype}"
                self.logger.error(msg)
                return MultiUsOfdmaPreEqAnalysisResponse(
                    mac_address     =   MacAddress.null(),
                    status          =   ServiceStatusCode.US_OFDMA_PRE_EQ_INVALID_ANALYSIS_TYPE,
                    message         =   msg,
                    data            =   AnalysisDataModel(analysis_type="UNKNOWN", results=[]))

            # Determine output type
            output_type:OutputType = request.analysis.output.type
            engine = analysis_map[atype](cda)
            analysis_result = engine.to_model()

            # Handle output formats
            if output_type == OutputType.JSON:
                err = analysis_result.error
                status = ServiceStatusCode.SUCCESS if not err else ServiceStatusCode.FAILURE
                message = err or f"Analysis {analysis_result.analysis_type} completed for group {capture_group_id}"

                data_model = AnalysisDataModel(
                    analysis_type   =   analysis_result.analysis_type,
                    results         =   [r.model_dump() for r in analysis_result.results])

                mac = engine.getMacAddresses()[0].mac_address
                self.logger.info(f"[analysis] type={atype.name} mac={mac} status={status.name} group={capture_group_id}")

                return MultiUsOfdmaPreEqAnalysisResponse(
                    mac_address =   mac,
                    status      =   status,
                    message     =   message,
                    data        =   data_model)

            elif output_type == OutputType.ARCHIVE:
                try:
                    rpt = engine.build_report()
                    self.logger.info(f"[analysis] Built archive report for group {capture_group_id}")
                    return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

                except Exception as e:
                    msg = f"Archive build failed: {e}"
                    self.logger.error(msg)
                    return MultiUsOfdmaPreEqAnalysisResponse(
                        mac_address     =   MacAddress.null(),
                        status          =   ServiceStatusCode.FAILURE,
                        message         =   msg,
                        data            =   AnalysisDataModel(analysis_type=atype.name, results=[]))

            # Unsupported output type
            msg = f"Unsupported output type: {output_type}"
            self.logger.error(msg)
            return MultiUsOfdmaPreEqAnalysisResponse(
                mac_address     =   MacAddress.null(),
                status          =   ServiceStatusCode.INVALID_OUTPUT_TYPE,
                message         =   msg,
                data            =   AnalysisDataModel(analysis_type=atype.name, results=[]))

    def _resolve_interface_parameters(self, channel_ids: list[ChannelId] | None) -> UpstreamOfdmaParameters | None:
        if channel_ids is None:
            return None
        if len(channel_ids) == 0:
            return None
        return UpstreamOfdmaParameters(channel_id=channel_ids)

# Auto-register
router = MultiUsOfdmaPreEqRouter().router

# FILE: src/pypnm/api/routes/advance/multi_us_ofdma_pre_eq/schemas.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from enum import IntEnum
from typing import Any

from pydantic import BaseModel, Field

from pypnm.api.routes.advance.analysis.signal_analysis.multi_ofdma_pre_eq_signal_analysis import (
    MultiOfdmaPreEqAnalysisType,
)
from pypnm.api.routes.advance.common.schema.common_capture_schema import (
    MultiCaptureParametersResponse,
    MultiCaptureRequest,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.common_req_resp import (
    CommonAnalysisResponse,
    CommonMatPlotConfigRequest,
    CommonOutput,
    CommonResponse,
)
from pypnm.lib.types import GroupId, OperationId


class MultiUsOfdmaPreEqMeasureModes(IntEnum):
    STANDARD = 0


class UsOfdmaPreEqMeasureParameters(BaseModel):
    mode: MultiUsOfdmaPreEqMeasureModes = Field(default=MultiUsOfdmaPreEqMeasureModes.STANDARD, description="Measurement mode: 0 for standard US OFDMA pre-equalization capture")
class AnalysisDataModel(BaseModel):
    """Typed container for analysis output."""
    analysis_type: str              = Field(..., description="Executed analysis type name.")
    results: list[dict[str, Any]]   = Field(..., description="List of per-channel analysis results (min/avg/max, group delay, anomalies, etc.).")

class MultiUsOfdmaPreEqAnalysisContainerModel(BaseModel):
    """Model for Multi-US-OFDMA Pre-Equalization analysis types."""
    type: MultiOfdmaPreEqAnalysisType   = Field(default=MultiOfdmaPreEqAnalysisType.MIN_AVG_MAX, description="Analysis type to perform, implementation-specific integer value")
    output: CommonOutput                = Field(default=CommonOutput(), description="Output type control: json or archive")
    plot: CommonMatPlotConfigRequest    = Field(default=CommonMatPlotConfigRequest(), description="Plot configuration for multi-ChannelEstimation analysis")

class MultiUsOfdmaPreEqAnalysisModel(BaseModel):
    """Request schema for performing signal analysis on a completed Multi-ChannelEstimation capture."""
    analysis: MultiUsOfdmaPreEqAnalysisContainerModel = Field(default=MultiUsOfdmaPreEqAnalysisContainerModel(), description="Analysis type to perform, implementation-specific integer value")

################################# REQUEST #################################

class MultiUsOfdmaPreEqAnalysisRequest(BaseModel):
    """Request schema for performing signal analysis on a completed Multi-ChannelEstimation capture."""
    analysis: MultiUsOfdmaPreEqAnalysisContainerModel = Field(default=MultiUsOfdmaPreEqAnalysisContainerModel(), description="Analysis type to perform, implementation-specific integer value")
    operation_id: OperationId               = Field(..., description="Operation ID to query status/results.")

################################# RESPONSE #################################

class MultiUsOfdmaPreEqRequest(MultiCaptureRequest):
    """Request schema for initiating a Multi-ChannelEstimation operation."""
    measure:UsOfdmaPreEqMeasureParameters = Field(..., description="Measurement parameters for the Multi-ChannelEstimation operation.")

class MultiUsOfdmaPreEqResponseStatus(MultiCaptureParametersResponse):
    """Status details about a Multi-ChannelEstimation capture operation."""
    pass

class MultiUsOfdmaPreEqStartResponse(CommonResponse):
    """Response returned when a multi-ChannelEstimation capture is kicked off."""
    group_id: GroupId           = Field(..., description="Capture group ID for this session")
    operation_id: OperationId   = Field(..., description="Operation ID to query status/results")

class MultiUsOfdmaPreEqStatusResponse(CommonResponse):
    """Response schema for checking the status of a Multi-ChannelEstimation capture operation."""
    operation: MultiUsOfdmaPreEqResponseStatus = Field(..., description="Detailed operation-level state and sample count (operation_id, state, collected, time_remaining, message).")

class MultiUsOfdmaPreEqAnalysisResponse(CommonAnalysisResponse):
    """Response schema for Multi-ChannelEstimation signal analysis."""
    data: AnalysisDataModel = Field(..., description="Structured analysis result container including the analysis_type and its corresponding per-channel results.")

# FILE: src/pypnm/api/routes/advance/analysis/signal_analysis/multi_chan_est_singnal_analysis.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pypnm.api.routes.advance.analysis.signal_analysis.multi_ofdm_chan_signal_analysis import (
    ChannelComplexMap,
    ChannelFrequencyMap,
    ChannelOccupiedBwMap,
    MultiOfdmChanSignalAnalysis,
)
from pypnm.api.routes.common.classes.analysis.analysis import Analysis
from pypnm.api.routes.common.classes.analysis.model.schema import (
    DsChannelEstAnalysisModel,
)
from pypnm.lib.types import ChannelId, StringEnum
from pypnm.pnm.parser.CmDsOfdmChanEstimateCoef import CmDsOfdmChanEstimateCoef


# ──────────────────────────────────────────────────────────────
# Enum
# ──────────────────────────────────────────────────────────────
class MultiChanEstAnalysisType(StringEnum):
    """Enumeration Of Supported Multi-ChannelEstimation Analysis Types."""
    MIN_AVG_MAX                 = "min-avg-max"
    GROUP_DELAY                 = "group-delay"
    ECHO_DETECTION_IFFT         = "echo-detection-ifft"
    LTE_DETECTION_PHASE_SLOPE   = "lte-detection-phase-slope"


# ──────────────────────────────────────────────────────────────
# Main Class
# ──────────────────────────────────────────────────────────────
class MultiChanEstimationSignalAnalysis(MultiOfdmChanSignalAnalysis):
    """Performs signal-quality analyses on grouped Multi-ChannelEstimation captures."""

    def _extract_channel_data(self) -> tuple[ChannelComplexMap, ChannelFrequencyMap, ChannelOccupiedBwMap]:
        """Collect Channel Estimation capture data into analysis-ready maps."""
        channel_data: ChannelComplexMap = {}
        freqs: ChannelFrequencyMap = {}
        obw: ChannelOccupiedBwMap = {}

        try:
            for tcm in self._trans_collect.getTransactionCollectionModel():
                model = CmDsOfdmChanEstimateCoef(tcm.data).to_model()
                result: DsChannelEstAnalysisModel = Analysis.basic_analysis_ds_chan_est_from_model(model)

                ch = ChannelId(result.channel_id)
                channel_data.setdefault(ch, []).append(result.carrier_values.complex)
                freqs[ch] = result.carrier_values.frequency
                obw[ch] = result.carrier_values.occupied_channel_bandwidth

        except Exception as e:
            self.logger.error(f"OFDM channel analysis parse failed: {e}")

        return channel_data, freqs, obw

# FILE: tests/test_multi_ofdma_pre_eq_analysis_data.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

from pypnm.api.routes.advance.analysis.signal_analysis.multi_chan_est_singnal_analysis import (
    MultiChanEstAnalysisType,
)
from pypnm.api.routes.advance.analysis.signal_analysis.multi_ofdma_pre_eq_signal_analysis import (
    MultiOfdmaPreEqSignalAnalysis,
)
from pypnm.api.routes.advance.common.capture_data_aggregator import (
    CaptureDataAggregator,
)
from pypnm.api.routes.advance.common.transactionsCollection import (
    TransactionCollection,
)
from pypnm.api.routes.common.classes.file_capture.types import (
    DeviceDetailsModel,
    TransactionRecordModel,
)
from pypnm.docsis.cm_snmp_operation import SystemDescriptor
from pypnm.lib.types import FileName, MacAddressStr, TimestampSec, TransactionId

DATA_DIR: Path = Path(__file__).parent / "files"
US_PREEQ_PATH: Path = DATA_DIR / "us_pre_equalizer_coef.bin"


class FakeCaptureDataAggregator(CaptureDataAggregator):
    def __init__(self, collection: TransactionCollection) -> None:
        self._collection = collection

    def collect(self) -> TransactionCollection:
        return self._collection


def _build_collection() -> TransactionCollection:
    collection = TransactionCollection()
    record = TransactionRecordModel(
        transaction_id  =   TransactionId("txn-1"),
        timestamp       =   TimestampSec(0),
        mac_address     =   MacAddressStr("aa:bb:cc:dd:ee:ff"),
        pnm_test_type   =   "us_pre_eq",
        filename        =   FileName("us_pre_equalizer_coef.bin"),
        device_details  =   DeviceDetailsModel(system_description=SystemDescriptor.empty().to_model()),
    )
    collection.add(record, US_PREEQ_PATH.read_bytes())
    return collection


def test_multi_ofdma_pre_eq_extract_channel_data() -> None:
    collection = _build_collection()
    analyzer = MultiOfdmaPreEqSignalAnalysis(
        FakeCaptureDataAggregator(collection),
        MultiChanEstAnalysisType.MIN_AVG_MAX,
    )

    channel_data, freqs, obw = analyzer._extract_channel_data()

    assert channel_data

    channel_id = next(iter(channel_data.keys()))
    assert channel_id in freqs
    assert channel_id in obw
    assert len(channel_data[channel_id]) >= 1
    assert freqs[channel_id]
    assert obw[channel_id] > 0

# FILE: AGENTS.md
# AGENTS.md

This file provides guidance for coding agents working in this repository.
Keep it short, accurate, and updated when workflows change.

## Agent Permissions

<environment_context>
    <sandbox_mode>danger-full-access</sandbox_mode>
    <network_access>enabled</network_access>
    <!-- Access is governed by this file and explicit user approval -->
</environment_context>

## Project Basics

- Language: Python (3.10+)
- This repo is NOT greenfield; extend existing code and patterns.
- Build/test entry points are defined in `pyproject.toml`, `Makefile`, or `scripts/`.
- Read `README.md` first for setup and usage.
- Type checking is strict; avoid `Any` and generic container types.
- Ruff compliance is required (do not auto-format unless explicitly requested).

## Agent Constraints

- General workflow:
  - Make minimal diffs; avoid formatting churn.
  - Preserve whitespace/alignment in existing files (no auto-reflow).
  - Do not add broad refactors unless explicitly requested.
  - Provide an end-of-run Agent Review Bundle summary: goal, changes, files, tests, notes.
- Typing and API style:
  - Strict typing everywhere; avoid `Dict`/`List`/`Tuple`/`Union` and avoid `Any`.
  - Prefer built-in generics (`dict[str, int]`, `list[str]`) and `A | B` rather than `Union`.
  - Prefer Pydantic `BaseModel` over dict returns for public interfaces.
  - `BaseModel` fields must be one-line `Field(...)` declarations with descriptions.
  - Prefer `match/case` over long if/else chains.
  - No one-line if statements (E701 compliance).
  - Avoid 3+ nested loops; 2 nested loops discouraged unless necessary.
- Code structure and documentation:
  - Prefer classes/static methods; minimize standalone global functions.
  - Public methods must have detailed docstrings; private methods minimal.
  - Keep code self-documented; avoid method-level debug logging.
  - Logger pattern in classes: `self.logger = logging.getLogger(f"{self.__class__.__name__}")`.
- Release hygiene / headers:
  - Any touched code files must have SPDX copyright year updated per Repo Hygiene rules (single year or range).
  - Do not add SPDX headers to Markdown files.
  - Remove SPDX lines embedded inside Markdown code blocks if encountered (especially SQL appendices).
- Docs / Markdown rules (MkDocs + GitHub compatible):
  - No emojis in docs.
  - No horizontal rules (`---`) in Markdown.
  - Keep tables ~132 characters wide when possible.
  - Use placeholders consistently in examples:
    - MAC: `aa:bb:cc:dd:ee:ff`
    - IP: `192.168.0.100`
    - system_description JSON: `{"HW_REV":"1.0","VENDOR":"LANCity","BOOTR":"NONE","SW_REV":"1.0.0","MODEL":"LCPET-3"}`
  - For code file links in docs: use HTTP GitHub links; relative links only for other Markdown files.
  - Always include a downloadable link at the end of any Markdown you generate (when generating Markdown as an artifact in chat; for repo docs, follow repo conventions).
- Shell scripts:
  - Proper indentation.
  - Emojis allowed only in `install.sh` and `pypnm-cmts` CLI output; do not use emojis elsewhere.
- Testing expectations:
  - Run at least: `python3 -m compileall src`, `ruff check src`, `ruff format --check .`, `pytest -q`.
  - After any code change, run `ruff check src` and `pytest -q`. If only Markdown changes are made, run `mkdocs build -s` instead.
  - If an integration test is optional/gated (for example Postgres DSN), note skips explicitly in the summary.

## External Consumers (Compatibility Contract)

- PyPNM is the authoritative engine and is consumed by downstream repos (example: PyPNM-CMTS).
- Preserve public API stability unless the user explicitly approves breaking changes.
- Do not embed downstream app concerns into PyPNM (keep PyPNM reusable and transport-agnostic).
- If a change affects downstream repos, call it out explicitly before making it.

## Repo Conventions (PyPNM)

- Persistence is filesystem-based artifacts plus metadata persistence per the DB backend design:
  - Binaries and derived artifacts remain on disk under `.data/` roots.
  - Transaction/group/operation metadata is DB-backed (SQLite or Postgres) per `docs/design/db/`.
- DB backend selection is owned by PyPNM at install time (no runtime “auto switching”).
- SQLite is intended for single-writer deployments (standalone/lab/demo).
- Postgres is recommended for multi-worker / multi-process deployments.

## Documentation

- Docs must follow the existing repo docs layout and conventions.
- Update docs alongside code changes (choose the correct location by inspecting the existing docs tree; do not invent parallel structures).
- Do not modify `mkdocs.yml` or navigation unless explicitly required by the task.
- Markdown must render correctly in both MkDocs and GitHub.
- No emojis in documentation.
- Use generic placeholders:
  - MAC: `aa:bb:cc:dd:ee:ff`
  - IP: `192.168.0.100`
- Emojis are allowed only in `install.sh`; they are prohibited everywhere else.
- When adding new terms or acronyms, update `docs/definition/index.md` and keep entries in alphabetical order.
- After completing a task, create a single “agent review” file that concatenates the full contents of all files changed in that task (path and naming should follow existing repo practice).
- Always regenerate the agent review bundle after any subsequent edits so it reflects every changed file.
- When an error is fixed, add or update a FAQ entry with the error and resolution, and add a TODO entry noting the FAQ update requirement.

### Reuse Index

- Agents MUST consult the existing reuse / symbol index under `tools/agent-review/` (if present) before introducing new:
  - types, validators, ID formats, storage conventions, persistence adapters, or config namespaces
- Any deviation requires an explicit gap justification and user approval.

## DB Backend Migration (Locked Decisions)

Agents working on the DB backend refactor MUST follow the locked decisions recorded in the design docs (see `docs/design/db/`):

- PyPNM owns persistence, schema initialization, and DB APIs.
- Install-time backend selection via `install.sh` flags + interactive default to SQLite.
- Postgres secrets via env var overrides (no plaintext requirement in tracked JSON).
- Idempotent schema apply using shipped DDL assets + seeding `UNKNOWN` sysDescr + default artifact store(s).
- SQLite for single-writer; Postgres recommended for multi-worker / multi-process (especially downstream orchestration use).
- Paths stored in DB are portable (app-root relative), resolved at runtime.
- CI validates SQLite (required) and Postgres (service container, recommended as required).
- JSON ledger persistence is deprecated and removed from runtime paths (optional offline migrator only).

## Configuration

- `system.json` is the single source of truth.
- New configuration namespaces must be implemented as Pydantic BaseModels.
- BaseModels must use one-line `Field(..., description="...")`.
- Avoid generic `str` for semantic identifiers or paths in public models and APIs; use an existing semantic type or add a new alias in `src/pypnm/lib/types.py`.
- When working with MAC or inet strings, validate using `MacAddress()` or `Inet()` instead of assuming `str(...)` formatting is valid.
- Request override defaults: missing or null means use `system.json` defaults; blank strings are invalid.

## Timestamp Conventions

- All stored timestamps are epoch seconds.
- Convert to ISO-8601 only at display or external response boundaries.

## Coding Guidelines (Strict)

- No generic container imports (`Dict`, `List`, `Tuple`, `Union`).
  Use built-in types and `|`.
- Avoid `Any` unless unavoidable; isolate and justify its usage.
- Every function argument must be annotated.
- Avoid `None` returns; prefer empty values unless `None` is semantically required.
- Avoid magic numbers; use named constants.
- Prefer `BaseModel` over raw dicts for public/stateful structures (state, configuration, persistence records).
- dicts are allowed only for short-lived internal glue logic.
- Prefer classes with static methods over standalone functions.
- Public methods MUST have detailed docstrings.
- Private methods may have minimal docstrings.
- Avoid method-level debug logs.
- Do not add Ruff ignores (`# noqa`, `# ruff: noqa`). If an ignore is needed, ask for permission first.
- Logging pattern in classes:

  ```python
  self.logger = logging.getLogger(f"{self.__class__.__name__}")
  ```

- Prefer `match/case` over long if/else chains.
- No code should contain 3+ nested loops. 2 nested loops are discouraged unless necessary.
- No one-line if statements (E701).
- If `STATUS` is used as a return type, return `STATUS_OK` or `STATUS_NOK` for readability.
- Preserve all existing whitespace and alignment.
- Never auto-format or re-align code.
- Do not enforce snake_case; keep existing naming conventions as-is.

## FastAPI Guidelines (PyPNM)

- Router files must be lean:
  - `router.py` contains routing glue only (APIRouter configuration, endpoint registration, HTTP status translation).
  - No business logic in `router.py`. Business logic must live in `service.py` for that route group (same folder) or a shared service module if reused.
- All request/response bodies must be Pydantic BaseModels.
- Prefer POST for payload submission and endpoint contracts (PyPNM default).
  - Allow GET only where already present or clearly appropriate (health, readiness, version, status).
- Reuse shared models under the existing `src/pypnm/api/common/` structure (inspect current tree before adding anything new).
- Do not block request paths with `time.sleep()`.

## Tests (Mandatory)

- Every phase deliverable MUST include pytest coverage for new or changed behavior.
- Do not claim a phase item is complete unless pytest has been added and executed (or a concrete blocker is documented).
- Tests must remain hermetic: no live CMTS/cable modem dependencies.

## Burndown Governance

- Agents MUST consult the current burndown and DB design docs before implementing work.
- Agents MUST NOT update burndown checkmarks unless explicitly instructed by the user.
- Code written does not imply progress accepted.

## Workflow Rules

- When the user says “train”, read code silently until told otherwise.
- Do not assume missing context; ask.
- Keep changes minimal and scoped.
- Do not refactor unrelated code.
- Avoid destructive commands unless explicitly requested.
- Do not print file contents into chat unless the user explicitly requests it.
- Keep a brief summary of user prompts after any request for a commit message and track changes since the most recent commit message request.
- When asked for a commit message, respond with the specified format, keep it succinct, and include all changes since the last commit message request.
- Default response content should be a summary, changed file list, commands run, and the review bundle path.
- Always end tasks with an agent review bundle containing the full contents of all files touched in the task.
- Agent review bundles must start with the standard summary template block below (before any `# FILE:` sections).
- If a review bundle exceeds 3000 lines, split it into multiple bundles without splitting files. Use a part naming convention like `name.part-1.review.md`, `name.part-2.review.md`, and repeat the summary block at the top of each part.
- When the user says `CAT_FILES`, create a single bundle file containing the full contents of every file touched in the task, each preceded by `# FILE: <path>`, and provide the `cat` command for the bundle.

### Commit Message Format

- One line summary (max 50 characters)
- Detailed description lines (max 72 characters per line); every line after the first must start with `-`

### Agent Review Bundle Summary Template (Standard)

Use this block at the very top of every `*.review.md` bundle (before any `# FILE:` sections).

## Agent Review Bundle Summary
- Goal:
- Changes:
- Files:
- Tests:
- Notes:

## Repo Hygiene

- License is Apache-2.0; keep SPDX headers and `NOTICE`.
- For any modified or newly created file, update the SPDX header year to 2026.
- If a file already has a SPDX year and the year has changed, update it as a range (example: 2025 -> 2025-2026).
- Keep `tools/` organized by category.
- Do not add files directly under `tools/` root.

## Agent Self-Checks

Before responding:

- Re-read this file and `README.md`.
- Confirm pytest coverage exists or is explicitly blocked.
- Confirm pytest and ruff output have no deprecation warnings (treat as failures).
- Confirm changes align to the current phase and do not leak scope.
- Confirm formatting and alignment are preserved.

## Training

When the user requests "train", read the following sources:

- `AGENTS.md`
- `docs/design/db/` (all files)
- `src/pypnm/lib/` (DB/persistence + config helpers)
- `src/pypnm/api/` (routing/service patterns, where applicable)
- `tools/agent-review/` (all files, if present)

# FILE: CODING_AGENTS.md
# General-Purpose AI Coding Guide

This document provides a generic coding guide for AI contributors. It focuses on code style,
reuse, and maintainability.

## Core Principles

- Reuse before adding: prefer existing types, helpers, models, and utilities.
- Keep diffs minimal and focused; avoid formatting churn.
- Preserve existing naming, alignment, and whitespace patterns.
- Favor clarity and explicit typing over clever shortcuts.
- Review this document before making any changes.
  This is a generic guide and does not replace `AGENTS.md`.

## Reuse-First Checklist

Before introducing new types, validators, formats, or storage conventions:

- Search for similar helpers in `src/pypnm/lib/` and `src/pypnm/api/`.
- Check `tools/agent-review/` for any reuse or symbol index guidance.
- Prefer existing semantic aliases over raw `str` identifiers.
- Prefer existing constants over inline values.
- Prefer existing Pydantic models for public data structures.
- Refer to shared utilities and helpers before creating new classes.

## Common Locations To Consult

- Types and semantic aliases: `src/pypnm/lib/types.py`
- Constants: `src/pypnm/lib/constants.py`
- Validators and parsing helpers: `src/pypnm/lib/`
- Config models and defaults: `src/pypnm/config/`
- Shared API models and schemas: `src/pypnm/api/` (including `src/pypnm/api/common/`)

## Coding Style (General)

- Use built-in generics (`list[str]`, `dict[str, int]`) and `A | B` unions.
- Avoid `Any` unless unavoidable; isolate and justify its usage.
- Annotate all function arguments and return types.
- Prefer classes or static methods over standalone functions.
- Use Pydantic `BaseModel` for public interfaces instead of raw dicts.
- Keep public method docstrings detailed; private method docstrings minimal.

## Workflow Guidance

- Validate changes with repository test entry points.
- When adding new behavior, include tests covering the change.
- New classes must have pytest coverage at a minimum for IPC and system calls.
- Avoid broad refactors unless explicitly requested.
- Keep a brief summary of user prompts after any request for a commit message and track changes since the most recent commit message request.
- When asked for a commit message, respond with the specified format, keep it succinct, and include all changes since the last commit message request.

### Commit Message Format

- One line summary (max 50 characters)
- Detailed description lines (max 72 characters per line); every line after the first must start with `-`

## Agent Constraints

- General workflow:
  - Make minimal diffs; avoid formatting churn.
  - Preserve whitespace/alignment in existing files (no auto-reflow).
  - Do not add broad refactors unless explicitly requested.
  - Provide an end-of-run Agent Review Bundle summary: goal, changes, files, tests, notes.
- Typing and API style:
  - Strict typing everywhere; avoid `Dict`/`List`/`Tuple`/`Union` and avoid `Any`.
  - Prefer built-in generics (`dict[str, int]`, `list[str]`) and `A | B` rather than `Union`.
  - Prefer Pydantic `BaseModel` over dict returns for public interfaces.
  - `BaseModel` fields must be one-line `Field(...)` declarations with descriptions.
  - Avoid generic returns; every method must have an explicit return type annotation.
  - Every method argument must have an explicit type annotation.
  - Public/shared method types must be defined in `src/pypnm/lib/types.py`.
  - Only define local types in a module when the type is strictly private and not reused.
  - Common folder methods must use types defined in `src/pypnm/lib/types.py`.
- Prefer `match/case` over long if/else chains.
- No one-line if statements (E701 compliance).
- Avoid 3+ nested loops; 2 nested loops discouraged unless necessary.
- If `STATUS` is used as a return type, return `STATUS_OK` or `STATUS_NOK` for readability.
- Code structure and documentation:
  - Prefer classes/static methods; minimize standalone global functions.
  - Public methods must have detailed docstrings; private methods minimal.
  - Keep code self-documented; avoid method-level debug logging.
  - Logger pattern in classes: `self.logger = logging.getLogger(f"{self.__class__.__name__}")`.
- Release hygiene / headers:
  - Code files must include `SPDX-License-Identifier: Apache-2.0`.
  - Copyright lines must include only the year or year range (no author names).
  - Any touched code files must have SPDX copyright year updated per Repo Hygiene rules (single year or range).
  - Do not add SPDX headers to Markdown files.
  - Remove SPDX lines embedded inside Markdown code blocks if encountered (especially SQL appendices).
- Docs / Markdown rules (MkDocs + GitHub compatible):
  - No emojis in docs.
  - No horizontal rules (`---`) in Markdown.
  - Keep tables ~132 characters wide when possible.
  - Use placeholders consistently in examples:
    - MAC: `aa:bb:cc:dd:ee:ff`
    - IP: `192.168.0.100`
    - system_description JSON: `{"HW_REV":"1.0","VENDOR":"LANCity","BOOTR":"NONE","SW_REV":"1.0.0","MODEL":"LCPET-3"}`
  - For code file links in docs: use HTTP GitHub links; relative links only for other Markdown files.
  - Always include a downloadable link at the end of any Markdown you generate (when generating Markdown as an artifact in chat; for repo docs, follow repo conventions).
- Shell scripts:
  - Proper indentation.
  - Emojis allowed only in `install.sh` and `pypnm-cmts` CLI output; do not use emojis elsewhere.
- Testing expectations:
  - Run at least: `python3 -m compileall src`, `ruff check src`, `ruff format --check .`, `pytest -q`.
  - After any code change, run `ruff check src` and `pytest -q`. If only Markdown changes are made, run `mkdocs build -s` instead.
  - If an integration test is optional/gated (for example Postgres DSN), note skips explicitly in the summary.

## Pytest Guidance (PyPNM Pattern)

- Place new tests under `tests/` with `test_*.py` naming.
- Prefer small, focused unit tests that mirror the existing test style.
- Use fixtures for shared data (see current `tests/` patterns).
- Prefer module-level test functions over new class wrappers unless an existing test uses classes.
- Reuse `tests/files/` for binary fixtures and sample data.
- Favor hermetic tests: no live devices, no external services.
- When testing IPC or system calls, isolate behavior with fakes/mocks and assert edge cases.
- Keep tests aligned with existing patterns in similar modules before introducing new structures.
  Start by locating a similar test file and mirror its structure.

## Notes

- This document is intentionally generic. Use `AGENTS.md` for this repository’s
  authoritative rules and workflow constraints.

