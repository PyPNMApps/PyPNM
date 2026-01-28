## Agent Review Bundle Summary
- Goal: Add Multi US OFDMA Pre-Equalization multi-capture endpoint modeled after multi_ds_chan_est.
- Changes: Added route/service/schemas + docs; added channel-id resolver test; updated multi index.
- Files: docs/api/fast-api/multi/index.md; docs/api/fast-api/multi/multi-capture-us-ofdma-pre-eq.md; src/pypnm/api/routes/advance/multi_us_ofdma_pre_eq/router.py; src/pypnm/api/routes/advance/multi_us_ofdma_pre_eq/schemas.py; src/pypnm/api/routes/advance/multi_us_ofdma_pre_eq/service.py; tests/test_multi_us_ofdma_preeq_channel_ids.py.
- Tests: python3 -m compileall src; ruff check src; ruff format --check . (fails: repo drift); pytest -q (541 passed, 3 skipped).
- Notes: pytest skips due to PNM_CM_IT not set; ruff format check failed because of pre-existing formatting drift.

# FILE: docs/api/fast-api/multi/index.md
# Multi-capture API index

Use these guides when you need periodic or scheduled captures (for example, hourly RxMER snapshots) along with downstream analysis.

> **Background**
> Read the [capture operation guide](capture-operation.md) first. It explains how capture operations, transactions, and storage hang together.

## Workflow at a glance

1. **Plan** - Decide whether you need multi-RxMER or multi-channel-estimation captures and confirm storage availability.
2. **Start** - Call the workflow-specific endpoint (for example, [multi-RxMER capture](multi-capture-rxmer.md)) with schedule, modem list, and retention options.
3. **Monitor** - Poll operation status and review logs via the [PyPNM system endpoints](../pypnm/index.md).
4. **Download** - Use the workflow guide or [file manager](../file-manager/file-manager-api.md) to grab ZIP archives once captures complete.
5. **Analyze** - Feed the captures into one of the advanced analysis modules listed below.

## Multi-capture workflows

| Workflow | Purpose |
|----------|---------|
| [Multi-RxMER capture](multi-capture-rxmer.md) | Periodic downstream OFDM RxMER sampling across multiple carriers. |
| [Multi-DS channel estimation](multi-capture-chan-est.md) | Scheduled OFDM channel estimation captures and reporting. |

## Advanced analysis modules

| Module | Purpose |
|--------|---------|
| [Multi-RxMER min/avg/max](analysis/multi-rxmer-min-avg-max.md) | Roll up RxMER across captures. |
| [Multi-ChanEst min/avg/max](analysis/multi-chanest-min-avg-max.md) | Summaries for channel estimation data. |
| [Group delay calculator](analysis/group-delay-calculator.md) | Compute group delay variations. |
| [OFDM performance 1:1](analysis/multi-rxmer-ofdm-performance-part-1.md) | Compare per-subcarrier capacity vs profile. |
| [OFDM echo detection](analysis/ofdm-echo-detection.md) | Detect reflections and echo artifacts. |
| [Phase slope LTE detection](analysis/phase-slope-lte-detection.md) | Spot LTE-related interference patterns. |
| [Signal statistics](analysis/signal-statistics.md) | Extract RMS/min/max variance from captures. |
- [Multi-Capture US OFDMA Pre-Equalization](multi-capture-us-ofdma-pre-eq.md)

# FILE: docs/api/fast-api/multi/multi-capture-us-ofdma-pre-eq.md
# Multi-Capture US OFDMA Pre-Equalization

This API runs periodic upstream OFDMA pre-equalization captures and stores each capture as PNM files. After the
capture window completes, you can download a ZIP of the PNM files or run post-capture signal analysis.

## Endpoints

| # | Method | Path | Description |
| - | ------ | ---- | ----------- |
| 1 | POST | `/advance/multiUsOfdmaPreEqualization/start` | Begin a multi-sample US OFDMA pre-equalization capture |
| 2 | GET | `/advance/multiUsOfdmaPreEqualization/status/{operation_id}` | Poll capture progress |
| 3 | GET | `/advance/multiUsOfdmaPreEqualization/results/{operation_id}` | Download a ZIP of captured PNM files |
| 4 | DELETE | `/advance/multiUsOfdmaPreEqualization/stop/{operation_id}` | Stop the capture after the current iteration |
| 5 | POST | `/advance/multiUsOfdmaPreEqualization/analysis` | Run post-capture signal analysis |

## Start capture

**Request** `POST /advance/multiUsOfdmaPreEqualization/start`

```json
{
  "cable_modem": {
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "ip_address": "192.168.0.100"
  },
  "capture": {
    "parameters": {
      "measurement_duration": 60,
      "sample_interval": 5
    }
  },
  "measure": {
    "mode": 0
  }
}
```

**Response**

```json
{
  "status": 0,
  "message": "Multi capture started",
  "group_id": "group-1",
  "operation_id": "op-1"
}
```

## Status

**Request** `GET /advance/multiUsOfdmaPreEqualization/status/{operation_id}`

**Response**

```json
{
  "status": 0,
  "message": "OK",
  "operation": {
    "operation_id": "op-1",
    "state": "running",
    "collected": 3,
    "time_remaining": 45,
    "message": null
  }
}
```

## Results

**Request** `GET /advance/multiUsOfdmaPreEqualization/results/{operation_id}`

Returns a ZIP file containing the captured PNM files for each iteration.

- ZIP name: `multiUsOfdmaPreEqualization_<mac>_<operation_id>.zip`

## Stop

**Request** `DELETE /advance/multiUsOfdmaPreEqualization/stop/{operation_id}`

Stops the capture after the current iteration finishes. The `status` endpoint will reflect final state once complete.

## Analysis

**Request** `POST /advance/multiUsOfdmaPreEqualization/analysis`

```json
{
  "operation_id": "op-1",
  "analysis": {
    "type": "MIN_AVG_MAX",
    "output": {
      "type": "JSON"
    },
    "plot": {
      "enable": false
    }
  }
}
```

Supported analysis types:

- MIN_AVG_MAX
- GROUP_DELAY
- LTE_DETECTION_PHASE_SLOPE
- ECHO_DETECTION_PHASE_SLOPE
- ECHO_DETECTION_IFFT

**Response**

```json
{
  "status": 0,
  "message": "OK",
  "data": {
    "analysis_type": "MIN_AVG_MAX",
    "results": []
  }
}
```

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

from pypnm.api.routes.advance.analysis.signal_analysis.multi_chan_est_singnal_analysis import (
    MultiChanEstAnalysisType,
    MultiChanEstimationSignalAnalysis,
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
            - LTE_DETECTION_PHASE_SLOPE
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
                atype = MultiChanEstAnalysisType(request.analysis.type)

            except ValueError:
                msg = f"Invalid analysis type: {request.analysis.type}"
                self.logger.error(msg)
                return MultiUsOfdmaPreEqAnalysisResponse(
                    mac_address =   MacAddress.null(),
                    status      =   ServiceStatusCode.DS_OFDM_CHAN_EST_INVALID_ANALYSIS_TYPE,
                    message     =   msg,
                    data        =   AnalysisDataModel(analysis_type="UNKNOWN", results=[]))

            # Dispatch map for type → analysis engine
            analysis_map: dict[MultiChanEstAnalysisType, Callable[[CaptureDataAggregator], MultiChanEstimationSignalAnalysis]] = {
                MultiChanEstAnalysisType.MIN_AVG_MAX:                lambda agg: MultiChanEstimationSignalAnalysis(agg, MultiChanEstAnalysisType.MIN_AVG_MAX),
                MultiChanEstAnalysisType.GROUP_DELAY:                lambda agg: MultiChanEstimationSignalAnalysis(agg, MultiChanEstAnalysisType.GROUP_DELAY),
                MultiChanEstAnalysisType.LTE_DETECTION_PHASE_SLOPE:  lambda agg: MultiChanEstimationSignalAnalysis(agg, MultiChanEstAnalysisType.LTE_DETECTION_PHASE_SLOPE),
                MultiChanEstAnalysisType.ECHO_DETECTION_IFFT:        lambda agg: MultiChanEstimationSignalAnalysis(agg, MultiChanEstAnalysisType.ECHO_DETECTION_IFFT),
            }

            if atype not in analysis_map:
                msg = f"Unsupported analysis type: {atype}"
                self.logger.error(msg)
                return MultiUsOfdmaPreEqAnalysisResponse(
                    mac_address     =   MacAddress.null(),
                    status          =   ServiceStatusCode.DS_OFDM_CHAN_EST_INVALID_ANALYSIS_TYPE,
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

from pypnm.api.routes.advance.analysis.signal_analysis.multi_chan_est_singnal_analysis import (
    MultiChanEstAnalysisType,
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
    """Model for Multi-ChannelEstimation analysis types."""
    type: MultiChanEstAnalysisType      = Field(default=MultiChanEstAnalysisType.MIN_AVG_MAX, description="Analysis type to perform, implementation-specific integer value")
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

# FILE: src/pypnm/api/routes/advance/multi_us_ofdma_pre_eq/service.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
from __future__ import annotations

import logging

from pypnm.api.routes.advance.common.capture_service import AbstractCaptureService
from pypnm.api.routes.common.extended.common_measure_schema import (
    UpstreamOfdmaParameters,
)
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.us.ofdma.pre_equalization.service import (
    CmUsOfdmaPreEqService,
)
from pypnm.docsis.cable_modem import CableModem, PnmConfigManager
from pypnm.lib.inet import Inet


class MultiUsOfdmaPreEqService(AbstractCaptureService):
    """
    Service to trigger a Cable Modem's US OFDMA Pre-Equalization capture via SNMP/TFTP and
    collect corresponding file-transfer transactions as CaptureSample objects.

    Each invocation of _capture_sample will:
      1. Send SNMP command to start US OFDMA Pre-Equalization capture and TFTP transfer.
      2. Await MessageResponse payload containing transaction entries.
      3. For each payload entry of type PNM_FILE_TRANSACTION with SUCCESS status:
         - Lookup the transaction record for filename retrieval.
         - Yield a CaptureSample(timestamp, transaction_id, filename).
      4. On SNMP/TFTP error or no valid entries, return a single CaptureSample
         with the appropriate error message.

    Inherited:
      - duration: total measurement duration in seconds.
      - interval: interval between captures in seconds.
    """
    def __init__(self, cm: CableModem,
                tftp_servers: tuple[Inet, Inet] = PnmConfigManager.get_tftp_servers(),
                tftp_path: str = PnmConfigManager.get_tftp_path(),
                 duration: float = 1, interval: float = 1,
                 interface_parameters: UpstreamOfdmaParameters | None = None,) -> None:
        """
        Initialize the MultiUsOfdmaPreEqService.

        Args:
            cm: Configured CableModem instance for SNMP/TFTP operations.
            tftp_servers: Tuple of Inet objects representing TFTP servers.
            tftp_path: Path on the TFTP server for file storage.
            duration: Total duration (seconds) to run periodic captures.
            interval: Time (seconds) between successive captures.
        """
        super().__init__(duration, interval)
        self.cm = cm
        self.tftp_servers = tftp_servers
        self.tftp_path = tftp_path
        self.logger = logging.getLogger(__name__)
        self._interface_parameters = interface_parameters

    async def _capture_message_response(self) -> MessageResponse:
        """
        Perform one US OFDMA Pre-Equalization capture cycle.

        Returns:
            A list of CaptureSample objects. On success, one per file-transfer
            transaction; on error, a single Sample with error filled.

        Error handling:
            - Catches exceptions from SNMP/TFTP invocation.
            - Validates payload type and entry contents.
        """
        try:
            msg_rsp: MessageResponse = await CmUsOfdmaPreEqService(
                self.cm,
                self.tftp_servers,
                self.tftp_path,
            ).set_and_go(interface_parameters=self._interface_parameters)

        except Exception as exc:
            err_msg = f"Exception during US OFDMA Pre-Equalization SNMP/TFTP operation: {exc}"
            self.logger.error(err_msg, exc_info=True)
            return MessageResponse(ServiceStatusCode.DS_OFDM_CHAN_EST_NOT_AVAILABLE)

        if msg_rsp.status != ServiceStatusCode.SUCCESS:
            err_msg = f"SNMP/TFTP failure: status={msg_rsp.status}"
            self.logger.error(err_msg)
            return MessageResponse(ServiceStatusCode.DS_OFDM_CHAN_EST_NOT_AVAILABLE)

        return msg_rsp

# FILE: tests/test_multi_us_ofdma_preeq_channel_ids.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pypnm.api.routes.advance.multi_us_ofdma_pre_eq.router import MultiUsOfdmaPreEqRouter
from pypnm.api.routes.common.extended.common_measure_schema import UpstreamOfdmaParameters
from pypnm.lib.types import ChannelId


def test_multi_us_ofdma_preeq_router_resolves_channel_ids() -> None:
    router = MultiUsOfdmaPreEqRouter()
    assert router._resolve_interface_parameters(None) is None
    assert router._resolve_interface_parameters([]) is None

    params = router._resolve_interface_parameters([ChannelId(4)])
    assert isinstance(params, UpstreamOfdmaParameters)
    assert params.channel_id == [ChannelId(4)]

