## Agent Review Bundle Summary
- Goal: Add measurement_stats into per-channel spectrum analyzer analysis JSON artifacts for OFDM/SC-QAM runs.
- Changes: Passed per-channel measurement stats into OFDM/SC-QAM report builders and injected them into per-channel JSON artifacts; added unit test to assert measurement_stats inclusion.
- Files: src/pypnm/api/routes/docs/pnm/spectrumAnalyzer/router.py; src/pypnm/api/routes/basic/ofdm_spec_analyzer_rpt.py; src/pypnm/api/routes/basic/scqam_spec_analyzer_rpt.py; tests/test_spectrum_analyzer_report_measurement_stats_json.py
- Tests: python3 -m compileall src (pass); ruff check src (pass); ruff format --check . (fails: would reformat existing files); pytest -q (pass, 3 skipped).
- Notes: Ruff format check fails due to pre-existing formatting drift across repo.

# FILE: src/pypnm/api/routes/docs/pnm/spectrumAnalyzer/router.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from typing import Any, cast

from fastapi import APIRouter
from starlette.responses import FileResponse

from pypnm.api.routes.basic.abstract.analysis_report import AnalysisRptMatplotConfig
from pypnm.api.routes.basic.ofdm_spec_analyzer_rpt import OfdmSpecAnalyzerAnalysisReport
from pypnm.api.routes.basic.scqam_spec_analyzer_rpt import (
    ScQamSpecAnalyzerAnalysisReport,
)
from pypnm.api.routes.basic.spec_analyzer_analysis_rpt import SpectrumAnalyzerReport
from pypnm.api.routes.common.classes.analysis.analysis import Analysis, AnalysisType
from pypnm.api.routes.common.classes.analysis.model.process import (
    AnalysisProcessParameters,
)
from pypnm.api.routes.common.classes.analysis.multi_analysis import MultiAnalysis
from pypnm.api.routes.common.classes.common_endpoint_classes.common.enum import (
    OutputType,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.request_defaults import (
    RequestDefaultsResolver,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schemas import (
    PnmAnalysisResponse,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.snmp.schemas import (
    SnmpResponse,
)
from pypnm.api.routes.common.classes.file_capture.file_type import FileType
from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.extended.common_process_service import CommonProcessService
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.files.service import PnmFileService
from pypnm.api.routes.docs.pnm.spectrumAnalyzer.schemas import (
    OfdmSpecAnaAnalysisRequest,
    OfdmSpecAnaAnalysisResponse,
    ScQamSpecAnaAnalysisRequest,
    ScQamSpecAnaAnalysisResponse,
    SingleCaptureSpectrumAnalyzerFriendlyRequest,
    SingleCaptureSpectrumAnalyzerRequest,
)
from pypnm.api.routes.docs.pnm.spectrumAnalyzer.service import (
    CmSpectrumAnalysisService,
    DsOfdmChannelSpectrumAnalyzer,
    DsScQamChannelSpectrumAnalyzer,
    SpectrumAnalyzerFriendlyCaptureBuilder,
)
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.DocsIf31CmDsOfdmChanEntry import (
    DocsIf31CmDsOfdmChanChannelEntry,
)
from pypnm.docsis.data_type.DocsIfDownstreamChannel import DocsIfDownstreamChannelEntry
from pypnm.docsis.data_type.pnm.DocsIf3CmSpectrumAnalysisEntry import (
    DocsIf3CmSpectrumAnalysisEntry,
)
from pypnm.lib.dict_utils import DictGenerate
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import ChannelId, FrequencyHz, InetAddressStr, MacAddressStr, Path


class SpectrumAnalyzerRouter:
    def __init__(self) -> None:
        prefix = "/docs/pnm/ds"
        self.base_endpoint = "/spectrumAnalyzer"
        self.router = APIRouter(prefix=prefix, tags=["PNM Operations - Spectrum Analyzer"])
        self.logger = logging.getLogger(f"{self.__class__.__name__}")
        self.__routes()

    @staticmethod
    def _build_channel_entry_lookup(
        entries: list[DocsIf31CmDsOfdmChanChannelEntry | DocsIfDownstreamChannelEntry],
    ) -> dict[ChannelId, DocsIf31CmDsOfdmChanChannelEntry | DocsIfDownstreamChannelEntry]:
        lookup: dict[ChannelId, DocsIf31CmDsOfdmChanChannelEntry | DocsIfDownstreamChannelEntry] = {}
        for entry in entries:
            if entry.channel_id <= 0:
                continue
            lookup[ChannelId(entry.channel_id)] = entry
        return lookup

    @classmethod
    def _build_measurement_stats_with_channel_stats(
        cls,
        measurement_stats: dict[ChannelId, list[DocsIf3CmSpectrumAnalysisEntry]],
        channel_entries: list[DocsIf31CmDsOfdmChanChannelEntry | DocsIfDownstreamChannelEntry],
    ) -> list[dict[str, Any]]:
        channel_lookup = cls._build_channel_entry_lookup(channel_entries)
        out: list[dict[str, Any]] = []

        for channel_id, entries in measurement_stats.items():
            channel_entry = channel_lookup.get(channel_id)
            channel_stats = channel_entry.model_dump() if channel_entry is not None else None

            for entry in entries:
                payload = entry.model_dump()
                payload["channel_id"] = channel_id
                if channel_stats is not None:
                    payload["channel_stats"] = channel_stats
                out.append(payload)

        return out

    def __routes(self) -> None:
        @self.router.post(
            f"{self.base_endpoint}/getCapture",
            summary="Get Spectrum Analyzer Capture",
            response_model=None,
            responses=FAST_API_RESPONSE,
        )
        async def get_capture(request: SingleCaptureSpectrumAnalyzerRequest) -> SnmpResponse | PnmAnalysisResponse | FileResponse:
            """
            Perform Spectrum Analyzer Capture And Return Analysis Results.

            This endpoint triggers a spectrum capture on the requested cable modem using the
            provided capture parameters. The measurement response is then processed through
            the common analysis pipeline and returned as either:

            - A JSON analysis payload containing decoded amplitude data and summary metrics.
            - An archive file containing plots and related report artifacts (ZIP).

            The cable modem must be PNM-ready and the capture parameters must respect the
            diplexer configuration and platform constraints (DOCSIS 3.x and DOCSIS 4.0 FDD).

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/spectrum-analyzer.md)

            """
            mac: MacAddressStr = request.cable_modem.mac_address
            ip: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(request.cable_modem.snmp)
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(request.cable_modem.pnm_parameters.tftp)

            self.logger.info("Starting Spectrum Analyzer capture for MAC: %s, IP: %s, Output Type: %s",
                mac, ip, request.analysis.output.type,)

            cm = CableModem(mac_address=MacAddress(mac),
                            inet=Inet(ip),
                            write_community=community,)

            status, msg = await CableModemServicePreCheck(
                cable_modem=cm,
                tftp_config=request.cable_modem.pnm_parameters.tftp,
                validate_pnm_ready_status=True,
            ).run_precheck()

            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse(mac_address=mac, status=status, message=msg)

            service = CmSpectrumAnalysisService(
                cable_modem=cm,
                tftp_servers=tftp_servers,
                capture_parameters=request.capture_parameters,)

            msg_rsp: MessageResponse = await service.set_and_go()

            if msg_rsp.status != ServiceStatusCode.SUCCESS:
                err = "Unable to complete Spectrum Analyzer capture."
                self.logger.error("%s Status: %s", err, msg_rsp.status.name)
                return SnmpResponse(mac_address=mac, status=msg_rsp.status, message=err)

            channel_ids = None
            measurement_stats: list[DocsIf3CmSpectrumAnalysisEntry] = cast(
                list[DocsIf3CmSpectrumAnalysisEntry],
                await service.getPnmMeasurementStatistics(channel_ids=channel_ids),)

            cps = CommonProcessService(msg_rsp)
            msg_rsp = cps.process()

            analysis = Analysis(AnalysisType.BASIC, msg_rsp, skip_automatic_process=True)
            analysis.process(cast(AnalysisProcessParameters, request.analysis.spectrum_analysis))

            if request.analysis.output.type == OutputType.JSON:
                payload: dict[str, Any] = cast(dict[str, Any], analysis.get_results())
                DictGenerate.pop_keys_recursive(payload, ["pnm_header", "mac_address", "channel_id"])

                primative = msg_rsp.payload_to_dict("primative")
                DictGenerate.pop_keys_recursive(
                    primative,
                    ["device_details", "channel_id", "amplitude_bin_segments_float"],
                )
                payload.update(cast(dict[str, Any], primative))
                payload.update(
                    DictGenerate.models_to_nested_dict(
                        measurement_stats,
                        "measurement_stats",
                    )
                )

                return PnmAnalysisResponse(
                    mac_address=mac,
                    status=ServiceStatusCode.SUCCESS,
                    data=payload,
                )

            if request.analysis.output.type == OutputType.ARCHIVE:
                theme = request.analysis.plot.ui.theme
                plot_config = AnalysisRptMatplotConfig(theme=theme)
                analysis_rpt = SpectrumAnalyzerReport(analysis, plot_config)
                rpt: Path = cast(Path, analysis_rpt.build_report())
                return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

            return PnmAnalysisResponse(
                mac_address=mac,
                status=ServiceStatusCode.INVALID_OUTPUT_TYPE,
                data={},
            )

        @self.router.post(
            f"{self.base_endpoint}/getCapture/friendly",
            summary="Get Spectrum Analyzer Capture (Friendly)",
            response_model=None,
            responses=FAST_API_RESPONSE,
        )
        async def get_capture_friendly(
            request: SingleCaptureSpectrumAnalyzerFriendlyRequest,
        ) -> SnmpResponse | PnmAnalysisResponse | FileResponse:
            """
            Perform Spectrum Analyzer Capture Using Friendly RBW Inputs.

            This endpoint accepts a resolution bandwidth (RBW) and a requested window,
            then derives a segment span and bin count using the spectrum-analysis-capture-set
            rules. The segment center frequencies are adjusted inward by half a segment
            span on each edge to satisfy the analyzer's scaled window constraints.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/spectrum-analyzer/spectrum-analyzer.md)
            """
            mac: MacAddressStr = request.cable_modem.mac_address
            ip: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(request.cable_modem.snmp)
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(request.cable_modem.pnm_parameters.tftp)

            self.logger.info("Starting Spectrum Analyzer friendly capture for MAC: %s, IP: %s, Output Type: %s",
                mac, ip, request.analysis.output.type,)

            cm = CableModem(mac_address=MacAddress(mac),
                            inet=Inet(ip),
                            write_community=community,)

            status, msg = await CableModemServicePreCheck(
                cable_modem=cm,
                tftp_config=request.cable_modem.pnm_parameters.tftp,
                validate_pnm_ready_status=True,
            ).run_precheck()

            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse(mac_address=mac, status=status, message=msg)

            try:
                capture_parameters = SpectrumAnalyzerFriendlyCaptureBuilder.build(
                    request.capture_parameters,
                )
            except ValueError as e:
                err = f"Invalid capture parameters: {e}"
                self.logger.error(err)
                return SnmpResponse(mac_address=mac, status=ServiceStatusCode.INVALID_CAPTURE_PARAMETERS, message=err)

            service = CmSpectrumAnalysisService(
                cable_modem=cm,
                tftp_servers=tftp_servers,
                capture_parameters=capture_parameters,)

            msg_rsp: MessageResponse = await service.set_and_go()

            if msg_rsp.status != ServiceStatusCode.SUCCESS:
                err = "Unable to complete Spectrum Analyzer capture."
                self.logger.error("%s Status: %s", err, msg_rsp.status.name)
                return SnmpResponse(mac_address=mac, status=msg_rsp.status, message=err)

            channel_ids = None
            measurement_stats: list[DocsIf3CmSpectrumAnalysisEntry] = cast(
                list[DocsIf3CmSpectrumAnalysisEntry],
                await service.getPnmMeasurementStatistics(channel_ids=channel_ids),)

            cps = CommonProcessService(msg_rsp)
            msg_rsp = cps.process()

            analysis = Analysis(AnalysisType.BASIC, msg_rsp, skip_automatic_process=True)
            analysis.process(cast(AnalysisProcessParameters, request.analysis.spectrum_analysis))

            if request.analysis.output.type == OutputType.JSON:
                payload: dict[str, Any] = cast(dict[str, Any], analysis.get_results())
                DictGenerate.pop_keys_recursive(payload, ["pnm_header", "mac_address", "channel_id"])

                primative = msg_rsp.payload_to_dict("primative")
                DictGenerate.pop_keys_recursive(
                    primative,
                    ["device_details", "channel_id", "amplitude_bin_segments_float"],
                )
                payload.update(cast(dict[str, Any], primative))
                payload.update(
                    DictGenerate.models_to_nested_dict(
                        measurement_stats,
                        "measurement_stats",
                    )
                )

                return PnmAnalysisResponse(
                    mac_address=mac,
                    status=ServiceStatusCode.SUCCESS,
                    data=payload,
                )

            if request.analysis.output.type == OutputType.ARCHIVE:
                theme = request.analysis.plot.ui.theme
                plot_config = AnalysisRptMatplotConfig(theme=theme)
                analysis_rpt = SpectrumAnalyzerReport(analysis, plot_config)
                rpt: Path = cast(Path, analysis_rpt.build_report())
                return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

            return PnmAnalysisResponse(
                mac_address=mac,
                status=ServiceStatusCode.INVALID_OUTPUT_TYPE,
                data={},
            )

        @self.router.post(
            f"{self.base_endpoint}/getCapture/ofdm",
            summary="Get OFDM Channels Spectrum Analyzer Capture",
            response_model=None,
            responses=FAST_API_RESPONSE,
        )
        async def get_ofdm_ds_channels_analysis(request: OfdmSpecAnaAnalysisRequest) -> OfdmSpecAnaAnalysisResponse | FileResponse:
            """
            Perform OFDM Downstream Spectrum Capture Across All DS OFDM Channels.

            This endpoint triggers spectrum capture operations on each DOCSIS 3.1 OFDM
            downstream channel of the requested cable modem. Each per-channel response is
            processed through the common analysis pipeline, aggregated into a multi-analysis
            structure, and then returned as either JSON or an archive.

            The cable modem must support OFDM downstream channels and be PNM-ready, and
            the spectrum capture parameters must be valid for the underlying platform and
            diplexer configuration.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/spectrum-analyzer.md)

            """
            mac: MacAddressStr = request.cable_modem.mac_address
            ip: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(request.cable_modem.snmp)
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(request.cable_modem.pnm_parameters.tftp)

            cm = CableModem(mac_address=MacAddress(mac),
                            inet=Inet(ip),
                            write_community=community)
            multi_analysis = MultiAnalysis()

            self.logger.info("DOCSIS 3.1 OFDM Downstream Spectrum Capture for MAC %s, IP %s", mac, ip,)

            status, msg = await CableModemServicePreCheck(
                cable_modem=cm,
                tftp_config=request.cable_modem.pnm_parameters.tftp,
                validate_ofdm_exist=True,
                validate_pnm_ready_status=True,
            ).run_precheck()

            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return OfdmSpecAnaAnalysisResponse(
                    mac_address=mac, status=status, message=msg, data={},)

            channel_ids = request.cable_modem.pnm_parameters.capture.channel_ids

            service = DsOfdmChannelSpectrumAnalyzer(
                cable_modem             =   cm,
                tftp_servers            =   tftp_servers,
                number_of_averages      =   request.capture_parameters.number_of_averages,
                resolution_bandwidth_hz =   request.capture_parameters.resolution_bandwidth_hz,
                channel_ids             =   channel_ids if channel_ids else None,
                spectrum_retrieval_type =   request.capture_parameters.spectrum_retrieval_type)

            msg_responses: list[tuple[ChannelId, MessageResponse]] = await service.start()

            measurement_stats = await service.getPnmMeasurementStatistics()
            channel_entries = await service.getChannelEntry()
            measurement_stats_with_channels = self._build_measurement_stats_with_channel_stats(
                measurement_stats,
                channel_entries,
            )
            measurement_stats_by_channel: dict[ChannelId, list[dict[str, Any]]] = {}
            for entry in measurement_stats_with_channels:
                channel_id = cast(ChannelId, entry["channel_id"])
                measurement_stats_by_channel.setdefault(channel_id, []).append(entry)

            primative: dict[str, dict[Any, Any]] = {"primative": {}}

            for idx, (chan_id, msg_rsp) in enumerate(msg_responses):
                cps_msg_rsp = CommonProcessService(msg_rsp).process()

                analysis = Analysis(AnalysisType.BASIC, cps_msg_rsp, skip_automatic_process=True,)
                analysis.process(cast(AnalysisProcessParameters, request.analysis.spectrum_analysis))
                multi_analysis.add(chan_id, analysis)

                primative_entry = cps_msg_rsp.payload_to_dict(idx)
                primative["primative"].update(primative_entry)

            analyzer_rpt = OfdmSpecAnalyzerAnalysisReport(
                multi_analysis,
                measurement_stats_by_channel=measurement_stats_by_channel,
            )
            analyzer_rpt.build_report()

            if request.analysis.output.type == OutputType.JSON:
                analyzer_rpt_dict = analyzer_rpt.to_dict()
                analyzer_rpt_dict.update(primative)
                analyzer_rpt_dict.update({"measurement_stats": measurement_stats_with_channels})

                return OfdmSpecAnaAnalysisResponse(
                    mac_address =   mac,
                    status      =   ServiceStatusCode.SUCCESS,
                    data        =   analyzer_rpt_dict,
                )

            if request.analysis.output.type == OutputType.ARCHIVE:
                return PnmFileService().get_file(
                    FileType.ARCHIVE, analyzer_rpt.get_archive(),
                )

            return OfdmSpecAnaAnalysisResponse(
                mac_address =   mac,
                status      =   ServiceStatusCode.INVALID_OUTPUT_TYPE,
                message     =   f"Unsupported output type: {request.analysis.output.type}",
                data={},
            )

        @self.router.post(
            f"{self.base_endpoint}/getCapture/scqam",
            summary="Get SC-QAM Downstream Channels Spectrum Analysis",
            response_model=None,
            responses=FAST_API_RESPONSE,
        )
        async def get_scqam_ds_channels_analysis(request: ScQamSpecAnaAnalysisRequest) -> ScQamSpecAnaAnalysisResponse | FileResponse:
            """
            Perform SC-QAM Downstream Spectrum Capture Across All DS SC-QAM Channels.

            This endpoint triggers spectrum capture operations on each DOCSIS 3.0 SC-QAM
            downstream channel of the requested cable modem. Each per-channel response is
            processed through the common analysis pipeline, aggregated into a multi-analysis
            structure, and then returned as either JSON or an archive.

            The cable modem must support SC-QAM downstream channels and be PNM-ready, and
            the spectrum capture parameters must be valid for the underlying platform and
            diplexer configuration.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/spectrum-analyzer.md)

            """
            mac: MacAddressStr = request.cable_modem.mac_address
            ip: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(request.cable_modem.snmp)
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(request.cable_modem.pnm_parameters.tftp)

            cm = CableModem(mac_address=MacAddress(mac), inet=Inet(ip), write_community=community)
            multi_analysis = MultiAnalysis()

            self.logger.info("DOCSIS 3.0 SC-QAM downstream spectrum capture for MAC %s, IP %s", mac, ip)

            status, msg = await CableModemServicePreCheck(
                cable_modem=cm,
                tftp_config=request.cable_modem.pnm_parameters.tftp,
                validate_scqam_exist=True,
                validate_pnm_ready_status=True,
            ).run_precheck()

            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return ScQamSpecAnaAnalysisResponse(
                    mac_address=mac,
                    status=status, message=msg, data={}, )

            number_of_averages: int = request.capture_parameters.number_of_averages
            spectrum_retrieval_type = request.capture_parameters.spectrum_retrieval_type
            resolution_bandwidth: FrequencyHz = request.capture_parameters.resolution_bandwidth_hz
            channel_ids = request.cable_modem.pnm_parameters.capture.channel_ids

            service = DsScQamChannelSpectrumAnalyzer(
                cable_modem             =   cm,
                tftp_servers            =   tftp_servers,
                number_of_averages      =   number_of_averages,
                resolution_bandwidth_hz =   resolution_bandwidth,
                channel_ids              =   channel_ids if channel_ids else None,
                spectrum_retrieval_type =   spectrum_retrieval_type,
            )

            msg_responses: list[tuple[ChannelId, MessageResponse]] = await service.start()

            measurement_stats = await service.getPnmMeasurementStatistics()
            channel_entries = await service.getChannelEntry()
            measurement_stats_with_channels = self._build_measurement_stats_with_channel_stats(
                measurement_stats,
                channel_entries,
            )
            measurement_stats_by_channel: dict[ChannelId, list[dict[str, Any]]] = {}
            for entry in measurement_stats_with_channels:
                channel_id = cast(ChannelId, entry["channel_id"])
                measurement_stats_by_channel.setdefault(channel_id, []).append(entry)

            primative: dict[str, dict[Any, Any]] = {"primative": {}}

            for idx, (chan_id, msg_rsp) in enumerate(msg_responses):
                cps_msg_rsp = CommonProcessService(msg_rsp).process()

                analysis = Analysis(AnalysisType.BASIC, cps_msg_rsp, skip_automatic_process=True,)
                analysis.process(cast(AnalysisProcessParameters, request.analysis.spectrum_analysis))
                multi_analysis.add(chan_id, analysis)

                primative_entry = cps_msg_rsp.payload_to_dict(idx)
                primative["primative"].update(primative_entry)

            analyzer_rpt = ScQamSpecAnalyzerAnalysisReport(
                multi_analysis,
                measurement_stats_by_channel=measurement_stats_by_channel,
            )
            analyzer_rpt.build_report()

            if request.analysis.output.type == OutputType.JSON:
                analyzer_rpt_dict = analyzer_rpt.to_dict()
                analyzer_rpt_dict.update(primative)
                analyzer_rpt_dict.update({"measurement_stats": measurement_stats_with_channels})

                return ScQamSpecAnaAnalysisResponse(
                    mac_address =   mac,
                    status      =   ServiceStatusCode.SUCCESS,
                    data        =   analyzer_rpt_dict,
                )

            if request.analysis.output.type == OutputType.ARCHIVE:
                return PnmFileService().get_file(FileType.ARCHIVE, analyzer_rpt.get_archive(),)

            return ScQamSpecAnaAnalysisResponse(
                mac_address=mac,
                status=ServiceStatusCode.INVALID_OUTPUT_TYPE,
                message=f"Unsupported output type: {request.analysis.output.type}",
                data={},
            )


# Required for dynamic auto-registration
router = SpectrumAnalyzerRouter().router

# FILE: src/pypnm/api/routes/basic/ofdm_spec_analyzer_rpt.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from typing import Any, cast

from pydantic import BaseModel

from pypnm.api.routes.basic.abstract.analysis_report import AnalysisReport
from pypnm.api.routes.basic.abstract.base_models.common_analysis import CommonAnalysis
from pypnm.api.routes.basic.spec_analyzer_analysis_rpt import (
    SpecAnaWindowAvgRptModel,
    SpectrumAnalyzerAnalysisRptModel,
    SpectrumAnalyzerSignalProcessRptModel,
)
from pypnm.api.routes.common.classes.analysis.analysis import Analysis
from pypnm.api.routes.common.classes.analysis.model.spectrum_analyzer_schema import (
    BaseAnalysisModel,
    SpectrumAnalyzerAnalysisModel,
)
from pypnm.api.routes.common.classes.analysis.multi_analysis import MultiAnalysis
from pypnm.config.pnm_config_manager import SystemConfigSettings
from pypnm.docsis.cable_modem import MacAddress
from pypnm.lib.archive.manager import ArchiveManager
from pypnm.lib.csv.manager import CSVManager
from pypnm.lib.db.json_transaction import JsonTransactionDb
from pypnm.lib.matplot.manager import MatplotManager, PlotConfig
from pypnm.lib.types import ArrayLike, ChannelId, FloatSeries, FrequencySeriesHz, Path, PathLike
from pypnm.lib.utils import Generate


class OfdmSpecAnalysisRptModel(BaseModel):
    """Pydantic model for a compiled OFDM Spectrum Analyzer report.
    """
    models:list[BaseAnalysisModel]


class OfdmSpecAnalyzerAnalysisReport:
    """Coordinator that compiles per-channel Spectrum Analyzer artifacts into a single deliverable.

    The class iterates over a :class:`MultiAnalysis` container, invokes
    :class:`SingleOfdmSpecAnalyzerReport` for each constituent
    :class:`Analysis`, collects all generated files (CSV/plots), and can bundle
    them into a zip archive.

    Parameters
    ----------
    multi_analysis : MultiAnalysis
        A container of individual Spectrum Analyzer analyses to be reported.

    Examples
    --------
    >>> rpt = OfdmSpecAnalyzerReport(multi_analysis)
    >>> rpt.build_report()
    >>> archive_path = rpt._build_archive()
    >>> rpt_dict = rpt.to_dict()
    """

    def __init__(
        self,
        multi_analysis: MultiAnalysis,
        measurement_stats_by_channel: dict[ChannelId, list[dict[str, Any]]] | None = None,
    ) -> None:
        """Initialize the report coordinator.

        Parameters
        ----------
        multi_analysis : MultiAnalysis
            Source of per-channel :class:`Analysis` objects to process.
        """
        self._multi_analysis = multi_analysis
        self._archive_path:PathLike = SystemConfigSettings.archive_dir()
        self._analysis_files:list[PathLike] = []
        self._archive_file:PathLike
        self._measurement_stats_by_channel = measurement_stats_by_channel

    def build_report(self) -> PathLike:
        """
        Generate and collect all per-channel analysis artifacts into a final archive.

        This method iterates over each :class:`Analysis` object within a
        :class:`MultiAnalysis` instance, generating CSVs and plots using
        :class:`SingleOfdmSpecAnalyzerReport`. It then aggregates all
        generated files and produces a single ZIP archive.

        Returns:
            PathLike: The path to the created archive file.

        Workflow:
            1. For each `Analysis`, create and execute a
            `SingleOfdmSpecAnalyzerReport`.
            2. Collect all generated files using
            :meth:`SingleOfdmSpecAnalyzerReport.get_all_generated_files`.
            3. Combine them into a single archive using :meth:`_build_archive`.

        Notes:
            - The internal list of report files is updated via `_analysis_files`.
            - Only the archive file path is returned; individual CSVs and plots
            remain accessible through their respective report instances.
        """
        for _ in self._get_analyses():
            rpt = SingleOfdmSpecAnalyzerReport(_, measurement_stats_by_channel=self._measurement_stats_by_channel)
            rpt.build_report()
            rpt.get_all_generated_files()
            self._analysis_files.extend(rpt.get_all_generated_files())

        return self._build_archive()

    def _get_models(self) -> list[BaseAnalysisModel]:
        """Return the list of models sourced from the bound :class:`MultiAnalysis`."""
        return self._multi_analysis.to_model()

    def _get_analyses(self) -> list[Analysis]:
        """Return the list of analyses sourced from the bound :class:`MultiAnalysis`."""
        return self._multi_analysis.get_analyses()

    def _report_files(self) -> list[PathLike]:
        """Return the list of file paths collected during :meth:`build_report`."""
        return self._analysis_files

    def _build_archive(self) -> PathLike:
        """Create a zip archive containing all collected report files.

        Returns
        -------
        PathLike
            Absolute or relative filesystem path to the generated archive.

        Notes
        -----
        The archive location defaults to :data:`SystemConfigSettings.archive_dir`
        and is cached internally for retrieval via :meth:`get_archive`.
        """
        self._archive_file = ArchiveManager().zip_files(files=self._report_files(),
                                                        archive_path=self._create_archive_fname())
        return self._archive_file

    def _create_archive_fname(self) -> PathLike:
        """Create a unique archive name based on the current timestamp.

        Returns
        -------
        PathLike
            The generated archive name.
        """
        mac = self.get_mac_address().to_mac_format()

        return Path(self._archive_path) / f"scqam_report_{mac}_{Generate.time_stamp()}.zip"

    def get_mac_address(self) -> MacAddress:
        """Return the MAC address associated with the report.

        Notes
        -----
        Assumes all analyses in the bound :class:`MultiAnalysis` share the same MAC.
        """
        analyses = self._get_analyses()
        if not analyses:
            raise ValueError("No analyses available to extract MAC address.")

        first_analysis:Analysis = analyses[0]

        return MacAddress(cast(BaseAnalysisModel, first_analysis.get_model()[0].mac_address))

    def get_archive(self) -> PathLike:
        """Return the path to the previously created archive.

        Notes
        -----
        Call :meth:`_build_archive` before invoking this method.
        """
        return self._archive_file

    def to_model(self) -> OfdmSpecAnalysisRptModel:
        """Return a structured model of the aggregated report output.

        Notes
        -----
        The model schema is minimal today and will evolve as fields stabilize.
        """
        return OfdmSpecAnalysisRptModel(
            models=self._multi_analysis.to_model())

    def to_dict(self) -> dict[str,Any]:
        """Return the report as a serializable ``dict`` via Pydantic's ``model_dump``."""
        return self._multi_analysis.to_dict()


class SingleOfdmSpecAnalyzerReport(AnalysisReport):
    """Emitter for CSV and plots from a single OFDM Spectrum Analyzer analysis.

    This concrete :class:`AnalysisReport`:
      * builds a CSV (Frequency, Magnitude dBmV, Moving Average),
      * generates two line plots per channel (raw spectrum, windowed average),
      * materializes a :class:`SpectrumAnalyzerAnalysisRptModel` for downstream use.

    Attributes
    ----------
    FNAME_TAG : str
        Base tag used in output filenames to consistently label Spectrum Analyzer artifacts.
    """
    FNAME_TAG: str = "ofdm_spec_ana_rpt"

    def __init__(
        self,
        analysis: Analysis,
        measurement_stats_by_channel: dict[ChannelId, list[dict[str, Any]]] | None = None,
    ) -> None:
        """Create a report instance bound to a single :class:`Analysis`.

        Parameters
        ----------
        analysis : Analysis
            The source analysis whose models/results will be rendered to artifacts.
        """
        super().__init__(analysis)
        self.logger = logging.getLogger("SingleOfdmSpecAnalyzerReport")
        self._results: dict[int, SpectrumAnalyzerAnalysisRptModel] = {}
        self._measurement_stats_by_channel = measurement_stats_by_channel

    def _build_common_analysis_json(self, channel_id: ChannelId, common_analysis: CommonAnalysis) -> None:
        payload = common_analysis.model_dump()
        if self._measurement_stats_by_channel is not None:
            stats = self._measurement_stats_by_channel.get(channel_id, [])
            if stats:
                payload["measurement_stats"] = stats

        full_path_fname = self.create_json_fname(tags=[str(channel_id), "analysis", str(Generate.time_stamp())])
        self.json_files.append(full_path_fname)
        JsonTransactionDb().write_json(
            data=payload,
            fname=Path(full_path_fname).parts[-1],
        )

    def create_csv(self, **kwargs: dict[str, object]) -> list[CSVManager]:
        """Emit a CSV per channel with ``Frequency``, ``Magnitude(dBmV)``, and ``MovingAverage``.

        Returns
        -------
        List[CSVManager]
            One manager per generated CSV (already populated and path-bound).

        Notes
        -----
        - Rows are aligned by index across frequency, amplitude, and moving-average series.
        - Filenames include the channel id and :data:`FNAME_TAG`.
        - Exceptions are logged; partial outputs may still be returned.
        """
        csv_mgr_list: list[CSVManager] = []

        for common_model in self.get_common_analysis_model():
            model = cast(SpectrumAnalyzerAnalysisRptModel, common_model)
            channel_id: int = model.channel_id
            sig = model.signal

            try:
                csv_mgr: CSVManager = self.csv_manager_factory()
                csv_mgr.set_header(["Frequency", "Magnitude(dBmV)", "MovingAverage"])

                # Rows aligned by index
                for f_hz, mag_dbmv, ma in zip(sig.frequencies, sig.amplitude, sig.window.windows_average, strict=False):
                    csv_mgr.insert_row ([f_hz, mag_dbmv, ma])

                csv_fname = self.create_csv_fname(tags=[str(channel_id), self.FNAME_TAG])
                csv_mgr.set_path_fname(csv_fname)

                self.logger.debug("CSV created: %s (rows=%s)", csv_fname, csv_mgr.get_row_count())
                csv_mgr_list.append(csv_mgr)

            except Exception as exc:
                self.logger.exception("Failed to create CSV: %s", exc, exc_info=True)

        return csv_mgr_list

    def create_matplot(self, **kwargs: dict[str, object]) -> list[MatplotManager]:
        """Create two figures per channel: raw spectrum and moving average."""
        out: list[MatplotManager] = []

        for common_model in self.get_common_analysis_model():
            m = cast(SpectrumAnalyzerAnalysisRptModel, common_model)
            sig = m.signal

            try:
                fname = self.create_png_fname(tags=[self.FNAME_TAG, "standard"])
                self.logger.debug("Creating Standard Spectrum Plot: %s", fname)

                cfg = PlotConfig(
                    title           =   "Spectrum Analysis · Standard",
                    x               =   cast(ArrayLike, sig.frequencies),
                    y               =   cast(ArrayLike, sig.amplitude),
                    xlabel          =   None,
                    xlabel_base     =   "Frequency",
                    x_tick_mode     =   "unit",
                    x_unit_from     =   "hz",
                    x_unit_out      =   "mhz",
                    x_tick_decimals =   0,
                    ylabel          =   "dB",
                    grid            =   False,
                    legend          =   False,
                    transparent     =   False,
                    theme           =   self.getAnalysisRptMatplotConfig().theme,)

                mgr = MatplotManager(default_cfg=cfg)
                mgr.plot_line(filename=fname)
                out.append(mgr)

            except Exception as exc:
                self.logger.exception("Failed to create plot for (standard): %s", exc, exc_info=True)

            try:
                fname = self.create_png_fname(tags=[self.FNAME_TAG, "moving_average"])
                self.logger.debug("Creating Window Average Spectrum Plot: %s", fname)

                cfg = PlotConfig(
                    title           =   f"Spectrum Analysis · Moving Average n={sig.window.window_size}",
                    x               =   cast(ArrayLike, sig.frequencies),
                    y               =   cast(ArrayLike, sig.window.windows_average),
                    xlabel          =   None,
                    xlabel_base     =   "Frequency",
                    x_tick_mode     =   "unit",
                    x_unit_from     =   "hz",
                    x_unit_out      =   "mhz",
                    x_tick_decimals =   0,
                    ylabel          =   "dB",
                    grid            =   False,
                    legend          =   False,
                    transparent     =   False,
                    theme           =   self.getAnalysisRptMatplotConfig().theme,)

                mgr = MatplotManager(default_cfg=cfg)
                mgr.plot_line(filename=fname)
                out.append(mgr)

            except Exception as exc:
                self.logger.exception("Failed to create plot for (moving avg): %s", exc, exc_info=True)

        return out

    def _process(self) -> None:
        """Convert SpectrumAnalyzerAnalysisModel → SpectrumAnalyzerAnalysisRptModel per channel."""
        models: list[SpectrumAnalyzerAnalysisModel] = \
            cast(list[SpectrumAnalyzerAnalysisModel], self.get_analysis_model())

        for _idx, _model in enumerate(models):

            sig_analysis = _model.signal_analysis
            freq_hz: FrequencySeriesHz  = [int(f) for f in sig_analysis.frequencies]
            mag_dbmv: FloatSeries       = list(sig_analysis.magnitudes)
            ma_vals: FloatSeries        = list(sig_analysis.window_average.magnitudes)

            # Anti-log in linear ratio (suitable for amplitude-like values)
            anti_log: FloatSeries = [10.0 ** (v / 20.0) for v in mag_dbmv]

            window = SpecAnaWindowAvgRptModel(
                window_size     =   sig_analysis.window_average.points,
                windows_average =   ma_vals,
                length          =   len(ma_vals),
            )

            signal = SpectrumAnalyzerSignalProcessRptModel(
                frequencies     =   freq_hz,
                amplitude       =   mag_dbmv,
                anti_log        =   anti_log,
                window          =   window,
            )

            rpt = SpectrumAnalyzerAnalysisRptModel(
                channel_id      =   _model.channel_id,
                signal          =   signal,
            )

            self.register_common_analysis_model(_model.channel_id, rpt)

# FILE: src/pypnm/api/routes/basic/scqam_spec_analyzer_rpt.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from typing import Any, cast

from pydantic import BaseModel

from pypnm.api.routes.basic.abstract.analysis_report import AnalysisReport
from pypnm.api.routes.basic.abstract.base_models.common_analysis import CommonAnalysis
from pypnm.api.routes.basic.spec_analyzer_analysis_rpt import (
    SpecAnaWindowAvgRptModel,
    SpectrumAnalyzerAnalysisRptModel,
    SpectrumAnalyzerSignalProcessRptModel,
)
from pypnm.api.routes.common.classes.analysis.analysis import Analysis
from pypnm.api.routes.common.classes.analysis.model.spectrum_analyzer_schema import (
    BaseAnalysisModel,
    SpectrumAnalyzerAnalysisModel,
)
from pypnm.api.routes.common.classes.analysis.multi_analysis import MultiAnalysis
from pypnm.config.pnm_config_manager import SystemConfigSettings
from pypnm.lib.archive.manager import ArchiveManager
from pypnm.lib.csv.manager import CSVManager
from pypnm.lib.db.json_transaction import JsonTransactionDb
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.matplot.manager import MatplotManager, PlotConfig
from pypnm.lib.types import ArrayLike, ChannelId, FloatSeries, FrequencySeriesHz, Path, PathLike
from pypnm.lib.utils import Generate


class ScQamSpecAnalysisRptModel(BaseModel):
    """Pydantic model for a compiled SC-QAM Spectrum Analyzer report.
    """
    models:list[BaseAnalysisModel]


class ScQamSpecAnalyzerAnalysisReport:
    """Coordinator that compiles per-channel Spectrum Analyzer artifacts into a single deliverable.

    The class iterates over a :class:`MultiAnalysis` container, invokes
    :class:`SingleScQamSpecAnalyzerReport` for each constituent
    :class:`Analysis`, collects all generated files (CSV/plots), and can bundle
    them into a zip archive.

    Parameters
    ----------
    multi_analysis : MultiAnalysis
        A container of individual Spectrum Analyzer analyses to be reported.

    Examples
    --------
    >>> rpt = ScQamSpecAnalyzerReport(multi_analysis)
    >>> rpt.build_report()
    >>> archive_path = rpt._build_archive()
    >>> rpt_dict = rpt.to_dict()
    """

    def __init__(
        self,
        multi_analysis: MultiAnalysis,
        measurement_stats_by_channel: dict[ChannelId, list[dict[str, Any]]] | None = None,
    ) -> None:
        """Initialize the report coordinator.

        Parameters
        ----------
        multi_analysis : MultiAnalysis
            Source of per-channel :class:`Analysis` objects to process.
        """
        self._multi_analysis = multi_analysis
        self._archive_path:PathLike = SystemConfigSettings.archive_dir()
        self._analysis_files:list[PathLike] = []
        self._archive_file:PathLike
        self._measurement_stats_by_channel = measurement_stats_by_channel

    def build_report(self) -> PathLike:
        """
        Generate and collect all per-channel analysis artifacts into a final archive.

        This method iterates over each :class:`Analysis` object within a
        :class:`MultiAnalysis` instance, generating CSVs and plots using
        :class:`SingleScQamSpecAnalyzerReport`. It then aggregates all
        generated files and produces a single ZIP archive.

        Returns:
            PathLike: The path to the created archive file.

        Workflow:
            1. For each `Analysis`, create and execute a
            `SingleScQamSpecAnalyzerReport`.
            2. Collect all generated files using
            :meth:`SingleScQamSpecAnalyzerReport.get_all_generated_files`.
            3. Combine them into a single archive using :meth:`_build_archive`.

        Notes:
            - The internal list of report files is updated via `_analysis_files`.
            - Only the archive file path is returned; individual CSVs and plots
            remain accessible through their respective report instances.
        """
        for a in self._get_analyses():
            rpt = SingleScQamSpecAnalyzerReport(a, measurement_stats_by_channel=self._measurement_stats_by_channel)
            rpt.build_report()
            rpt.get_all_generated_files()
            self._analysis_files.extend(rpt.get_all_generated_files())

        return self._build_archive()

    def _get_analyses(self) -> list[Analysis]:
        """Return the list of analyses sourced from the bound :class:`MultiAnalysis`."""
        return self._multi_analysis.get_analyses()

    def _report_files(self) -> list[PathLike]:
        """Return the list of file paths collected during :meth:`build_report`."""
        return self._analysis_files

    def _build_archive(self) -> PathLike:
        """Create a zip archive containing all collected report files.

        Returns
        -------
        PathLike
            Absolute or relative filesystem path to the generated archive.

        Notes
        -----
        The archive location defaults to :data:`SystemConfigSettings.archive_dir`
        and is cached internally for retrieval via :meth:`get_archive`.
        """
        self._archive_file = ArchiveManager().zip_files(files=self._report_files(),
                                                        archive_path=self._create_archive_fname())
        return self._archive_file

    def _create_archive_fname(self) -> PathLike:
        """Create a unique archive name based on the current timestamp.

        Returns
        -------
        PathLike
            The generated archive name.
        """
        mac = self.get_mac_address().to_mac_format()

        return Path(self._archive_path) / f"scqam_report_{mac}_{Generate.time_stamp()}.zip"

    def get_mac_address(self) -> MacAddress:
        """Return the MAC address associated with the report.

        Notes
        -----
        Assumes all analyses in the bound :class:`MultiAnalysis` share the same MAC.
        """
        analyses = self._get_analyses()
        if not analyses:
            raise ValueError("No analyses available to extract MAC address.")

        first_analysis = analyses[0]

        return MacAddress(cast(BaseAnalysisModel, first_analysis.get_model()[0].mac_address))

    def get_archive(self) -> PathLike:
        """Return the path to the previously created archive.

        Notes
        -----
        Call :meth:`_build_archive` before invoking this method.
        """
        return self._archive_file

    def to_model(self) -> ScQamSpecAnalysisRptModel:
        """Return a structured model of the aggregated report output.

        Notes
        -----
        The model schema is minimal today and will evolve as fields stabilize.
        """
        return ScQamSpecAnalysisRptModel(
            models=self._multi_analysis.to_model())

    def to_dict(self) -> dict[str,Any]:
        """Return the report as a serializable ``dict`` via Pydantic's ``model_dump``."""
        return self._multi_analysis.to_dict()


class SingleScQamSpecAnalyzerReport(AnalysisReport):
    """Emitter for CSV and plots from a single SC-QAM Spectrum Analyzer analysis.

    This concrete :class:`AnalysisReport`:
      * builds a CSV (Frequency, Magnitude dBmV, Moving Average),
      * generates two line plots per channel (raw spectrum, windowed average),
      * materializes a :class:`SpectrumAnalyzerAnalysisRptModel` for downstream use.

    Attributes
    ----------
    FNAME_TAG : str
        Base tag used in output filenames to consistently label Spectrum Analyzer artifacts.
    """
    FNAME_TAG: str = "scqam_spec_ana_rpt"

    def __init__(
        self,
        analysis: Analysis,
        measurement_stats_by_channel: dict[ChannelId, list[dict[str, Any]]] | None = None,
    ) -> None:
        """Create a report instance bound to a single :class:`Analysis`.

        Parameters
        ----------
        analysis : Analysis
            The source analysis whose models/results will be rendered to artifacts.
        """
        super().__init__(analysis)
        self.logger = logging.getLogger("SpectrumAnalyzerReport")
        self._results: dict[int, SpectrumAnalyzerAnalysisRptModel] = {}
        self._measurement_stats_by_channel = measurement_stats_by_channel

    def _build_common_analysis_json(self, channel_id: ChannelId, common_analysis: CommonAnalysis) -> None:
        payload = common_analysis.model_dump()
        if self._measurement_stats_by_channel is not None:
            stats = self._measurement_stats_by_channel.get(channel_id, [])
            if stats:
                payload["measurement_stats"] = stats

        full_path_fname = self.create_json_fname(tags=[str(channel_id), "analysis", str(Generate.time_stamp())])
        self.json_files.append(full_path_fname)
        JsonTransactionDb().write_json(
            data=payload,
            fname=Path(full_path_fname).parts[-1],
        )

    def create_csv(self) -> list[CSVManager]:
        """Emit a CSV per channel with ``Frequency``, ``Magnitude(dBmV)``, and ``MovingAverage``.

        Returns
        -------
        List[CSVManager]
            One manager per generated CSV (already populated and path-bound).

        Notes
        -----
        - Rows are aligned by index across frequency, amplitude, and moving-average series.
        - Filenames include the channel id and :data:`FNAME_TAG`.
        - Exceptions are logged; partial outputs may still be returned.
        """
        csv_mgr_list: list[CSVManager] = []

        for common_model in self.get_common_analysis_model():
            model = cast(SpectrumAnalyzerAnalysisRptModel, common_model)
            channel_id: int = model.channel_id
            sig = model.signal

            try:
                csv_mgr: CSVManager = self.csv_manager_factory()
                csv_mgr.set_header(["Frequency", "Magnitude(dBmV)", "MovingAverage"])

                # Rows aligned by index
                for f_hz, mag_dbmv, ma in zip(sig.frequencies, sig.amplitude, sig.window.windows_average, strict=False):
                    csv_mgr.insert_row ([f_hz, mag_dbmv, ma])

                csv_fname = self.create_csv_fname(tags=[str(channel_id), self.FNAME_TAG])
                csv_mgr.set_path_fname(csv_fname)

                self.logger.debug("CSV created: %s (rows=%s)", csv_fname, csv_mgr.get_row_count())
                csv_mgr_list.append(csv_mgr)

            except Exception as exc:
                self.logger.exception("Failed to create CSV: %s", exc, exc_info=True)

        return csv_mgr_list

    def create_matplot(self) -> list[MatplotManager]:
        """Create two figures per channel: raw spectrum and moving average."""
        out: list[MatplotManager] = []

        for common_model in self.get_common_analysis_model():
            m = cast(SpectrumAnalyzerAnalysisRptModel, common_model)
            sig = m.signal

            try:
                fname = self.create_png_fname(tags=[self.FNAME_TAG, "standard"])
                self.logger.debug("Creating Standard Spectrum Plot: %s", fname)

                cfg = PlotConfig(
                    title           =   "Spectrum Analysis · Standard",
                    x               =   cast(ArrayLike, sig.frequencies),
                    y               =   cast(ArrayLike, sig.amplitude),
                    xlabel          =   None,
                    xlabel_base     =   "Frequency",
                    x_tick_mode     =   "unit",
                    x_unit_from     =   "hz",
                    x_unit_out      =   "mhz",
                    x_tick_decimals =   0,
                    ylabel          =   "dB",
                    grid            =   False,
                    legend          =   False,
                    transparent     =   False,
                    theme           =   self.getAnalysisRptMatplotConfig().theme,)

                mgr = MatplotManager(default_cfg=cfg)
                mgr.plot_line(filename=fname)
                out.append(mgr)

            except Exception as exc:
                self.logger.exception("Failed to create plot for (standard): %s", exc, exc_info=True)

            try:
                fname = self.create_png_fname(tags=[self.FNAME_TAG, "moving_average"])
                self.logger.debug("Creating Window Average Spectrum Plot: %s", fname)

                cfg = PlotConfig(
                    title           =   f"Spectrum Analysis · Moving Average n={sig.window.window_size}",
                    x               =   cast(ArrayLike, sig.frequencies),
                    y               =   cast(ArrayLike, sig.window.windows_average),
                    xlabel          =   None,
                    xlabel_base     =   "Frequency",
                    x_tick_mode     =   "unit",
                    x_unit_from     =   "hz",
                    x_unit_out      =   "mhz",
                    x_tick_decimals =   0,
                    ylabel          =   "dB",
                    grid            =   False,
                    legend          =   False,
                    transparent     =   False,
                    theme           =   self.getAnalysisRptMatplotConfig().theme,)

                mgr = MatplotManager(default_cfg=cfg)
                mgr.plot_line(filename=fname)
                out.append(mgr)

            except Exception as exc:
                self.logger.exception("Failed to create plot for (moving avg): %s", exc, exc_info=True)

        return out

    def _process(self) -> None:
        """Convert SpectrumAnalyzerAnalysisModel → SpectrumAnalyzerAnalysisRptModel per channel."""
        models: list[SpectrumAnalyzerAnalysisModel] = \
            cast(list[SpectrumAnalyzerAnalysisModel], self.get_analysis_model())

        for _idx, _model in enumerate(models):

            sig_analysis = _model.signal_analysis
            freq_hz: FrequencySeriesHz  = [int(f) for f in sig_analysis.frequencies]
            mag_dbmv: FloatSeries       = list(sig_analysis.magnitudes)
            ma_vals: FloatSeries        = list(sig_analysis.window_average.magnitudes)

            # Anti-log in linear ratio (suitable for amplitude-like values)
            anti_log: FloatSeries = [10.0 ** (v / 20.0) for v in mag_dbmv]

            window = SpecAnaWindowAvgRptModel(
                window_size     =   sig_analysis.window_average.points,
                windows_average =   ma_vals,
                length          =   len(ma_vals),
            )

            signal = SpectrumAnalyzerSignalProcessRptModel(
                frequencies     =   freq_hz,
                amplitude       =   mag_dbmv,
                anti_log        =   anti_log,
                window          =   window,
            )

            rpt = SpectrumAnalyzerAnalysisRptModel(
                channel_id      =   _model.channel_id,
                signal          =   signal,
            )

            self.register_common_analysis_model(_model.channel_id, rpt)

# FILE: tests/test_spectrum_analyzer_report_measurement_stats_json.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from typing import cast

from pypnm.api.routes.basic.ofdm_spec_analyzer_rpt import SingleOfdmSpecAnalyzerReport
from pypnm.api.routes.basic.spec_analyzer_analysis_rpt import (
    SpecAnaWindowAvgRptModel,
    SpectrumAnalyzerAnalysisRptModel,
    SpectrumAnalyzerSignalProcessRptModel,
)
from pypnm.lib.db.json_transaction import JsonTransactionDb
from pypnm.lib.types import ChannelId, FrequencySeriesHz, FloatSeries


class _FakeAnalysis:
    def __init__(self) -> None:
        self._results = {
            "analysis": [
                {
                    "mac_address": "aa:bb:cc:dd:ee:ff",
                    "device_details": {
                        "system_description": {
                            "HW_REV": "1.0",
                            "VENDOR": "LANCity",
                            "BOOTR": "NONE",
                            "SW_REV": "1.0.0",
                            "MODEL": "LCPET-3",
                        }
                    },
                }
            ]
        }

    def get_results(self, full_dict: bool = True) -> dict[str, object]:
        return self._results

    def get_model(self) -> list[object]:
        return []


def _build_report_model(channel_id: ChannelId) -> SpectrumAnalyzerAnalysisRptModel:
    frequencies: FrequencySeriesHz = [100]
    magnitudes: FloatSeries = [1.0]
    windows: FloatSeries = [1.0]

    window = SpecAnaWindowAvgRptModel(
        window_size=1,
        windows_average=windows,
        length=1,
    )

    signal = SpectrumAnalyzerSignalProcessRptModel(
        frequencies=frequencies,
        amplitude=magnitudes,
        anti_log=[1.0],
        window=window,
    )

    return SpectrumAnalyzerAnalysisRptModel(
        channel_id=channel_id,
        signal=signal,
    )


def test_ofdm_report_json_includes_measurement_stats(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def _fake_write_json(self, data: dict[str, object], fname: str, extension: str = "json") -> None:
        captured["data"] = data
        captured["fname"] = fname
        captured["extension"] = extension

    monkeypatch.setattr(JsonTransactionDb, "write_json", _fake_write_json)

    channel_id = ChannelId(3)
    measurement_stats_by_channel = {
        channel_id: [
            {
                "channel_id": channel_id,
                "entry": {"docsIf3CmSpectrumAnalysisCtrlCmdEnable": True},
            }
        ]
    }

    report = SingleOfdmSpecAnalyzerReport(
        _FakeAnalysis(),
        measurement_stats_by_channel=measurement_stats_by_channel,
    )
    report.register_common_analysis_model(channel_id, _build_report_model(channel_id))

    payload = cast(dict[str, object], captured.get("data", {}))
    assert payload.get("channel_id") == channel_id
    measurement_stats = cast(list[dict[str, object]], payload["measurement_stats"])
    assert measurement_stats[0]["channel_id"] == channel_id
