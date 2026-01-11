# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from fastapi.responses import FileResponse

from pypnm.api.routes.common.classes.common_endpoint_classes.schemas import (
    PnmAnalysisResponse,
    PnmMeasurementResponse,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.snmp.schemas import (
    SnmpResponse,
)

MeasurementCommonResponse = PnmMeasurementResponse | SnmpResponse
MeasurementStatsCommonResponse = SnmpResponse
AnalysisCommonResponse = PnmAnalysisResponse | FileResponse | SnmpResponse
