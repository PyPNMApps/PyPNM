# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import pathlib
import sys

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from pypnm.api.utils.auto_load import RouterRegistrar
from pypnm.startup.startup import StartUp
from pypnm.version import __version__

project_root = pathlib.Path(__file__).resolve()
while project_root.name != "src" and project_root != project_root.parent:
    project_root = project_root.parent

if project_root.name == "src" and str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

StartUp.initialize()

fast_api_description = """
**Proactive Network Maintenance (PNM) FastAPI For DOCSIS 3.x/4.0**

PyPNM exposes DOCSIS PNM workflows as a FastAPI service so you can script,
automate, and visualize modem telemetry instead of working with ad-hoc
SNMP walks and raw binary files.

**Core capabilities include:**
- Downstream and upstream OFDM/OFDMA diagnostics
- Single-capture and multi-capture RxMER / Channel-Estimation analysis
- Multipath Echo-Detection, OFDM Impulse-Response, and OFDM Profile Performance
- Modulation-Profile decoding and FEC-Summary statistics
- Spectrum capture, OFDM Constellation-Display, and OFDMA Pre-Equalization helpers
- File management for PNM captures (transactions, uploads, demo data)
- DOCSIS Event-Log reporting and SCQAM Status and Statistics

Use it from dashboards, CI pipelines, or engineering tools to inspect plant
health, track impairments over time, and validate DOCSIS device behavior.

[**PyPNM Homepage**](https://github.com/PyPNMApps/PyPNM)
"""

app = FastAPI(
    title="PyPNM REST API",
    version=__version__,
    description=fast_api_description,
    openapi_url="/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
)


@app.get("/health", tags=["health"])
def health() -> dict[str, str]:
    """Lightweight health endpoint for probes."""
    return {"status": "ok", "version": __version__}


app.add_middleware(GZipMiddleware, minimum_size=100_000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

RouterRegistrar().register(app)
