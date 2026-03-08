# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import pathlib
import sys
from collections.abc import Awaitable, Callable

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.routing import APIRoute
from starlette.requests import Request
from starlette.responses import JSONResponse

from pypnm.api.utils.auto_load import RouterRegistrar
from pypnm.config.runtime_flags import (
    ENV_MUTE_TAGS,
    ENV_MUTE_TAGS_HARD,
    is_env_flag_enabled,
    read_env_csv_set,
)
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

_hard_muted_routes: list[APIRoute] = []


def _route_tag_set(route: APIRoute) -> set[str]:
    tags = route.tags or []
    return {str(tag).strip().lower() for tag in tags if str(tag).strip() != ""}


def _apply_muted_tag_policy(app_instance: FastAPI) -> None:
    _hard_muted_routes.clear()
    muted_tags = read_env_csv_set(ENV_MUTE_TAGS)
    if not muted_tags:
        return

    hard_mute = is_env_flag_enabled(ENV_MUTE_TAGS_HARD)
    for route in app_instance.router.routes:
        if not isinstance(route, APIRoute):
            continue
        if not (_route_tag_set(route) & muted_tags):
            continue
        route.include_in_schema = False
        if hard_mute:
            _hard_muted_routes.append(route)


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
_apply_muted_tag_policy(app)


@app.middleware("http")
async def _deny_hard_muted_tag_routes(
    request: Request,
    call_next: Callable[[Request], Awaitable[object]],
) -> JSONResponse | object:
    if _hard_muted_routes:
        for route in _hard_muted_routes:
            methods = route.methods or set()
            if request.method.upper() not in methods:
                continue
            if route.path_regex.fullmatch(request.scope["path"]) is None:
                continue
            return JSONResponse(
                status_code=403,
                content={"detail": "Endpoint disabled by policy"},
                headers={"X-Endpoint-Policy": "muted-tag"},
            )
    return await call_next(request)
