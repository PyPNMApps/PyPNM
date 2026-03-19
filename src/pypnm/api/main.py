# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import pathlib
import re
import sys
from collections.abc import Awaitable, Callable
from time import monotonic, time

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.routing import APIRoute
from pydantic import BaseModel, Field
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
API_START_MONOTONIC: float = monotonic()
API_START_EPOCH: int = int(time())


class HealthServiceModel(BaseModel):
    name: str = Field(..., description="Service name from pyproject metadata.")
    version: str = Field(..., description="Running PyPNM service version.")


class HealthUptimeModel(BaseModel):
    starttime: int = Field(..., description="Service start time as Unix epoch seconds.")
    uptime: int = Field(..., description="Elapsed uptime in whole seconds since starttime.")


class HealthDataModel(BaseModel):
    path: str = Field(..., description="Repository-local data directory path.")
    size_bytes: int = Field(..., description="Recursive apparent size of the data directory in bytes.")
    directories: dict[str, int] = Field(default_factory=dict, description="Recursive apparent sizes for first-level directories under the data root.")


class HealthMemoryModel(BaseModel):
    rss_bytes: int = Field(..., description="Resident memory usage for the running PyPNM process in bytes.")
    total_bytes: int = Field(..., description="Total system memory available on the current host in bytes.")
    free_bytes: int = Field(..., description="Free system memory on the current host in bytes.")
    available_bytes: int = Field(..., description="Available system memory on the current host in bytes.")
    usage_percent: float = Field(..., description="Resident process memory as a percentage of total system memory.")


class HealthResponseModel(BaseModel):
    status: str = Field(..., description="Top-level health status for readiness probes.")
    service: HealthServiceModel = Field(..., description="Service identity and version metadata.")
    uptime: HealthUptimeModel = Field(..., description="Service process start time and uptime.")
    memory: HealthMemoryModel = Field(..., description="Process memory usage for the running PyPNM service.")
    data: HealthDataModel = Field(..., description="Runtime data directory sizing details.")


def _route_tag_set(route: APIRoute) -> set[str]:
    tags = route.tags or []
    return {str(tag).strip().lower() for tag in tags if str(tag).strip() != ""}


def _read_project_name() -> str:
    """Read the project name from pyproject.toml, falling back to a stable default."""
    pyproject_path = project_root.parent / "pyproject.toml"
    if not pyproject_path.is_file():
        return "pypnm-docsis"

    pyproject_text = pyproject_path.read_text(encoding="utf-8")
    project_match = re.search(r"^\[project\]\s*$", pyproject_text, re.MULTILINE)
    if project_match is None:
        return "pypnm-docsis"

    tail_text = pyproject_text[project_match.end() :]
    name_match = re.search(r'^\s*name\s*=\s*"([^"]+)"\s*$', tail_text, re.MULTILINE)
    if name_match is None:
        return "pypnm-docsis"

    return name_match.group(1).strip()


def _service_uptime_seconds() -> int:
    """Return process uptime in whole seconds since API module initialization."""
    elapsed_seconds = int(monotonic() - API_START_MONOTONIC)
    return max(elapsed_seconds, 0)


SERVICE_NAME: str = _read_project_name()


def _data_root_path() -> pathlib.Path:
    """Return the repository-local `.data` directory used for runtime artifacts."""
    return pathlib.Path(".data")


def _folder_size_bytes(folder_path: pathlib.Path) -> int:
    """Return recursive folder size in bytes, ignoring inaccessible entries."""
    if not folder_path.exists():
        return 0

    total_bytes = 0
    for path in folder_path.rglob("*"):
        total_bytes += _file_size_bytes(path)
    return total_bytes


def _file_size_bytes(path: pathlib.Path) -> int:
    """Return file size in bytes, or zero for non-files and inaccessible paths."""
    try:
        if path.is_file():
            return path.stat().st_size
    except OSError:
        return 0
    return 0


def _first_level_directory_sizes(folder_path: pathlib.Path) -> dict[str, int]:
    """Return recursive sizes for each first-level directory under the given root."""
    if not folder_path.exists():
        return {}

    sizes: dict[str, int] = {}
    for child in folder_path.iterdir():
        if not child.is_dir():
            continue
        sizes[child.name] = _folder_size_bytes(child)
    return sizes


def _process_rss_bytes() -> int:
    """Return resident memory for the current process in bytes using Linux procfs."""
    status_path = pathlib.Path("/proc/self/status")
    if not status_path.is_file():
        return 0

    try:
        for line in status_path.read_text(encoding="utf-8").splitlines():
            if not line.startswith("VmRSS:"):
                continue
            parts = line.split()
            if len(parts) < 2:
                return 0
            return int(parts[1]) * 1024
    except (OSError, ValueError):
        return 0

    return 0


def _system_total_memory_bytes() -> int:
    """Return total system memory in bytes using Linux procfs."""
    meminfo_path = pathlib.Path("/proc/meminfo")
    if not meminfo_path.is_file():
        return 0

    try:
        for line in meminfo_path.read_text(encoding="utf-8").splitlines():
            if not line.startswith("MemTotal:"):
                continue
            parts = line.split()
            if len(parts) < 2:
                return 0
            return int(parts[1]) * 1024
    except (OSError, ValueError):
        return 0

    return 0


def _read_meminfo_bytes(field_name: str) -> int:
    """Return a specific `/proc/meminfo` field in bytes."""
    meminfo_path = pathlib.Path("/proc/meminfo")
    if not meminfo_path.is_file():
        return 0

    try:
        for line in meminfo_path.read_text(encoding="utf-8").splitlines():
            if not line.startswith(f"{field_name}:"):
                continue
            parts = line.split()
            if len(parts) < 2:
                return 0
            return int(parts[1]) * 1024
    except (OSError, ValueError):
        return 0

    return 0


def _system_free_memory_bytes() -> int:
    """Return free system memory in bytes using Linux procfs."""
    return _read_meminfo_bytes("MemFree")


def _system_available_memory_bytes() -> int:
    """Return available system memory in bytes using Linux procfs."""
    return _read_meminfo_bytes("MemAvailable")


def _process_memory_usage_percent(rss_bytes: int, total_bytes: int) -> float:
    """Return process RSS as a percentage of total system memory."""
    if total_bytes <= 0:
        return 0.0
    return round((rss_bytes / total_bytes) * 100.0, 2)


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


@app.get("/health", tags=["health"], response_model=HealthResponseModel)
def health() -> HealthResponseModel:
    """Lightweight health endpoint for probes."""
    uptime_seconds = _service_uptime_seconds()
    data_root = _data_root_path()
    rss_bytes = _process_rss_bytes()
    total_memory_bytes = _system_total_memory_bytes()
    free_memory_bytes = _system_free_memory_bytes()
    available_memory_bytes = _system_available_memory_bytes()
    return HealthResponseModel(
        status="ok",
        service=HealthServiceModel(name=SERVICE_NAME, version=__version__),
        uptime=HealthUptimeModel(starttime=API_START_EPOCH, uptime=uptime_seconds),
        memory=HealthMemoryModel(
            rss_bytes=rss_bytes,
            total_bytes=total_memory_bytes,
            free_bytes=free_memory_bytes,
            available_bytes=available_memory_bytes,
            usage_percent=_process_memory_usage_percent(rss_bytes, total_memory_bytes),
        ),
        data=HealthDataModel(
            path=str(data_root),
            size_bytes=_folder_size_bytes(data_root),
            directories=_first_level_directory_sizes(data_root),
        ),
    )

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
