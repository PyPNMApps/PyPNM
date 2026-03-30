# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pydantic import BaseModel, Field


class PyPnmWebServiceRuntimeProfileModel(BaseModel):
    profile_env_path: str = Field(..., description="Path to the generated worker-profile env file.")
    profile_exists: bool = Field(..., description="Whether the generated worker-profile env file exists on disk.")
    detected_cpu_count: int | None = Field(default=None, description="CPU count detected when the worker profile was seeded.")
    detected_total_memory_gib: float | None = Field(default=None, description="Total host memory in GiB detected when the worker profile was seeded.")
    seeded_workers: int | None = Field(default=None, description="Worker count written by the worker-profile helper.")
    seeded_limit_max_requests: int | None = Field(default=None, description="Recycle threshold written by the worker-profile helper.")
    active_workers: int | None = Field(default=None, description="Worker count active in the current running service.")
    active_limit_max_requests: int | None = Field(default=None, description="Request recycle threshold active in the current running service.")
    active_source: str = Field(default="", description="How the active runtime values were chosen, for example explicit_cli or seeded_profile.")


class PyPnmWebServiceRuntimeProfileResponse(BaseModel):
    status: str = Field(default="success", description="Top-level API status.")
    profile: PyPnmWebServiceRuntimeProfileModel = Field(..., description="Resolved worker profile for the running web service.")
