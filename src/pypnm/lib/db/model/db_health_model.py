# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pydantic import BaseModel, Field

from pypnm.lib.types import DatabaseBackend


class DatabaseHealthModel(BaseModel):
    """
    Database health status for schema diagnostics.
    """

    backend: DatabaseBackend = Field(..., description="Database backend under test")
    schema_version: int = Field(
        ..., description="Detected schema version (0 when missing)"
    )
    missing_tables: list[str] = Field(
        default_factory=list, description="Required tables that are missing"
    )
    unknown_sysdescr_present: bool = Field(
        ..., description="Whether the canonical UNKNOWN sysDescr row exists"
    )
    default_artifact_store_present: bool = Field(
        ..., description="Whether the default artifact store row exists"
    )
    json_artifact_store_present: bool = Field(
        ..., description="Whether the JSON artifact store row exists"
    )
    ok: bool = Field(..., description="True when schema is healthy and complete")
    details: str = Field("", description="Diagnostic summary")
