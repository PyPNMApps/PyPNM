from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
from pydantic import BaseModel, Field


class DocsisBaseCapability(BaseModel):
    docsis_version: str = Field()
    clabs_docsis_version: int = Field()
