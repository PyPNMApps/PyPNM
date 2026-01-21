# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import os
from types import ModuleType

import pytest

from pypnm.lib.types import DatabaseDsn


def require_postgres() -> tuple[DatabaseDsn, ModuleType]:
    if os.environ.get("PYPNM_TEST_POSTGRES", "").strip() != "1":
        pytest.skip(
            "PYPNM_TEST_POSTGRES not set; export PYPNM_TEST_POSTGRES=1 to enable Postgres tests"
        )
    dsn = os.environ.get("PYPNM_DB_POSTGRES_DSN", "").strip()
    if dsn == "":
        pytest.skip(
            "PYPNM_DB_POSTGRES_DSN not set; export PYPNM_DB_POSTGRES_DSN=postgresql://USER:PASS@HOST:PORT/DB"
        )
    try:
        import psycopg
    except ImportError:
        pytest.skip("psycopg not installed; install with pypnm-docsis[postgres]")
    return DatabaseDsn(dsn), psycopg
