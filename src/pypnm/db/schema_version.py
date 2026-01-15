# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

SCHEMA_META_ID_SEED: int = 1
SCHEMA_VERSION_SEED: int = 1

SCHEMA_VERSION_DDL: str = (
    "CREATE TABLE IF NOT EXISTS schema_meta (schema_meta_id INTEGER PRIMARY KEY, "
    "schema_version INTEGER NOT NULL)"
)
SCHEMA_VERSION_COUNT: str = "SELECT COUNT(*) FROM schema_meta"
SQLITE_SCHEMA_VERSION_INSERT: str = (
    "INSERT INTO schema_meta (schema_meta_id, schema_version) VALUES (?, ?)"
)
POSTGRES_SCHEMA_VERSION_INSERT: str = (
    "INSERT INTO schema_meta (schema_meta_id, schema_version) VALUES (%s, %s)"
)
