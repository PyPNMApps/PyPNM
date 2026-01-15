# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from typing import cast

from pydantic import BaseModel, Field, model_validator

from pypnm.lib.types import DatabaseBackend, DatabaseDsn, DatabasePath

DEFAULT_SQLITE_DB_PATH: DatabasePath = cast(DatabasePath, ".data/db/pypnm.sqlite3")
DEFAULT_POSTGRES_DSN: DatabaseDsn = cast(DatabaseDsn, "")
POSTGRES_DSN_ENV_VAR: str = "PYPNM_DB_POSTGRES_DSN"


class DatabaseSqliteSettings(BaseModel):
    """SQLite Configuration Settings."""

    path: DatabasePath = Field(
        DEFAULT_SQLITE_DB_PATH, description="SQLite database path (app-root relative)"
    )


class DatabasePostgresSettings(BaseModel):
    """Postgres Configuration Settings."""

    dsn: DatabaseDsn = Field(
        DEFAULT_POSTGRES_DSN, description="Postgres DSN; use env override for secrets"
    )


class DatabaseSettings(BaseModel):
    """Database Backend Configuration Contract."""

    backend: DatabaseBackend = Field(
        DatabaseBackend.SQLITE,
        description="Database backend selector (sqlite or postgres)",
    )
    sqlite: DatabaseSqliteSettings = Field(
        default_factory=DatabaseSqliteSettings, description="SQLite settings"
    )
    postgres: DatabasePostgresSettings = Field(
        default_factory=DatabasePostgresSettings, description="Postgres settings"
    )

    @classmethod
    def from_sources(
        cls,
        backend_value: str | None,
        env_backend: str,
        sqlite_value: str | None,
        postgres_value: str | None,
        env_postgres_dsn: str,
    ) -> DatabaseSettings:
        backend = ""
        if backend_value is not None:
            backend = str(backend_value).strip()
        if env_backend != "":
            backend = env_backend

        if sqlite_value is None:
            sqlite_path = DEFAULT_SQLITE_DB_PATH
        else:
            sqlite_path = DatabasePath(str(sqlite_value))

        if postgres_value is None:
            postgres_dsn = DEFAULT_POSTGRES_DSN
        else:
            postgres_dsn = DatabaseDsn(str(postgres_value))

        if env_postgres_dsn != "":
            postgres_dsn = DatabaseDsn(env_postgres_dsn)

        if backend == "":
            return cls(
                sqlite=DatabaseSqliteSettings(path=sqlite_path),
                postgres=DatabasePostgresSettings(dsn=postgres_dsn),
            )

        return cls(
            backend=backend,
            sqlite=DatabaseSqliteSettings(path=sqlite_path),
            postgres=DatabasePostgresSettings(dsn=postgres_dsn),
        )

    @model_validator(mode="after")
    def _validate_backend_config(self) -> DatabaseSettings:
        if str(self.sqlite.path).strip() == "":
            raise ValueError("Database.sqlite.path cannot be blank")
        if (
            self.backend == DatabaseBackend.POSTGRES
            and str(self.postgres.dsn).strip() == ""
        ):
            raise ValueError(
                "Database.postgres.dsn cannot be blank when backend is postgres"
            )
        return self
