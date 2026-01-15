# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging

from pydantic import ValidationError

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.db.database_adapter import DatabaseAdapter
from pypnm.db.postgres_adapter import PostgresDatabaseAdapter
from pypnm.db.sqlite_adapter import SQLiteDatabaseAdapter
from pypnm.lib.types import DatabaseBackend


class DatabaseManager:
    """
    Select and cache the configured database adapter.
    """

    _adapter: DatabaseAdapter | None = None
    _logger = logging.getLogger("DatabaseManager")

    @classmethod
    def get_adapter(cls) -> DatabaseAdapter:
        if cls._adapter is not None:
            return cls._adapter

        try:
            settings = SystemConfigSettings.database_settings()
            backend = settings.backend
        except ValidationError as exc:
            cls._logger.error("Invalid Database configuration: %s", exc)
            backend = DatabaseBackend.SQLITE
            settings = None

        match backend:
            case DatabaseBackend.POSTGRES:
                if settings is None:
                    adapter = SQLiteDatabaseAdapter(
                        SystemConfigSettings.database_sqlite_path()
                    )
                else:
                    adapter = PostgresDatabaseAdapter(settings.postgres.dsn)
            case DatabaseBackend.SQLITE:
                if settings is None:
                    adapter = SQLiteDatabaseAdapter(
                        SystemConfigSettings.database_sqlite_path()
                    )
                else:
                    adapter = SQLiteDatabaseAdapter(settings.sqlite.path)
            case _:
                adapter = SQLiteDatabaseAdapter(
                    SystemConfigSettings.database_sqlite_path()
                )

        cls._adapter = adapter
        return adapter

    @classmethod
    def initialize(cls) -> bool:
        try:
            adapter = cls.get_adapter()
            backend = SystemConfigSettings.database_backend()
        except Exception as exc:
            cls._logger.error("Database initialize failed before connect: %s", exc)
            return False

        try:
            adapter.connect()
        except Exception as exc:
            cls._logger.error(
                "Database initialize connect failed (%s): %s", backend, exc
            )
            return False

        try:
            adapter.apply_schema()
        except Exception as exc:
            cls._logger.error(
                "Database initialize apply_schema failed (%s): %s", backend, exc
            )
            return False

        try:
            return adapter.healthcheck()
        except Exception as exc:
            cls._logger.error(
                "Database initialize healthcheck failed (%s): %s", backend, exc
            )
            return False

    @classmethod
    def close(cls) -> None:
        if cls._adapter is None:
            return
        try:
            cls._adapter.close()
        except Exception as exc:
            cls._logger.error("Database adapter close failed: %s", exc)
        finally:
            cls._adapter = None
