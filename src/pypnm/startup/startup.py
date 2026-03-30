# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
import os

from pypnm.api.routes.common.extended.common_process_service import SystemConfigSettings
from pypnm.cli import _runtime_profile_selection_message
from pypnm.config.log_config import LoggerConfigurator
from pypnm.tools.tmp_cache_cleanup import TmpCacheCleanupScheduler


class StartUp:
    """
    Class to handle the startup process of the PyPNM application.
    It initializes the system configuration settings and prepares the environment.
    """
    _tmp_cache_scheduler: TmpCacheCleanupScheduler | None = None

    @classmethod
    def initialize(cls) -> None:
        """
        Initialize the system configuration settings and set up logging.
        This method should be called at the start of the application.
        """
        SystemConfigSettings.initialize_directories()

        LoggerConfigurator(SystemConfigSettings.log_dir(),
                           SystemConfigSettings.log_filename(),
                           SystemConfigSettings.log_level())
        cls._log_runtime_profile_selection()
        cls._start_tmp_cache_cleanup()

    @classmethod
    def _log_runtime_profile_selection(cls) -> None:
        logger = logging.getLogger(cls.__name__)
        workers = os.environ.get("PYPNM_ACTIVE_WORKERS", "").strip()
        limit_max_requests = os.environ.get("PYPNM_ACTIVE_LIMIT_MAX_REQUESTS", "").strip()
        if workers == "" or limit_max_requests == "":
            return
        try:
            logger.info(
                _runtime_profile_selection_message(
                    workers=int(workers),
                    limit_max_requests=int(limit_max_requests),
                ),
            )
        except ValueError:
            logger.warning(
                "Unable to log runtime profile selection: workers=%r limit_max_requests=%r",
                workers,
                limit_max_requests,
            )

    @classmethod
    def _start_tmp_cache_cleanup(cls) -> None:
        """
        Start the tmp cache cleanup scheduler in the background.
        """
        logger = logging.getLogger(cls.__name__)
        if cls._tmp_cache_scheduler is not None:
            return

        cls._tmp_cache_scheduler = TmpCacheCleanupScheduler()
        try:
            cls._tmp_cache_scheduler.start()
        except Exception as exc:
            logger.error("Failed to start tmp cache cleanup scheduler: %s", exc)
