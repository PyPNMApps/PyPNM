# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE


class PyPnmSystemLog:
    """
    Provide An API Endpoint To Download The PyPNM System Log File.

    This router exposes a simple download endpoint that returns the current
    PyPNM system log. It is primarily intended for diagnostics, debugging,
    and automated log collection from the backend service.
    """

    def __init__(self) -> None:
        """
        Initialize The PyPNM System Log API Router And Bind Routes.
        """
        self.logger = logging.getLogger(f"{self.__class__.__name__}")
        self.router = APIRouter(
            prefix = "/pypnm/system/log",
            tags   = ["PyPNM System Log"],
        )
        self.router.add_api_route(
            path          = "/download",
            endpoint      = self.get_pypnm_log,
            methods       = ["GET"],
            summary       = "Download PyPNM System Log File",
            response_model= None,
            responses     = FAST_API_RESPONSE,
        )

    async def get_pypnm_log(self) -> FileResponse:
        """
        Download PyPNM System Log File.

        This endpoint retrieves the current PyPNM system log as a downloadable
        text file. It returns HTTP 404 if the log file does not exist and
        HTTP 500 for unexpected errors.

        [API Guide - PyPNM System Log](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/pypnm/system/download-log.md)
        """
        log_dir      = SystemConfigSettings.log_dir()
        log_filename = SystemConfigSettings.log_filename()
        log_path     = Path(log_dir) / log_filename

        if not log_path.is_file():
            self.logger.error("System log file not found at '%s'", log_path)
            raise HTTPException(
                status_code = 404,
                detail      = f"Log file not found at: {log_path}",
            )

        try:
            return FileResponse(
                path      = str(log_path),
                filename  = log_filename,
                media_type= "text/plain",
            )
        except Exception as exc:
            self.logger.error(
                "Failed to stream system log file '%s': %s", log_path, exc
            )
            raise HTTPException(
                status_code = 500,
                detail      = f"Failed to retrieve log: {exc}",
            ) from exc


# Expose router for FastAPI
router = PyPnmSystemLog().router
