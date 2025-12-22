# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException

from pypnm.lib.fastapi_constants import FAST_API_RESPONSE


class PyPnmSystemWebServiceAPI:
    """
    API Class For Managing PyPNM System Web Service Endpoints.
    """

    def __init__(self) -> None:
        """
        Initialize The PyPNM System Web Service API Router And Bind Routes.
        """
        self.router = APIRouter(
            prefix="/pypnm/system/webService",
            tags=["PyPNM System Web Service"],
        )

        self.router.add_api_route(
            path="/reload",
            endpoint=self.trigger_reload,
            methods=["GET"],
            summary="Trigger PyPNM Web Service Reload",
            response_model=dict[str, str],
            responses=FAST_API_RESPONSE,
        )

    async def trigger_reload(self) -> dict[str, str]:
        """
        **Trigger PyPNM System Web Service Reload**

        This endpoint triggers a hot reload of the PyPNM web service by
        touching this route module. When the server is running with
        auto-reload enabled (for example, `uvicorn --reload`), modifying the
        file timestamp signals the process to reload application code.

        [API Guide - PyPNM System Web Service Reload]
        (https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/system/reload-web-service.md)
        """
        try:
            Path(__file__).touch()
            return {"status": "reload triggered"}
        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to trigger reload: {exc}",
            ) from exc


router = PyPnmSystemWebServiceAPI().router
