# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from pypnm.api.routes.common.extended.common_process_service import SystemConfigSettings
from pypnm.config.log_config import LoggerConfigurator


class StartUp:
    """
    Class to handle the startup process of the PyPNM application.
    It initializes the system configuration settings and prepares the environment.
    """

    @classmethod
    def initialize(cls) -> None:
        """
        Initialize the system configuration settings and set up logging.
        This method should be called at the start of the application.
        """
        SystemConfigSettings.initialize_directories()

        LoggerConfigurator(
            SystemConfigSettings.log_dir(),
            SystemConfigSettings.log_filename(),
            SystemConfigSettings.log_level(),
        )
