# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from pypnm.lib.types import FileNameStr, PathLike


class LoggerConfigurator:
    """
    Configure application logging to a file (and optionally console),
    with optional rotation and a standardized startup banner.
    """

    def __init__(
        self,
        log_dir: PathLike,
        log_filename: FileNameStr,
        level: str = "INFO",
        to_console: bool = False,
        rotate: bool = False,
    ) -> None:
        """
        Initialize the LoggerConfigurator.

        Args:
            log_dir (str): Directory path where log files will be stored. Created if missing.
            log_filename (str): Name of the log file (e.g. 'pypnm.log').
            level (str): Logging level name ('DEBUG', 'INFO', etc.).
            to_console (bool): If True, also output logs to stderr.
            rotate (bool): If True, use RotatingFileHandler (10MB max, 5 backups).
        """
        self.log_dir = Path(log_dir)
        self.log_filename = log_filename
        self.level = getattr(logging, level.upper(), logging.INFO)
        self.to_console = to_console
        self.rotate = rotate

        self.__setup()

    def __setup(self) -> None:
        """
        Internal method to configure the root logger:
        """
        self.log_dir.mkdir(parents=True, exist_ok=True)
        log_file = self.log_dir / self.log_filename
        if self.rotate:
            # Rotate after ~10MB, keep up to 5 old log files
            handler = RotatingFileHandler(
                log_file, maxBytes=10 * 1024 * 1024, backupCount=5
            )
        else:
            handler = logging.FileHandler(log_file)

        # 3. Define log message format
        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        handler.setFormatter(fmt)

        # 4. Configure root logger
        root = logging.getLogger()
        root.setLevel(self.level)
        root.addHandler(handler)

        # Optionally, add console output
        if self.to_console:
            console = logging.StreamHandler(sys.stderr)
            console.setFormatter(fmt)
            root.addHandler(console)

        # 5. Startup banner to mark the beginning of a new run
        root.info("==== PyPNM REST API Starting ====")
