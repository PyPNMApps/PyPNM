# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
import subprocess


class SystemCall:
    """
    Unified subprocess wrapper with logging and consistent error handling.
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger(f"{self.__class__.__name__}")

    def run(self, args: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
        """
        Execute a system command and return the completed process result.

        Parameters
        ----------
        args:
            Command argument list to execute.
        check:
            When True, raise on non-zero return code.
        """
        self.logger.debug("System call: %s", " ".join(args))
        try:
            result = subprocess.run(
                args,
                check=check,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.strip() if exc.stderr else "no stderr"
            self.logger.error("System call failed: %s (rc=%s, stderr=%s)", " ".join(args), exc.returncode, stderr)
            raise

        if result.returncode != 0 and check is False:
            stderr = result.stderr.strip() if result.stderr else "no stderr"
            self.logger.warning(
                "System call returned non-zero rc=%s for %s (stderr=%s)",
                result.returncode,
                " ".join(args),
                stderr,
            )

        return result
