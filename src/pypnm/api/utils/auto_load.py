from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
import importlib
import logging
import pathlib
import sys
import traceback

from fastapi import FastAPI


class RouterRegistrar:
    """
    Auto-discovers and registers FastAPI routers by scanning for 'router.py' files
    under src/pypnm/api/routes. Skips modules marked as non-routable and collects
    import/registration errors for summary reporting.

    Uses structured logging: debug for normal flow, error for failures.
    """

    def __init__(self, base_dir: pathlib.Path = None) -> None:
        self.logger = logging.getLogger(__name__)
        # Locate project root (up to 'pypnm')
        self.project_root = base_dir or pathlib.Path(__file__).resolve()
        while self.project_root.name != "pypnm":
            if self.project_root == self.project_root.parent:
                msg = "Could not find 'pypnm' directory in path."
                self.logger.error(msg)
                raise RuntimeError(msg)
            self.project_root = self.project_root.parent

        # Determine routes directory
        self.routes_path = self.project_root / "api" / "routes"
        if not self.routes_path.exists():
            msg = f"Path not found: {self.routes_path}"
            self.logger.error(msg)
            raise RuntimeError(msg)

        # Ensure project_root on sys.path
        if str(self.project_root) not in sys.path:
            sys.path.insert(0, str(self.project_root))
            self.logger.debug(f"Added project root to sys.path: {self.project_root}")

        self.errors = []

    def register(self, app: FastAPI) -> None:
        """
        Scan for 'router.py' under routes_path and register each router
        with the provided FastAPI app.
        """
        self.logger.debug("Starting router registration")
        self.logger.debug(f"Scanning directory for routers: {self.routes_path}")

        for router_file in self.routes_path.rglob("router.py"):
            self.logger.debug(f"Discovered router file: {router_file}")
            try:
                relative = router_file.relative_to(self.project_root).with_suffix("")
                module_path = ".".join(relative.parts)
                self.logger.debug(f"Importing module '{module_path}'")

                module = importlib.import_module(module_path)
                if getattr(module, "__skip_autoregister__", False):
                    self.logger.debug(f"Skipping non-routable module: {module_path}")
                    continue

                router = getattr(module, "router", None)
                if not router:
                    self.logger.debug(f"No 'router' attribute in module: {module_path}")
                    continue

                app.include_router(router)
                self.logger.debug(f"Registered router from module: {module_path}")

            except Exception:
                error_tb = traceback.format_exc()
                self.logger.error(
                    f"Failed to register router from '{router_file}':\n{error_tb}"
                )
                self.errors.append(
                    (
                        module_path if "module_path" in locals() else str(router_file),
                        error_tb,
                    )
                )

        self._report_summary()

    def _report_summary(self) -> None:
        """
        Log a summary of any errors encountered during registration.
        """
        if self.errors:
            for module, tb in self.errors:
                self.logger.error(f"Error in module '{module}':\n{tb}")
        else:
            self.logger.debug("Router registration completed without errors.")
