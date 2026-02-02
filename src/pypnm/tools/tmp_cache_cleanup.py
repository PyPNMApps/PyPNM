# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path

from pypnm.config.config_manager import ConfigManager
from pypnm.config.pnm_artifact_storage import PnmArtifactStorageConfig


class TmpCacheCleaner:
    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        config = ConfigManager().get("PnmArtifactStorage")
        self._config = PnmArtifactStorageConfig.from_config(config if isinstance(config, dict) else None)
        self._tmp_root = Path(self._config.cache.tmp_root)

    def run(self) -> int:
        """
        Clean expired ingress and materialized cache entries.

        Returns:
            int: Process exit code (0 for success).
        """
        self.logger.info("Starting tmp cache cleanup.")
        ingress_dir = self._tmp_root / self._config.cache.ingress_dir
        materialized_dir = self._tmp_root / self._config.cache.materialized_dir

        self._cleanup_dir(ingress_dir, self._config.cache.ingress_ttl_seconds)
        self._cleanup_dir(materialized_dir, self._config.cache.materialized_ttl_seconds)
        return 0

    def _cleanup_dir(self, root: Path, ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            return
        if not root.exists():
            return
        now = time.time()
        for path in root.rglob("*"):
            if path.is_file():
                age = now - path.stat().st_mtime
                if age >= ttl_seconds:
                    path.unlink(missing_ok=True)
        for path in sorted(root.rglob("*"), reverse=True):
            if path.is_dir():
                age = now - path.stat().st_mtime
                if age < ttl_seconds:
                    continue
                try:
                    path.rmdir()
                except OSError:
                    continue


class TmpCacheCleanupScheduler:
    """
    Periodic tmp cache cleanup runner driven by configured cleanup interval.
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        config = ConfigManager().get("PnmArtifactStorage")
        self._config = PnmArtifactStorageConfig.from_config(config if isinstance(config, dict) else None)
        self._interval_seconds = int(self._config.cache.cleanup_interval_seconds)
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._cleaner = TmpCacheCleaner()

    def start(self) -> None:
        """
        Start the background cleanup thread if configured to run.
        """
        if self._interval_seconds <= 0:
            self.logger.info("Tmp cache cleanup scheduler disabled (interval <= 0).")
            return
        if self._thread is not None:
            return

        self._thread = threading.Thread(target=self._run, name="TmpCacheCleanup", daemon=True)
        self._thread.start()
        self.logger.info("Tmp cache cleanup scheduler started with interval=%s", self._interval_seconds)

    def stop(self) -> None:
        """
        Stop the background cleanup thread.
        """
        self._stop_event.set()
        if self._thread is None:
            return
        self._thread.join(timeout=5)
        self._thread = None
        self.logger.info("Tmp cache cleanup scheduler stopped.")

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._cleaner.run()
            except Exception as exc:
                self.logger.error("Tmp cache cleanup failed: %s", exc)
            self._stop_event.wait(self._interval_seconds)


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    return TmpCacheCleaner().run()


if __name__ == "__main__":
    raise SystemExit(main())
