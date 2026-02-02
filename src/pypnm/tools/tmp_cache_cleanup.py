# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
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


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    return TmpCacheCleaner().run()


if __name__ == "__main__":
    raise SystemExit(main())
