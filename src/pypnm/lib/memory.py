# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026

from __future__ import annotations

import ctypes
import gc
import logging


class ProcessMemory:
    """Helpers for best-effort process memory reclamation on long-running services."""

    @staticmethod
    def release_unused_memory() -> None:
        """
        Trigger Python garbage collection and best-effort libc heap trimming.

        This is primarily useful after large analysis/capture objects have been
        released and the service wants to return unused heap pages to the OS on
        Linux/glibc systems. Failures are intentionally ignored.
        """
        gc.collect()

        try:
            libc = ctypes.CDLL("libc.so.6")
            malloc_trim = getattr(libc, "malloc_trim", None)
            if callable(malloc_trim):
                malloc_trim(0)
        except Exception as exc:
            logging.getLogger(ProcessMemory.__name__).debug(
                "malloc_trim not available or failed: %s",
                exc,
            )
