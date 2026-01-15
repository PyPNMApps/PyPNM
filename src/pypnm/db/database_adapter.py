# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from typing import Protocol


class DatabaseAdapter(Protocol):
    """
    Minimal DB adapter contract for backend lifecycle control.
    """

    def connect(self) -> None:
        """Establish a backend connection."""

    def close(self) -> None:
        """Close any active backend connection."""

    def apply_schema(self) -> None:
        """Apply minimal schema assets required by the adapter."""

    def healthcheck(self) -> bool:
        """Return True when the backend is reachable and healthy."""
