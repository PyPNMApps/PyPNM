from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
from enum import Enum


class OperationState(str, Enum):
    """
    Enumeration of possible states for a periodic capture operation.

    Attributes:
        RUNNING:
            The capture task is currently in progress.
        COMPLETED:
            The capture task finished normally (duration elapsed).
        STOPPED:
            The capture task was halted early by user request.
        UNKNOWN:
            The operation ID is not recognized or the state cannot be determined.
    """

    RUNNING = "running"  # Task is active and samples are being collected
    COMPLETED = "completed"  # Task reached its full duration and ended
    STOPPED = "stopped"  # Task was explicitly stopped before completion
    UNKNOWN = "unknown"  # No such operation ID or state is indeterminate
