# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from collections import deque

from pypnm.lib.types import FloatSeries


class MovingAverage:
    """
    Class for calculating a moving average of a list of numerical values.
    """

    def __init__(
        self, data: FloatSeries | None = None, exclude_value: float | None = None
    ) -> None:
        """
        Initialize the MovingAverage object.

        Parameters:
        - data (List[float]): List of numerical values.
        - exclude_value (float): Value to exclude from calculations, if any.
        """
        self.entries = deque(data or [])
        self.exclude_value = exclude_value
        self.exclude_value_set = exclude_value is not None

    def add(self, entry: float) -> None:
        """
        Add a numerical value to the list.

        Parameters:
        - entry (float): Numerical value to add to the list.
        """
        self.entries.append(entry)

    def size(self) -> int:
        """
        Get the size of the current list.

        Returns:
        - int: Size of the list.
        """
        return len(self.entries)

    def _calculate_window_average(self, window_data: FloatSeries) -> float | None:
        """
        Calculate the average of a window.

        Parameters:
        - window_data (List[float]): List of numerical values within the window.

        Returns:
        - Optional[float]: Calculated average or None if the window is empty.
        """
        if not window_data:
            return None
        return sum(window_data) / len(window_data)

    def get_average(self, window: int) -> list[float | None]:
        """
        Calculate the moving average over a specified window size.

        Parameters:
        - window (int): Size of the moving average window.

        Returns:
        - List[Optional[float]]: List of calculated moving averages.
        """
        average_list = []

        for i, entry in enumerate(self.entries):
            if self.exclude_value_set and entry == self.exclude_value:
                continue

            window_data = list(self.entries)[max(0, i - window + 1) : i + 1]
            average = self._calculate_window_average(window_data)
            average_list.append(average)

        return average_list
