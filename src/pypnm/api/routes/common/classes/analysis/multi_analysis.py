# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from typing import Any, cast, overload

from pypnm.api.routes.common.classes.analysis.analysis import (
    Analysis,
    BaseAnalysisModel,
)
from pypnm.lib.types import ChannelId


class MultiAnalysis:
    """
    Container for managing multiple `Analysis` objects and their associated models.

    This class is designed to:
    - Store multiple `Analysis` instances.
    - Provide easy access to their models and combined data.
    - Convert collected models into Python dictionaries for JSON serialization.
    """

    def __init__(self) -> None:
        """Initialize an empty MultiAnalysis container."""
        self._analysis_list: list[Analysis] = []
        self._models: list[BaseAnalysisModel] = []
        self._dicts: list[dict[str, Any]] = []

    @overload
    def add(self, analysis: Analysis) -> None: ...

    @overload
    def add(self, channel_id: ChannelId, analysis: Analysis) -> None: ...

    def add(self, *args: Any, **kwargs: Any) -> None:
        """
        Add a new `Analysis` to the collection, optionally binding it to a channel.

        Supported call forms
        --------------------
        - add(analysis)
        - add(channel_id, analysis)

        Parameters
        ----------
        args :
            Positional arguments matching one of the supported call forms.
        kwargs :
            Keyword arguments are not supported and will raise an error.

        Raises
        ------
        TypeError
            If the arguments do not match one of the supported call forms.
        """
        if kwargs:
            raise TypeError("add() does not accept keyword arguments")

        channel_id: ChannelId | None
        analysis: Analysis

        if len(args) == 1 and isinstance(args[0], Analysis):
            channel_id = None
            analysis = args[0]
        elif len(args) == 2 and isinstance(args[1], Analysis):
            channel_id = cast(ChannelId, args[0])
            analysis = cast(Analysis, args[1])
        else:
            raise TypeError("add() expects (analysis) or (channel_id, analysis)")

        models = cast(list[BaseAnalysisModel], analysis.get_model())

        if channel_id is not None:
            for model in models:
                model.channel_id = channel_id

        self._models.extend(models)

        dicts = analysis.get_dicts()
        if dicts:
            self._dicts.extend(dicts)

        self._analysis_list.append(analysis)

    def get_analyses(self) -> list[Analysis]:
        """
        Retrieve all stored analyses.

        Returns
        -------
        List[Analysis]
            A list of Analysis objects in the order they were added.
        """
        return self._analysis_list

    def length(self) -> int:
        """
        Get the total number of stored analyses.

        Returns
        -------
        int
            The count of stored Analysis objects.
        """
        return len(self._analysis_list)

    def to_model(self) -> list[BaseAnalysisModel]:
        """
        Get a flattened list of all models from all analyses.

        Returns
        -------
        List[BaseAnalysisModel]
            A list of all models collected from the added analyses.
        """
        return self._models

    def to_dict(self) -> dict[str, Any]:
        """
        Convert all collected analysis data into a structured dictionary.

        Returns
        -------
        Dict[str, Any]
            A dictionary containing all collected analysis dictionaries.

        Example
        -------
        >>> multi_analysis.to_dict()
        {
            "analyses": [
                {"channel_id": 1, "metrics": {...}},
                {"channel_id": 2, "metrics": {...}}
            ]
        }
        """
        return {"analyses": self._dicts if self._dicts else []}
