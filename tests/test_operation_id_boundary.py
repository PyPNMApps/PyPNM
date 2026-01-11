# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import inspect
from importlib import import_module
from pkgutil import walk_packages

from pydantic import BaseModel

import pypnm.api.routes as api_routes
from pypnm.api.routes.advance.multi_ds_chan_est.schemas import (
    MultiChanEstimationStartResponse,
)
from pypnm.api.routes.advance.multi_rxmer.schemas import MultiRxMerStartResponse


def _iter_schema_module_names() -> list[str]:
    modules: list[str] = []
    for module_info in walk_packages(api_routes.__path__, f"{api_routes.__name__}."):
        name = module_info.name
        if (
            name.endswith(".schemas")
            or name.endswith(".schema")
            or ".schemas." in name
            or ".schema." in name
        ):
            modules.append(name)
    return modules


def _iter_pydantic_models(module: object) -> list[type[BaseModel]]:
    classes: list[type[BaseModel]] = []
    for obj in vars(module).values():
        if not inspect.isclass(obj):
            continue
        if not issubclass(obj, BaseModel) or obj is BaseModel:
            continue
        classes.append(obj)
    return classes


def test_no_sg_operation_id_in_schema_models() -> None:
    offenders: list[str] = []
    for module_name in _iter_schema_module_names():
        module = import_module(module_name)
        offenders.extend(
            [
                f"{module_name}.{model.__name__}"
                for model in _iter_pydantic_models(module)
                if "sg_operation_id" in model.model_fields
            ]
        )
    assert not offenders, f"sg_operation_id found in schema models: {offenders}"


def test_start_responses_include_operation_id() -> None:
    start_models = [MultiChanEstimationStartResponse, MultiRxMerStartResponse]
    for model in start_models:
        assert "operation_id" in model.model_fields
