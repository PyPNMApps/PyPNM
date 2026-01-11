# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import os
from typing import Any

from pydantic import BaseModel

from pypnm.config.pnm_config_manager import SystemConfigSettings
from pypnm.lib.file_processor import FileProcessor
from pypnm.lib.types import PathLike


class LogFile:
    @classmethod
    def write(
        cls,
        fname: PathLike,
        data: BaseModel | dict[Any, Any] | str | bytes,
        log_dir: PathLike | None = None,
    ) -> None:
        """
        Write log data.

        Supports:
        ----------
        - BaseModel  → serialized via `.model_dump_json(indent=2)`
        - dict       → serialized as JSON string
        - str/bytes  → written directly
        """
        if log_dir is None:
            log_dir = SystemConfigSettings.log_dir()
        full_path = os.path.join(log_dir, str(fname))
        fp = FileProcessor(full_path)

        if isinstance(data, BaseModel):
            fp.write_file(data.model_dump_json(indent=2))

        elif isinstance(data, dict):
            from json import dumps

            fp.write_file(dumps(data, indent=2))

        else:
            fp.write_file(data)

        fp.close()
