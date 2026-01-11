# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from typing import Any, NewType

from pypnm.lib.types import ChannelId

MultiBasicAnalysis = NewType("MultiBasicAnalysis", dict[ChannelId, Any])
