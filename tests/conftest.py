# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import pytest
from tests.ledger_guard import guard_legacy_ledger_reads


@pytest.fixture(autouse=True)
def _guard_legacy_ledgers_for_pnm_tests(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    if request.node.get_closest_marker("pnm") is None:
        return
    guard_legacy_ledger_reads(monkeypatch)
