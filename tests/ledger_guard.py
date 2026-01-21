# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import builtins
from pathlib import Path

import pytest

_DEFAULT_LEDGER_FILES: tuple[str, ...] = ("transactions.json",)


def guard_legacy_ledger_reads(
    monkeypatch: pytest.MonkeyPatch,
    ledger_files: tuple[str, ...] = _DEFAULT_LEDGER_FILES,
) -> None:
    """
    Fail fast if legacy ledger files are opened or read during tests.
    """
    original_open = Path.open
    original_read_text = Path.read_text
    original_read_bytes = Path.read_bytes
    original_builtin_open = builtins.open
    blocked = {name.lower() for name in ledger_files}

    def _is_blocked(value: object) -> bool:
        if isinstance(value, Path):
            name = value.name
        elif isinstance(value, str):
            name = Path(value).name
        else:
            return False
        return name.lower() in blocked

    def _guarded_open(
        self: Path, *args: tuple[object, ...], **kwargs: dict[str, object]
    ) -> object:
        if _is_blocked(self):
            raise AssertionError(f"Unexpected JSON ledger access: {self}")
        return original_open(self, *args, **kwargs)

    def _guarded_read_text(
        self: Path, *args: tuple[object, ...], **kwargs: dict[str, object]
    ) -> str:
        if _is_blocked(self):
            raise AssertionError(f"Unexpected JSON ledger access: {self}")
        return original_read_text(self, *args, **kwargs)

    def _guarded_read_bytes(self: Path) -> bytes:
        if _is_blocked(self):
            raise AssertionError(f"Unexpected JSON ledger access: {self}")
        return original_read_bytes(self)

    def _guarded_builtin_open(
        file: object, *args: tuple[object, ...], **kwargs: dict[str, object]
    ) -> object:
        if _is_blocked(file):
            raise AssertionError(f"Unexpected JSON ledger access: {file}")
        return original_builtin_open(file, *args, **kwargs)

    monkeypatch.setattr(Path, "open", _guarded_open)
    monkeypatch.setattr(Path, "read_text", _guarded_read_text)
    monkeypatch.setattr(Path, "read_bytes", _guarded_read_bytes)
    monkeypatch.setattr(builtins, "open", _guarded_builtin_open)
