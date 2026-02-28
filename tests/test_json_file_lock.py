# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from pypnm.lib.db.json_file_lock import JsonFileLock


def _hold_lock(target: Path, ready: threading.Event, release: threading.Event) -> None:
    with JsonFileLock(target, timeout=1.0, poll_interval=0.01):
        ready.set()
        release.wait(1.0)


def test_json_file_lock_timeout(tmp_path: Path) -> None:
    target = tmp_path / "capture_group.json"
    target.write_text("{}", encoding="utf-8")

    ready = threading.Event()
    release = threading.Event()
    thread = threading.Thread(target=_hold_lock, args=(target, ready, release))
    thread.start()

    assert ready.wait(1.0)
    with pytest.raises(TimeoutError), JsonFileLock(target, timeout=0.1, poll_interval=0.01):
        pass

    release.set()
    thread.join()
