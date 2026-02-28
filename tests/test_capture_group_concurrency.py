# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from multiprocessing import get_context
from multiprocessing.synchronize import Event
from pathlib import Path

from pypnm.api.routes.common.classes.file_capture.capture_group import CaptureGroup
from pypnm.lib.types import GroupId, TransactionId


def _add_transaction_worker(
    db_path: str,
    group_id: GroupId,
    txn_id: TransactionId,
    ready_event: Event,
    start_event: Event,
) -> None:
    ready_event.set()
    start_event.wait(5.0)
    capture_group = CaptureGroup(group_id=group_id, db_path=Path(db_path))
    capture_group.add_transaction(txn_id)


def test_capture_group_add_transaction_concurrent_processes(tmp_path: Path) -> None:
    ctx = get_context("fork")
    process_count = 250
    db_path = tmp_path / "capture_group.json"
    group_id = GroupId("group-250")

    CaptureGroup(group_id=group_id, db_path=db_path).create_group()

    start_event = ctx.Event()
    ready_events: list[Event] = []
    processes = []
    txn_ids = [TransactionId(f"txn-{idx}") for idx in range(process_count)]

    for txn_id in txn_ids:
        ready_event = ctx.Event()
        proc = ctx.Process(
            target=_add_transaction_worker,
            args=(str(db_path), group_id, txn_id, ready_event, start_event),
        )
        proc.start()
        ready_events.append(ready_event)
        processes.append(proc)

    assert all(ev.wait(5.0) for ev in ready_events)
    start_event.set()

    for proc in processes:
        proc.join(10.0)
        assert proc.exitcode == 0

    capture_group = CaptureGroup(group_id=group_id, db_path=db_path)
    collected = set(capture_group.getTransactionIds())
    assert collected == set(txn_ids)
