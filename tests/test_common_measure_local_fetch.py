# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from pypnm.api.routes.common.extended.common_measure_service import CommonMeasureService
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.lib.types import FileNameStr, TransactionId
from pypnm.pnm.lib.pnm_artifact_store import ArtifactCommitResult


@pytest.mark.asyncio
async def test_handle_local_fetch_retries_until_file_appears(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = CommonMeasureService.__new__(CommonMeasureService)
    service.logger = logging.getLogger("CommonMeasureService")
    service.log_prefix = "CommonMeasureService"

    src_dir = tmp_path / "src"
    src_dir.mkdir(parents=True)
    dest_path = tmp_path / "dest" / "capture.bin"
    filename = "capture.bin"

    monkeypatch.setattr(
        "pypnm.api.routes.common.extended.common_measure_service.SystemConfigSettings.local_src_dir",
        lambda: str(src_dir),
    )
    monkeypatch.setattr(
        "pypnm.api.routes.common.extended.common_measure_service.SystemConfigSettings.file_retrieval_retries",
        lambda: 3,
    )

    sleep_count = {"count": 0}

    async def fake_sleep(_: float) -> None:
        sleep_count["count"] += 1
        if sleep_count["count"] == 1:
            (src_dir / filename).write_bytes(b"payload")

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    status = await service._handle_local_fetch(filename, dest_path)

    assert status == ServiceStatusCode.SUCCESS
    assert dest_path.exists()
    assert dest_path.read_bytes() == b"payload"


@pytest.mark.asyncio
async def test_get_and_move_pnm_file_uses_fallback_ingress_when_default_not_writable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = CommonMeasureService.__new__(CommonMeasureService)
    service.logger = logging.getLogger("CommonMeasureService")
    service.log_prefix = "CommonMeasureService"
    service.pnm_test_type = SimpleNamespace(name="DS_OFDM_RXMER_PER_SUBCAR")

    default_ingress = tmp_path / "default-ingress" / "capture.bin"
    fallback_root = tmp_path / "tmp-pypnm"
    expected_fallback_parent = fallback_root / "ingress-1001"
    expected_fallback_path = expected_fallback_parent / "capture.bin"

    commit_paths: list[Path] = []

    class _FakeArtifactStore:
        def ingress_path(self, filename: FileNameStr, transaction_id: TransactionId | None = None) -> Path:
            return default_ingress

        def commit_ingress_file(self, pnm_type: str, ingress_path: Path, original_filename: FileNameStr) -> ArtifactCommitResult:
            commit_paths.append(ingress_path)
            return ArtifactCommitResult(
                stored_filename=FileNameStr(Path(str(original_filename)).name),
                stored_path=ingress_path,
                compression=None,
                size_before=1,
                size_after=1,
            )

    service._artifact_store = _FakeArtifactStore()
    service._get_transaction_id_by_filename = lambda _name: "tx-1"

    async def fake_local_fetch(_filename: str, dest_path: Path) -> ServiceStatusCode:
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        dest_path.write_bytes(b"x")
        return ServiceStatusCode.SUCCESS

    service._handle_local_fetch = fake_local_fetch

    monkeypatch.setattr(
        "pypnm.api.routes.common.extended.common_measure_service.SystemConfigSettings.retrieval_method",
        lambda: "local",
    )
    monkeypatch.setattr(
        "pypnm.api.routes.common.extended.common_measure_service.os.access",
        lambda path, mode: path != default_ingress.parent,
    )
    monkeypatch.setattr(
        "pypnm.api.routes.common.extended.common_measure_service.os.getuid",
        lambda: 1001,
    )
    monkeypatch.setattr(
        "pypnm.api.routes.common.extended.common_measure_service.Path",
        lambda *parts: Path(str(fallback_root)) if parts == ("/tmp/pypnm",) else Path(*parts),
    )
    monkeypatch.setattr(
        "pypnm.api.routes.common.extended.common_measure_service.PnmFileTransaction.update_record_compression",
        lambda self, trans_id, fn, comp: True,
    )

    status, commit_result = await service._get_and_move_pnm_file(FileNameStr("capture.bin"))

    assert status == ServiceStatusCode.SUCCESS
    assert commit_result is not None
    assert commit_paths == [expected_fallback_path]

