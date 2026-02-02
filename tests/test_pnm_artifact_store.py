# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import os
import time
from pathlib import Path

from pypnm.config.pnm_artifact_storage import (
    ArtifactCacheConfig,
    ArtifactCompressionPolicyConfig,
    PnmArtifactStorageConfig,
)
from pypnm.lib.types import FileNameStr, TransactionId
from pypnm.pnm.lib.pnm_artifact_store import PnmArtifactStore


def _build_config(tmp_root: Path, min_bytes: int) -> PnmArtifactStorageConfig:
    return PnmArtifactStorageConfig(
        compression=ArtifactCompressionPolicyConfig(
            enabled=True,
            min_bytes=min_bytes,
            conditional_max_ratio=0.92,
            conditional_min_savings_bytes=8192,
            deny=[],
            always=["test_type"],
            conditional=[],
            primary_codec="gzip",
            gzip_fallback=False,
            zstd_level=3,
            gzip_level=6,
        ),
        cache=ArtifactCacheConfig(
            tmp_root=str(tmp_root),
            ingress_dir="ingress",
            materialized_dir="materialized",
            ingress_ttl_seconds=900,
            materialized_ttl_seconds=86400,
            cleanup_interval_seconds=0,
        ),
    )


def test_commit_ingress_file_gzip_compresses(tmp_path: Path) -> None:
    cfg = _build_config(tmp_path / "tmp", min_bytes=0)
    pnm_dir = tmp_path / "pnm"
    store = PnmArtifactStore(config=cfg, pnm_dir=pnm_dir)

    txn_id = TransactionId("tx1")
    ingress = store.ingress_path(FileNameStr("test.bin"), txn_id)
    ingress.write_bytes(b"0" * 10000)

    result = store.commit_ingress_file("test_type", ingress, FileNameStr("test.bin"))
    assert str(result.stored_filename).endswith(".gz")
    assert result.compression is not None
    assert result.compression.get("is_compressed") is True
    assert result.size_after < result.size_before


def test_commit_ingress_file_min_bytes_skips_compression(tmp_path: Path) -> None:
    cfg = _build_config(tmp_path / "tmp", min_bytes=20000)
    pnm_dir = tmp_path / "pnm"
    store = PnmArtifactStore(config=cfg, pnm_dir=pnm_dir)

    ingress = store.ingress_path(FileNameStr("test.bin"), TransactionId("tx2"))
    ingress.write_bytes(b"1" * 10000)

    result = store.commit_ingress_file("test_type", ingress, FileNameStr("test.bin"))
    assert str(result.stored_filename).endswith("test.bin")
    assert result.compression is not None
    assert result.compression.get("is_compressed") is False


def test_materialize_decompresses_gzip(tmp_path: Path) -> None:
    cfg = _build_config(tmp_path / "tmp", min_bytes=0)
    pnm_dir = tmp_path / "pnm"
    store = PnmArtifactStore(config=cfg, pnm_dir=pnm_dir)

    txn_id = TransactionId("tx3")
    ingress = store.ingress_path(FileNameStr("test.bin"), txn_id)
    payload = b"abc" * 5000
    ingress.write_bytes(payload)

    result = store.commit_ingress_file("test_type", ingress, FileNameStr("test.bin"))
    materialized = store.materialize(txn_id, result.stored_filename, result.compression)

    assert materialized.read_bytes() == payload


def test_resolve_physical_path_prefers_raw_when_missing_compressed(tmp_path: Path) -> None:
    cfg = _build_config(tmp_path / "tmp", min_bytes=0)
    pnm_dir = tmp_path / "pnm"
    store = PnmArtifactStore(config=cfg, pnm_dir=pnm_dir)

    raw_path = pnm_dir / "raw.bin"
    raw_path.write_bytes(b"raw")

    compression = {
        "is_compressed": True,
        "codec": "zstd",
        "level": 3,
        "size_before": 3,
        "size_after": 2,
    }
    resolved = store.resolve_physical_path(FileNameStr("raw.bin"), compression)
    assert resolved == raw_path


def test_cleanup_dir_keeps_recent_empty_dirs(tmp_path: Path) -> None:
    cfg = _build_config(tmp_path / "tmp", min_bytes=0)
    pnm_dir = tmp_path / "pnm"
    store = PnmArtifactStore(config=cfg, pnm_dir=pnm_dir)

    recent = store.ingress_path(FileNameStr("recent.bin"), TransactionId("recent"))
    recent.write_bytes(b"r")

    old_file = store.ingress_path(FileNameStr("old.bin"), TransactionId("old"))
    old_file.write_bytes(b"o")
    old_time = time.time() - 1000
    os.utime(old_file, (old_time, old_time))

    store._cleanup_dir(store._ingress_dir, ttl_seconds=900)

    assert recent.exists()
    assert not old_file.exists()
