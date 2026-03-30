# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import os
import time
from pathlib import Path

from pytest import MonkeyPatch

from pypnm.config.pnm_artifact_storage import (
    ArtifactCacheConfig,
    ArtifactCompressionPolicyConfig,
    PnmArtifactStorageConfig,
)
from pypnm.config.system_config_settings import SystemConfigSettings
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
    assert materialized.parent.name == str(txn_id)
    assert materialized.parent.parent.name == "materialized"


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


def test_tmp_shared_root_permissions_sets_0777_for_owned_tree(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    cfg = _build_config(tmp_path / "tmp", min_bytes=0)
    pnm_dir = tmp_path / "pnm"
    store = PnmArtifactStore(config=cfg, pnm_dir=pnm_dir)
    store._tmp_root = Path("/tmp/pypnm")

    calls: dict[str, list[tuple[object, ...]]] = {"chmod": []}
    owned_uid = 1234

    monkeypatch.setattr("os.getuid", lambda: owned_uid)
    monkeypatch.setattr(Path, "rglob", lambda self, _pattern: [Path("/tmp/pypnm/ingress"), Path("/tmp/pypnm/materialized")])
    monkeypatch.setattr(
        Path,
        "stat",
        lambda self: type("Stat", (), {"st_uid": owned_uid, "st_mtime": 0.0})(),
    )
    monkeypatch.setattr(
        "os.chmod",
        lambda path, mode: calls["chmod"].append((Path(path), mode)),
    )

    store._ensure_tmp_pypnm_permissions()

    assert calls["chmod"] == [
        (Path("/tmp/pypnm"), 0o777),
        (Path("/tmp/pypnm/ingress"), 0o777),
        (Path("/tmp/pypnm/materialized"), 0o777),
    ]


def test_tmp_shared_root_permissions_skips_non_owned_paths(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    cfg = _build_config(tmp_path / "tmp", min_bytes=0)
    pnm_dir = tmp_path / "pnm"
    store = PnmArtifactStore(config=cfg, pnm_dir=pnm_dir)
    store._tmp_root = Path("/tmp/pypnm")

    calls: dict[str, list[tuple[object, ...]]] = {"chmod": []}
    owner_uid = 1111
    other_uid = 2222

    monkeypatch.setattr("os.getuid", lambda: owner_uid)
    monkeypatch.setattr(Path, "rglob", lambda self, _pattern: [Path("/tmp/pypnm/owned"), Path("/tmp/pypnm/foreign")])

    def _fake_stat(path: Path) -> object:
        uid = owner_uid if path == Path("/tmp/pypnm/owned") else other_uid
        return type("Stat", (), {"st_uid": uid, "st_mtime": 0.0})()

    monkeypatch.setattr(Path, "stat", _fake_stat)
    monkeypatch.setattr(
        "os.chmod",
        lambda path, mode: calls["chmod"].append((Path(path), mode)),
    )

    store._ensure_tmp_pypnm_permissions()

    assert calls["chmod"] == [(Path("/tmp/pypnm/owned"), 0o777)]


def test_tmp_permissions_skip_non_shared_root(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    cfg = _build_config(tmp_path / "tmp", min_bytes=0)
    pnm_dir = tmp_path / "pnm"
    store = PnmArtifactStore(config=cfg, pnm_dir=pnm_dir)

    calls: dict[str, int] = {"chmod": 0}

    monkeypatch.setattr("os.chmod", lambda *args, **kwargs: calls.__setitem__("chmod", calls["chmod"] + 1))

    store._ensure_tmp_pypnm_permissions()

    assert calls["chmod"] == 0


def test_cache_dirs_fallback_to_user_scoped_when_unwritable(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    cfg = _build_config(tmp_path / "tmp", min_bytes=0)
    pnm_dir = tmp_path / "pnm"

    uid = 1001
    ingress_default = (tmp_path / "tmp" / "ingress").resolve()
    materialized_default = (tmp_path / "tmp" / "materialized").resolve()
    ingress_fallback = (tmp_path / "tmp" / f"ingress-{uid}").resolve()
    materialized_fallback = (tmp_path / "tmp" / f"materialized-{uid}").resolve()

    monkeypatch.setattr("os.getuid", lambda: uid)
    real_access = os.access

    def _fake_access(path: object, mode: int) -> bool:
        p = Path(path).resolve()
        if p in (ingress_default, materialized_default):
            return False
        if p in (ingress_fallback, materialized_fallback):
            return True
        return real_access(path, mode)

    monkeypatch.setattr("os.access", _fake_access)

    store = PnmArtifactStore(config=cfg, pnm_dir=pnm_dir)

    assert store._ingress_dir == ingress_fallback
    assert store._materialized_dir == materialized_fallback
    assert store._ingress_dir.exists()
    assert store._materialized_dir.exists()


def test_load_pnm_dir_falls_back_to_system_config(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    cfg = _build_config(tmp_path / "tmp", min_bytes=0)
    fallback_pnm_dir = tmp_path / "configured-pnm"

    monkeypatch.setattr("pypnm.pnm.lib.pnm_artifact_store.ConfigManager.get", lambda self, *args: None)
    monkeypatch.setattr(SystemConfigSettings, "pnm_dir", lambda: str(fallback_pnm_dir))

    store = PnmArtifactStore(config=cfg, pnm_dir=None)

    assert store._pnm_dir == fallback_pnm_dir
