# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026

from __future__ import annotations

from pathlib import Path

import pytest

from pypnm.api.routes.common.classes.common_endpoint_classes.common.enum import (
    AnalysisType,
    OutputType,
)
from pypnm.api.routes.docs.pnm.files.schemas import FileAnalysisRequest
from pypnm.api.routes.docs.pnm.files.service import PnmFileService
from pypnm.config.pnm_artifact_storage import PnmArtifactStorageConfig
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.mac_address import MacAddress
from pypnm.pnm.parser.pnm_file_type import PnmFileType

DATA_DIR = Path(__file__).parent / "files"


def _patch_file_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pnm_dir = tmp_path / "pnm"
    archive_dir = tmp_path / "archive"
    transaction_db = tmp_path / "transactions.json"
    artifact_cache_root = tmp_path / "artifact-cache"

    pnm_dir.mkdir(parents=True, exist_ok=True)
    archive_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(
        SystemConfigSettings,
        "pnm_dir",
        classmethod(lambda cls: str(pnm_dir)),
        raising=False,
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "archive_dir",
        classmethod(lambda cls: str(archive_dir)),
        raising=False,
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "transaction_db",
        classmethod(lambda cls: str(transaction_db)),
        raising=False,
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "pnm_artifact_storage",
        classmethod(
            lambda cls: PnmArtifactStorageConfig.from_config(
                {
                    "compression": {
                        "enabled": False,
                        "min_bytes": 4096,
                        "conditional_max_ratio": 0.92,
                        "conditional_min_savings_bytes": 8192,
                        "deny": [],
                        "always": [],
                        "conditional": [],
                        "primary_codec": "zstd",
                        "gzip_fallback": True,
                        "zstd_level": 3,
                        "gzip_level": 6,
                    },
                    "cache": {
                        "tmp_root": str(artifact_cache_root),
                        "ingress_dir": "ingress",
                        "materialized_dir": "materialized",
                        "ingress_ttl_seconds": 900,
                        "materialized_ttl_seconds": 86400,
                        "cleanup_interval_seconds": 3600,
                    },
                }
            )
        ),
        raising=False,
    )


def _build_analysis_request(transaction_id: str, output_type: OutputType = OutputType.JSON) -> FileAnalysisRequest:
    return FileAnalysisRequest.model_validate(
        {
            "search": {
                "transaction_id": transaction_id,
            },
            "analysis": {
                "type": AnalysisType.BASIC,
                "output": {
                    "type": output_type,
                },
                "plot": {
                    "ui": {
                        "theme": "dark",
                    },
                },
            },
        }
    )


@pytest.mark.pnm
def test_uploaded_spectrum_file_supports_basic_analysis(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_file_storage(tmp_path, monkeypatch)
    service = PnmFileService()

    upload = service.upload_file(
        filename="spectrum_analyzer.bin",
        data=(DATA_DIR / "spectrum_analyzer.bin").read_bytes(),
    )

    analysis_model, file_type = service.get_analysis(_build_analysis_request(upload.transaction_id))

    assert file_type == PnmFileType.SPECTRUM_ANALYSIS
    assert str(MacAddress(analysis_model.mac_address)) == str(MacAddress(upload.mac_address))
    assert analysis_model.channel_id >= 0
    assert analysis_model.signal_analysis.bin_bandwidth > 0
    assert analysis_model.signal_analysis.segment_length > 0
    assert analysis_model.signal_analysis.frequencies
    assert analysis_model.signal_analysis.magnitudes
    assert len(analysis_model.signal_analysis.frequencies) == len(analysis_model.signal_analysis.magnitudes)


@pytest.mark.pnm
def test_uploaded_spectrum_file_supports_archive_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_file_storage(tmp_path, monkeypatch)
    service = PnmFileService()

    upload = service.upload_file(
        filename="spectrum_analyzer.bin",
        data=(DATA_DIR / "spectrum_analyzer.bin").read_bytes(),
    )

    archive = service.get_archive(_build_analysis_request(upload.transaction_id, OutputType.ARCHIVE))

    assert archive.path is not None
    assert Path(str(archive.path)).is_file()
    assert str(archive.path).endswith(".zip")
