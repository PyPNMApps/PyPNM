# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026

from __future__ import annotations

from pathlib import Path

import pytest

from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.api.routes.docs.pnm.files.service import PnmFileService
from pypnm.config.pnm_artifact_storage import PnmArtifactStorageConfig
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.mac_address import MacAddress
from pypnm.pnm.parser.pnm_file_type import PnmFileType
from pypnm.pnm.parser.pnm_type_header_mapper import PnmFileTypeMapper

DATA_DIR = Path(__file__).parent / "files"


def _patch_upload_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    pnm_dir = tmp_path / "pnm"
    transaction_db = tmp_path / "transactions.json"
    artifact_cache_root = tmp_path / "artifact-cache"

    pnm_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(
        SystemConfigSettings,
        "pnm_dir",
        classmethod(lambda cls: str(pnm_dir)),
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

    return pnm_dir


@pytest.mark.pnm
@pytest.mark.parametrize(
    "filename, expected_file_type",
    [
        ("rxmer.bin", PnmFileType.RECEIVE_MODULATION_ERROR_RATIO),
        ("channel_estimation.bin", PnmFileType.OFDM_CHANNEL_ESTIMATE_COEFFICIENT),
        ("const_display.bin", PnmFileType.DOWNSTREAM_CONSTELLATION_DISPLAY),
        ("histogram.bin", PnmFileType.DOWNSTREAM_HISTOGRAM),
        ("fec_summary.bin", PnmFileType.OFDM_FEC_SUMMARY),
        ("modulation_profile.bin", PnmFileType.OFDM_MODULATION_PROFILE),
        ("spectrum_analyzer.bin", PnmFileType.SPECTRUM_ANALYSIS),
        ("us_pre_equalizer_coef.bin", PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS),
        ("us_pre_equalizer_coef_last.bin", PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE),
    ],
)
def test_upload_file_accepts_supported_fixture_types(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
    expected_file_type: PnmFileType,
) -> None:
    pnm_dir = _patch_upload_paths(tmp_path, monkeypatch)
    service = PnmFileService()

    payload = (DATA_DIR / filename).read_bytes()
    response = service.upload_file(filename=filename, data=payload)

    stored_path = pnm_dir / response.filename
    assert stored_path.is_file()

    record = PnmFileTransaction().get_record(response.transaction_id)
    assert record is not None
    assert record["filename"] == response.filename
    assert str(MacAddress(record["mac_address"])) == str(MacAddress(response.mac_address))
    assert record["pnm_test_type"] == PnmFileTypeMapper.get_test_type(expected_file_type).name
