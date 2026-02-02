# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pydantic import BaseModel, Field


class ArtifactCompressionPolicyConfig(BaseModel):
    enabled: bool = Field(..., description="Enable policy-driven compression for PNM artifacts.")
    min_bytes: int = Field(..., description="Skip compression for artifacts smaller than this size in bytes.")
    conditional_max_ratio: float = Field(..., description="Maximum compressed/original ratio to allow conditional compression.")
    conditional_min_savings_bytes: int = Field(..., description="Minimum byte savings required for conditional compression.")
    deny: list[str] = Field(default_factory=list, description="PNM types that never compress.")
    always: list[str] = Field(default_factory=list, description="PNM types that always compress.")
    conditional: list[str] = Field(default_factory=list, description="PNM types that compress if thresholds are met.")
    primary_codec: str = Field(..., description="Primary compression codec (zstd).")
    gzip_fallback: bool = Field(..., description="Allow gzip when zstd is unavailable.")
    zstd_level: int = Field(..., description="Zstd compression level.")
    gzip_level: int = Field(..., description="Gzip compression level.")


class ArtifactCacheConfig(BaseModel):
    tmp_root: str = Field(..., description="Root directory for ephemeral artifact caches.")
    ingress_dir: str = Field(..., description="Ingress cache directory name under tmp_root.")
    materialized_dir: str = Field(..., description="Materialized cache directory name under tmp_root.")
    ingress_ttl_seconds: int = Field(..., description="Ingress cache TTL in seconds.")
    materialized_ttl_seconds: int = Field(..., description="Materialized cache TTL in seconds.")
    cleanup_interval_seconds: int = Field(..., description="Minimum seconds between opportunistic cleanups.")


class PnmArtifactStorageConfig(BaseModel):
    compression: ArtifactCompressionPolicyConfig = Field(..., description="Artifact compression policy configuration.")
    cache: ArtifactCacheConfig = Field(..., description="Artifact cache configuration.")

    @classmethod
    def defaults(cls) -> PnmArtifactStorageConfig:
        return cls(
            compression=ArtifactCompressionPolicyConfig(
                enabled=True,
                min_bytes=4096,
                conditional_max_ratio=0.92,
                conditional_min_savings_bytes=8192,
                deny=["ds_ofdm_chan_est_coef"],
                always=["ds_ofdm_codeword_error_rate", "ds_ofdm_modulation_profile"],
                conditional=["ds_ofdm_rxmer_per_subcar", "us_pre_equalizer_coef"],
                primary_codec="zstd",
                gzip_fallback=True,
                zstd_level=3,
                gzip_level=6,
            ),
            cache=ArtifactCacheConfig(
                tmp_root="/tmp/pypnm",
                ingress_dir="ingress",
                materialized_dir="materialized",
                ingress_ttl_seconds=900,
                materialized_ttl_seconds=86400,
                cleanup_interval_seconds=3600,
            ),
        )

    @classmethod
    def from_config(cls, config: dict[str, object] | None) -> PnmArtifactStorageConfig:
        if not isinstance(config, dict):
            return cls.defaults()
        try:
            return cls(**config)
        except Exception:
            return cls.defaults()
