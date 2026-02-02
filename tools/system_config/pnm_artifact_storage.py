#!/usr/bin/env python3
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia


import json
import sys
from pathlib import Path

from common import (
    JsonObject,
    JSON_INDENT_WIDTH,
    DEFAULT_CONFIG_PATH,
    SystemJsonEditorBase,
)

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))


class PnmArtifactStorageEditor(SystemJsonEditorBase):
    """
    Interactive Editor For The PnmArtifactStorage Section.

    Updates compression policy and cache settings for artifact storage,
    then displays and applies the proposed configuration when confirmed.
    """

    def _section(self) -> JsonObject:
        section = self.data.get("PnmArtifactStorage")
        if not isinstance(section, dict):
            section = {}
            self.data["PnmArtifactStorage"] = section
        return section

    @staticmethod
    def _prompt_float(label: str, current: float | None) -> float | None:
        if current is None:
            prompt = f"{label} (currently unset, Enter to keep unset): "
        else:
            prompt = f"{label} [current: {current}] (Enter to keep): "
        value = input(prompt).strip()
        if value == "":
            return None
        try:
            return float(value)
        except ValueError:
            print("Invalid float input; ignoring change.")
            return None

    @staticmethod
    def _prompt_list(label: str, current: list[str] | None) -> list[str] | None:
        current_value = ", ".join(current or [])
        prompt = f"{label} [current: {current_value}] (comma-separated, Enter to keep): "
        value = input(prompt).strip()
        if value == "":
            return None
        items = [item.strip() for item in value.split(",") if item.strip()]
        return items

    def run(self) -> int:
        """
        Run The Interactive PnmArtifactStorage Editor.

        Prompts for compression and cache settings, then displays and
        applies the proposed changes when confirmed.
        """
        section = self._section()

        compression = section.get("compression")
        if not isinstance(compression, dict):
            compression = {}
            section["compression"] = compression

        cache = section.get("cache")
        if not isinstance(cache, dict):
            cache = {}
            section["cache"] = cache

        print("Editing PnmArtifactStorage in system.json\n")
        print("List prompts use comma-separated values, for example:")
        print("  Deny list (PNM types) [current: ds_ofdm_chan_est_coef] (comma-separated, Enter to keep):\n")

        enabled_new = self.prompt_bool("Compression enabled", compression.get("enabled"))
        min_bytes_new = self.prompt_int("Compression min_bytes", compression.get("min_bytes"))
        max_ratio_new = self._prompt_float("Conditional max ratio", compression.get("conditional_max_ratio"))
        min_savings_new = self.prompt_int(
            "Conditional min savings bytes",
            compression.get("conditional_min_savings_bytes"),
        )
        deny_new = self._prompt_list("Deny list (PNM types)", compression.get("deny"))
        always_new = self._prompt_list("Always list (PNM types)", compression.get("always"))
        conditional_new = self._prompt_list("Conditional list (PNM types)", compression.get("conditional"))
        primary_codec_new = self.prompt_str("Primary codec (zstd/gzip)", compression.get("primary_codec"))
        gzip_fallback_new = self.prompt_bool("Allow gzip fallback", compression.get("gzip_fallback"))
        zstd_level_new = self.prompt_int("Zstd level", compression.get("zstd_level"))
        gzip_level_new = self.prompt_int("Gzip level", compression.get("gzip_level"))

        tmp_root_new = self.prompt_str("Cache tmp_root", cache.get("tmp_root"))
        ingress_dir_new = self.prompt_str("Cache ingress_dir", cache.get("ingress_dir"))
        materialized_dir_new = self.prompt_str("Cache materialized_dir", cache.get("materialized_dir"))
        ingress_ttl_new = self.prompt_int("Ingress TTL seconds", cache.get("ingress_ttl_seconds"))
        materialized_ttl_new = self.prompt_int("Materialized TTL seconds", cache.get("materialized_ttl_seconds"))
        cleanup_interval_new = self.prompt_int("Cleanup interval seconds", cache.get("cleanup_interval_seconds"))

        if enabled_new is not None:
            compression["enabled"] = enabled_new
        if min_bytes_new is not None:
            compression["min_bytes"] = min_bytes_new
        if max_ratio_new is not None:
            compression["conditional_max_ratio"] = max_ratio_new
        if min_savings_new is not None:
            compression["conditional_min_savings_bytes"] = min_savings_new
        if deny_new is not None:
            compression["deny"] = deny_new
        if always_new is not None:
            compression["always"] = always_new
        if conditional_new is not None:
            compression["conditional"] = conditional_new
        if primary_codec_new is not None:
            compression["primary_codec"] = primary_codec_new
        if gzip_fallback_new is not None:
            compression["gzip_fallback"] = gzip_fallback_new
        if zstd_level_new is not None:
            compression["zstd_level"] = zstd_level_new
        if gzip_level_new is not None:
            compression["gzip_level"] = gzip_level_new

        if tmp_root_new is not None:
            cache["tmp_root"] = tmp_root_new
        if ingress_dir_new is not None:
            cache["ingress_dir"] = ingress_dir_new
        if materialized_dir_new is not None:
            cache["materialized_dir"] = materialized_dir_new
        if ingress_ttl_new is not None:
            cache["ingress_ttl_seconds"] = ingress_ttl_new
        if materialized_ttl_new is not None:
            cache["materialized_ttl_seconds"] = materialized_ttl_new
        if cleanup_interval_new is not None:
            cache["cleanup_interval_seconds"] = cleanup_interval_new

        print("\nProposed changes:")
        print(json.dumps({"PnmArtifactStorage": section}, indent=JSON_INDENT_WIDTH))

        confirm = input("\nApply these changes? [y/N]: ").strip().lower()
        if confirm != "y":
            print("Changes discarded.")
            return 0

        self._save()
        print(f"Updated {self.config_path}")
        return 0


def main() -> int:
    """
    Main Entry Point For The PnmArtifactStorage Editor.

    Prompts for the configuration path and runs the interactive editor
    for the PnmArtifactStorage section.
    """
    config_path = SystemJsonEditorBase.prompt_config_path(DEFAULT_CONFIG_PATH)
    editor      = PnmArtifactStorageEditor(config_path)
    return editor.run()


if __name__ == "__main__":
    raise SystemExit(main())
