#!/usr/bin/env python3
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia


import json
import sys
from pathlib import Path
from typing import Any

from common import (
    JsonObject,
    JSON_INDENT_WIDTH,
    DEFAULT_CONFIG_PATH,
    SystemJsonEditorBase,
)

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))



class PnmBulkDataTransferEditor(SystemJsonEditorBase):
    """
    Interactive Editor For The PnmBulkDataTransfer Section.

    Updates the bulk method plus TFTP, HTTP, and HTTPS parameters. Shows
    current values, prompts for new values, and writes changes after the
    user confirms the proposed configuration.
    """

    def _section(self) -> JsonObject:
        section = self.data.get("PnmBulkDataTransfer")
        if not isinstance(section, dict):
            section = {}
            self.data["PnmBulkDataTransfer"] = section
        return section

    def run(self) -> int:
        """
        Run The Interactive PnmBulkDataTransfer Editor.

        Allows editing of the 'method' field along with TFTP ip_v4/ip_v6
        and remote_dir, plus HTTP and HTTPS base_url and port values.
        """
        section = self._section()

        tftp = section.get("tftp")
        if not isinstance(tftp, dict):
            tftp = {}
            section["tftp"] = tftp

        http = section.get("http")
        if not isinstance(http, dict):
            http = {}
            section["http"] = http

        https = section.get("https")
        if not isinstance(https, dict):
            https = {}
            section["https"] = https

        print("Editing PnmBulkDataTransfer in system.json\n")

        method_new     = self.prompt_str("Bulk method (tftp/http/https)", section.get("method"))
        tftp_ipv4_new  = self.prompt_str("TFTP ip_v4", tftp.get("ip_v4"))
        tftp_ipv6_new  = self.prompt_str("TFTP ip_v6", tftp.get("ip_v6"))
        tftp_dir_new   = self.prompt_str("TFTP remote_dir", tftp.get("remote_dir"))
        http_base_new  = self.prompt_str("HTTP base_url", http.get("base_url"))
        http_port_new  = self.prompt_int("HTTP port", http.get("port"))
        https_base_new = self.prompt_str("HTTPS base_url", https.get("base_url"))
        https_port_new = self.prompt_int("HTTPS port", https.get("port"))

        if method_new is not None:
            section["method"] = method_new

        if tftp_ipv4_new is not None:
            tftp["ip_v4"] = tftp_ipv4_new
        if tftp_ipv6_new is not None:
            tftp["ip_v6"] = tftp_ipv6_new
        if tftp_dir_new is not None:
            tftp["remote_dir"] = tftp_dir_new

        if http_base_new is not None:
            http["base_url"] = http_base_new
        if http_port_new is not None:
            http["port"] = http_port_new

        if https_base_new is not None:
            https["base_url"] = https_base_new
        if https_port_new is not None:
            https["port"] = https_port_new

        print("\nProposed changes:")
        print(json.dumps({"PnmBulkDataTransfer": section}, indent=JSON_INDENT_WIDTH))

        confirm = input("\nApply these changes? [y/N]: ").strip().lower()
        if confirm != "y":
            print("Changes discarded.")
            return 0

        self._save()
        print(f"Updated {self.config_path}")
        return 0


def main() -> int:
    """
    Main Entry Point For The PnmBulkDataTransfer Editor.

    Prompts for the configuration path and runs the interactive editor
    for the PnmBulkDataTransfer section.
    """
    config_path = SystemJsonEditorBase.prompt_config_path(DEFAULT_CONFIG_PATH)
    editor      = PnmBulkDataTransferEditor(config_path)
    return editor.run()


if __name__ == "__main__":
    raise SystemExit(main())
