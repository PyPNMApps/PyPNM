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


class SnmpEditor(SystemJsonEditorBase):
    """
    Interactive Editor For The SNMP Section.

    Updates the SNMP timeout plus selected v2c and v3 parameters. Shows
    current values, prompts for replacements, and commits changes only
    after user confirmation.
    """

    def _snmp(self) -> JsonObject:
        section = self.data.get("SNMP")
        if not isinstance(section, dict):
            section = {}
            self.data["SNMP"] = section
        return section

    def _version_section(self, version: str) -> JsonObject:
        snmp = self._snmp()
        versions = snmp.get("version")
        if not isinstance(versions, dict):
            versions = {}
            snmp["version"] = versions

        entry = versions.get(version)
        if not isinstance(entry, dict):
            entry = {}
            versions[version] = entry
        return entry

    def run(self) -> int:
        """
        Run The Interactive SNMP Editor.

        Prompts for SNMP timeout, v2c enable/retries/communities, and v3
        enable/retries/security parameters. Displays a summary of the
        proposed changes and writes them when confirmed.
        """
        snmp = self._snmp()
        v2c  = self._version_section("2c")
        v3   = self._version_section("3")

        print("Editing SNMP in system.json\n")

        timeout_new = self.prompt_int("SNMP timeout (seconds)", snmp.get("timeout"))

        v2c_enable_new  = self.prompt_bool("SNMP v2c enable", v2c.get("enable"))
        v2c_retries_new = self.prompt_int("SNMP v2c retries", v2c.get("retries"))
        v2c_read_new    = self.prompt_str("SNMP v2c read_community", v2c.get("read_community"))
        v2c_write_new   = self.prompt_str("SNMP v2c write_community", v2c.get("write_community"))

        v3_enable_new   = self.prompt_bool("SNMP v3 enable", v3.get("enable"))
        v3_retries_new  = self.prompt_int("SNMP v3 retries", v3.get("retries"))
        v3_user_new     = self.prompt_str("SNMP v3 username", v3.get("username"))
        v3_sec_new      = self.prompt_str("SNMP v3 securityLevel", v3.get("securityLevel"))
        v3_authp_new    = self.prompt_str("SNMP v3 authProtocol", v3.get("authProtocol"))
        v3_authpw_new   = self.prompt_str("SNMP v3 authPassword", v3.get("authPassword"))
        v3_privp_new    = self.prompt_str("SNMP v3 privProtocol", v3.get("privProtocol"))
        v3_privpw_new   = self.prompt_str("SNMP v3 privPassword", v3.get("privPassword"))

        if timeout_new is not None:
            snmp["timeout"] = timeout_new

        if v2c_enable_new is not None:
            v2c["enable"] = v2c_enable_new
        if v2c_retries_new is not None:
            v2c["retries"] = v2c_retries_new
        if v2c_read_new is not None:
            v2c["read_community"] = v2c_read_new
        if v2c_write_new is not None:
            v2c["write_community"] = v2c_write_new

        if v3_enable_new is not None:
            v3["enable"] = v3_enable_new
        if v3_retries_new is not None:
            v3["retries"] = v3_retries_new
        if v3_user_new is not None:
            v3["username"] = v3_user_new
        if v3_sec_new is not None:
            v3["securityLevel"] = v3_sec_new
        if v3_authp_new is not None:
            v3["authProtocol"] = v3_authp_new
        if v3_authpw_new is not None:
            v3["authPassword"] = v3_authpw_new
        if v3_privp_new is not None:
            v3["privProtocol"] = v3_privp_new
        if v3_privpw_new is not None:
            v3["privPassword"] = v3_privpw_new

        print("\nProposed changes:")
        print(json.dumps({"SNMP": snmp}, indent=JSON_INDENT_WIDTH))

        confirm = input("\nApply these changes? [y/N]: ").strip().lower()
        if confirm != "y":
            print("Changes discarded.")
            return 0

        self._save()
        print(f"Updated {self.config_path}")
        return 0


def main() -> int:
    """
    Main Entry Point For The SNMP Editor.

    Prompts for the configuration path and runs the interactive SNMP
    editor against that system.json file.
    """
    config_path = SystemJsonEditorBase.prompt_config_path(DEFAULT_CONFIG_PATH)
    editor      = SnmpEditor(config_path)
    return editor.run()


if __name__ == "__main__":
    raise SystemExit(main())
