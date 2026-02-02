## Agent Review Bundle Summary
- Goal: Show list prompt example in PnmArtifactStorage menu editor.
- Changes: Added inline list prompt example before inputs.
- Files: See file list below.
- Tests: `ruff check src`, `pytest -q`.
- Notes: None.
# FILE: docs/system/menu.md
# PyPNM system configuration menu

Interactive Wrapper For Editing `system.json` Using Dedicated Helper Scripts.

This menu script provides a single entry point for all configuration helpers that
operate on the canonical PyPNM configuration file managed by `ConfigManager`.

- **Menu Script**: `tools/system_config/menu.py`
- **Section Editors**: `tools/system_config/*.py`
- **File Setup Helper**: `tools/pnm/pnm_file_retrieval_setup.py`

## Table of contents

[Overview](#overview)  
[Prerequisites](#prerequisites)  
[Launching-The-Menu](#launching-the-menu)  
[Menu-Options](#menu-options)  
[Configuration-Path-Handling](#configuration-path-handling)  
[Typical-Workflow](#typical-workflow)  
[Related-Files](#related-files)

## Overview

The **PyPNM System Configuration Menu** is a small interactive tool that wraps all
of the `system.json` editors into a single, easy-to-use interface.

Instead of remembering individual script names, you can launch one menu and
select which configuration section you want to edit:

- Default FastAPI request parameters.
- SNMP settings.
- Bulk-data transfer settings.
- PNM file retrieval behavior.
- Logging options.
- TestMode flags.
- Initial PNM file-retrieval directory setup.

The menu script itself never modifies `system.json` directly. It only dispatches
to the underlying editor scripts, each of which shows the current values,
prompts for new ones, and asks for confirmation before writing anything.

> **Note:** Because the menu shells out to the individual editors, any validation logic or confirmations live in those scripts. You can quit at any time before approving a change.

## Prerequisites

1. You are running from the **project root**, for example:

   ```bash
   cd /path/to/PyPNM
   ```

2. The **virtual environment** is activated (if you use one), for example:

   ```bash
   source .env/bin/activate
   ```

3. `src/` is at the standard location so that `ConfigManager` can resolve the
   canonical configuration file.

> **Tip:** Activate the same virtual environment you use for `pypnm` before launching the menu so the helper scripts inherit the correct dependencies and config paths.

## Launching the menu

From the project root, run:

```bash
python tools/system_config/menu.py
```

You should see output similar to:

```text
PyPNM System Configuration Menu
================================
Select an option:
  1) Edit FastApiRequestDefault
  2) Edit SNMP
  3) Edit PnmBulkDataTransfer
  4) Edit PnmFileRetrieval (retrieval_method only)
  5) Edit PnmArtifactStorage
  6) Edit Logging
  7) Edit TestMode
  8) Run PnmFileRetrieval Setup (directory initialization)
  q) Quit
Enter selection:
```

The menu stays active until you choose `q` to quit.

## Menu options

Each menu entry launches a dedicated script using the same Python interpreter
that invoked `menu.py`. The underlying scripts remain fully interactive and
preserve their own confirmation prompts.

### 1. Edit FastApiRequestDefault

- **Script**: `tools/system_config/fastapi_request_default.py`
- **Config Section**: `FastApiRequestDefault`

This editor updates the default MAC address and IP address used by PyPNM
FastAPI request models.

It will:

- Read the current `FastApiRequestDefault` values.
- Prompt you for new values (press Enter to keep the existing ones).
- Show a JSON preview of the proposed section.
- Ask for confirmation before saving.

### 2. Edit SNMP

- **Script**: `tools/system_config/snmp.py`
- **Config Section**: `SNMP`

This editor manages global SNMP settings, including:

- Top-level timeout.
- SNMP v2c enable/retries/communities.
- SNMP v3 enable/retries/security parameters.

As with other editors, you can:

- Press Enter to keep existing values.
- Change only the fields you care about.
- Review the final JSON subset before applying it.

### 3. Edit PnmBulkDataTransfer

- **Script**: `tools/system_config/pnm_bulk_data_transfer.py`
- **Config Section**: `PnmBulkDataTransfer`

This editor updates the transport parameters used when a cable modem sends PNM
files (RxMER, FEC Summary, etc.) to a server.

It allows you to modify:

- The preferred bulk method (`tftp`, `http`, or `https`).
- TFTP `ip_v4`, `ip_v6`, and `remote_dir`.
- HTTP/HTTPS `base_url` and `port` values.

Only the fields you explicitly change are updated; the rest of the section is
preserved as-is.

### 4. Edit PnmFileRetrieval (retrieval_method only)

- **Script**: `tools/system_config/pnm_file_retrieval.py`
- **Config Section**: `PnmFileRetrieval.retrieval_method`

This editor **only** touches the retrieval behavior, leaving all storage
directories and JSON database paths unchanged.

It manages:

- `retrieval_method.method`
- `retrieval_method.methods.local.src_dir`

The prompt for the method uses the pipe-separated form:

```text
Retrieval method (local | tftp | sftp | http | https)
```

This lets you switch between local-directory retrieval, TFTP, SFTP, or
HTTP(S)-based retrieval without accidentally altering any of the PNM storage
layout fields.

### 5. Edit PnmArtifactStorage

- **Script**: `tools/system_config/pnm_artifact_storage.py`
- **Config Section**: `PnmArtifactStorage`

This editor updates compression policy and cache settings for artifact storage.

It supports:

- Compression enable/threshold settings.
- Compression lists (deny/always/conditional) using comma-separated input.
- Codec selection and levels.
- Cache root and subdirectory names.
- Cache TTLs and cleanup interval.

List prompts show the current values, for example:

```text
Deny list (PNM types) [current: ds_ofdm_chan_est_coef] (comma-separated, Enter to keep):
```

### 6. Edit logging

- **Script**: `tools/system_config/logging_config.py`
- **Config Section**: `logging`

This editor controls how PyPNM logs are written:

- `log_level` (for example `DEBUG`, `INFO`, `WARN`, `ERROR`)
- `log_dir` (directory where logs are stored)
- `log_filename` (primary log file name)

It prints a small JSON preview of the updated `logging` section before asking
for confirmation.

### 7. Edit TestMode

- **Script**: `tools/system_config/testmode.py`
- **Config Section**: `TestMode`

This editor manages the global and per-class **TestMode** flags used by PyPNM
for synthetic/demo operation.

It supports:

- A global `TestMode.global.mode.enable` toggle.
- A single per-class override per run via `TestMode.class_name.<Class>.mode.enable`.

Typical usage:

1. Turn on global TestMode for development.
2. Optionally enable or disable TestMode for a specific class.

As with all editors, no changes are written until you confirm the proposed
configuration.

### 8. Run PnmFileRetrieval setup (directory initialization)

- **Script**: `tools/pnm/pnm_file_retrieval_setup.py`
- **Config Section(s)**: Reads `PnmFileRetrieval`

This helper focuses on the **filesystem side** of PNM file handling. It reads
the `PnmFileRetrieval` configuration and ensures that the required directories
exist on disk (for example the `.data/*` folders configured for PNM binaries,
CSV, JSON, PNG, archives, and metadata).

Typical behavior:

- Inspect the configured PNM storage and database paths.
- Create any missing directories, preserving existing contents.
- Provide a summary of what was created or already present.

This script does not change `system.json`; it only reconciles the filesystem
with whatever configuration is already present.

> **Warning:** Run the setup helper from the project root so the relative paths in `system.json` resolve correctly; otherwise you may end up creating directories in unexpected locations.

## Configuration path handling

All of the section editors and the setup helper ultimately operate on the same
configuration file used by the PyPNM runtime, resolved via `ConfigManager`.

The **default path** is derived from:

- `pypnm.config.config_manager.ConfigManager`
- Correct project layout (for example `src/pypnm/settings/system.json`)

When you launch any editor from the menu, you will see a prompt similar to:

```text
Path to system.json [<resolved-path>]:
```

You can:

- Press Enter to use the default path reported by `ConfigManager`, or
- Type a custom path (for example a staging or test configuration file).

This makes it easy to test changes on a copy of `system.json` before applying
them to a production configuration.

## Typical workflow

A suggested flow when bringing up a new environment:

1. **Verify FastAPI Defaults**  
   Use option `1` to set a default `mac_address` and `ip_address` appropriate
   for your lab device (for example `aa:bb:cc:dd:ee:ff` and `192.168.0.100`).

2. **Configure SNMP**  
   Use option `2` to set `timeout`, `retries`, and the correct SNMP v2c or v3
   credentials for your deployment.

3. **Configure Bulk Transfer**  
   Use option `3` to make sure the modem sends PNM files to a reachable TFTP or
   HTTP(S) server.

4. **Configure File Retrieval Behavior**  
   Use option `4` to select `local` vs `tftp`/`sftp`/`http`/`https`
   for how PyPNM retrieves PNM files and to point `local.src_dir` at the right
   directory when using local retrieval.

5. **Initialize PNM Directories**  
   Use option `7` to run the PnmFileRetrieval setup helper, creating any missing
   `.data/*` directories referenced by `PnmFileRetrieval`.

6. **Tune Logging And TestMode**  
   Use options `5` and `6` to control logging verbosity and TestMode behavior
   for development, integration testing, or demo environments.

## Related files

Key files involved in the system configuration tooling:

- `src/pypnm/settings/system.json`  
  Canonical configuration file loaded by `ConfigManager` and used by all PyPNM
  components.

- `src/pypnm/config/config_manager.py`  
  Implements `ConfigManager`, which resolves the configuration path and
  exposes helpers for reading and writing the JSON file.

- `tools/system_config/common.py`  
  Shared helpers and base class used by all section editors, including prompt
  utilities and default-config-path resolution via `ConfigManager`.

- `tools/system_config/menu.py`  
  Interactive menu entry point that dispatches to each editor and the PNM file
  retrieval setup helper.

- `tools/pnm/pnm_file_retrieval_setup.py`  
  Directory and filesystem setup helper, ensuring the paths defined under
  `PnmFileRetrieval` exist on disk.
# FILE: tools/system_config/menu.py
#!/usr/bin/env python3
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia


import subprocess
import sys
from pathlib import Path


class SystemConfigMenu:
    """
    Interactive Wrapper For PyPNM System Configuration Tools.

    Provides a text-based menu for invoking individual system.json
    editors and the PnmFileRetrieval setup helper. Each menu item
    launches the corresponding script using the current Python
    interpreter, preserving the existing interactive behavior of the
    underlying tools.
    """

    def __init__(self) -> None:
        self.base_dir  = Path(__file__).resolve().parent
        self.tools_dir = self.base_dir.parent

        self.fastapi_request_default = self.base_dir / "fastapi_request_default.py"
        self.snmp                    = self.base_dir / "snmp.py"
        self.pnm_bulk_data_transfer  = self.base_dir / "pnm_bulk_data_transfer.py"
        self.pnm_file_retrieval      = self.base_dir / "pnm_file_retrieval.py"
        self.pnm_artifact_storage    = self.base_dir / "pnm_artifact_storage.py"
        self.logging_config          = self.base_dir / "logging_config.py"
        self.testmode                = self.base_dir / "testmode.py"

        # pnm_file_retrieval_setup.py sits one level up in tools/
        self.pnm_file_setup          = self.tools_dir / "pnm_file_retrieval_setup.py"
        # Resolve config via shared helper (handles deploy vs baked-in paths)
        try:
            from .common import _default_config_path  # type: ignore[attr-defined]
        except Exception:
            # Allow running as a script without package context
            sys.path.insert(0, str(self.base_dir))
            from common import _default_config_path  # type: ignore[attr-defined]

        self.config_path             = _default_config_path()

    def _print_header(self) -> None:
        print("\nPyPNM System Configuration Menu")
        print("================================")

    def _print_menu(self) -> None:
        self._print_header()
        print("Select an option:")
        print("  1) Edit FastApiRequestDefault")
        print("  2) Edit SNMP")
        print("  3) Edit PnmBulkDataTransfer")
        print("  4) Edit PnmFileRetrieval (retrieval_method only)")
        print("  5) Edit PnmArtifactStorage")
        print("  6) Edit Logging")
        print("  7) Edit TestMode")
        print("  8) Run PnmFileRetrieval Setup (directory initialization)")
        print("  p) Print current system.json")
        print("  q) Quit")

    def _run_script(self, script_path: Path) -> int:
        """
        Execute A Child Script Using The Current Python Interpreter.

        Parameters
        ----------
        script_path:
            Full path to the script that should be invoked.

        Returns
        -------
        int
            Exit code returned by the child process.
        """
        if not script_path.exists():
            print(f"\nError: script not found: {script_path}\n")
            return 1

        print(f"\nRunning: {script_path}\n")
        result = subprocess.run(
            [sys.executable, str(script_path)],
            check=False,
        )
        if result.returncode != 0:
            print(f"\nScript exited with code {result.returncode}\n")
        else:
            print("\nScript completed successfully.\n")
        return result.returncode

    def run(self) -> int:
        """
        Run The Interactive System Configuration Menu.

        Presents a numbered menu, accepts user selections, and dispatches
        to the corresponding configuration helper script until the user
        chooses to quit.
        """
        while True:
            self._print_menu()
            try:
                choice = input("Enter selection: ").strip().lower()
            except KeyboardInterrupt:
                print("\n(CTRL-C ignored; use 'q' or Ctrl-D to exit)\n")
                continue
            except EOFError:
                choice = ""  # Ctrl-D

            if choice in ("\x1b", ""):  # Esc or empty -> exit
                print("Exiting System Configuration Menu.")
                self._print_post_hint()
                return 0

            if choice in ("q", "quit", "x"):
                print("Exiting System Configuration Menu.")
                self._print_post_hint()
                return 0

            if choice == "1":
                self._run_script(self.fastapi_request_default)
                continue

            if choice == "2":
                self._run_script(self.snmp)
                continue

            if choice == "3":
                self._run_script(self.pnm_bulk_data_transfer)
                continue

            if choice == "4":
                self._run_script(self.pnm_file_retrieval)
                continue

            if choice == "5":
                self._run_script(self.pnm_artifact_storage)
                continue

            if choice == "6":
                self._run_script(self.logging_config)
                continue

            if choice == "7":
                self._run_script(self.testmode)
                continue

            if choice == "8":
                self._run_script(self.pnm_file_setup)
                continue

            if choice == "p":
                self._print_config()
                continue

            print("Invalid selection, please try again.\n")

        return 0

    def _print_config(self) -> None:
        """
        Print the current system.json contents to the console.
        """
        if not self.config_path.exists():
            print(f"\nConfig file not found at {self.config_path}\n")
            return

        try:
            content = self.config_path.read_text(encoding="utf-8")
        except Exception as exc:
            print(f"\nFailed to read config: {exc}\n")
            return

        print("\nCurrent system.json:\n")
        print(content)
        print()

        self._print_post_hint()

    def _print_post_hint(self) -> None:
        cfg = str(self.config_path)
        if cfg.startswith("/app/"):
            print("Next step: sudo docker compose restart pypnm-api\n")
        else:
            print("Reminder: reload PyPNM after changes, e.g.:")
            print("  curl -X GET http://127.0.0.1:8000/pypnm/system/webService/reload -H 'accept: application/json'\n")


def main() -> int:
    """
    Main Entry Point For The System Configuration Menu.

    Constructs the menu wrapper and starts the interactive loop that
    allows the user to launch individual configuration tools.
    """
    menu = SystemConfigMenu()
    return menu.run()


if __name__ == "__main__":
    raise SystemExit(main())
7
# FILE: tools/system_config/pnm_artifact_storage.py
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
