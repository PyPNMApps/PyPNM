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
