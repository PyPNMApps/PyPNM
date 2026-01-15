# PyPNM - Support Bundle Builder

Create Sanitized Support Bundles For PNM File And Capture Issues.

## Table Of Contents

- [Overview](#overview)
- [What Gets Collected](#what-gets-collected)
- [Sanitization Rules](#sanitization-rules)
- [Command-Line Usage](#command-line-usage)
- [Examples](#examples)
  - [1. Build Bundle From A Single Transaction ID](#1-build-bundle-from-a-single-transaction-id)
  - [2. Build Bundle From An Operation ID (Multi-Capture)](#2-build-bundle-from-an-operation-id-multi-capture)
  - [3. Build Bundle From A MAC Address](#3-build-bundle-from-a-mac-address)
  - [4. Build Bundle With No Sanitization](#4-build-bundle-with-no-sanitization)
- [Bundle Layout](#bundle-layout)
- [Submitting A Bundle](#submitting-a-bundle)

## Overview

The **Support Bundle Builder** is an offline helper script that creates a
sanitized archive (.zip) containing only the PNM files and metadata required to
debug a specific PyPNM issue.

Instead of sharing your full `.data/` tree, you can run this tool locally and
send a compact bundle that contains:

- Only the captures relevant to your issue (by Transaction ID, Operation ID, or MAC).
- Sanitized MAC addresses (rewritten to `aa:bb:cc:dd:ee:ff` by default).
- Sanitized `system_description` fields using the canonical demo descriptor:

```json
{
  "HW_REV":  "1.0",
  "VENDOR":  "LANCity",
  "BOOTR":   "NONE",
  "SW_REV":  "1.0.0",
  "MODEL":   "LCPET-3"
}
```

The original data stays on your system. The bundle is safe to attach to a
support ticket or email when requesting help.

## What Gets Collected

Given a set of input selectors (Transaction ID, Operation ID, or MAC address),
the tool:

1. Uses the configured DB backend (SQLite or Postgres) to discover the relevant transactions
   via `transaction_records`, `capture_groups`, and `operation_captures`.

2. Resolves each transaction into:

   - The capture file under `.data/pnm`
   - The corresponding transaction record from the transaction DB

3. Builds a temporary **support dataset** under a working directory using the
   same structure as `.data`:

```text
.data/
  pnm/
    <capture files>
  db/
    pypnm.sqlite3
```

4. Sanitizes the dataset (MAC address, filename MAC fragments, and
   `system_description`) so it can be safely shared.

5. Packs the dataset into a ZIP file using the `ArchiveManager.zip_files`
   helper. Unless you pass an absolute `--output-zip` path, the ZIP is created
   under an `issues/` directory in the current working tree.

## Sanitization Rules

By default, the support bundle is sanitized to remove customer-specific identity
details while preserving structure and relative relationships.

### MAC Address

- All MAC addresses in:
  - Transaction JSON records (`mac_address` field)
  - Filenames that include MAC fragments
  - Any capture files passed through `pnm-mac-updater.py`
- Are rewritten to the generic MAC address:

```text
aa:bb:cc:dd:ee:ff
```

This preserves per-modem grouping while removing the original hardware identity.

### System Descriptor

For each transaction record that includes `device_details.system_description`,
the script overwrites the contents with the canonical demo descriptor:

```json
{
  "HW_REV":  "1.0",
  "VENDOR":  "LANCity",
  "BOOTR":   "NONE",
  "SW_REV":  "1.0.0",
  "MODEL":   "LCPET-3"
}
```

This keeps the field present (so parsing and models behave normally) but removes
real vendor and model information.

### Opt-Out

Optional flags allow you to keep real MAC addresses and/or system descriptions
when absolutely necessary for debugging. See the [Examples](#examples) section
for usage notes.

## Command-Line Usage

The support bundle script is intended to live under `tools/`:

```text
tools/build/support_bundle_builder.py
```

Basic invocation:

```bash
./tools/build/support_bundle_builder.py [OPTIONS]
```

Core selectors (you must provide at least one):

- `--transaction-id TRANSACTION_ID`  
  Build a bundle for a single transaction.

- `--operation-id OPERATION_ID`  
  Build a bundle containing all transactions associated with a multi-capture
  operation.

- `--mac-address MAC_ADDRESS`  
  Build a bundle containing all transactions and captures for a cable modem
  MAC address.

Sanitization and behavior flags:

- `--keep-original-mac`  
  Keep the original MAC address in JSON and filenames, and skip binary MAC
  rewriting. By default, all MAC addresses are sanitized to `aa:bb:cc:dd:ee:ff`.

- `--keep-original-sysdescr`  
  Keep the original `device_details.system_description` instead of the demo
  descriptor.

- `--output-zip PATH`  
  Name or path of the output ZIP file. When PATH is relative (the default is
  `pypnm_support_bundle.zip`), the file is written under the `issues/`
  directory (for example, `issues/pypnm_support_bundle.zip`). When PATH is
  absolute, it is used as-is.

- `--support-root PATH`  
  Temporary working directory used to construct the `.data` tree before zipping
  (default: `.support_bundle`). This directory can be safely deleted after the
  bundle is created.

- `--clean-output`  
  Remove any existing `--support-root` directory before building the bundle.

- `--verbose`  
  Enable per-file logging during bundle creation.

The script prints the final ZIP file path at the end, for example:

```text
Support bundle created at: issues/pypnm_support_bundle.zip
```

## Examples

### 1. Build Bundle From A Single Transaction ID

You have a failing analysis for a single capture and want to share that file and
its metadata only.

```bash
./tools/build/support_bundle_builder.py   --transaction-id ea18519a572e2487
```

Results:

- All files and JSON records related to `ea18519a572e2487` are copied into a
  temporary `.data` tree.
- MAC address and system_description are sanitized.
- A ZIP file is created under `issues/` and the full path is printed.

### 2. Build Bundle From An Operation ID (Multi-Capture)

You ran a multi-capture test (for example, multi-RxMER or multi-constellation)
and want to share the entire capture group.

```bash
./tools/build/support_bundle_builder.py   --operation-id ed2fcba02bba42f6
```

The tool:

1. Looks up the capture group for `ed2fcba02bba42f6` via the operation DB.
2. Retrieves all transaction IDs listed for that group.
3. Collects all related capture files and transaction records.
4. Sanitizes and archives them into a single support bundle ZIP under `issues/`.

### 3. Build Bundle From A MAC Address

You suspect a specific modem is mis-behaving and want to share all captures
PyPNM has stored for that MAC address.

```bash
./tools/build/support_bundle_builder.py   --mac-address aa:bb:cc:dd:ee:ff
```

All transactions whose `mac_address` matches the provided value are included in
the bundle, and the sanitized ZIP is written to `issues/pypnm_support_bundle.zip`
by default.

### 4. Build Bundle With No Sanitization

If you are working in a lab environment and want to keep the real MAC and
system_description values, you can disable sanitization:

```bash
./tools/build/support_bundle_builder.py   --transaction-id ea18519a572e2487   \
                                    --keep-original-mac                 \
                                    --keep-original-sysdescr
```

Use this only when you are comfortable with sharing identifying details.

## Bundle Layout

Inside the ZIP file, the support bundle uses a **minimal** `.data` layout that
mirrors the PyPNM runtime structure but contains only the files needed to
reproduce the issue:

```text
.data/
  pnm/
    ds_ofdm_rxmer_per_subcar_aa_bb_cc_dd_ee_ff_194_1764820674.bin
    ds_ofdm_constellation_aa_bb_cc_dd_ee_ff_194_1764820678.bin
    ...
  db/
    pypnm.sqlite3
```

Key points:

- Only PNM files and JSON metadata for the selected transactions are included.
- Paths are relative to `.data/` so the bundle can be dropped into another
  PyPNM instance for reproduction.
- If sanitization is enabled, the contents are safe to share outside your
  environment.

## Submitting A Bundle

When you open a support request for PyPNM, include:

1. The generated ZIP file (for example:  
   `issues/pypnm_support_bundle.zip`)

2. A short description of the problem:
   - Which endpoint or CLI command you used.
   - What you expected to happen.
   - The actual error message or behavior.

3. Any relevant screenshots or logs (for example, `logs/pypnm.log`).

With a sanitized support bundle attached, PyPNM maintainers can reproduce and
investigate issues without requiring full access to your production data.
