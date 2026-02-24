# PyPNM Demonstration

This directory contains demonstration configuration and (optionally) example PNM files that can be used to explore
PyPNM without talking to a live cable modem or TFTP server.

Demo mode is intended for evaluations, training, and UI development where you want to exercise the analysis stack
(single-capture and multi-capture workflows) using pre-collected PNM data.

## What demo mode does

When you install PyPNM with **demo mode** enabled, the installer:

1. Backs up your current system configuration to:

   ```text
   backup/src/pypnm/settings/system.json
   ```

2. Copies the demo configuration into place:

   ```text
   demo/settings/system.json  →  src/pypnm/settings/system.json
   ```

The `demo/settings/system.json` file is pre-configured so that all relevant paths (capture directories, analysis
outputs, etc.) point into the `demo/` tree. This lets you use the PyPNM CLI and FastAPI service against
pre-built PNM files instead of live captures.

## Enabling demo mode

From the project root:

```bash
./install.sh --demo-mode
```

This will:

- Create or update the virtual environment
- Install PyPNM and its dependencies
- Run the test suite
- Back up the existing `src/pypnm/settings/system.json`
- Replace it with `demo/settings/system.json`

To revert to your original (production) configuration:

```bash
./install.sh --production
```

This restores `src/pypnm/settings/system.json` from the backup created earlier.

If you installed into a custom demo environment (for example, `.env-demo`), activate it with:

```bash
source .env-demo/bin/activate
```

## Preparing and sanitizing demo data

PyPNM includes helper tools under `tools/` to build and sanitize a demo dataset that is safe to share.

### Copy project data into the demo tree

The demo sanitizer can copy existing captures from the project `.data/` tree into a demo dataset:

```bash
./tools/pnm/pnm-demo-sanitizer.py --copy-data --demo-root demo
```

This copies:

```text
.data/*  →  demo/.demo/*
```

Use this when you want to create a self-contained demo dataset based on your current local PNM captures.

### Clean the demo dataset

To wipe any existing demo content and start fresh:

```bash
./tools/pnm/pnm-demo-sanitizer.py --clean-demo \
                              --demo-root demo
```

This removes all subdirectories under the demo dataset root:

- If `demo/.demo/` exists, it removes `demo/.demo/*` subdirectories.
- Otherwise, it removes subdirectories directly under `demo/`.

Files at the root level are left intact.

You can combine cleaning and copying in one step:

```bash
./tools/pnm/pnm-demo-sanitizer.py --clean-demo  \
                              --copy-data   \
                              --demo-root demo
```

### Sanitize MAC addresses and system details

For sharing or publishing, you typically do not want real MAC addresses or device identifiers in the demo data.
The demo sanitizer uses transaction JSON files as **ground truth** and rewrites both metadata and filenames.

Common workflow (full reset, copy, and sanitize):

```bash
./tools/pnm/pnm-demo-sanitizer.py   --clean-demo                  \
                                --copy-data                   \
                                --force-new-mac               \
                                --new-mac aa:bb:cc:dd:ee:ff   \
                                --demo-root demo
```

This will:

- Clean the current demo dataset
- Copy `.data/*` into `demo/.demo/*`
- Scan transaction JSON files under `demo/.demo`
- For each transaction entry:
  - Locate the capture file by `filename`
  - Rewrite the binary MAC using `pnm-mac-updater.py --mac-address aa:bb:cc:dd:ee:ff --file <capture>`
  - Rename the capture file so the MAC chunk in the filename matches `aa:bb:cc:dd:ee:ff`
  - Update the JSON entry:
    - `mac_address` → `aa:bb:cc:dd:ee:ff`
    - `filename` → updated filename
    - `device_details.system_description` → generic demo values:
    - If canonical API response JSON is present, sanitize:
      - `device.mac_address` → `aa:bb:cc:dd:ee:ff`
      - `device.system_description` → generic demo values
    - Legacy top-level `system_description` is also sanitized when present

      ```json
      {
        "HW_REV":  "1.0",
        "VENDOR":  "LANCity",
        "BOOTR":   "NONE",
        "SW_REV":  "1.0.0",
        "MODEL":   "LCPET-3"
      }
      ```

By default, `--force-new-mac` updates **all** transaction entries to the demo MAC. For a targeted update, you can
specify an original MAC:

```bash
./tools/pnm/pnm-demo-sanitizer.py   --old-mac 00:00:ca:12:03:60   \
                                --new-mac aa:bb:cc:dd:ee:ff   \
                                --demo-root demo
```

In targeted mode:

- Only entries whose `mac_address` matches `--old-mac` are rewritten.
- The same filename, binary MAC, and system description updates are applied.

You can enable per-file logging with:

```bash
./tools/pnm/pnm-demo-sanitizer.py   --force-new-mac               \
                                --new-mac aa:bb:cc:dd:ee:ff   \
                                --demo-root demo              \
                                --verbose
```

### Direct use of pnm-mac-updater

The sanitizer drives `tools/pnm/pnm-mac-updater.py` for you, but you can also run it directly to inspect or adjust PNM
files in place:

```bash
# Show MAC and type information for all PNM files in the demo dataset
./tools/pnm/pnm-mac-updater.py --all-files demo/.demo/pnm/ --show-info

# Rewrite MAC addresses in a single PNM file
./tools/pnm/pnm-mac-updater.py    --mac-address aa:bb:cc:dd:ee:ff   \
                              --file demo/.demo/pnm/ds_ofdm_rxmer_per_subcar_XXXXXXXXXXXX_194_1764820674.bin
```

The demo sanitizer uses this same interface under the hood when normalizing demo datasets.

## What you can do in demo mode

In demo mode you can:

- Start the FastAPI service (`pypnm`, `pypnm --reload`)
- Browse the API documentation (Swagger, ReDoc, MkDocs)
- Run **analysis endpoints** against pre-collected PNM files, including:
  - Single-capture workflows (for example, a single OFDM RxMER capture)
  - Multi-capture workflows (for example, multi-RxMER or multi-channel-estimate analysis)
- Exercise the file-based analysis pipeline end-to-end without requiring an active CM or SNMP access

This is ideal for:

- Demonstrations on a laptop without lab access
- Validating UI behavior with realistic data
- Sharing reproducible examples with others using sanitized captures

## What demo mode does not do

In demo mode you **do not**:

- Poll a live cable modem via SNMP
- Trigger new PNM captures on a CM
- Retrieve new files from a TFTP/HTTP/HTTPS server

Those operations either rely on real network connectivity or are intentionally disabled by the demo configuration.

If you need full functionality (live SNMP polling and capture orchestration), switch back to production mode with:

```bash
./install.sh --production
```

and update `src/pypnm/settings/system.json` to match your environment.

## Files in this directory

- `settings/system.json`  
  Demo system configuration used when `--demo-mode` is enabled. Paths are redirected to the `demo/` tree so that
  PyPNM operates entirely on demonstration data.

- `README.md`  
  This file. Describes how demo mode works and how to prepare, sanitize, and reset demo datasets.

Additional demo data (for example, pre-captured PNM files for single-capture or multi-capture workflows) is stored
under `demo/.demo/` once generated by the sanitizer and can be regenerated at any time using the tools described above.

## Demo Data Sanitization Tool

This script helps prepare and sanitize demo datasets for PyPNM by copying existing capture data,
updating MAC addresses, and cleaning sensitive information.

```bash

# Clean existing demo data
./tools/pnm/pnm-demo-sanitizer.py --clean-demo      \
                              --demo-root demo  \
                              --verbose

# Copy project capture data into the demo dataset
./tools/pnm/pnm-demo-sanitizer.py \
  --copy-data                 \
  --force-new-mac             \
  --new-mac aa:bb:cc:dd:ee:ff \
  --demo-root demo          \
  --verbose

```
