# PyPNM - Reporting An Issue

Standard Operating Procedure For Submitting PyPNM Bugs And Support Requests.

## Table Of Contents

- [Purpose](#purpose)
- [Before You Open An Issue](#before-you-open-an-issue)
- [Building A Sanitized Support Bundle](#building-a-sanitized-support-bundle)
  - [Step 1 - Identify The Affected Capture](#step-1--identify-the-affected-capture)
  - [Step 2 - Run The Support Bundle Script](#step-2--run-the-support-bundle-script)
- [Collecting Logs](#collecting-logs)
- [Opening The GitHub Issue](#opening-the-github-issue)

## Purpose

This guide explains what information to collect and how to package it so PyPNM
issues can be reproduced and diagnosed quickly.

## Before You Open An Issue

Please gather the following details (copy and paste into your issue body):

1. **PyPNM Version**
   - Output of:

     ```bash
     python -m pip show pypnm-docsis
     ```

2. **Environment**
   - Linux distribution and version (for example: Ubuntu 22.04).
   - Python version (for example: 3.10.x).
   - How you are running PyPNM:
     - CLI only, or
     - FastAPI (for example: `pypnm serve --reload`), or
     - Docker (when available).

3. **What You Were Doing**
   - CLI command or FastAPI endpoint you invoked.
   - Example:
     - CLI: `pypnm ds-ofdm-rxmer --channel-id 194 --mac aa:bb:cc:dd:ee:ff`
     - API: `POST /docs/pnm/ds/ofdm/rxMer/getCapture`

4. **Expected Result**
   - Short description of what you expected to see.

5. **Actual Result**
   - Exact error message, stack trace, or unexpected behavior.
   - Screenshots are useful for GUI or Postman usage.

## Building A Sanitized Support Bundle

If your issue involves PNM capture files or multi-capture operations, please
include a **sanitized support bundle** created with the helper script:

```text
tools/build/support_bundle_builder.py
```

The bundle contains only the PNM files and JSON metadata required to reproduce
the problem, with MAC addresses and system descriptions sanitized by default.

### Step 1 - Identify The Affected Capture {#step-1--identify-the-affected-capture}

You can select data to bundle by:

- **OperationId**   (for multi-capture runs only)
- **TransactionId** (for single-captures / multi-capture runs)
- **MAC address**

If possible, prefer the most specific selector (TransactionId).

### Step 2 - Run The Support Bundle Script {#step-2--run-the-support-bundle-script}

Refer to the dedicated guide for full details:

[Support Bundle Builder](support-bundle.md)

From the PyPNM project root:

#### Example A - Single Transaction

```bash
./tools/build/support_bundle_builder.py   --transaction-id ea18519a572e2487 \
                                    --verbose
```

#### Example B - Multi-Capture Operation

```bash
./tools/build/support_bundle_builder.py   --operation-id ed2fcba02bba42f6 \
                                    --clean-output                  \
                                    --verbose
```

#### Example C - All Captures For A MAC Address

```bash
./tools/build/support_bundle_builder.py   --mac-address aa:bb:cc:dd:ee:ff \
                                    --clean-output                  \
                                    --verbose
```

By default, the script:

- Creates a temporary support tree under `.support_bundle/.data`.
- Copies only the relevant PNM files and JSON databases.
- Sanitizes:
  - `mac_address` fields and filename MAC segments to `aa:bb:cc:dd:ee:ff`.
  - `device_details.system_description` to:

    ```json
    {
      "HW_REV":  "1.0",
      "VENDOR":  "LANCity",
      "BOOTR":   "NONE",
      "SW_REV":  "1.0.0",
      "MODEL":   "LCPET-3"
    }
    ```

- Writes a ZIP file into the `issues/` directory (created if needed), for example:

  ```shell
  issues/pypnm_support_bundle.zip
  ```

If you need to keep real MAC and sysDescr values (for lab-only data), you can
use the flags:

```bash
./tools/build/support_bundle_builder.py   --transaction-id ea18519a572e2487 \
                                    --keep-original-mac               \
                                    --keep-original-sysdescr
```

Only use these options if you are comfortable sharing identifying information.

## Collecting Logs

If the issue involves crashes or unexpected behavior, please include the
runtime log file when possible:

```shell
logs/pypnm.log
```

You can truncate this file using `tools/maintenance/clean.sh --logs` between runs to keep
only the relevant session.

## Opening The GitHub Issue

When you have the information and files ready:

01. Go to the PyPNM GitHub repository **Issues** page.
02. Click **New Issue** and choose the most appropriate template (for example: **Bug - PNM Capture**).
03. In the issue body, include the following:

    - PyPNM version
    - Environment details
    - Exact CLI command or API payload
    - Expected vs actual behavior

04. Attach the relevant files:

    - `issues/pypnm_support_bundle.zip`
    - Optional: `logs/pypnm.log` for the failing run
    - Optional: screenshots or Postman export if relevant

Clear, repeatable reports with sanitized support bundles make it much easier to
reproduce problems and provide fixes without exposing production data.
