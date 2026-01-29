## Agent Review Bundle Summary
- Goal: Add a friendly spectrum analyzer capture endpoint that derives segment span and bins from RBW.
- Changes: Added friendly capture request schema and builder, new friendly endpoint, updated spectrum analyzer docs, added tests, documented commit message formatting requirement.
- Files: AGENTS.md; CODING_AGENTS.md; src/pypnm/api/routes/docs/pnm/spectrumAnalyzer/schemas.py; src/pypnm/api/routes/docs/pnm/spectrumAnalyzer/service.py; src/pypnm/api/routes/docs/pnm/spectrumAnalyzer/router.py; docs/api/fast-api/single/spectrum-analyzer/spectrum-analyzer.md; tests/test_spectrum_analyzer_friendly_capture.py
- Tests: python3 -m compileall src; ruff check src; ruff format --check . (fails: repo-wide formatting changes needed); pytest -q (initial timeout, re-run succeeded)
- Notes: Ruff format check fails in existing files; pytest required a longer timeout to complete.

# FILE: AGENTS.md
# AGENTS.md

This file provides guidance for coding agents working in this repository.
Keep it short, accurate, and updated when workflows change.

## Agent Permissions

<environment_context>
    <sandbox_mode>danger-full-access</sandbox_mode>
    <network_access>enabled</network_access>
    <!-- Access is governed by this file and explicit user approval -->
</environment_context>

## Project Basics

- Language: Python (3.10+)
- This repo is NOT greenfield; extend existing code and patterns.
- Build/test entry points are defined in `pyproject.toml`, `Makefile`, or `scripts/`.
- Read `README.md` first for setup and usage.
- Type checking is strict; avoid `Any` and generic container types.
- Ruff compliance is required (do not auto-format unless explicitly requested).

## Agent Constraints

- General workflow:
  - Make minimal diffs; avoid formatting churn.
  - Preserve whitespace/alignment in existing files (no auto-reflow).
  - Do not add broad refactors unless explicitly requested.
  - Provide an end-of-run Agent Review Bundle summary: goal, changes, files, tests, notes.
- Typing and API style:
  - Strict typing everywhere; avoid `Dict`/`List`/`Tuple`/`Union` and avoid `Any`.
  - Prefer built-in generics (`dict[str, int]`, `list[str]`) and `A | B` rather than `Union`.
  - Prefer Pydantic `BaseModel` over dict returns for public interfaces.
  - `BaseModel` fields must be one-line `Field(...)` declarations with descriptions.
  - Prefer `match/case` over long if/else chains.
  - No one-line if statements (E701 compliance).
  - Avoid 3+ nested loops; 2 nested loops discouraged unless necessary.
- Code structure and documentation:
  - Prefer classes/static methods; minimize standalone global functions.
  - Public methods must have detailed docstrings; private methods minimal.
  - Keep code self-documented; avoid method-level debug logging.
  - Logger pattern in classes: `self.logger = logging.getLogger(f"{self.__class__.__name__}")`.
- Release hygiene / headers:
  - Any touched code files must have SPDX copyright year updated per Repo Hygiene rules (single year or range).
  - Do not add SPDX headers to Markdown files.
  - Remove SPDX lines embedded inside Markdown code blocks if encountered (especially SQL appendices).
- Docs / Markdown rules (MkDocs + GitHub compatible):
  - No emojis in docs.
  - No horizontal rules (`---`) in Markdown.
  - Keep tables ~132 characters wide when possible.
  - Use placeholders consistently in examples:
    - MAC: `aa:bb:cc:dd:ee:ff`
    - IP: `192.168.0.100`
    - system_description JSON: `{"HW_REV":"1.0","VENDOR":"LANCity","BOOTR":"NONE","SW_REV":"1.0.0","MODEL":"LCPET-3"}`
  - For code file links in docs: use HTTP GitHub links; relative links only for other Markdown files.
  - Always include a downloadable link at the end of any Markdown you generate (when generating Markdown as an artifact in chat; for repo docs, follow repo conventions).
- Shell scripts:
  - Proper indentation.
  - Emojis allowed only in `install.sh` and `pypnm-cmts` CLI output; do not use emojis elsewhere.
- Testing expectations:
  - Run at least: `python3 -m compileall src`, `ruff check src`, `ruff format --check .`, `pytest -q`.
  - After any code change, run `ruff check src` and `pytest -q`. If only Markdown changes are made, run `mkdocs build -s` instead.
  - If an integration test is optional/gated (for example Postgres DSN), note skips explicitly in the summary.
- Troubleshooting:
  - When debugging endpoint behavior, include `tail -n 25 /home/dev01/Projects/PyPNM/logs/pypnm.log` in the troubleshooting steps.

## External Consumers (Compatibility Contract)

- PyPNM is the authoritative engine and is consumed by downstream repos (example: PyPNM-CMTS).
- Preserve public API stability unless the user explicitly approves breaking changes.
- Do not embed downstream app concerns into PyPNM (keep PyPNM reusable and transport-agnostic).
- If a change affects downstream repos, call it out explicitly before making it.

## Repo Conventions (PyPNM)

- Persistence is filesystem-based artifacts plus metadata persistence per the DB backend design:
  - Binaries and derived artifacts remain on disk under `.data/` roots.
  - Transaction/group/operation metadata is DB-backed (SQLite or Postgres) per `docs/design/db/`.
- DB backend selection is owned by PyPNM at install time (no runtime “auto switching”).
- SQLite is intended for single-writer deployments (standalone/lab/demo).
- Postgres is recommended for multi-worker / multi-process deployments.

## Documentation

- Docs must follow the existing repo docs layout and conventions.
- Update docs alongside code changes (choose the correct location by inspecting the existing docs tree; do not invent parallel structures).
- Do not modify `mkdocs.yml` or navigation unless explicitly required by the task.
- Markdown must render correctly in both MkDocs and GitHub.
- No emojis in documentation.
- Use generic placeholders:
  - MAC: `aa:bb:cc:dd:ee:ff`
  - IP: `192.168.0.100`
- Emojis are allowed only in `install.sh`; they are prohibited everywhere else.
- When adding new terms or acronyms, update `docs/definition/index.md` and keep entries in alphabetical order.
- After completing a task, create a single “agent review” file that concatenates the full contents of all files changed in that task (path and naming should follow existing repo practice).
- Always regenerate the agent review bundle after any subsequent edits so it reflects every changed file.
- When an error is fixed, add or update a FAQ entry with the error and resolution, and add a TODO entry noting the FAQ update requirement.

### Reuse Index

- Agents MUST consult the existing reuse / symbol index under `tools/agent-review/` (if present) before introducing new:
  - types, validators, ID formats, storage conventions, persistence adapters, or config namespaces
- Any deviation requires an explicit gap justification and user approval.

## DB Backend Migration (Locked Decisions)

Agents working on the DB backend refactor MUST follow the locked decisions recorded in the design docs (see `docs/design/db/`):

- PyPNM owns persistence, schema initialization, and DB APIs.
- Install-time backend selection via `install.sh` flags + interactive default to SQLite.
- Postgres secrets via env var overrides (no plaintext requirement in tracked JSON).
- Idempotent schema apply using shipped DDL assets + seeding `UNKNOWN` sysDescr + default artifact store(s).
- SQLite for single-writer; Postgres recommended for multi-worker / multi-process (especially downstream orchestration use).
- Paths stored in DB are portable (app-root relative), resolved at runtime.
- CI validates SQLite (required) and Postgres (service container, recommended as required).
- JSON ledger persistence is deprecated and removed from runtime paths (optional offline migrator only).

## Configuration

- `system.json` is the single source of truth.
- New configuration namespaces must be implemented as Pydantic BaseModels.
- BaseModels must use one-line `Field(..., description="...")`.
- Avoid generic `str` for semantic identifiers or paths in public models and APIs; use an existing semantic type or add a new alias in `src/pypnm/lib/types.py`.
- When working with MAC or inet strings, validate using `MacAddress()` or `Inet()` instead of assuming `str(...)` formatting is valid.
- Request override defaults: missing or null means use `system.json` defaults; blank strings are invalid.

## Timestamp Conventions

- All stored timestamps are epoch seconds.
- Convert to ISO-8601 only at display or external response boundaries.

## Coding Guidelines (Strict)

- No generic container imports (`Dict`, `List`, `Tuple`, `Union`).
  Use built-in types and `|`.
- Avoid `Any` unless unavoidable; isolate and justify its usage.
- Every function argument must be annotated.
- Avoid `None` returns; prefer empty values unless `None` is semantically required.
- Avoid magic numbers; use named constants.
- Prefer `BaseModel` over raw dicts for public/stateful structures (state, configuration, persistence records).
- dicts are allowed only for short-lived internal glue logic.
- Prefer classes with static methods over standalone functions.
- Public methods MUST have detailed docstrings.
- Private methods may have minimal docstrings.
- Avoid method-level debug logs.
- Do not add Ruff ignores (`# noqa`, `# ruff: noqa`). If an ignore is needed, ask for permission first.
- Logging pattern in classes:

  ```python
  self.logger = logging.getLogger(f"{self.__class__.__name__}")
  ```

- Prefer `match/case` over long if/else chains.
- No code should contain 3+ nested loops. 2 nested loops are discouraged unless necessary.
- No one-line if statements (E701).
- If `STATUS` is used as a return type, return `STATUS_OK` or `STATUS_NOK` for readability.
- Preserve all existing whitespace and alignment.
- Never auto-format or re-align code.
- Do not enforce snake_case; keep existing naming conventions as-is.

## FastAPI Guidelines (PyPNM)

- Router files must be lean:
  - `router.py` contains routing glue only (APIRouter configuration, endpoint registration, HTTP status translation).
  - No business logic in `router.py`. Business logic must live in `service.py` for that route group (same folder) or a shared service module if reused.
- All request/response bodies must be Pydantic BaseModels.
- Prefer POST for payload submission and endpoint contracts (PyPNM default).
  - Allow GET only where already present or clearly appropriate (health, readiness, version, status).
- Reuse shared models under the existing `src/pypnm/api/common/` structure (inspect current tree before adding anything new).
- Do not block request paths with `time.sleep()`.

## Tests (Mandatory)

- Every phase deliverable MUST include pytest coverage for new or changed behavior.
- Do not claim a phase item is complete unless pytest has been added and executed (or a concrete blocker is documented).
- Tests must remain hermetic: no live CMTS/cable modem dependencies.

## Burndown Governance

- Agents MUST consult the current burndown and DB design docs before implementing work.
- Agents MUST NOT update burndown checkmarks unless explicitly instructed by the user.
- Code written does not imply progress accepted.

## Workflow Rules

- When the user says “train”, read code silently until told otherwise.
- Do not assume missing context; ask.
- Keep changes minimal and scoped.
- Do not refactor unrelated code.
- Avoid destructive commands unless explicitly requested.
- Do not print file contents into chat unless the user explicitly requests it.
- Keep a brief summary of user prompts after any request for a commit message and track changes since the most recent commit message request.
- When asked for a commit message, respond with the specified format, keep it succinct, and include all changes since the last commit message request.
- Commit messages must be returned in Markdown text format (use a code block).
- Default response content should be a summary, changed file list, commands run, and the review bundle path.
- Always end tasks with an agent review bundle containing the full contents of all files touched in the task.
- Agent review bundles must start with the standard summary template block below (before any `# FILE:` sections).
- If a review bundle exceeds 3000 lines, split it into multiple bundles without splitting files. Use a part naming convention like `name.part-1.review.md`, `name.part-2.review.md`, and repeat the summary block at the top of each part.
- When the user says `CAT_FILES`, create a single bundle file containing the full contents of every file touched in the task, each preceded by `# FILE: <path>`, and provide the `cat` command for the bundle.

### Commit Message Format

- One line summary (max 50 characters)
- Detailed description lines (max 72 characters per line); every line after the first must start with `-`

### Agent Review Bundle Summary Template (Standard)

Use this block at the very top of every `*.review.md` bundle (before any `# FILE:` sections).

## Agent Review Bundle Summary
- Goal:
- Changes:
- Files:
- Tests:
- Notes:

## Repo Hygiene

- License is Apache-2.0; keep SPDX headers and `NOTICE`.
- For any modified or newly created file, update the SPDX header year to 2026.
- If a file already has a SPDX year and the year has changed, update it as a range (example: 2025 -> 2025-2026).
- Keep `tools/` organized by category.
- Do not add files directly under `tools/` root.

## Agent Self-Checks

Before responding:

- Re-read this file and `README.md`.
- Confirm pytest coverage exists or is explicitly blocked.
- Confirm pytest and ruff output have no deprecation warnings (treat as failures).
- Confirm changes align to the current phase and do not leak scope.
- Confirm formatting and alignment are preserved.

## Training

When the user requests "train", read the following sources:

- `AGENTS.md`
- `docs/design/db/` (all files)
- `src/pypnm/lib/` (DB/persistence + config helpers)
- `src/pypnm/api/` (routing/service patterns, where applicable)
- `tools/agent-review/` (all files, if present)

# FILE: CODING_AGENTS.md
# General-Purpose AI Coding Guide

This document provides a generic coding guide for AI contributors. It focuses on code style,
reuse, and maintainability.

## Core Principles

- Reuse before adding: prefer existing types, helpers, models, and utilities.
- Keep diffs minimal and focused; avoid formatting churn.
- Preserve existing naming, alignment, and whitespace patterns.
- Favor clarity and explicit typing over clever shortcuts.
- Review this document before making any changes.
  This is a generic guide and does not replace `AGENTS.md`.

## Reuse-First Checklist

Before introducing new types, validators, formats, or storage conventions:

- Search for similar helpers in `src/pypnm/lib/` and `src/pypnm/api/`.
- Check `tools/agent-review/` for any reuse or symbol index guidance.
- Prefer existing semantic aliases over raw `str` identifiers.
- Prefer existing constants over inline values.
- Prefer existing Pydantic models for public data structures.
- Refer to shared utilities and helpers before creating new classes.

## Common Locations To Consult

- Types and semantic aliases: `src/pypnm/lib/types.py`
- Constants: `src/pypnm/lib/constants.py`
- Validators and parsing helpers: `src/pypnm/lib/`
- Config models and defaults: `src/pypnm/config/`
- Shared API models and schemas: `src/pypnm/api/` (including `src/pypnm/api/common/`)

## Coding Style (General)

- Use built-in generics (`list[str]`, `dict[str, int]`) and `A | B` unions.
- Avoid `Any` unless unavoidable; isolate and justify its usage.
- Annotate all function arguments and return types.
- Prefer classes or static methods over standalone functions.
- Use Pydantic `BaseModel` for public interfaces instead of raw dicts.
- Keep public method docstrings detailed; private method docstrings minimal.

## Workflow Guidance

- Validate changes with repository test entry points.
- When adding new behavior, include tests covering the change.
- New classes must have pytest coverage at a minimum for IPC and system calls.
- Avoid broad refactors unless explicitly requested.
- Keep a brief summary of user prompts after any request for a commit message and track changes since the most recent commit message request.
- When asked for a commit message, respond with the specified format, keep it succinct, and include all changes since the last commit message request.
- Commit messages must be returned in Markdown text format (use a code block).

### Commit Message Format

- One line summary (max 50 characters)
- Detailed description lines (max 72 characters per line); every line after the first must start with `-`

## Agent Constraints

- General workflow:
  - Make minimal diffs; avoid formatting churn.
  - Preserve whitespace/alignment in existing files (no auto-reflow).
  - Do not add broad refactors unless explicitly requested.
  - Provide an end-of-run Agent Review Bundle summary: goal, changes, files, tests, notes.
- Typing and API style:
  - Strict typing everywhere; avoid `Dict`/`List`/`Tuple`/`Union` and avoid `Any`.
  - Prefer built-in generics (`dict[str, int]`, `list[str]`) and `A | B` rather than `Union`.
  - Prefer Pydantic `BaseModel` over dict returns for public interfaces.
  - `BaseModel` fields must be one-line `Field(...)` declarations with descriptions.
  - Avoid generic returns; every method must have an explicit return type annotation.
  - Every method argument must have an explicit type annotation.
  - Public/shared method types must be defined in `src/pypnm/lib/types.py`.
  - Only define local types in a module when the type is strictly private and not reused.
  - Common folder methods must use types defined in `src/pypnm/lib/types.py`.
- Prefer `match/case` over long if/else chains.
- No one-line if statements (E701 compliance).
- Avoid 3+ nested loops; 2 nested loops discouraged unless necessary.
- If `STATUS` is used as a return type, return `STATUS_OK` or `STATUS_NOK` for readability.
- Code structure and documentation:
  - Prefer classes/static methods; minimize standalone global functions.
  - Public methods must have detailed docstrings; private methods minimal.
  - Keep code self-documented; avoid method-level debug logging.
  - Logger pattern in classes: `self.logger = logging.getLogger(f"{self.__class__.__name__}")`.
- Release hygiene / headers:
  - Code files must include `SPDX-License-Identifier: Apache-2.0`.
  - Copyright lines must include only the year or year range (no author names).
  - Any touched code files must have SPDX copyright year updated per Repo Hygiene rules (single year or range).
  - Do not add SPDX headers to Markdown files.
  - Remove SPDX lines embedded inside Markdown code blocks if encountered (especially SQL appendices).
- Docs / Markdown rules (MkDocs + GitHub compatible):
  - No emojis in docs.
  - No horizontal rules (`---`) in Markdown.
  - Keep tables ~132 characters wide when possible.
  - Use placeholders consistently in examples:
    - MAC: `aa:bb:cc:dd:ee:ff`
    - IP: `192.168.0.100`
    - system_description JSON: `{"HW_REV":"1.0","VENDOR":"LANCity","BOOTR":"NONE","SW_REV":"1.0.0","MODEL":"LCPET-3"}`
  - For code file links in docs: use HTTP GitHub links; relative links only for other Markdown files.
  - Always include a downloadable link at the end of any Markdown you generate (when generating Markdown as an artifact in chat; for repo docs, follow repo conventions).
- Shell scripts:
  - Proper indentation.
  - Emojis allowed only in `install.sh` and `pypnm-cmts` CLI output; do not use emojis elsewhere.
- Testing expectations:
  - Run at least: `python3 -m compileall src`, `ruff check src`, `ruff format --check .`, `pytest -q`.
  - After any code change, run `ruff check src` and `pytest -q`. If only Markdown changes are made, run `mkdocs build -s` instead.
  - If an integration test is optional/gated (for example Postgres DSN), note skips explicitly in the summary.
- Troubleshooting:
  - When debugging endpoint behavior, include `tail -n 25 /home/dev01/Projects/PyPNM/logs/pypnm.log` in the troubleshooting steps.

## Pytest Guidance (PyPNM Pattern)

- Place new tests under `tests/` with `test_*.py` naming.
- Prefer small, focused unit tests that mirror the existing test style.
- Use fixtures for shared data (see current `tests/` patterns).
- Prefer module-level test functions over new class wrappers unless an existing test uses classes.
- Reuse `tests/files/` for binary fixtures and sample data.
- Favor hermetic tests: no live devices, no external services.
- When testing IPC or system calls, isolate behavior with fakes/mocks and assert edge cases.
- Keep tests aligned with existing patterns in similar modules before introducing new structures.
  Start by locating a similar test file and mirror its structure.

## Notes

- This document is intentionally generic. Use `AGENTS.md` for this repository’s
  authoritative rules and workflow constraints.

# FILE: src/pypnm/api/routes/docs/pnm/spectrumAnalyzer/schemas.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from pypnm.api.routes.common.classes.common_endpoint_classes.common_req_resp import (
    CableModemPnmConfig,
    CommonSingleCaptureAnalysisType,
    TftpConfig,
    default_ip,
    default_mac,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_snmp import (
    SNMPConfig,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schemas import (
    PnmAnalysisResponse,
    PnmDataResponse,
    PnmSingleCaptureRequest,
)
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import FrequencyHz, InetAddressStr, MacAddressStr, ResolutionBw
from pypnm.pnm.data_type.DocsIf3CmSpectrumAnalysisCtrlCmd import (
    SpectrumRetrievalType,
    WindowFunction,
)


class SpecAnMovingAvgParameters(BaseModel):
    points:int                                          = Field(default=10, description="")

class SpecAnCapturePara(BaseModel):
    inactivity_timeout       : int                      = Field(default=60, description="Timeout in seconds for inactivity during spectrum analysis.")
    first_segment_center_freq: FrequencyHz              = Field(default=FrequencyHz(300_000_000), description="First segment center frequency in Hz.")
    last_segment_center_freq : FrequencyHz              = Field(default=FrequencyHz(900_000_000), description="Last segment center frequency in Hz.")
    segment_freq_span        : FrequencyHz              = Field(default=FrequencyHz(1_000_000), description="Frequency span of each segment in Hz.")
    num_bins_per_segment     : int                      = Field(default=256, description="Number of FFT bins per segment.")
    noise_bw                 : int                      = Field(default=150, description="Equivalent noise bandwidth in kHz.")
    window_function          : WindowFunction           = Field(default=WindowFunction.HANN, description="FFT window function to apply. See WindowFunction enum for options.")
    num_averages             : int                      = Field(default=1, description="Number of averages per segment.")
    spectrum_retrieval_type  : SpectrumRetrievalType    = Field(default=SpectrumRetrievalType.FILE,
                                                                description=f"Method of spectrum data retrieval: "
                                                                            f"PNM ({SpectrumRetrievalType.FILE}) | "
                                                                            f"SNMP({SpectrumRetrievalType.SNMP}).")

class SpecAnCaptureParaFriendly(BaseModel):
    inactivity_timeout       : int                      = Field(default=60, description="Timeout in seconds for inactivity during spectrum analysis.")
    first_segment_center_freq: FrequencyHz              = Field(default=FrequencyHz(300_000_000), description="Requested first segment center frequency in Hz.")
    last_segment_center_freq : FrequencyHz              = Field(default=FrequencyHz(900_000_000), description="Requested last segment center frequency in Hz.")
    resolution_bw            : ResolutionBw             = Field(default=ResolutionBw(30_000), description="Resolution bandwidth in Hz used to derive segment span and bins.")
    noise_bw                 : int                      = Field(default=150, description="Equivalent noise bandwidth in kHz.")
    window_function          : WindowFunction           = Field(default=WindowFunction.HANN, description="FFT window function to apply. See WindowFunction enum for options.")
    num_averages             : int                      = Field(default=1, description="Number of averages per segment.")
    spectrum_retrieval_type  : SpectrumRetrievalType    = Field(default=SpectrumRetrievalType.FILE,
                                                                description=f"Method of spectrum data retrieval: "
                                                                            f"PNM ({SpectrumRetrievalType.FILE}) | "
                                                                            f"SNMP({SpectrumRetrievalType.SNMP}).")

class SpectrumAnalysisExtention(BaseModel):
    moving_average:SpecAnMovingAvgParameters = Field(default=SpecAnMovingAvgParameters(), description="")

class ExtendCommonSingleCaptureAnalysisType(CommonSingleCaptureAnalysisType):
    spectrum_analysis: SpectrumAnalysisExtention = Field(description="Spectrum Analysis Extension")

class ExtendSingleCaptureSpecAnaRequest(BaseModel):
    cable_modem: CableModemPnmConfig                    = Field(description="Cable modem configuration")
    analysis: ExtendCommonSingleCaptureAnalysisType     = Field(description="Analysis type to perform")

class ExtendPnmSingleCaptureRequest(PnmSingleCaptureRequest):
    moving_average:int = Field(...,description="")

# -------------- MAIN REQUEST ------------------

class SpectrumAnalyzerPnmParameters(BaseModel):
    tftp: TftpConfig = Field(..., description="TFTP configuration")
    model_config = {"extra": "forbid"}

class SpectrumAnalyzerCableModemConfig(BaseModel):
    mac_address: MacAddressStr                    = Field(default=default_mac, description="MAC address of the cable modem")
    ip_address: InetAddressStr                    = Field(default=default_ip, description="Inet address of the cable modem")
    pnm_parameters: SpectrumAnalyzerPnmParameters = Field(description="PNM parameters such as TFTP server configuration")
    snmp: SNMPConfig                              = Field(description="SNMP configuration")

    @field_validator("mac_address")
    def validate_mac(cls, v: str) -> MacAddressStr:
        try:
            return MacAddress(v).mac_address
        except Exception as e:
            raise ValueError(f"Invalid MAC address: {v}, reason: ({e})") from e

class SingleCaptureSpectrumAnalyzerRequest(BaseModel):
    cable_modem: SpectrumAnalyzerCableModemConfig       = Field(description="Cable modem configuration")
    analysis: ExtendCommonSingleCaptureAnalysisType     = Field(description="Analysis type to perform")
    capture_parameters: SpecAnCapturePara               = Field(description="Spectrum capture Parameters.")

class SingleCaptureSpectrumAnalyzerFriendlyRequest(BaseModel):
    cable_modem: SpectrumAnalyzerCableModemConfig       = Field(description="Cable modem configuration")
    analysis: ExtendCommonSingleCaptureAnalysisType     = Field(description="Analysis type to perform")
    capture_parameters: SpecAnCaptureParaFriendly       = Field(description="Spectrum capture Parameters.")

class SingleCaptureSpectrumAnalyzer(ExtendSingleCaptureSpecAnaRequest):
    capture_parameters: SpecAnCapturePara       = Field(..., description="Spectrum capture Parameters.")

class CmSpecAnaAnalysisRequest(ExtendPnmSingleCaptureRequest):
    capture_parameters: SpecAnCapturePara       = Field(..., description="Spectrum capture Parameters.")

# -------------- MAIN-RESPONSE------------------

class CmSpecAnaAnalysisResponse(PnmDataResponse):
    """Generic response container for most PNM operations."""

# -------------- MAIN-OFDM-REQUEST ------------------

class OfdmSpecAna(BaseModel):
    number_of_averages: int  = Field(default=10, description="Number of samples to calculate the average per-bin")
    resolution_bandwidth_hz: FrequencyHz = Field(default=FrequencyHz(25_000), description="Resolution Bandwidth in Hz")
    spectrum_retrieval_type: SpectrumRetrievalType = Field(default=SpectrumRetrievalType.FILE,
                                                           description=f"Method of spectrum data retrieval: "
                                                                       f"PNM ({SpectrumRetrievalType.FILE}) | "
                                                                       f"SNMP({SpectrumRetrievalType.SNMP}).")
class OfdmSpecAnaAnalysisRequest(ExtendSingleCaptureSpecAnaRequest):
    capture_parameters:OfdmSpecAna = Field(default=OfdmSpecAna(), description="")

# -------------- MAIN-OFDM-RESPONSE------------------

class OfdmSpecAnaAnalysisResponse(PnmAnalysisResponse):
    pass

# -------------- MAIN-SCQAM-REQUEST ------------------

class ScQamSpecAna(BaseModel):
    number_of_averages: int  = Field(default=10, description="Number of samples to calculate the average per-bin")
    resolution_bandwidth_hz: FrequencyHz = Field(default=FrequencyHz(25_000), description="Resolution Bandwidth in Hz")
    spectrum_retrieval_type: SpectrumRetrievalType = Field(default=SpectrumRetrievalType.FILE,
                                                           description=f"Method of spectrum data retrieval: "
                                                                       f"PNM ({SpectrumRetrievalType.FILE}) | "
                                                                       f"SNMP({SpectrumRetrievalType.SNMP}).")

class ScQamSpecAnaAnalysisRequest(ExtendSingleCaptureSpecAnaRequest):
    capture_parameters:ScQamSpecAna = Field(default=ScQamSpecAna(), description="")

# -------------- MAIN-SCQAM-RESPONSE------------------

class ScQamSpecAnaAnalysisResponse(PnmAnalysisResponse):
    pass

# FILE: src/pypnm/api/routes/docs/pnm/spectrumAnalyzer/service.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from typing import cast

from pypnm.api.routes.common.classes.analysis.analysis import (
    WindowFunction,  # type: ignore[import-untyped]
)
from pypnm.api.routes.common.extended.common_measure_service import (
    CommonMeasureService,  # type: ignore[import-untyped]
)
from pypnm.api.routes.common.extended.common_process_service import (
    MessageResponse,  # type: ignore[import-untyped]
)
from pypnm.api.routes.docs.pnm.spectrumAnalyzer.abstract.com_spec_chan_ana import (  # type: ignore[import-untyped]
    CommonChannelSpectumBwLut,
    CommonSpectrumBw,
    CommonSpectrumChannelAnalyzer,
    OfdmSpectrumBwLut,
    ScQamSpectrumBwLut,
)
from pypnm.api.routes.docs.pnm.spectrumAnalyzer.schemas import (
    SpecAnCapturePara,  # type: ignore[import-untyped]
    SpecAnCaptureParaFriendly,  # type: ignore[import-untyped]
)
from pypnm.config.pnm_config_manager import (
    PnmConfigManager,  # type: ignore[import-untyped]
)
from pypnm.docsis.cable_modem import CableModem  # type: ignore[import-untyped]
from pypnm.docsis.cm_snmp_operation import (  # type: ignore[import-untyped]
    DocsIf31CmDsOfdmChanChannelEntry,
    DocsIfDownstreamChannelEntry,
    SpectrumRetrievalType,
)
from pypnm.lib.conversions.rbw import RBWConversion
from pypnm.lib.inet import Inet  # type: ignore[import-untyped]
from pypnm.lib.types import (  # type: ignore[import-untyped]
    ChannelId,
    FrequencyHz,
    ResolutionBw,
    ResolutionBwSettings,
    SubcarrierIdx,
)
from pypnm.pnm.data_type.pnm_test_types import (
    DocsPnmCmCtlTest,  # type: ignore[import-untyped]
)


class CmSpectrumAnalysisService(CommonMeasureService):
    """
    Service For Cable Modem Spectrum Analysis (Single Run)

    Purpose
    -------
    Orchestrates a single spectrum analyzer measurement on a target cable modem,
    applying the provided capture parameters and the PNM TFTP/SNMP configuration.
    Selects the correct `DocsPnmCmCtlTest` based on the retrieval type (FILE vs SNMP).

    Parameters
    ----------
    cable_modem : CableModem
        Target cable modem on which to run the measurement.
    tftp_servers : tuple[Inet, Inet], optional
        Primary/secondary TFTP server addresses used for result file storage.
        Defaults to values from :func:`PnmConfigManager.get_tftp_servers`.
    tftp_path : str, optional
        Remote TFTP directory where result files are written.
        Defaults to :func:`PnmConfigManager.get_tftp_path`.
    capture_parameters : SpecAnCapturePara
        Fully specified capture configuration (timeouts, segment layout,
        binning, ENBW, windowing, averaging, retrieval type).

    Notes
    -----
    - If ``capture_parameters.spectrum_retrieval_type == SpectrumRetrievalType.SNMP``,
      the service switches to ``DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA``.
    - After construction, call :meth:`set_and_go` (via ``CommonMeasureService``) to execute.
    """

    def __init__(self,
        cable_modem: CableModem,
        tftp_servers: tuple[Inet, Inet] = PnmConfigManager.get_tftp_servers(),
        tftp_path: str = PnmConfigManager.get_tftp_path(),*,
        capture_parameters: SpecAnCapturePara,) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)

        pnmCmCtlTest = DocsPnmCmCtlTest.SPECTRUM_ANALYZER

        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

        if capture_parameters.spectrum_retrieval_type == SpectrumRetrievalType.SNMP:
            self.logger.debug('Selecting: SPECTRUM_ANALYZER_SNMP_AMP_DATA')
            pnmCmCtlTest = DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA

        super().__init__(
            pnmCmCtlTest,
            cable_modem,
            tftp_servers,
            tftp_path,
            cable_modem.getWriteCommunity(),)

        self.setSpectrumCaptureParameters(capture_parameters)

class SpectrumAnalyzerFriendlyCaptureBuilder:
    """
    Build Spectrum Analyzer capture parameters from the friendly request shape.

    Uses the spectrum-analysis-capture-set algorithm to derive segment span,
    bins per segment, and adjusted first/last segment center frequencies
    based on the requested window and resolution bandwidth.
    """

    MIN_SEGMENT_SPAN_HZ: int = 1_000_000
    MAX_BINS: int = 2048
    MAX_TRIES: int = 64

    @staticmethod
    def _floor_to_multiple(value: int, base: int) -> int:
        if base <= 0:
            return value
        return (value // base) * base

    @staticmethod
    def _pick_seg_span_and_bins(freq_span: int, rbw_hz: int) -> tuple[int, int]:
        if rbw_hz <= 0:
            raise ValueError("resolution_bw must be > 0")
        if freq_span < (2 * SpectrumAnalyzerFriendlyCaptureBuilder.MIN_SEGMENT_SPAN_HZ):
            raise ValueError("Frequency span too small to support scaled window rules with minimum segment span")

        best_seg_span = 0
        best_bins = 0
        best_err = float("inf")

        max_seg_span = freq_span // 2
        if max_seg_span < SpectrumAnalyzerFriendlyCaptureBuilder.MIN_SEGMENT_SPAN_HZ:
            max_seg_span = SpectrumAnalyzerFriendlyCaptureBuilder.MIN_SEGMENT_SPAN_HZ

        seg_span = SpectrumAnalyzerFriendlyCaptureBuilder.MIN_SEGMENT_SPAN_HZ
        while seg_span <= max_seg_span:
            k = freq_span // seg_span
            if k < 2:
                seg_span += SpectrumAnalyzerFriendlyCaptureBuilder.MIN_SEGMENT_SPAN_HZ
                continue

            bins = int(round(float(seg_span) / float(rbw_hz)))
            if bins < 1:
                bins = 1
            if bins > SpectrumAnalyzerFriendlyCaptureBuilder.MAX_BINS:
                seg_span += SpectrumAnalyzerFriendlyCaptureBuilder.MIN_SEGMENT_SPAN_HZ
                continue

            rbw_actual = float(seg_span) / float(bins)
            err = abs(rbw_actual - float(rbw_hz)) / float(rbw_hz)

            if (err < best_err) or ((err == best_err) and (seg_span < best_seg_span)):
                best_err = err
                best_seg_span = seg_span
                best_bins = bins

            seg_span += SpectrumAnalyzerFriendlyCaptureBuilder.MIN_SEGMENT_SPAN_HZ

        if best_seg_span <= 0 or best_bins <= 0:
            raise ValueError("No valid segment span/bins combination found for the requested resolution bandwidth")

        return best_seg_span, best_bins

    @staticmethod
    def build(capture_parameters: SpecAnCaptureParaFriendly) -> SpecAnCapturePara:
        """
        Convert friendly capture settings into a concrete spectrum analyzer command.

        The returned parameters are aligned such that the raw window is divisible
        by the derived segment span and the configured segment centers are
        offset inward by half a segment span on each side.
        """
        req_first = int(capture_parameters.first_segment_center_freq)
        req_last = int(capture_parameters.last_segment_center_freq)
        rbw_hz = int(capture_parameters.resolution_bw)

        if req_first <= 0 or req_last <= 0:
            raise ValueError("Requested frequencies must be > 0")
        if req_last <= req_first:
            raise ValueError("Invalid range: last_segment_center_freq must be greater than first_segment_center_freq")

        first = req_first
        last = req_last
        tries = 0
        first_scaled = 0
        last_scaled = 0
        seg_span = SpectrumAnalyzerFriendlyCaptureBuilder.MIN_SEGMENT_SPAN_HZ
        bins = 0

        while tries < SpectrumAnalyzerFriendlyCaptureBuilder.MAX_TRIES:
            tries += 1

            freq_span = int(last - first)
            seg_span, bins = SpectrumAnalyzerFriendlyCaptureBuilder._pick_seg_span_and_bins(
                freq_span=freq_span,
                rbw_hz=rbw_hz,
            )

            if (freq_span % seg_span) != 0:
                usable = SpectrumAnalyzerFriendlyCaptureBuilder._floor_to_multiple(freq_span, seg_span)
                if usable <= 0:
                    usable = seg_span

                candidate_last = first + usable
                if candidate_last > last:
                    candidate_last = last
                if candidate_last > req_last:
                    candidate_last = req_last

                if candidate_last <= first:
                    candidate_first = last - usable
                    if candidate_first < req_first:
                        candidate_first = req_first
                    first = candidate_first
                    continue

                last = candidate_last
                continue

            half = seg_span // 2
            first_scaled = first + half
            last_scaled = last - half

            if last_scaled <= first_scaled:
                last = max(first + seg_span, first + 1)
                continue

            break

        if tries >= SpectrumAnalyzerFriendlyCaptureBuilder.MAX_TRIES:
            raise ValueError("Unable to find settings within bounds that satisfy rules")

        return SpecAnCapturePara(
            inactivity_timeout          = capture_parameters.inactivity_timeout,
            first_segment_center_freq   = FrequencyHz(first_scaled),
            last_segment_center_freq    = FrequencyHz(last_scaled),
            segment_freq_span           = FrequencyHz(seg_span),
            num_bins_per_segment        = bins,
            noise_bw                    = capture_parameters.noise_bw,
            window_function             = capture_parameters.window_function,
            num_averages                = capture_parameters.num_averages,
            spectrum_retrieval_type     = capture_parameters.spectrum_retrieval_type,
        )

class OfdmChanSpecAnalyzerService(CommonMeasureService):
    """
    Helper Service For OFDM Spectrum Analyzer Runs

    Purpose
    -------
    Thin wrapper over :class:`CommonMeasureService` that preconfigures the PNM
    Spectrum Analyzer test for a downstream OFDM capture on a single modem.

    Parameters
    ----------
    cable_modem : CableModem
        Target cable modem instance.
    tftp_servers : tuple[Inet, Inet], optional
        Primary/secondary TFTP servers used for capture file transfer.
        Defaults to :func:`PnmConfigManager.get_tftp_servers`.
    tftp_path : str, optional
        Remote TFTP directory where capture files are written.
        Defaults to :func:`PnmConfigManager.get_tftp_path`.

    Usage
    -----
    1) Construct the service.
    2) Call :meth:`setSpectrumCaptureParameters` with a :class:`SpecAnCapturePara`.
    3) Execute :meth:`set_and_go` to run the test.
    """

    def __init__(
        self,
        cable_modem: CableModem,
        tftp_servers: tuple[Inet, Inet] = PnmConfigManager.get_tftp_servers(),
        tftp_path: str = PnmConfigManager.get_tftp_path(),
    ) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        super().__init__(
            DocsPnmCmCtlTest.SPECTRUM_ANALYZER,
            cable_modem,
            tftp_servers,
            tftp_path,
            cable_modem.getWriteCommunity(),
        )

class DsOfdmChannelSpectrumAnalyzer(CommonSpectrumChannelAnalyzer):
    """
    Downstream OFDM Channel Spectrum Analyzer Orchestrator

    Responsibilities
    ----------------
    1) Query the cable modem for DS OFDM channel configuration.
    2) Compute per-channel spectrum bandwidth tuples: (start_hz, plc_hz, end_hz).
    3) Build :class:`SpecAnCapturePara` for each channel and invoke
       :class:`OfdmChanSpecAnalyzerService` to capture.

    Parameters
    ----------
    cable_modem : CableModem
        Cable modem whose downstream OFDM channels will be analyzed.
    number_of_averages : int, default 2
        Number of averages to request per segment in the capture.
    resolution_bandwidth : ResolutionBw, optional
        Resolution bandwidth in Hz; defaults to 300 kHz if not provided.
    spectrum_retrieval_type : SpectrumRetrievalType, default SpectrumRetrievalType.FILE
        Data retrieval mechanism (file-based or SNMP amplitude data).
    """

    def __init__(self, cable_modem: CableModem,
                 tftp_servers: tuple[Inet, Inet] = PnmConfigManager.get_tftp_servers(),
                 number_of_averages: int = 2,
                 resolution_bandwidth_hz: ResolutionBw | None = None,
                 spectrum_retrieval_type:SpectrumRetrievalType = SpectrumRetrievalType.FILE,) -> None:
        super().__init__(cable_modem)
        self.logger = logging.getLogger(self.__class__.__name__)
        self._number_of_averages = number_of_averages
        self._resolution_bandwidth = (
            resolution_bandwidth_hz
            if resolution_bandwidth_hz is not None
            else RBWConversion.DEFAULT_RBW_HZ
        )
        self._spectrum_retrieval_type = spectrum_retrieval_type
        self._pnm_test_type = DocsPnmCmCtlTest.SPECTRUM_ANALYZER
        self.log_prefix = f"DsOfdmChannelSpectrumAnalyzer - CM {self._cm.get_mac_address}"
        self._tftp_servers = tftp_servers

    async def start(self, capture_per_channel: bool = False) -> list[tuple[ChannelId, MessageResponse]]:
        """
        Run Spectrum Captures Across All OFDM Channels

        Behavior
        --------
        - Retrieves per-channel (start/plc/end) frequency tuples via
          :meth:`calculate_channel_spectrum_bandwidth`.
        - Builds a :class:`SpecAnCapturePara` for each channel using:
            * first_segment_center_freq = start_hz
            * last_segment_center_freq  = end_hz
            * segment_freq_span         = 1_000_000 Hz (default here)
            * num_bins_per_segment      = 256 (default here)
            * window_function           = HANN
            * num_averages              = instance default
            * spectrum_retrieval_type   = instance default
        - Executes :meth:`set_and_go` for each channel via
          :class:`OfdmChanSpecAnalyzerService`.

        Parameters
        ----------
        capture_per_channel : bool, optional
            Reserved flag for future modes; current implementation always
            iterates all channels. Default False.

        Returns
        -------
        list[tuple[ChannelId, MessageResponse]]
            Per-channel results from the spectrum analyzer run.

        Notes
        -----
        - The notion of "center" from this analyzer is not used to configure the
          capture here; the capture aligns to the *first* and *last* frequencies
          (start/end) as provided by the OFDM channel range.
        """
        channel_specCapture:list[tuple[ChannelId, SpecAnCapturePara]] = []
        out:list[tuple[ChannelId, MessageResponse]] = []

        # Compute the bandwidth mapping for all OFDM channels
        bw_by_channel: OfdmSpectrumBwLut = await self.calculate_channel_spectrum_bandwidth()

        rbw_settings: ResolutionBwSettings = RBWConversion.getSpectrumRbwSetttings(
            self._resolution_bandwidth,
        )

        num_bins_per_segment    = rbw_settings[1]
        number_of_averages      = self._number_of_averages
        spectrum_retrieval_type = self._spectrum_retrieval_type
        inactivity_timeout      = 30
        noise_bw                = 150
        segment_freq_span       = rbw_settings[2]

        for chan_id, (start_hz, plc_hz, end_hz) in bw_by_channel.items():
            self.logger.debug(
                f"OFDM - Mac: {self._cm.get_mac_address} - "
                f"Channel Settings: {chan_id}, {start_hz}, {plc_hz}, {end_hz}"
            )

            capture_parameter = SpecAnCapturePara(
                inactivity_timeout          = inactivity_timeout,
                first_segment_center_freq   = FrequencyHz(start_hz),
                last_segment_center_freq    = FrequencyHz(end_hz),
                segment_freq_span           = FrequencyHz(segment_freq_span),
                num_bins_per_segment        = num_bins_per_segment,
                noise_bw                    = noise_bw,
                window_function             = WindowFunction.HANN,
                num_averages                = number_of_averages,
                spectrum_retrieval_type     = spectrum_retrieval_type,
            )

            self.logger.debug(
                f"OFDM - Mac: {self._cm.get_mac_address} - "
                f"Capture Parameters: {capture_parameter.model_dump()}"
            )

            channel_specCapture.append((chan_id, capture_parameter))

        for chan_id, capture_parameter in channel_specCapture:
            service = OfdmChanSpecAnalyzerService(self._cm, tftp_servers=self._tftp_servers)
            service.setSpectrumCaptureParameters(capture_parameter)
            out.append((chan_id, await service.set_and_go()))
            await self.updatePnmMeasurementStatistics(chan_id)

        return out

    async def calculate_channel_spectrum_bandwidth(self) -> CommonChannelSpectumBwLut:
        """
        Calculate Per-Channel OFDM Spectrum Tuples

        Returns
        -------
        CommonChannelSpectumBwLut
            Mapping of ``ChannelId → (start_hz, plc_hz, end_hz)`` where:
            - ``start_hz = zero_freq + first_active * subcarrier_spacing``
            - ``end_hz   = zero_freq + (last_active + 1) * subcarrier_spacing``
            - ``plc_hz`` is the PLC frequency reported by the modem.

        Notes
        -----
        - Uses DOCSIS 3.1 fields from ``DocsIf31CmDsOfdmChanEntry``:
          SubcarrierZeroFreq, FirstActiveSubcarrierNum, LastActiveSubcarrierNum,
          SubcarrierSpacing, PlcFreq.
        - Start/End reflect the occupied OFDM spectrum range for each channel.
        """
        out: CommonChannelSpectumBwLut = {}

        channels: list[DocsIf31CmDsOfdmChanChannelEntry] = await self._cm.getDocsIf31CmDsOfdmChanEntry()
        if not channels:
            self.logger.warning("No downstream OFDM channels returned from cable modem.")
            return out

        for channel in channels:
            entry = channel.entry

            zero_freq: FrequencyHz      = cast(FrequencyHz, entry.docsIf31CmDsOfdmChanSubcarrierZeroFreq)
            first_active: SubcarrierIdx = cast(SubcarrierIdx, entry.docsIf31CmDsOfdmChanFirstActiveSubcarrierNum)
            last_active: SubcarrierIdx  = cast(SubcarrierIdx, entry.docsIf31CmDsOfdmChanLastActiveSubcarrierNum)
            sub_spacing: FrequencyHz    = cast(FrequencyHz, entry.docsIf31CmDsOfdmChanSubcarrierSpacing)
            plc_freq: FrequencyHz       = cast(FrequencyHz, entry.docsIf31CmDsOfdmChanPlcFreq)
            chan_id: ChannelId          = cast(ChannelId, entry.docsIf31CmDsOfdmChanChannelId)

            if (chan_id is None or zero_freq is None or
                first_active is None or last_active is None or
                sub_spacing is None or plc_freq is None ):

                self.logger.debug(
                    "Skipping channel with missing data: "
                    f"id={chan_id}, zero_freq={zero_freq}, first_active={first_active}, "
                    f"last_active={last_active}, spacing={sub_spacing}, plc_freq={plc_freq}")

                continue

            # For now, starting at zero_freq as per current implementation
            start_freq  = zero_freq + (first_active * sub_spacing)
            end_freq    = zero_freq + ((last_active + 1) * sub_spacing)

            out[chan_id] = (FrequencyHz(start_freq), FrequencyHz(plc_freq), FrequencyHz(end_freq))

            self.logger.debug(
                "Computed OFDM channel frequencies: "
                f"ch_id={chan_id}, start={start_freq}, plc={plc_freq}, end={end_freq}, "
                f"first_active={first_active}, last_active={last_active}, spacing={sub_spacing}"
            )

        return out

    async def calculate_spectrum_bandwidth(self) -> CommonSpectrumBw:
        """
        Retrieve The Precomputed Spectrum Bandwidth Mapping (Placeholder)

        Returns
        -------
        CommonSpectrumBw
            Placeholder tuple ``(0, 0, 0)``. This method is intentionally a stub
            in this class; see the SC-QAM variant for a complete implementation.

        Notes
        -----
        - Intentional placeholder to keep interface symmetry with
          :class:`DsScQamChannelSpectrumAnalyzer`. The OFDM flow typically
          uses per-channel tuples directly.
        """
        return (FrequencyHz(0), FrequencyHz(0), FrequencyHz(0))  # Placeholder implementation

class ScQamChanSpecAnalyzerService(CommonMeasureService):
    """
    Helper Service For SC-QAM Spectrum Analyzer Runs

    Purpose
    -------
    Thin wrapper around :class:`CommonMeasureService` that configures a
    single spectrum analyzer capture for a downstream SC-QAM channel set.

    Parameters
    ----------
    cable_modem : CableModem
        Target cable modem instance.
    tftp_servers : tuple[Inet, Inet], optional
        Primary/secondary TFTP servers for capture file transfer.
        Defaults to :func:`PnmConfigManager.get_tftp_servers`.
    tftp_path : str, optional
        Remote TFTP directory for capture output.
        Defaults to :func:`PnmConfigManager.get_tftp_path`.

    Usage
    -----
    1) Construct the service.
    2) Call :meth:`setSpectrumCaptureParameters` with :class:`SpecAnCapturePara`.
    3) Execute :meth:`set_and_go` to run the test.
    """

    def __init__(
        self,
        cable_modem: CableModem,
        tftp_servers: tuple[Inet, Inet] = PnmConfigManager.get_tftp_servers(),
        tftp_path: str = PnmConfigManager.get_tftp_path(),
    ) -> None:
        """
        Initialize The SC-QAM Spectrum Analyzer Service

        Notes
        -----
        - This constructor does not validate parameter contents; they are passed
          unchanged to :class:`CommonMeasureService`.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        super().__init__(
            DocsPnmCmCtlTest.SPECTRUM_ANALYZER,
            cable_modem,
            tftp_servers,
            tftp_path,
            cable_modem.getWriteCommunity(),)

class DsScQamChannelSpectrumAnalyzer(CommonSpectrumChannelAnalyzer):
    """
    Downstream SC-QAM Channel Spectrum Analyzer Orchestrator

    Responsibilities
    ----------------
    1) Fetch downstream SC-QAM channel list from the cable modem.
    2) Compute per-channel tuples (start_hz, center_hz, end_hz) using
       the reported center frequency and channel width.
    3) Build :class:`SpecAnCapturePara` and run captures per channel via
       :class:`ScQamChanSpecAnalyzerService`.

    Parameters
    ----------
    cable_modem : CableModem
        Cable modem to analyze.
    number_of_averages : int, default 1
        Number of averages per segment to request.
    resolution_bandwidth : ResolutionBw, optional
        Resolution bandwidth in Hz; defaults to 300 kHz if not provided.
    spectrum_retrieval_type : SpectrumRetrievalType, default SpectrumRetrievalType.FILE
        Data retrieval mechanism for captures.
    """

    def __init__(self, cable_modem: CableModem,
                 tftp_servers: tuple[Inet, Inet] = PnmConfigManager.get_tftp_servers(),
                 number_of_averages: int = 1,
                 resolution_bandwidth_hz: ResolutionBw | None = None,
                 spectrum_retrieval_type:SpectrumRetrievalType = SpectrumRetrievalType.FILE,) -> None:
        super().__init__(cable_modem)
        self.logger = logging.getLogger(self.__class__.__name__)
        self._number_of_averages = number_of_averages
        self._resolution_bandwidth = resolution_bandwidth_hz if resolution_bandwidth_hz is not None else ResolutionBw(25_000)
        self._spectrum_retrieval_type = spectrum_retrieval_type
        self._tftp_servers = tftp_servers

        self.log_prefix = f"DsScQamChannelSpectrumAnalyzer - CM {self._cm.get_mac_address}"
        self._test_mode = False

    async def start(self, capture_per_channel: bool = False) -> list[tuple[ChannelId, MessageResponse]]:
        """
        Run Spectrum Captures Across All SC-QAM Channels

        Behavior
        --------
        - Computes per-channel (start/center/end) tuples via
          :meth:`calculate_channel_spectrum_bandwidth`.
        - Configures :class:`SpecAnCapturePara` per channel using:
            * first_segment_center_freq = start_hz
            * last_segment_center_freq  = end_hz
            * segment_freq_span         = 1_000_000 Hz (default here)
            * num_bins_per_segment      = 256 (default here)
            * window_function           = HANN
            * num_averages              = instance default
            * spectrum_retrieval_type   = instance default
        - Executes :meth:`set_and_go` for each channel.

        Parameters
        ----------
        capture_per_channel : bool, optional
            Reserved for future modes; current implementation iterates all
            channels. Default False.

        Returns
        -------
        list[tuple[ChannelId, MessageResponse]]
            Per-channel results from the spectrum analyzer run.
        """
        channel_spec_capture: list[tuple[ChannelId, SpecAnCapturePara]] = []
        out: list[tuple[ChannelId, MessageResponse]] = []

        bw_by_channel: ScQamSpectrumBwLut = await self.calculate_channel_spectrum_bandwidth()
        rbw_settings:ResolutionBwSettings = RBWConversion.getSpectrumRbwSetttings(self._resolution_bandwidth)

        num_bins_per_segment = rbw_settings[1]
        number_of_averages = self._number_of_averages
        spectrum_retrieval_type = self._spectrum_retrieval_type
        inactivity_timeout = 60
        noise_bw = 150
        segment_freq_span = rbw_settings[2]

        for count, (chan_id, (start_hz, _center_hz, end_hz)) in enumerate(bw_by_channel.items()):

            if self._test_mode and count > 1:
                self.logger.warning("Test mode active: processing only first 2 channels.")
                break

            capture_parameter = SpecAnCapturePara(
                inactivity_timeout        = inactivity_timeout,
                first_segment_center_freq = FrequencyHz(start_hz),
                last_segment_center_freq  = FrequencyHz(end_hz),
                segment_freq_span         = FrequencyHz(segment_freq_span),
                num_bins_per_segment      = num_bins_per_segment,
                noise_bw                  = noise_bw,
                window_function           = WindowFunction.HANN,
                num_averages              = number_of_averages,
                spectrum_retrieval_type   = spectrum_retrieval_type,
            )

            channel_spec_capture.append((chan_id, capture_parameter))

        for chan_id, capture_parameter in channel_spec_capture:
            service = ScQamChanSpecAnalyzerService(self._cm, tftp_servers=self._tftp_servers)
            service.setSpectrumCaptureParameters(capture_parameter)
            out.append((chan_id, await service.set_and_go()))
            await self.updatePnmMeasurementStatistics(chan_id)

        return out

    async def calculate_channel_spectrum_bandwidth(self) -> CommonChannelSpectumBwLut:
        """
        Calculate Per-Channel SC-QAM Spectrum Tuples

        Method
        ------
        For each SC-QAM channel, computes:
            start = center - width/2
            end   = center + width/2

        Returns
        -------
        CommonChannelSpectumBwLut
            Mapping of ``ChannelId → (start_hz, center_hz, end_hz)``.

        Notes
        -----
        - Pulls channel center frequency and width from
          :class:`DocsIfDownstreamChannelEntry` via the modem.
        - Channels with missing data are skipped and logged.
        """
        out: CommonChannelSpectumBwLut = {}

        channels: list[DocsIfDownstreamChannelEntry] = await self._cm.getDocsIfDownstreamChannel()
        if not channels:
            self.logger.warning("No downstream SC-QAM channels returned from cable modem.")
            return out

        for channel in channels:
            cfreq: FrequencyHz = cast(FrequencyHz, channel.entry.docsIfDownChannelFrequency)
            cwidth: FrequencyHz = cast(FrequencyHz, channel.entry.docsIfDownChannelWidth)
            chan_id: ChannelId = cast(ChannelId, channel.entry.docsIfDownChannelId)

            if cfreq is None or cwidth is None or chan_id is None:
                self.logger.debug(
                    "Skipping channel with missing data: id=%s, freq=%s, width=%s",
                    chan_id,
                    cfreq,
                    cwidth,
                )
                continue

            half_width: FrequencyHz = cast(FrequencyHz, cwidth // 2)
            start: FrequencyHz = cast(FrequencyHz, cfreq - half_width)
            end: FrequencyHz = cast(FrequencyHz, cfreq + half_width)

            self.logger.debug(
                "Calculate SC-QAM Spectrum Settings: Mac: %s - Channel-Settings: Ch=%s, Start=%s, Center=%s, End=%s",
                self._cm.get_mac_address, chan_id, start, cfreq, end,
            )

            out[chan_id] = (start, cfreq, end)

        return out

    async def calculate_spectrum_bandwidth(self) -> CommonSpectrumBw:
        """
        Compute Overall SC-QAM Spectrum Bounds

        Purpose
        -------
        Folds all per-channel tuples into a single band by selecting the lowest
        start frequency and highest end frequency among channels, and computes a
        *nominal* midpoint as ``center = (start_global + end_global) // 2``.

        Returns
        -------
        CommonSpectrumBw
            Tuple ``(start_hz_global, center_hz_global, end_hz_global)``.

        Notes
        -----
        - The returned "center" is a nominal midpoint only. When configuring
          captures you typically prefer explicit first/last frequencies.
        - Logs incremental accumulation for traceability.
        """
        channels: CommonChannelSpectumBwLut = await self.calculate_channel_spectrum_bandwidth()
        if not channels:
            self.logger.warning("SC-QAM: no channels available to compute overall bandwidth.")
            return (FrequencyHz(0), FrequencyHz(0), FrequencyHz(0))

        # Initialize using the first entry
        iterator = iter(channels.items())
        first_key, (start_hz, _, end_hz) = next(iterator)
        start_hz_global: FrequencyHz = FrequencyHz(start_hz)
        end_hz_global: FrequencyHz = FrequencyHz(end_hz)

        # Fold the rest
        for channel_id, (ch_start, _ch_center, ch_end) in iterator:
            s = FrequencyHz(ch_start)
            e = FrequencyHz(ch_end)
            if s < start_hz_global:
                start_hz_global = s
            if e > end_hz_global:
                end_hz_global = e

            self.logger.debug(
                "SC-QAM accumulate: ch=%s, start=%d, end=%d → global=(%d, %d)",
                channel_id, s, e, start_hz_global, end_hz_global
            )

        center_hz_global: FrequencyHz = FrequencyHz((start_hz_global + end_hz_global) // 2)

        self.logger.debug(
            "SC-QAM overall bandwidth: start=%d Hz, end=%d Hz (width=%d Hz); nominal center=%d Hz",
            start_hz_global, end_hz_global, end_hz_global - start_hz_global, center_hz_global
        )

        return (start_hz_global, center_hz_global, end_hz_global)

# FILE: src/pypnm/api/routes/docs/pnm/spectrumAnalyzer/router.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from typing import Any, cast

from fastapi import APIRouter
from starlette.responses import FileResponse

from pypnm.api.routes.basic.abstract.analysis_report import AnalysisRptMatplotConfig
from pypnm.api.routes.basic.ofdm_spec_analyzer_rpt import OfdmSpecAnalyzerAnalysisReport
from pypnm.api.routes.basic.scqam_spec_analyzer_rpt import (
    ScQamSpecAnalyzerAnalysisReport,
)
from pypnm.api.routes.basic.spec_analyzer_analysis_rpt import SpectrumAnalyzerReport
from pypnm.api.routes.common.classes.analysis.analysis import Analysis, AnalysisType
from pypnm.api.routes.common.classes.analysis.model.process import (
    AnalysisProcessParameters,
)
from pypnm.api.routes.common.classes.analysis.multi_analysis import MultiAnalysis
from pypnm.api.routes.common.classes.common_endpoint_classes.common.enum import (
    OutputType,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.request_defaults import (
    RequestDefaultsResolver,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schemas import (
    PnmAnalysisResponse,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.snmp.schemas import (
    SnmpResponse,
)
from pypnm.api.routes.common.classes.file_capture.file_type import FileType
from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.extended.common_process_service import CommonProcessService
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.files.service import PnmFileService
from pypnm.api.routes.docs.pnm.spectrumAnalyzer.schemas import (
    OfdmSpecAnaAnalysisRequest,
    OfdmSpecAnaAnalysisResponse,
    ScQamSpecAnaAnalysisRequest,
    ScQamSpecAnaAnalysisResponse,
    SingleCaptureSpectrumAnalyzerFriendlyRequest,
    SingleCaptureSpectrumAnalyzerRequest,
)
from pypnm.api.routes.docs.pnm.spectrumAnalyzer.service import (
    CmSpectrumAnalysisService,
    DsOfdmChannelSpectrumAnalyzer,
    DsScQamChannelSpectrumAnalyzer,
    SpectrumAnalyzerFriendlyCaptureBuilder,
)
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.pnm.DocsIf3CmSpectrumAnalysisEntry import (
    DocsIf3CmSpectrumAnalysisEntry,
)
from pypnm.lib.dict_utils import DictGenerate
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import ChannelId, FrequencyHz, InetAddressStr, MacAddressStr, Path


class SpectrumAnalyzerRouter:
    def __init__(self) -> None:
        prefix = "/docs/pnm/ds"
        self.base_endpoint = "/spectrumAnalyzer"
        self.router = APIRouter(prefix=prefix, tags=["PNM Operations - Spectrum Analyzer"])
        self.logger = logging.getLogger(f"{self.__class__.__name__}")
        self.__routes()

    def __routes(self) -> None:
        @self.router.post(
            f"{self.base_endpoint}/getCapture",
            summary="Get Spectrum Analyzer Capture",
            response_model=None,
            responses=FAST_API_RESPONSE,
        )
        async def get_capture(request: SingleCaptureSpectrumAnalyzerRequest) -> SnmpResponse | PnmAnalysisResponse | FileResponse:
            """
            Perform Spectrum Analyzer Capture And Return Analysis Results.

            This endpoint triggers a spectrum capture on the requested cable modem using the
            provided capture parameters. The measurement response is then processed through
            the common analysis pipeline and returned as either:

            - A JSON analysis payload containing decoded amplitude data and summary metrics.
            - An archive file containing plots and related report artifacts (ZIP).

            The cable modem must be PNM-ready and the capture parameters must respect the
            diplexer configuration and platform constraints (DOCSIS 3.x and DOCSIS 4.0 FDD).

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/spectrum-analyzer.md)

            """
            mac: MacAddressStr = request.cable_modem.mac_address
            ip: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(request.cable_modem.snmp)
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(request.cable_modem.pnm_parameters.tftp)

            self.logger.info("Starting Spectrum Analyzer capture for MAC: %s, IP: %s, Output Type: %s",
                mac, ip, request.analysis.output.type,)

            cm = CableModem(mac_address=MacAddress(mac),
                            inet=Inet(ip),
                            write_community=community,)

            status, msg = await CableModemServicePreCheck(
                cable_modem=cm,
                tftp_config=request.cable_modem.pnm_parameters.tftp,
                validate_pnm_ready_status=True,
            ).run_precheck()

            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse(mac_address=mac, status=status, message=msg)

            service = CmSpectrumAnalysisService(
                cable_modem=cm,
                tftp_servers=tftp_servers,
                capture_parameters=request.capture_parameters,)

            msg_rsp: MessageResponse = await service.set_and_go()

            if msg_rsp.status != ServiceStatusCode.SUCCESS:
                err = "Unable to complete Spectrum Analyzer capture."
                self.logger.error("%s Status: %s", err, msg_rsp.status.name)
                return SnmpResponse(mac_address=mac, status=msg_rsp.status, message=err)

            channel_ids = None
            measurement_stats: list[DocsIf3CmSpectrumAnalysisEntry] = cast(
                list[DocsIf3CmSpectrumAnalysisEntry],
                await service.getPnmMeasurementStatistics(channel_ids=channel_ids),)

            cps = CommonProcessService(msg_rsp)
            msg_rsp = cps.process()

            analysis = Analysis(AnalysisType.BASIC, msg_rsp, skip_automatic_process=True)
            analysis.process(cast(AnalysisProcessParameters, request.analysis.spectrum_analysis))

            if request.analysis.output.type == OutputType.JSON:
                payload: dict[str, Any] = cast(dict[str, Any], analysis.get_results())
                DictGenerate.pop_keys_recursive(payload, ["pnm_header", "mac_address", "channel_id"])

                primative = msg_rsp.payload_to_dict("primative")
                DictGenerate.pop_keys_recursive(
                    primative,
                    ["device_details", "channel_id", "amplitude_bin_segments_float"],
                )
                payload.update(cast(dict[str, Any], primative))
                payload.update(
                    DictGenerate.models_to_nested_dict(
                        measurement_stats,
                        "measurement_stats",
                    )
                )

                return PnmAnalysisResponse(
                    mac_address=mac,
                    status=ServiceStatusCode.SUCCESS,
                    data=payload,
                )

            if request.analysis.output.type == OutputType.ARCHIVE:
                theme = request.analysis.plot.ui.theme
                plot_config = AnalysisRptMatplotConfig(theme=theme)
                analysis_rpt = SpectrumAnalyzerReport(analysis, plot_config)
                rpt: Path = cast(Path, analysis_rpt.build_report())
                return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

            return PnmAnalysisResponse(
                mac_address=mac,
                status=ServiceStatusCode.INVALID_OUTPUT_TYPE,
                data={},
            )

        @self.router.post(
            f"{self.base_endpoint}/getCapture/friendly",
            summary="Get Spectrum Analyzer Capture (Friendly)",
            response_model=None,
            responses=FAST_API_RESPONSE,
        )
        async def get_capture_friendly(
            request: SingleCaptureSpectrumAnalyzerFriendlyRequest,
        ) -> SnmpResponse | PnmAnalysisResponse | FileResponse:
            """
            Perform Spectrum Analyzer Capture Using Friendly RBW Inputs.

            This endpoint accepts a resolution bandwidth (RBW) and a requested window,
            then derives a segment span and bin count using the spectrum-analysis-capture-set
            rules. The segment center frequencies are adjusted inward by half a segment
            span on each edge to satisfy the analyzer's scaled window constraints.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/spectrum-analyzer/spectrum-analyzer.md)
            """
            mac: MacAddressStr = request.cable_modem.mac_address
            ip: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(request.cable_modem.snmp)
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(request.cable_modem.pnm_parameters.tftp)

            self.logger.info("Starting Spectrum Analyzer friendly capture for MAC: %s, IP: %s, Output Type: %s",
                mac, ip, request.analysis.output.type,)

            cm = CableModem(mac_address=MacAddress(mac),
                            inet=Inet(ip),
                            write_community=community,)

            status, msg = await CableModemServicePreCheck(
                cable_modem=cm,
                tftp_config=request.cable_modem.pnm_parameters.tftp,
                validate_pnm_ready_status=True,
            ).run_precheck()

            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse(mac_address=mac, status=status, message=msg)

            try:
                capture_parameters = SpectrumAnalyzerFriendlyCaptureBuilder.build(
                    request.capture_parameters,
                )
            except ValueError as e:
                err = f"Invalid capture parameters: {e}"
                self.logger.error(err)
                return SnmpResponse(mac_address=mac, status=ServiceStatusCode.INVALID_CAPTURE_PARAMETERS, message=err)

            service = CmSpectrumAnalysisService(
                cable_modem=cm,
                tftp_servers=tftp_servers,
                capture_parameters=capture_parameters,)

            msg_rsp: MessageResponse = await service.set_and_go()

            if msg_rsp.status != ServiceStatusCode.SUCCESS:
                err = "Unable to complete Spectrum Analyzer capture."
                self.logger.error("%s Status: %s", err, msg_rsp.status.name)
                return SnmpResponse(mac_address=mac, status=msg_rsp.status, message=err)

            channel_ids = None
            measurement_stats: list[DocsIf3CmSpectrumAnalysisEntry] = cast(
                list[DocsIf3CmSpectrumAnalysisEntry],
                await service.getPnmMeasurementStatistics(channel_ids=channel_ids),)

            cps = CommonProcessService(msg_rsp)
            msg_rsp = cps.process()

            analysis = Analysis(AnalysisType.BASIC, msg_rsp, skip_automatic_process=True)
            analysis.process(cast(AnalysisProcessParameters, request.analysis.spectrum_analysis))

            if request.analysis.output.type == OutputType.JSON:
                payload: dict[str, Any] = cast(dict[str, Any], analysis.get_results())
                DictGenerate.pop_keys_recursive(payload, ["pnm_header", "mac_address", "channel_id"])

                primative = msg_rsp.payload_to_dict("primative")
                DictGenerate.pop_keys_recursive(
                    primative,
                    ["device_details", "channel_id", "amplitude_bin_segments_float"],
                )
                payload.update(cast(dict[str, Any], primative))
                payload.update(
                    DictGenerate.models_to_nested_dict(
                        measurement_stats,
                        "measurement_stats",
                    )
                )

                return PnmAnalysisResponse(
                    mac_address=mac,
                    status=ServiceStatusCode.SUCCESS,
                    data=payload,
                )

            if request.analysis.output.type == OutputType.ARCHIVE:
                theme = request.analysis.plot.ui.theme
                plot_config = AnalysisRptMatplotConfig(theme=theme)
                analysis_rpt = SpectrumAnalyzerReport(analysis, plot_config)
                rpt: Path = cast(Path, analysis_rpt.build_report())
                return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

            return PnmAnalysisResponse(
                mac_address=mac,
                status=ServiceStatusCode.INVALID_OUTPUT_TYPE,
                data={},
            )

        @self.router.post(
            f"{self.base_endpoint}/getCapture/ofdm",
            summary="Get OFDM Channels Spectrum Analyzer Capture",
            response_model=None,
            responses=FAST_API_RESPONSE,
        )
        async def get_ofdm_ds_channels_analysis(request: OfdmSpecAnaAnalysisRequest) -> OfdmSpecAnaAnalysisResponse | FileResponse:
            """
            Perform OFDM Downstream Spectrum Capture Across All DS OFDM Channels.

            This endpoint triggers spectrum capture operations on each DOCSIS 3.1 OFDM
            downstream channel of the requested cable modem. Each per-channel response is
            processed through the common analysis pipeline, aggregated into a multi-analysis
            structure, and then returned as either JSON or an archive.

            The cable modem must support OFDM downstream channels and be PNM-ready, and
            the spectrum capture parameters must be valid for the underlying platform and
            diplexer configuration.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/spectrum-analyzer.md)

            """
            mac: MacAddressStr = request.cable_modem.mac_address
            ip: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(request.cable_modem.snmp)
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(request.cable_modem.pnm_parameters.tftp)

            cm = CableModem(mac_address=MacAddress(mac),
                            inet=Inet(ip),
                            write_community=community)
            multi_analysis = MultiAnalysis()

            self.logger.info("DOCSIS 3.1 OFDM Downstream Spectrum Capture for MAC %s, IP %s", mac, ip,)

            status, msg = await CableModemServicePreCheck(
                cable_modem=cm,
                tftp_config=request.cable_modem.pnm_parameters.tftp,
                validate_ofdm_exist=True,
                validate_pnm_ready_status=True,
            ).run_precheck()

            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return OfdmSpecAnaAnalysisResponse(
                    mac_address=mac, status=status, message=msg, data={},)

            service = DsOfdmChannelSpectrumAnalyzer(
                cable_modem             =   cm,
                tftp_servers            =   tftp_servers,
                number_of_averages      =   request.capture_parameters.number_of_averages,
                resolution_bandwidth_hz =   request.capture_parameters.resolution_bandwidth_hz,
                spectrum_retrieval_type =   request.capture_parameters.spectrum_retrieval_type)

            msg_responses: list[tuple[ChannelId, MessageResponse]] = await service.start()

            measurement_stats: list[DocsIf3CmSpectrumAnalysisEntry] = cast(
                list[DocsIf3CmSpectrumAnalysisEntry],
                await service.getPnmMeasurementStatisticsFlat(),
            )

            primative: dict[str, dict[Any, Any]] = {"primative": {}}

            for idx, (chan_id, msg_rsp) in enumerate(msg_responses):
                cps_msg_rsp = CommonProcessService(msg_rsp).process()

                analysis = Analysis(AnalysisType.BASIC, cps_msg_rsp, skip_automatic_process=True,)
                analysis.process(cast(AnalysisProcessParameters, request.analysis.spectrum_analysis))
                multi_analysis.add(chan_id, analysis)

                primative_entry = cps_msg_rsp.payload_to_dict(idx)
                primative["primative"].update(primative_entry)

            analyzer_rpt = OfdmSpecAnalyzerAnalysisReport(multi_analysis)
            analyzer_rpt.build_report()

            if request.analysis.output.type == OutputType.JSON:
                analyzer_rpt_dict = analyzer_rpt.to_dict()
                analyzer_rpt_dict.update(primative)
                analyzer_rpt_dict.update(
                    DictGenerate.models_to_nested_dict(measurement_stats, "measurement_stats",))

                return OfdmSpecAnaAnalysisResponse(
                    mac_address =   mac,
                    status      =   ServiceStatusCode.SUCCESS,
                    data        =   analyzer_rpt_dict,
                )

            if request.analysis.output.type == OutputType.ARCHIVE:
                return PnmFileService().get_file(
                    FileType.ARCHIVE, analyzer_rpt.get_archive(),
                )

            return OfdmSpecAnaAnalysisResponse(
                mac_address =   mac,
                status      =   ServiceStatusCode.INVALID_OUTPUT_TYPE,
                message     =   f"Unsupported output type: {request.analysis.output.type}",
                data={},
            )

        @self.router.post(
            f"{self.base_endpoint}/getCapture/scqam",
            summary="Get SC-QAM Downstream Channels Spectrum Analysis",
            response_model=None,
            responses=FAST_API_RESPONSE,
        )
        async def get_scqam_ds_channels_analysis(request: ScQamSpecAnaAnalysisRequest) -> ScQamSpecAnaAnalysisResponse | FileResponse:
            """
            Perform SC-QAM Downstream Spectrum Capture Across All DS SC-QAM Channels.

            This endpoint triggers spectrum capture operations on each DOCSIS 3.0 SC-QAM
            downstream channel of the requested cable modem. Each per-channel response is
            processed through the common analysis pipeline, aggregated into a multi-analysis
            structure, and then returned as either JSON or an archive.

            The cable modem must support SC-QAM downstream channels and be PNM-ready, and
            the spectrum capture parameters must be valid for the underlying platform and
            diplexer configuration.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/spectrum-analyzer.md)

            """
            mac: MacAddressStr = request.cable_modem.mac_address
            ip: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(request.cable_modem.snmp)
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(request.cable_modem.pnm_parameters.tftp)

            cm = CableModem(mac_address=MacAddress(mac), inet=Inet(ip), write_community=community)
            multi_analysis = MultiAnalysis()

            self.logger.info("DOCSIS 3.0 SC-QAM downstream spectrum capture for MAC %s, IP %s", mac, ip)

            status, msg = await CableModemServicePreCheck(
                cable_modem=cm,
                tftp_config=request.cable_modem.pnm_parameters.tftp,
                validate_scqam_exist=True,
                validate_pnm_ready_status=True,
            ).run_precheck()

            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return ScQamSpecAnaAnalysisResponse(
                    mac_address=mac,
                    status=status, message=msg, data={}, )

            number_of_averages: int = request.capture_parameters.number_of_averages
            spectrum_retrieval_type = request.capture_parameters.spectrum_retrieval_type
            resolution_bandwidth: FrequencyHz = request.capture_parameters.resolution_bandwidth_hz

            service = DsScQamChannelSpectrumAnalyzer(
                cable_modem             =   cm,
                tftp_servers            =   tftp_servers,
                number_of_averages      =   number_of_averages,
                resolution_bandwidth_hz =   resolution_bandwidth,
                spectrum_retrieval_type =   spectrum_retrieval_type,
            )

            msg_responses: list[tuple[ChannelId, MessageResponse]] = await service.start()

            measurement_stats: list[DocsIf3CmSpectrumAnalysisEntry] = cast(
                list[DocsIf3CmSpectrumAnalysisEntry],
                await service.getPnmMeasurementStatisticsFlat(),
            )

            primative: dict[str, dict[Any, Any]] = {"primative": {}}

            for idx, (chan_id, msg_rsp) in enumerate(msg_responses):
                cps_msg_rsp = CommonProcessService(msg_rsp).process()

                analysis = Analysis(AnalysisType.BASIC, cps_msg_rsp, skip_automatic_process=True,)
                analysis.process(cast(AnalysisProcessParameters, request.analysis.spectrum_analysis))
                multi_analysis.add(chan_id, analysis)

                primative_entry = cps_msg_rsp.payload_to_dict(idx)
                primative["primative"].update(primative_entry)

            analyzer_rpt = ScQamSpecAnalyzerAnalysisReport(multi_analysis)
            analyzer_rpt.build_report()

            if request.analysis.output.type == OutputType.JSON:
                analyzer_rpt_dict = analyzer_rpt.to_dict()
                analyzer_rpt_dict.update(primative)
                analyzer_rpt_dict.update(
                    DictGenerate.models_to_nested_dict(measurement_stats, "measurement_stats",))

                return ScQamSpecAnaAnalysisResponse(
                    mac_address =   mac,
                    status      =   ServiceStatusCode.SUCCESS,
                    data        =   analyzer_rpt_dict,
                )

            if request.analysis.output.type == OutputType.ARCHIVE:
                return PnmFileService().get_file(FileType.ARCHIVE, analyzer_rpt.get_archive(),)

            return ScQamSpecAnaAnalysisResponse(
                mac_address=mac,
                status=ServiceStatusCode.INVALID_OUTPUT_TYPE,
                message=f"Unsupported output type: {request.analysis.output.type}",
                data={},
            )


# Required for dynamic auto-registration
router = SpectrumAnalyzerRouter().router

# FILE: docs/api/fast-api/single/spectrum-analyzer/spectrum-analyzer.md
# PNM Operations - Spectrum Analyzer

Downstream Spectrum Capture And Per-Channel Analysis For DOCSIS 3.x/4.0 Cable Modems.

## Overview

[`SpectrumAnalyzerRouter`](http://github.com/PyPNMApps/PyPNM/blob/main/src/pypnm/api/routes/docs/pnm/spectrumAnalyzer/router.py)
exposes four related endpoints that drive downstream spectrum capture and analysis:

* A single spectrum capture endpoint (`/getCapture`) for free-form frequency sweeps.
* A single spectrum capture endpoint with friendly RBW inputs (`/getCapture/friendly`).
* An OFDM-focused endpoint (`/getCapture/ofdm`) that walks all downstream OFDM channels.
* An SC-QAM-focused endpoint (`/getCapture/scqam`) that walks all downstream SC-QAM channels.

Each capture is processed through the common analysis pipeline and can return either a JSON
analysis payload or an archive (ZIP) with Matplotlib plots and CSV exports.

For RBW auto-scale outcomes, see the [Spectrum analyzer RBW permutations](../spectrum-analyzer.md) reference.

> The cable modem must be PNM-ready and the requested frequency range must fall within the
> configured diplexer band. Use the diplexer configuration API to verify allowed frequency
> boundaries.

### Diplexer Configuration Endpoint

| DOCSIS | Endpoint | Description |
|-------|----------|-------------|
| [DOCSIS 3.1](../general/diplexer-configuration.md)                | `POST /docs/if31/system/diplexer`              | Retrieve the diplexer for spectrum capture. |
| [DOCSIS 4.0](../fdd/fdd-system-diplexer-configuration.md) | `POST /docs/fdd/system/diplexer/configuration` | Retrieve the diplexer for spectrum capture. |

## Endpoints

All endpoints share the same base prefix: `/docs/pnm/ds`.

| Purpose                        | Method | Path                                             |
| ------------------------------ | ------ | ------------------------------------------------ |
| Single spectrum capture        | POST   | `/docs/pnm/ds/spectrumAnalyzer/getCapture`       |
| Single spectrum capture (RBW)  | POST   | `/docs/pnm/ds/spectrumAnalyzer/getCapture/friendly` |
| All OFDM downstream channels   | POST   | `/docs/pnm/ds/spectrumAnalyzer/getCapture/ofdm`  |
| All SC-QAM downstream channels | POST   | `/docs/pnm/ds/spectrumAnalyzer/getCapture/scqam` |

Each endpoint accepts a common cable modem block and analysis controls. Capture-specific
settings are provided under `capture_parameters`.

> Note: A modem can only run either downstream or upstream spectrum at a time. The router
> documented here is downstream (`/ds`) only.

## Common Request Shape

Refer to [Common → Request](../../common/request.md).  
These endpoints add optional `analysis` controls and a `capture_parameters` section.

### Analysis Delta Table

| JSON path                | Type   | Allowed values / format | Default | Description                                                                                               |
| ------------------------ | ------ | ----------------------- | ------- | --------------------------------------------------------------------------------------------------------- |
| `analysis.type`          | string | "basic"                 | "basic" | Selects the analysis mode used during processing.                                                         |
| `analysis.output.type`   | string | "json", "archive"       | "json"  | Output format. **`json`** returns inline `data`; **`archive`** returns a ZIP (CSV exports and PNG plots). |
| `analysis.plot.ui.theme` | string | "light", "dark"         | "dark"  | Theme hint for Matplotlib plots (colors, grid, ticks). Does not affect raw metrics/CSV.                   |
| `analysis.spectrum_analysis.moving_average.points` | int | >= 1 | 10 | Window size for the moving average applied to spectrum magnitudes. |

When `analysis.output.type = "archive"`, the HTTP response body is the file (no `data` JSON payload).

## Single Capture - `/spectrumAnalyzer/getCapture`

Single downstream spectrum capture using the modem's generic spectrum engine. This is the
most flexible entry point and allows arbitrary sweep settings (within diplexer limits).

### Single Capture Example Request

```json
{
  "cable_modem": {
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "ip_address": "192.168.0.100",
    "pnm_parameters": {
      "tftp": {
        "ipv4": "192.168.0.10",
        "ipv6": "2001:db8::10"
      }
    },
    "snmp": {
      "snmpV2C": {
        "community": "private"
      }
    }
  },
  "analysis": {
    "type": "basic",
    "output": { "type": "json" },
    "plot": { "ui": { "theme": "dark" } },
    "spectrum_analysis": {
      "moving_average": { "points": 10 }
    }
  },
  "capture_parameters": {
    "inactivity_timeout": 60,
    "first_segment_center_freq": 300000000,
    "last_segment_center_freq": 900000000,
    "segment_freq_span": 1000000,
    "num_bins_per_segment": 256,
    "noise_bw": 150,
    "window_function": 1,
    "num_averages": 1,
    "spectrum_retrieval_type": 1
  }
}
```

### Capture Parameters

| JSON path                                      | Type | Description                                                                  |
| ---------------------------------------------- | ---- | ---------------------------------------------------------------------------- |
| `capture_parameters.inactivity_timeout`        | int  | Timeout (seconds) before aborting idle spectrum acquisition.                 |
| `capture_parameters.first_segment_center_freq` | int  | Center frequency (Hz) of the first sweep segment.                            |
| `capture_parameters.last_segment_center_freq`  | int  | Center frequency (Hz) of the last sweep segment.                             |
| `capture_parameters.segment_freq_span`         | int  | Frequency span (Hz) covered by each sweep segment.                           |
| `capture_parameters.num_bins_per_segment`      | int  | Number of FFT bins per segment.                                              |
| `capture_parameters.noise_bw`                  | int  | Equivalent noise bandwidth in kHz.                                            |
| `capture_parameters.window_function`           | int  | Window function enum value.                                                    |
| `capture_parameters.num_averages`              | int  | Number of averages per segment for noise reduction.                           |
| `capture_parameters.spectrum_retrieval_type`   | int  | Retrieval mode enum value (FILE = 1, SNMP = 2).                                 |

### Note

`pnm_parameters.capture.channel_ids` is not supported for this endpoint. Use the OFDM or SC-QAM endpoints when channel scoping is required.

#### Window Function Values

| Value | Enum name |
| ----- | --------- |
| 0     | OTHER |
| 1     | HANN |
| 2     | BLACKMAN_HARRIS |
| 3     | RECTANGULAR |
| 4     | HAMMING |
| 5     | FLAT_TOP |
| 6     | GAUSSIAN |
| 7     | CHEBYSHEV |

#### Note

> `spectrum_retrieval_type` Use 1 (PNM_FILE) is preferred for most use cases. Use `2` (SNMP) when PNM file transfer is not available.

## Single Capture (Friendly) - `/spectrumAnalyzer/getCapture/friendly`

This variant accepts a resolution bandwidth and a requested window, then derives
the segment span and bin count using the spectrum-analysis-capture-set rules. The
first and last segment center frequencies are adjusted inward by half a segment
span to satisfy the analyzer's scaled window constraints.

### Friendly Capture Example Request

```json
{
  "cable_modem": {
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "ip_address": "192.168.0.100",
    "pnm_parameters": {
      "tftp": {
        "ipv4": "192.168.0.10",
        "ipv6": "2001:db8::10"
      }
    },
    "snmp": {
      "snmpV2C": {
        "community": "private"
      }
    }
  },
  "analysis": {
    "type": "basic",
    "output": { "type": "json" },
    "plot": { "ui": { "theme": "dark" } },
    "spectrum_analysis": {
      "moving_average": { "points": 10 }
    }
  },
  "capture_parameters": {
    "inactivity_timeout": 60,
    "first_segment_center_freq": 300000000,
    "last_segment_center_freq": 900000000,
    "resolution_bw": 30000,
    "noise_bw": 150,
    "window_function": 1,
    "num_averages": 1,
    "spectrum_retrieval_type": 1
  }
}
```

### Friendly Capture Parameters

| JSON path                                      | Type | Description                                                                  |
| ---------------------------------------------- | ---- | ---------------------------------------------------------------------------- |
| `capture_parameters.inactivity_timeout`        | int  | Timeout (seconds) before aborting idle spectrum acquisition.                 |
| `capture_parameters.first_segment_center_freq` | int  | Requested first segment center frequency (Hz) for the capture window.        |
| `capture_parameters.last_segment_center_freq`  | int  | Requested last segment center frequency (Hz) for the capture window.         |
| `capture_parameters.resolution_bw`             | int  | Resolution bandwidth (Hz) used to derive segment span and bin count.         |
| `capture_parameters.noise_bw`                  | int  | Equivalent noise bandwidth in kHz.                                           |
| `capture_parameters.window_function`           | int  | Window function enum value.                                                  |
| `capture_parameters.num_averages`              | int  | Number of averages per segment.                                              |
| `capture_parameters.spectrum_retrieval_type`   | int  | Retrieval mode enum value (FILE = 1, SNMP = 2).                              |

Note: The computed `segment_freq_span`, `num_bins_per_segment`, and adjusted segment
center frequencies are returned in the analysis payload.

### Abbreviated JSON Response (Output Type `"json"`)

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": 0,
  "message": null,
  "data": {
    "analysis": [
      {
        "device_details": {
          "system_description": {
            "HW_REV": "1.0",
            "VENDOR": "LANCity",
            "BOOTR": "NONE",
            "SW_REV": "1.0.0",
            "MODEL": "LCPET-3"
          }
        },
        "capture_parameters": {
          "inactivity_timeout": 60,
          "first_segment_center_freq": 300000000,
          "last_segment_center_freq": 900000000,
          "segment_freq_span": 1000000,
          "num_bins_per_segment": 100,
          "noise_bw": 0,
          "window_function": 1,
          "num_averages": 1,
          "spectrum_retrieval_type": 1
        },
        "signal_analysis": {
          "bin_bandwidth": 10000,
          "segment_length": 100,
          "frequencies": [],
          "magnitudes": [],
          "window_average": {
            "points": 20,
            "magnitudes": []
          }
        }
      }
    ],
    "primative": [
      {
        "status": "SUCCESS",
        "pnm_header": {
          "file_type": "PNN",
          "file_type_version": 9,
          "major_version": 1,
          "minor_version": 0,
          "capture_time": 1762839675
        },
        "mac_address": "aa:bb:cc:dd:ee:ff",
        "first_segment_center_frequency": 300000000,
        "last_segment_center_frequency": 900000000,
        "segment_frequency_span": 1000000,
        "num_bins_per_segment": 100,
        "equivalent_noise_bandwidth": 110.0,
        "window_function": 1,
        "bin_frequency_spacing": 10000,
        "spectrum_analysis_data_length": 120200,
        "spectrum_analysis_data": "e570e3...40e340"
      }
    ],
    "measurement_stats": [
      {
        "index": 0,
        "entry": {
          "docsIf3CmSpectrumAnalysisCtrlCmdEnable": true,
          "docsIf3CmSpectrumAnalysisCtrlCmdInactivityTimeout": 60,
          "docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency": 300000000,
          "docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency": 900000000,
          "docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan": 1000000,
          "docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment": 100,
          "docsIf3CmSpectrumAnalysisCtrlCmdEquivalentNoiseBandwidth": 110,
          "docsIf3CmSpectrumAnalysisCtrlCmdWindowFunction": 1,
          "docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages": 1,
          "docsIf3CmSpectrumAnalysisCtrlCmdFileEnable": true,
          "docsIf3CmSpectrumAnalysisCtrlCmdMeasStatus": "sample_ready",
          "docsIf3CmSpectrumAnalysisCtrlCmdFileName": "spectrum_analyzer_aabbccddeeff_0_1762839621.bin"
        }
      }
    ]
  }
}
```

### Single-Capture Return Structure

Top-level envelope:

| Field         | Type          | Description                                                               |
| ------------- | ------------- | ------------------------------------------------------------------------- |
| `mac_address` | string        | Request echo of the modem MAC.                                            |
| `status`      | int           | 0 on success, non-zero on error.                                          |
| `message`     | string\|null  | Optional message describing status.                                       |
| `data`        | object        | Container for results (`analysis`, `primative`, `measurement_stats`).     |

**Payload: `data.analysis[]`**

| Field                            | Type   | Description                                                           |
| -------------------------------- | ------ | --------------------------------------------------------------------- |
| device_details.*                 | object | System descriptor captured at analysis time.                          |
| capture_parameters.*             | object | Echo of the capture parameters effective for this run.               |
| signal_analysis.bin_bandwidth    | int    | Effective bin bandwidth (Hz) derived from bin spacing/windowing.     |
| signal_analysis.segment_length   | int    | Number of FFT bins per segment used in analysis.                     |
| signal_analysis.frequencies      | array  | Frequency axis for the analyzed spectrum (per-bin center frequency). |
| signal_analysis.magnitudes       | array  | Amplitude values aligned with `frequencies`.                         |
| signal_analysis.window_average.* | object | Optional moving-average smoothing applied to `magnitudes`.           |

**Payload: `data.primative[]`**

| Field                          | Type       | Description                                               |
| ------------------------------ | ---------- | --------------------------------------------------------- |
| status                         | string     | Result for this capture (e.g., `"SUCCESS"`).              |
| pnm_header.*                   | object     | PNM file header (type, version, capture time).            |
| mac_address                    | string     | MAC address.                                              |
| first_segment_center_frequency | int (Hz)   | Center frequency of the first sweep segment.              |
| last_segment_center_frequency  | int (Hz)   | Center frequency of the last sweep segment.               |
| segment_frequency_span         | int (Hz)   | Frequency span covered by each segment.                   |
| num_bins_per_segment           | int        | Number of FFT bins per segment.                           |
| equivalent_noise_bandwidth     | float (Hz) | Equivalent noise bandwidth used for amplitude scaling.    |
| window_function                | int        | Window function index.                                    |
| bin_frequency_spacing          | float (Hz) | Frequency spacing between adjacent bins.                  |
| spectrum_analysis_data_length  | int        | Byte length of `spectrum_analysis_data`.                  |
| spectrum_analysis_data         | string     | Raw spectrum data encoded as hexadecimal text.            |

**Payload: `data.measurement_stats[]`**

| Field                                                     | Type    | Description                                              |
| --------------------------------------------------------- | ------- | -------------------------------------------------------- |
| index                                                               | int     | SNMP table row index.                                    |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdEnable                        | boolean | Whether capture was enabled for this measurement.        |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdInactivityTimeout             | int     | Inactivity timeout (seconds) used for the capture.       |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency   | int (Hz) | First segment center frequency at capture time.  |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency    | int (Hz) | Last segment center frequency at capture time.   |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan          | int (Hz) | Segment frequency span in Hz.                   |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment             | int     | Number of bins per segment.                      |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdEquivalentNoiseBandwidth      | int     | Equivalent noise bandwidth in Hz.                |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdWindowFunction                | int     | Window function index.                           |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages              | int     | Number of averages used for this capture.        |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdFileEnable                    | boolean | Whether capture-to-file was enabled.             |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdMeasStatus                    | string  | Measurement status (e.g., `"sample_ready"`).     |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdFileName                      | string  | Device-side filename of the captured spectrum.   |

## OFDM Downstream Capture - `/spectrumAnalyzer/getCapture/ofdm`

This endpoint iterates across all downstream OFDM channels on the modem, performing a
spectrum capture per channel and aggregating the results into a multi-analysis structure.

Each per-channel capture is processed like the single capture. Results are returned as:

* `data.analyses[]` - list of per-channel analysis views (one entry per capture).
* `data.primative` - dictionary of raw capture payloads indexed by channel position.
* `data.measurement_stats[]` - flattened SNMP spectrum-analysis entries.

DOCSIS constraints:

* DOCSIS 3.1: up to **2** downstream OFDM channels.  
* DOCSIS 4.0 FDD/FDX: up to **5** downstream OFDM channels.

### OFDM Capture Example Request

```json
{
  "cable_modem": {
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "ip_address": "192.168.0.100",
    "pnm_parameters": {
      "tftp": {
        "ipv4": "192.168.0.10",
        "ipv6": "2001:db8::10"
      },
      "capture": {
        "channel_ids": [193, 194]
      }
    },
    "snmp": {
      "snmpV2C": {
        "community": "private"
      }
    }
  },
  "analysis": {
    "type": "basic",
    "output": { "type": "json" },
    "plot": { "ui": { "theme": "dark" } },
    "spectrum_analysis": {
      "moving_average": { "points": 10 }
    }
  },
  "capture_parameters": {
    "number_of_averages": 10,
    "resolution_bandwidth_hz": 25000,
    "spectrum_retrieval_type": 1
  }
}
```

### OFDM Capture Parameters

| JSON path                                   | Type | Description                                                                  |
| ------------------------------------------- | ---- | ---------------------------------------------------------------------------- |
| `capture_parameters.number_of_averages`     | int  | Number of samples used to compute the per-bin average.                       |
| `capture_parameters.resolution_bandwidth_hz`| int  | Resolution bandwidth (Hz) used to derive segment span and bin count.         |
| `capture_parameters.spectrum_retrieval_type`| int  | Retrieval mode enum value (FILE = 1, SNMP = 2).                              |

> `resolution_bandwidth_hz` is used to auto-scale RBW settings (segment span and bins per segment).

To scope captures to specific OFDM channels, set `pnm_parameters.capture.channel_ids`. Omit or use an empty list to capture all downstream OFDM channels.

### Abbreviated JSON Response (OFDM View)

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": 0,
  "message": null,
  "data": {
    "analyses": [
      {
        "device_details": {
          "system_description": {
            "HW_REV": "1.0",
            "VENDOR": "LANCity",
            "BOOTR": "NONE",
            "SW_REV": "1.0.0",
            "MODEL": "LCPET-3"
          }
        },
        "capture_parameters": {
          "inactivity_timeout": 60,
          "first_segment_center_freq": 739000000,
          "last_segment_center_freq": 833000000,
          "segment_freq_span": 1000000,
          "num_bins_per_segment": 100,
          "noise_bw": 0,
          "window_function": 1,
          "num_averages": 1,
          "spectrum_retrieval_type": 1
        },
        "signal_analysis": {
          "bin_bandwidth": 10000,
          "segment_length": 100,
          "frequencies": [],
          "magnitudes": [],
          "window_average": {
            "points": 10,
            "magnitudes": []
          }
        }
      }
    ],
    "primative": {
      "0": [
        {
          "status": "SUCCESS",
          "pnm_header": {
            "file_type": "PNN",
            "file_type_version": 9,
            "major_version": 1,
            "minor_version": 0,
            "capture_time": 1762840213
          },
          "channel_id": 0,
          "mac_address": "aa:bb:cc:dd:ee:ff",
          "first_segment_center_frequency": 739000000,
          "last_segment_center_frequency": 833000000,
          "segment_frequency_span": 1000000,
          "num_bins_per_segment": 100,
          "equivalent_noise_bandwidth": 110.0,
          "window_function": 1,
          "bin_frequency_spacing": 10000,
          "spectrum_analysis_data_length": 19000,
          "spectrum_analysis_data": "",
          "amplitude_bin_segments_float": []
        }
      ],
      "1": []
    },
    "measurement_stats": [
      {
        "index": 0,
        "entry": {
          "docsIf3CmSpectrumAnalysisCtrlCmdEnable": true,
          "docsIf3CmSpectrumAnalysisCtrlCmdInactivityTimeout": 30,
          "docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency": 739000000,
          "docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency": 833000000,
          "docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan": 1000000,
          "docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment": 100,
          "docsIf3CmSpectrumAnalysisCtrlCmdEquivalentNoiseBandwidth": 110,
          "docsIf3CmSpectrumAnalysisCtrlCmdWindowFunction": 1,
          "docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages": 2,
          "docsIf3CmSpectrumAnalysisCtrlCmdFileEnable": true,
          "docsIf3CmSpectrumAnalysisCtrlCmdMeasStatus": "sample_ready",
          "docsIf3CmSpectrumAnalysisCtrlCmdFileName": "spectrum_analyzer_aabbccddeeff_0_1762840189.bin"
        }
      },
      {
        "index": 0,
        "entry": {
          "docsIf3CmSpectrumAnalysisCtrlCmdEnable": true,
          "docsIf3CmSpectrumAnalysisCtrlCmdInactivityTimeout": 30,
          "docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency": 619000000,
          "docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency": 737000000,
          "docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan": 1000000,
          "docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment": 100,
          "docsIf3CmSpectrumAnalysisCtrlCmdEquivalentNoiseBandwidth": 110,
          "docsIf3CmSpectrumAnalysisCtrlCmdWindowFunction": 1,
          "docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages": 2,
          "docsIf3CmSpectrumAnalysisCtrlCmdFileEnable": true,
          "docsIf3CmSpectrumAnalysisCtrlCmdMeasStatus": "sample_ready",
          "docsIf3CmSpectrumAnalysisCtrlCmdFileName": "spectrum_analyzer_aabbccddeeff_0_1762840227.bin"
        }
      }
    ]
  }
}
```

### OFDM Multi-Channel Return Structure

**Payload: `data.analyses[]` (OFDM)**

| Field                          | Type   | Description                                                          |
| ------------------------------ | ------ | -------------------------------------------------------------------- |
| `[index]`.device_details.*     | object | System descriptor captured at analysis time for that channel.        |
| `[index]`.capture_parameters.* | object | Effective capture parameters for that OFDM channel.                  |
| `[index]`.signal_analysis.*    | object | Per-channel spectrum analysis (frequencies, magnitudes, smoothing).  |

**Payload: `data.primative` (OFDM)**

| Field           | Type  | Description                                                             |
| --------------- | ----- | ----------------------------------------------------------------------- |
| `"0"`, `"1"`, … | array | Raw per-channel capture payloads for each OFDM channel position.       |

**Payload: `data.measurement_stats[]` (OFDM)**

Reuses the single-capture `measurement_stats` field definitions, repeated per OFDM channel.

## SC-QAM Downstream Capture - `/spectrumAnalyzer/getCapture/scqam`

This endpoint iterates across all downstream SC-QAM channels, performing spectrum captures
per channel and aggregating the results into a multi-analysis view similar to the OFDM
endpoint.

DOCSIS constraints:

* DOCSIS 3.1 and DOCSIS 4.0 support up to **32** downstream SC-QAM channels (implementation-dependent).

The response shape for SC-QAM captures mirrors the OFDM multi-channel layout:

* `data.analyses[]` - list of per-channel analysis views.
* `data.primative` - dictionary of raw capture payloads indexed by channel position.
* `data.measurement_stats[]` - flattened SNMP statistics per captured channel.

### Example Request

```json
{
  "cable_modem": {
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "ip_address": "192.168.0.100",
    "pnm_parameters": {
      "tftp": {
        "ipv4": "192.168.0.10",
        "ipv6": "2001:db8::10"
      },
      "capture": {
        "channel_ids": [1, 2]
      }
    },
    "snmp": {
      "snmpV2C": {
        "community": "private"
      }
    }
  },
  "analysis": {
    "type": "basic",
    "output": { "type": "json" },
    "plot": { "ui": { "theme": "dark" } },
    "spectrum_analysis": {
      "moving_average": { "points": 10 }
    }
  },
  "capture_parameters": {
    "number_of_averages": 10,
    "resolution_bandwidth_hz": 25000,
    "spectrum_retrieval_type": 1
  }
}
```

### SC-QAM Capture Parameters

| JSON path                                   | Type | Description                                                                  |
| ------------------------------------------- | ---- | ---------------------------------------------------------------------------- |
| `capture_parameters.number_of_averages`     | int  | Number of samples used to compute the per-bin average.                       |
| `capture_parameters.resolution_bandwidth_hz`| int  | Resolution bandwidth (Hz) used to derive segment span and bin count.         |
| `capture_parameters.spectrum_retrieval_type`| int  | Retrieval mode enum value (FILE = 1, SNMP = 2).                              |

> `resolution_bandwidth_hz` is used to auto-scale RBW settings (segment span and bins per segment).

To scope captures to specific SC-QAM channels, set `pnm_parameters.capture.channel_ids`. Omit or use an empty list to capture all downstream SC-QAM channels.

### SC-QAM Multi-Channel Return Structure

**Payload: `data.analyses[]` (SC-QAM)**

Same as OFDM: each list element represents a per-channel analysis view with
`device_details`, `capture_parameters`, and `signal_analysis`.

**Payload: `data.primative` (SC-QAM)**

| Field           | Type  | Description                                                             |
| --------------- | ----- | ----------------------------------------------------------------------- |
| `"0"`, `"1"`, … | array | Raw per-channel capture payloads for each SC-QAM channel position.     |

**Payload: `data.measurement_stats[]` (SC-QAM)**

Reuses the single-capture `measurement_stats` field definitions, per SC-QAM channel.

## Archive Output

For all three endpoints, when `analysis.output.type = "archive"`:

* The response body is a ZIP file (no JSON `data` envelope).
* Contents typically include:
  * CSV exports of amplitude vs frequency.
  * Matplotlib PNG plots per channel and aggregate views.

Examples of generated plots:

| Standard Plot  | Moving Average Plot  | Description |
| -------------- | -------------------- | ----------- |
| [DS Full Bandwidth](../images/spectrum/spec-analysis-standard.png) | [DS Full Bandwidth](../images/spectrum/spec-analysis-moving-average.png)    | Single-capture standard vs moving-average spectrum views.       |
| [SCQAM](../images/spectrum/scqam-2-spec-analysis-standard.png)     | [SCQAM](../images/spectrum/scqam-2-spec-analysis-moving-average.png)        | Example SC-QAM channel standard and moving-average plots.       |
| [OFDM](../images/spectrum/ofdm-34-spec-analysis-standard.png)      | [OFDM](../images/spectrum/ofdm-34-spec-analysis-moving-average.png)         | Example OFDM channel standard and moving-average plots.         |

## Notes

* Always validate requested frequency ranges against the modem diplexer configuration.  
* Spectrum captures can be long-running operations depending on span and averaging.  

# FILE: tests/test_spectrum_analyzer_friendly_capture.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import pytest

from pypnm.api.routes.docs.pnm.spectrumAnalyzer.schemas import (
    SpecAnCaptureParaFriendly,
)
from pypnm.api.routes.docs.pnm.spectrumAnalyzer.service import (
    SpectrumAnalyzerFriendlyCaptureBuilder,
)
from pypnm.lib.types import FrequencyHz, ResolutionBw


def test_friendly_capture_builder_matches_helper_tool_example() -> None:
    friendly = SpecAnCaptureParaFriendly(
        inactivity_timeout=60,
        first_segment_center_freq=FrequencyHz(300_000_000),
        last_segment_center_freq=FrequencyHz(900_000_000),
        resolution_bw=ResolutionBw(30_000),
        noise_bw=150,
        window_function=1,
        num_averages=1,
        spectrum_retrieval_type=1,
    )

    capture = SpectrumAnalyzerFriendlyCaptureBuilder.build(friendly)

    assert capture.segment_freq_span == FrequencyHz(3_000_000)
    assert capture.num_bins_per_segment == 100
    assert capture.first_segment_center_freq == FrequencyHz(301_500_000)
    assert capture.last_segment_center_freq == FrequencyHz(898_500_000)


def test_friendly_capture_builder_rejects_invalid_range() -> None:
    friendly = SpecAnCaptureParaFriendly(
        inactivity_timeout=60,
        first_segment_center_freq=FrequencyHz(900_000_000),
        last_segment_center_freq=FrequencyHz(300_000_000),
        resolution_bw=ResolutionBw(30_000),
        noise_bw=150,
        window_function=1,
        num_averages=1,
        spectrum_retrieval_type=1,
    )

    with pytest.raises(ValueError, match="last_segment_center_freq"):
        SpectrumAnalyzerFriendlyCaptureBuilder.build(friendly)
