## Agent Review Bundle Summary Template (Standard)

### Summary
Updated SPDX copyright headers to use a 2025-2026 range per policy on previously touched files; no functional changes to code or docs beyond header alignment. Synced the AGENTS.md file to the PersonalDevelopment environment as requested.

### Modified Files
- src/pypnm/tools/loop_nesting_checker.py
- src/pypnm/tools/qa_checker.py
- tests/test_loop_nesting_checker.py
- docs/tests/pypnm-software-qa.md
- src/pypnm/api/routes/advance/analysis/signal_analysis/detection/anolamaly/heatmap_anomaly_detection.py
- src/pypnm/api/routes/advance/analysis/signal_analysis/multi_rxmer_signal_analysis.py
- src/pypnm/api/routes/basic/fec_summary_analysis_rpt.py
- src/pypnm/api/routes/basic/modulation_profile_analysis_rpt.py
- src/pypnm/api/routes/common/classes/analysis/analysis.py

### Commands Executed And Results
- `python3 -m compileall src` -> not run (not required for header-only update)

### Tests
- `pytest` -> not run (not required for header-only update)
- `ruff` -> not run (not required for header-only update)

### Notes / Warnings
- AGENTS.md was copied to `/home/dev01/Projects/PersonalDevelopmentEnviroment/PyPNM/AGENTS.md` as requested.

### Remaining TODOs / Follow-Ups
- None
# FILE: src/pypnm/tools/loop_nesting_checker.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import ast
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class LoopNestingFinding:
    file_path: str
    function_name: str
    line_number: int
    max_depth: int


class LoopNestingAnalyzer:
    _LOOP_TYPES = (ast.For, ast.AsyncFor, ast.While)
    _SKIP_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)

    @staticmethod
    def analyze_source(source: str, file_path: str) -> list[LoopNestingFinding]:
        tree = ast.parse(source, filename=file_path)
        return LoopNestingAnalyzer._analyze_tree(tree=tree, file_path=file_path)

    @staticmethod
    def analyze_path(path: Path) -> list[LoopNestingFinding]:
        source = path.read_text(encoding="utf-8")
        return LoopNestingAnalyzer.analyze_source(source=source, file_path=str(path))

    @staticmethod
    def _analyze_tree(tree: ast.AST, file_path: str) -> list[LoopNestingFinding]:
        findings: list[LoopNestingFinding] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                depth = LoopNestingAnalyzer._max_depth_in_nodes(node.body, 0)
                findings.append(
                    LoopNestingFinding(
                        file_path=file_path,
                        function_name=node.name,
                        line_number=node.lineno,
                        max_depth=depth,
                    )
                )
        return findings

    @staticmethod
    def _max_depth_in_nodes(nodes: list[ast.stmt], current_depth: int) -> int:
        max_depth = current_depth
        for node in nodes:
            max_depth = max(max_depth, LoopNestingAnalyzer._max_depth_in_node(node, current_depth))
        return max_depth

    @staticmethod
    def _max_depth_in_node(node: ast.AST, current_depth: int) -> int:
        if isinstance(node, LoopNestingAnalyzer._SKIP_TYPES):
            return current_depth

        if isinstance(node, LoopNestingAnalyzer._LOOP_TYPES):
            loop_depth = current_depth + 1
            max_depth = loop_depth
            max_depth = max(max_depth, LoopNestingAnalyzer._max_depth_in_nodes(node.body, loop_depth))
            max_depth = max(max_depth, LoopNestingAnalyzer._max_depth_in_nodes(node.orelse, loop_depth))
            return max_depth

        max_depth = current_depth
        for block in LoopNestingAnalyzer._child_blocks(node):
            max_depth = max(max_depth, LoopNestingAnalyzer._max_depth_in_nodes(block, current_depth))
        return max_depth

    @staticmethod
    def _child_blocks(node: ast.AST) -> list[list[ast.stmt]]:
        blocks: list[list[ast.stmt]] = []
        if isinstance(node, ast.If):
            blocks.append(node.body)
            blocks.append(node.orelse)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            blocks.append(node.body)
        elif isinstance(node, ast.Try):
            blocks.append(node.body)
            blocks.append(node.orelse)
            blocks.append(node.finalbody)
            for handler in node.handlers:
                blocks.append(handler.body)
        elif isinstance(node, ast.Match):
            for case in node.cases:
                blocks.append(case.body)
        elif isinstance(node, ast.ExceptHandler):
            blocks.append(node.body)
        return blocks


class LoopNestingChecker:
    _FAIL_DEPTH = 3
    _WARN_DEPTH = 2

    @staticmethod
    def run(paths: list[str]) -> int:
        files = LoopNestingChecker._collect_files(paths)
        if not files:
            print("No Python files found for loop nesting check.", flush=True)
            return 2

        findings: list[LoopNestingFinding] = []
        for path in files:
            findings.extend(LoopNestingAnalyzer.analyze_path(path))

        warnings = [f for f in findings if f.max_depth == LoopNestingChecker._WARN_DEPTH]
        errors = [f for f in findings if f.max_depth >= LoopNestingChecker._FAIL_DEPTH]

        for finding in warnings:
            LoopNestingChecker._print_finding(prefix="WARNING", finding=finding)

        for finding in errors:
            LoopNestingChecker._print_finding(prefix="ERROR", finding=finding)

        if errors:
            print(
                f"Loop nesting check failed: {len(errors)} function(s) reach depth "
                f"{LoopNestingChecker._FAIL_DEPTH} or higher.",
                flush=True,
            )
            return 1

        print("Loop nesting check passed.", flush=True)
        return 0

    @staticmethod
    def _collect_files(paths: list[str]) -> list[Path]:
        files: list[Path] = []
        for raw in paths:
            files.extend(LoopNestingChecker._collect_from_path(Path(raw)))
        return LoopNestingChecker._dedupe_paths(files)

    @staticmethod
    def _collect_from_path(path: Path) -> list[Path]:
        if path.is_dir():
            return [p for p in path.rglob("*.py") if p.is_file()]
        if path.is_file() and path.suffix == ".py":
            return [path]
        print(f"Skipping missing path: {path}", flush=True)
        return []

    @staticmethod
    def _dedupe_paths(paths: list[Path]) -> list[Path]:
        seen: set[Path] = set()
        unique: list[Path] = []
        for path in paths:
            if path in seen:
                continue
            seen.add(path)
            unique.append(path)
        return unique

    @staticmethod
    def _print_finding(prefix: str, finding: LoopNestingFinding) -> None:
        print(
            f"{prefix}: {finding.file_path}:{finding.line_number} "
            f"{finding.function_name} max_depth={finding.max_depth}",
            flush=True,
        )


def main() -> None:
    raw_args = sys.argv[1:]
    paths = raw_args if raw_args else ["src"]
    exit_code = LoopNestingChecker.run(paths=paths)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
# FILE: src/pypnm/tools/qa_checker.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import subprocess
import sys


Command = tuple[str, list[str]]


def _run_command(label: str, cmd: list[str]) -> int:
    """
    Run A Single QA Tool Command And Stream Its Output.

    Parameters
    ----------
    label : str
        Human-readable label for the tool (e.g., "ruff", "pyright").
    cmd : Sequence[str]
        The command and arguments to execute.

    Returns
    -------
    int
        The process return code (0 on success, non-zero on failure).
    """
    print(f"\n=== [{label}] running: {' '.join(cmd)} ===", flush=True)
    try:
        proc = subprocess.run(cmd, check=False)
        if proc.returncode == 0:
            print(f"=== [{label}] OK ===", flush=True)
        else:
            print(f"=== [{label}] FAILED (exit code {proc.returncode}) ===", flush=True)
        return proc.returncode
    except FileNotFoundError:
        print(f"=== [{label}] NOT FOUND on PATH ===", flush=True)
        return 127


def _build_commands(include_pyright: bool, pytest_args: list[str]) -> list[Command]:
    """
    Build The Ordered List Of QA Commands To Run.

    Parameters
    ----------
    include_pyright : bool
        If True, include a `pyright` static type-check step after Ruff.
    pytest_args : Sequence[str]
        Additional arguments to pass through to pytest (for example, via
        the CLI separator ``--``).

    Returns
    -------
    list[Command]
        Ordered list of (label, cmd) tuples to execute.
    """
    python_cmd = sys.executable or "python"
    commands: list[Command] = [
        ("secrets", ["./tools/security/scan-secrets.sh"]),
        ("enc-secrets", [python_cmd, "./tools/security/scan-enc-secrets.py"]),
        ("macs", ["./tools/security/scan-mac-addresses.py", "--fail-on-found"]),
        ("headers", ["./tools/build/add-required-python-headers.py"]),
        ("ruff", ["ruff", "check", "src"]),
    ]

    if include_pyright:
        # Insert Pyright after Ruff but before loop nesting and pytest for faster feedback.
        commands.append(("pyright", ["pyright"]))

    commands.append(("loop-nesting", [python_cmd, "-m", "pypnm.tools.loop_nesting_checker", "src"]))
    commands.append(("pytest", ["pytest", *pytest_args]))

    return commands


def main() -> None:
    """
    Run The Standard PyPNM Software QA Suite.

    Default Behavior
    ----------------
    By default, this helper aggregates the core quality checks configured for
    the project:

    1) secrets             - secret scanning via ./tools/security/scan-secrets.sh
                             (gitleaks + .gitleaks.toml if available).
    2) enc-secrets         - encrypted password pattern scan (ENC[v1] + password_enc).
    3) macs                - repository scan for non-approved MAC addresses.
    4) headers             - ensure SPDX/license headers (./tools/build/add-required-python-headers.py).
    5) ruff check src      - syntax, style, and common bug patterns.
    6) loop nesting        - ensure no function exceeds 3+ nested loops.
    7) pytest              - unit tests (pytest options from pyproject.toml).

    Optional Pyright
    ----------------
    To enable static type checking with Pyright, pass the flag:

        pypnm-software-qa-checker --with-pyright

    This will run an additional step:

    - pyright              - static type analysis using [tool.pyright] settings,
                             executed after Ruff but before loop nesting and pytest.

    Passing Extra Pytest Arguments
    ------------------------------
    To pass additional arguments directly to pytest, use ``--`` as a separator.
    Any arguments after ``--`` are forwarded only to pytest. For example:

        pypnm-software-qa-checker --with-pyright -- -k \"fast\" --maxfail=1

    In this example, pytest will be invoked as:

        pytest -k \"fast\" --maxfail=1

    The process exit code is non-zero if any check fails.
    """
    raw_args = sys.argv[1:]

    pytest_args: list[str] = []
    qa_args: list[str] = raw_args

    if "--" in raw_args:
        sep_index = raw_args.index("--")
        qa_args = raw_args[:sep_index]
        pytest_args = raw_args[sep_index + 1 :]

    include_pyright = "--with-pyright" in qa_args
    filtered_qa_args = [a for a in qa_args if a != "--with-pyright"]

    # Preserve a minimal sys.argv for any downstream libraries that inspect it.
    sys.argv = [sys.argv[0], *filtered_qa_args]

    commands = _build_commands(include_pyright=include_pyright, pytest_args=pytest_args)

    overall_rc = 0
    for label, cmd in commands:
        rc = _run_command(label, cmd)
        if rc != 0 and overall_rc == 0:
            overall_rc = rc

    print("\n=== PyPNM Software QA Suite Finished ===", flush=True)
    if overall_rc == 0:
        print("All checks passed.", flush=True)
    else:
        print(f"One or more checks failed (exit code {overall_rc}).", flush=True)

    sys.exit(overall_rc)


if __name__ == "__main__":
    main()
# FILE: tests/test_loop_nesting_checker.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pypnm.tools.loop_nesting_checker import LoopNestingAnalyzer


def _depths_by_function(source: str) -> dict[str, int]:
    findings = LoopNestingAnalyzer.analyze_source(source=source, file_path="snippet.py")
    return {finding.function_name: finding.max_depth for finding in findings}


def test_loop_depth_zero() -> None:
    source = "def demo():\n    value = 1\n"
    depths = _depths_by_function(source)
    assert depths["demo"] == 0


def test_loop_depth_one() -> None:
    source = "def demo():\n    for idx in range(3):\n        value = idx\n"
    depths = _depths_by_function(source)
    assert depths["demo"] == 1


def test_loop_depth_two() -> None:
    source = (
        "def demo():\n"
        "    for idx in range(3):\n"
        "        while idx > 0:\n"
        "            idx -= 1\n"
    )
    depths = _depths_by_function(source)
    assert depths["demo"] == 2


def test_loop_depth_three() -> None:
    source = (
        "def demo():\n"
        "    for idx in range(3):\n"
        "        if idx > 0:\n"
        "            while idx > 0:\n"
        "                for jdx in range(2):\n"
        "                    idx -= jdx\n"
    )
    depths = _depths_by_function(source)
    assert depths["demo"] == 3


def test_nested_function_loops_not_counted_in_parent() -> None:
    source = (
        "def demo():\n"
        "    for idx in range(2):\n"
        "        def inner():\n"
        "            for jdx in range(2):\n"
        "                for kdx in range(2):\n"
        "                    pass\n"
        "        value = idx\n"
    )
    depths = _depths_by_function(source)
    assert depths["demo"] == 1
    assert depths["inner"] == 2
# FILE: docs/tests/pypnm-software-qa.md
# pypnm-software-qa-checker User Guide

A lightweight command-line helper that runs a standard set of **software quality checks** for the PyPNM
codebase. It is intended for local development (before commits) and for simple CI pipelines.

## 1. Prerequisites

Before using the QA checker, make sure you have the development dependencies installed in your virtual
environment:

```bash
cd ~/Projects/PyPNM
pip install -e '.[dev]'
```

This ensures the following tools are available (as defined in `pyproject.toml`):

- `ruff` - linting and unused-code detection
- `pytest` - unit and integration tests
- `pycycle` - import cycle detection
- `pyright` - optional static type checking (when enabled via CLI flag)

## 2. Command Overview

Once installed via `pyproject.toml` as a console script, the QA checker is available as:

```bash
pypnm-software-qa-checker [OPTIONS]
```

By default (with no options), it runs a **standard QA sweep** over your project:

1. `./tools/security/scan-secrets.sh`
2. `python ./tools/security/scan-enc-secrets.py`
3. `./tools/security/scan-mac-addresses.py --fail-on-found`
4. `./tools/build/add-required-python-headers.py`
5. `ruff check src`
6. `python -m pypnm.tools.loop_nesting_checker src`
7. `pytest`
8. `pycycle --here` (from the project root)

Each step is run in sequence; if any step fails (non-zero exit code), the script exits with that code and
prints the failing command.

If you enable the optional Pyright step (see below), it will run **after Ruff** and **before pytest**.

## 3. Options

The CLI is intentionally minimal and focused on the PyPNM layout (`src/`).

| Option            | Description                                                                                     |
|-------------------|-------------------------------------------------------------------------------------------------|
| `--with-pyright`  | Add a `pyright` static type-check step after Ruff and before pytest.                            |

Any additional arguments you pass are forwarded to underlying tools where applicable (for example, `pytest`
arguments will still behave as expected when appended after the QA checker command).

### 3.1 Enabling Pyright

When you want to run a deeper static analysis pass with Pyright in addition to the default checks, use:

```bash
pypnm-software-qa-checker --with-pyright
```

This is effectively equivalent to:

1. `./tools/security/scan-secrets.sh`
2. `python ./tools/security/scan-enc-secrets.py`
3. `./tools/security/scan-mac-addresses.py --fail-on-found`
4. `./tools/build/add-required-python-headers.py`
5. `ruff check src`
6. `pyright`
7. `python -m pypnm.tools.loop_nesting_checker src`
8. `pytest`
9. `pycycle --here`

If Pyright is not installed or not on `PATH`, the QA checker will report it as “NOT FOUND” and continue
based on Pyright’s exit status.

## 4. Typical Workflows

### 4.1 Full QA before pushing (fast path, no Pyright)

Use this when you are about to push a feature branch or submit a PR and you want a quick but comprehensive
check (lint + tests + cycle detection):

```bash
pypnm-software-qa-checker
```

Effectively runs:

- Lint (style / unused / basic correctness via `ruff`)
- Loop nesting guard (`python -m pypnm.tools.loop_nesting_checker src`)
- Tests (`pytest`)
- Import cycle detection (`pycycle --here`)

### 4.2 Full QA including Pyright

Use this when you want to include static type checking via Pyright (for example before a release or when
working on critical modules):

```bash
pypnm-software-qa-checker --with-pyright
```

Effectively runs:

- Secret scanning (`./tools/security/scan-secrets.sh`)
- Encrypted password scan (`python ./tools/security/scan-enc-secrets.py`)
- MAC address scan (`./tools/security/scan-mac-addresses.py --fail-on-found`)
- SPDX/license header scan (`./tools/build/add-required-python-headers.py`)
- Lint (`ruff check src`)
- Static type checking (`pyright`)
- Loop nesting guard (`python -m pypnm.tools.loop_nesting_checker src`)
- Tests (`pytest`)
- Import cycle detection (`pycycle --here`)

### 4.3 Running individual tools directly

You can still run each tool directly when you need fine-grained control:

```bash
./tools/security/scan-secrets.sh
python ./tools/security/scan-enc-secrets.py
./tools/security/scan-mac-addresses.py --fail-on-found
./tools/build/add-required-python-headers.py
ruff check src
python -m pypnm.tools.loop_nesting_checker src
pytest -m 'not slow'
pycycle --here
pyright
```

The QA checker is simply a convenience wrapper that standardizes a good default sequence for PyPNM.

## 5. Exit Codes and CI Integration

The script is designed to be CI-friendly:

- Exit code `0` - all selected checks passed
- Non-zero exit code - the first failing step’s exit code

A simple GitHub Actions step could look like:

```yaml
- name: PyPNM software QA
  run: pypnm-software-qa-checker
```

To include Pyright as well:

```yaml
- name: PyPNM software QA (with Pyright)
  run: pypnm-software-qa-checker --with-pyright
```

### 5.1 Postgres Backend Validation

CI validates both SQLite and Postgres. To run Postgres validation locally, start a Postgres instance (Docker is fine) and set:

```bash
export PYPNM_DB_BACKEND=postgres
export PYPNM_DB_POSTGRES_DSN=postgresql://pypnm:pypnm@localhost:5432/pypnm
python -m compileall src
pytest
ruff check .
ruff format --check .
```

The `pypnm` credentials are intended for local and CI use only.

## 6. Troubleshooting

### 6.1 `pypnm-software-qa-checker: command not found`

- Make sure you are in the right virtual environment.
- Reinstall in editable mode with dev extras:

  ```bash
  pip install -e '.[dev]'
  ```

- Confirm the console script is listed by running:

  ```bash
  pip show pypnm
  ```

### 6.2 Ruff, Pyright, pytest, or pycycle not installed

If the script reports that it cannot find `ruff`, `pyright`, `pytest`, or `pycycle`, verify that:

- You are in the environment where `.[dev]` was installed.
- The tools appear in `pip list` for that environment.

If you prefer not to install Pyright, simply avoid the `--with-pyright` flag; the default QA sweep does
not require it.

## 7. Where the Script Lives

The recommended layout is:

- Script module: `src/pypnm/tools/qa_checker.py`
- Console entry point in `pyproject.toml`:

  ```toml
  [project.scripts]
  pypnm      = "pypnm.cli:main"
  docs-serve = "mkdocs.__main__:serve"
  docs-build = "mkdocs.__main__:build"
  pypnm-software-qa-checker  = "pypnm.tools.qa_checker:main"
  ```

This keeps all tooling namespaced under `pypnm.tools` while giving you a short,
memorable `pypnm-software-qa-checker` command from the shell.
# FILE: src/pypnm/api/routes/advance/analysis/signal_analysis/detection/anolamaly/heatmap_anomaly_detection.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
from __future__ import annotations

from collections.abc import Generator

import numpy as np


class HeatmapAnomalyDetector:
    """
    Detect anomalies in a 2D array via global z-score thresholding
    and extract bounding boxes around each connected component.

    Attributes:
        data (np.ndarray): 2D input array of measurements.
        threshold (float): z-score cutoff; defaults to 3.0.
        zmap (np.ndarray): computed z-score map.
        mask (np.ndarray): boolean mask where |z| > threshold.
        boxes (List[Tuple[int, int, int, int]]): list of
            (row_min, col_min, row_max, col_max) bounding boxes.
    """

    def __init__(self, data: np.ndarray, threshold: float = 3.0) -> None:
        self.data = np.asarray(data, dtype=float)
        if self.data.ndim != 2:
            raise ValueError("Input must be a 2-D array.")
        self.threshold: float = threshold
        self.zmap: np.ndarray = None  # will be computed
        self.mask: np.ndarray = None
        self.boxes: list[tuple[int, int, int, int]] = []

    def compute_zmap(self) -> np.ndarray:
        """
        Compute the z-score map of the input data.

        Returns:
            np.ndarray: z-score normalized array.
        """
        mu = self.data.mean()
        sigma = self.data.std()
        # Avoid division by zero
        if sigma == 0:
            self.zmap = np.zeros_like(self.data)
        else:
            self.zmap = (self.data - mu) / sigma
        return self.zmap

    def detect(self) -> np.ndarray:
        """
        Apply the threshold to form a boolean anomaly mask.

        Returns:
            np.ndarray: boolean mask where anomalies are True.
        """
        if self.zmap is None:
            self.compute_zmap()
        self.mask = np.abs(self.zmap) > self.threshold
        return self.mask

    def find_boxes(self) -> list[tuple[int, int, int, int]]:
        """
        Identify connected components in the anomaly mask (4-connectivity)
        and compute their bounding boxes.

        Returns:
            List[Tuple[int, int, int, int]]: list of bounding boxes
            as (row_min, col_min, row_max, col_max).
        """
        if self.mask is None:
            self.detect()

        visited = np.zeros_like(self.mask, dtype=bool)
        rows, cols = self.data.shape
        boxes: list[tuple[int, int, int, int]] = []

        boxes = [
            self._walk_component(i, j, visited)
            for i in range(rows)
            for j in range(cols)
            if self.mask[i, j] and not visited[i, j]
        ]

        self.boxes = boxes
        return boxes

    def to_json(self) -> dict[str, object]:
        """
        Convert the detected boxes into a JSON-friendly dictionary.

        Returns:
            Dict[str, Any]: dictionary with threshold and boxes list.
        """
        return {
            "threshold": self.threshold,
            "boxes": [
                {"row_min": r0, "col_min": c0, "row_max": r1, "col_max": c1}
                for r0, c0, r1, c1 in self.boxes
            ],
        }

    def _neighbors(
        self, row: int, col: int, rows: int, cols: int
    ) -> Generator[tuple[int, int], None, None]:
        for dr, dc in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            nr, nc = row + dr, col + dc
            if 0 <= nr < rows and 0 <= nc < cols:
                yield nr, nc

    def _walk_component(
        self, start_row: int, start_col: int, visited: np.ndarray
    ) -> tuple[int, int, int, int]:
        rmin = rmax = start_row
        cmin = cmax = start_col
        stack = [(start_row, start_col)]
        visited[start_row, start_col] = True
        rows, cols = self.data.shape

        while stack:
            row, col = stack.pop()
            rmin = min(rmin, row)
            rmax = max(rmax, row)
            cmin = min(cmin, col)
            cmax = max(cmax, col)
            for nr, nc in self._neighbors(row, col, rows, cols):
                if self.mask[nr, nc] and not visited[nr, nc]:
                    visited[nr, nc] = True
                    stack.append((nr, nc))

        return rmin, cmin, rmax, cmax
# FILE: src/pypnm/api/routes/advance/analysis/signal_analysis/multi_rxmer_signal_analysis.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from typing import Any, cast

import numpy as np
from pydantic import BaseModel, Field

from pypnm.api.routes.advance.analysis.report.multi_analysis_rpt import MultiAnalysisRpt
from pypnm.api.routes.advance.common.capture_data_aggregator import (
    CaptureDataAggregator,
)
from pypnm.api.routes.advance.common.transactionsCollection import (
    TransactionCollectionModel,
)
from pypnm.api.routes.common.classes.analysis.model.schema import (
    DsModulationProfileAnalysisModel,
    ProfileAnalysisEntryModel,
)
from pypnm.api.routes.common.classes.collection.ds_modulation_profile_aggregator import (
    DsModulationProfileAggregator,
)
from pypnm.api.routes.common.classes.collection.ds_rxmer_aggregator import (
    DsRxMerAggregator,
)
from pypnm.api.routes.common.classes.collection.fec_summary_aggregator import (
    FecSummaryAggregator,
    FecSummaryTotalsModel,
)
from pypnm.lib.constants import INVALID_CAPTURE_TIME
from pypnm.lib.csv.manager import CSVManager
from pypnm.lib.matplot.manager import MatplotManager, PlotConfig
from pypnm.lib.signal_processing.shan.series import ShannonSeries
from pypnm.lib.types import (
    ArrayLike,
    CaptureTime,
    ChannelId,
    FloatSeries,
    FrequencySeriesHz,
    MacAddressStr,
    MagnitudeSeries,
    StringEnum,
    TimeStamp,
    TimestampSec,
)
from pypnm.pnm.lib.min_avg_max import MinAvgMax
from pypnm.pnm.parser.CmDsOfdmFecSummary import CmDsOfdmFecSummary
from pypnm.pnm.parser.CmDsOfdmModulationProfile import (
    CmDsOfdmModulationProfile,
    ProfileId,
)
from pypnm.pnm.parser.CmDsOfdmRxMer import CmDsOfdmRxMer, CmDsOfdmRxMerModel


class MultiRxMerAnalysisType(StringEnum):
    MIN_AVG_MAX = "min-avg-max"
    RXMER_HEAT_MAP = "rxmer-heat-map"
    OFDM_PROFILE_PERFORMANCE_1 = "ofdm-profile-performance-1"


class MultiRxMerAnalysisBaseModel(BaseModel):
    channel_id: ChannelId = Field(
        ..., description="OFDM channel identifier for this result set."
    )
    frequency: FrequencySeriesHz = Field(
        ..., description="Per-subcarrier frequency bins (Hz)."
    )


class MinAvgMaxAnalysisModel(MultiRxMerAnalysisBaseModel):
    min: FloatSeries = Field(..., description="Per-subcarrier minimum values.")
    avg: FloatSeries = Field(..., description="Per-subcarrier average values.")
    max: FloatSeries = Field(..., description="Per-subcarrier maximum values.")


class ProfileEntryModel(BaseModel):
    capture_time: CaptureTime = Field(..., description="Epoch capture timestamp.")
    profile_id: ProfileId = Field(
        ..., description="Modulation profile index for the capture."
    )
    profile_min_mer: FloatSeries = Field(
        ..., description="Per-subcarrier Shannon limits (bits/s/Hz) for the profile."
    )
    capacity_delta: FloatSeries = Field(
        ...,
        description="Average measured MER Subcarrier vs. Min Subcarrier Shannon MER",
    )
    fec_summary: FecSummaryTotalsModel = Field(..., description="")


class ChannelOfdmProfilePerf01Model(MultiRxMerAnalysisBaseModel):
    avg_mer: FloatSeries = Field(..., description="Per-subcarrier average MER (dB).")
    mer_shannon_limits: FloatSeries = Field(
        ..., description="Per-subcarrier Shannon limits derived from avg MER."
    )
    profiles: list[ProfileEntryModel] = Field(
        ..., description="Per-capture per-profile deltas/limits."
    )


class ChannelHeatMapModel(MultiRxMerAnalysisBaseModel):
    timestamps: list[TimestampSec] = Field(
        ..., description="Capture timestamps (epoch) for rows of the heatmap."
    )
    values: list[MagnitudeSeries] = Field(
        ..., description="Matrix: rows=captures, cols=subcarriers; MER values."
    )


MultiRxMerTemporalObjType = (
    CmDsOfdmRxMer | CmDsOfdmFecSummary | CmDsOfdmModulationProfile
)
TemporalMapping = tuple[CaptureTime, MultiRxMerTemporalObjType]

MinAvgMaxMap = dict[ChannelId, MinAvgMaxAnalysisModel]
OfdmProfilePerf01Map = dict[ChannelId, ChannelOfdmProfilePerf01Model]
HeatMapMap = dict[ChannelId, ChannelHeatMapModel]
MultiRxMerAnalysisMap = MinAvgMaxMap | OfdmProfilePerf01Map | HeatMapMap


class MultiRxMerAnalysisResult(BaseModel):
    mac_address: MacAddressStr = Field(
        ..., description="Cable modem MAC address associated with this analysis."
    )
    analysis_type: MultiRxMerAnalysisType = Field(
        ..., description="Type of multi-RxMER analysis performed."
    )
    data: MultiRxMerAnalysisMap = Field(
        ..., description="Analysis results mapping (per-channel model)."
    )
    error: str | None = Field(
        default="", description="Optional error message if analysis failed."
    )


# ---------------------------
# Analyzer (models built during processing; single CM)
# ---------------------------


class MultiRxMerSignalAnalysis(MultiAnalysisRpt):
    def __init__(
        self,
        capt_data_agg: CaptureDataAggregator,
        analysis_type: MultiRxMerAnalysisType,
    ) -> None:
        super().__init__(capt_data_agg)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.analysis_type = analysis_type
        self._model: MultiRxMerAnalysisResult | None = None
        self._mac: MacAddressStr | None = None

        self._sorted_temporal_mapping: list[TemporalMapping] = []
        self._analysis_map: MultiRxMerAnalysisMap = {}
        self._is_process: bool = False

    # -----------------------
    # Public API
    # -----------------------

    def to_model(self) -> MultiRxMerAnalysisResult:
        if not self._is_process:
            self._process()

        if self._model is not None:
            return self._model

        mac = self.getMacAddresses()

        if len(mac) > 1:
            self.logger.error(
                f"Found #({len(mac)}), Not Expection more than 1 MacAddress -> {mac}"
            )

        mac = mac[0].to_mac_format()

        try:
            data = self._dispatch_build()
            self._model = MultiRxMerAnalysisResult(
                mac_address=mac,
                analysis_type=self.analysis_type,
                data=data,
            )

        except Exception as e:
            self.logger.error(f"Unable to create MultiRxMerAnalysisResult, reason: {e}")
            self._model = MultiRxMerAnalysisResult(
                mac_address=mac,
                analysis_type=self.analysis_type,
                data=None,
                error=str(e),
            )

        return self._model

    def to_dict(self) -> dict[str, Any]:
        return self.to_model().model_dump()

    # -----------------------
    # Internals
    # -----------------------

    def _get_temporal_pnm_data(self) -> list[TemporalMapping]:
        self.logger.debug(
            f"Temporal PNM Data - Record Count: [{len(self._sorted_temporal_mapping)}]"
        )
        return self._sorted_temporal_mapping

    def _get_capture_times(
        self, channel_id: ChannelId, obj_type: type
    ) -> list[TimestampSec]:
        capture_times: list[TimestampSec] = []

        for capture_time, obj in self._get_temporal_pnm_data():
            chan_id: ChannelId = cast(ChannelId, obj.to_model().channel_id)

            if channel_id == chan_id and isinstance(obj, obj_type):
                capture_times.append(cast(TimestampSec, capture_time))

        return capture_times

    def _dispatch_build(self) -> MultiRxMerAnalysisMap:
        if self.analysis_type == MultiRxMerAnalysisType.MIN_AVG_MAX:
            return self._analyze_min_avg_max_models()

        if self.analysis_type == MultiRxMerAnalysisType.OFDM_PROFILE_PERFORMANCE_1:
            return self._analyze_ofdm_profile_perf_1_models()

        if self.analysis_type == MultiRxMerAnalysisType.RXMER_HEAT_MAP:
            return self._analyze_rxmer_heat_map_models()

        raise ValueError(f"Unsupported analysis type: {self.analysis_type}")

    # --------------------------------------------------------------------------
    #               Analyses (single MAC; return channel->model)
    # --------------------------------------------------------------------------
    def _analyze_min_avg_max_models(self) -> MinAvgMaxMap:
        """
        Aggregate per-subcarrier RxMER across time (by channel) using CmDsOfdmRxMerModel.

        For each CmDsOfdmRxMer object in `self._sorted_temporal_mapping`, this:
        - Converts to CmDsOfdmRxMerModel (`obj.to_model()`),
        - Collects `values` (FloatSeries) per `channel_id`,
        - Applies MinAvgMax across captures to produce per-index min/avg/max arrays.

        Returns
        -------
        MinAvgMaxMap
            Mapping of ChannelId -> MinAvgMaxModel (min/avg/max lists per subcarrier index).
        """
        self.logger.debug("Building MinAvgMax Signal Analysis")

        chan_series: dict[ChannelId, list[MagnitudeSeries]] = {}
        chan_freq: dict[ChannelId, FrequencySeriesHz] = {}
        mamap: MinAvgMaxMap = {}

        for _, obj in self._get_temporal_pnm_data():
            if not isinstance(obj, CmDsOfdmRxMer):
                self.logger.debug("Not a CmDsOfdmRxMer Object, skipping")
                continue

            model: CmDsOfdmRxMerModel = obj.to_model()

            if model.channel_id not in chan_series:
                chan_series[model.channel_id] = []

            chan_series[model.channel_id].append(model.values)
            chan_freq[model.channel_id] = self._build_frequencies(model)

        for cid, series in chan_series.items():
            self.logger.debug(f"Building MinAvgMaxAnalysisModel for Channel: {cid}")
            frequencies = self._build_frequencies(chan_freq.get(cid))

            try:
                mam = MinAvgMax(series, precision=2)
                mam_model = mam.to_model()

                mamap[cid] = MinAvgMaxAnalysisModel(
                    channel_id=cid,
                    frequency=frequencies,
                    min=mam_model.min,
                    avg=mam_model.avg,
                    max=mam_model.max,
                )

            except ValueError as e:
                self.logger.warning(
                    "MinAvgMax failed for channel %s: %s", str(cid), str(e)
                )
                continue

        return mamap

    def _analyze_rxmer_heat_map_models(self) -> HeatMapMap:
        """
        Build RxMER HeatMap Signal Analysis by aggregating per-subcarrier MER values
        across all captures for each channel.

        Returns
        -------
        HeatMapMap
            Mapping of ChannelId -> ChannelHeatMapModel containing timestamps and MER matrix.
        """
        self.logger.info("Building RxMER HeatMap Signal Analysis")

        # Store per-channel temporal data
        channel_data: dict[ChannelId, list[MagnitudeSeries]] = {}
        channel_freqs: dict[ChannelId, FrequencySeriesHz] = {}
        heatmap_map: HeatMapMap = {}

        # Aggregate values for each capture per channel
        for _, obj in self._get_temporal_pnm_data():
            if not isinstance(obj, CmDsOfdmRxMer):
                self.logger.debug(
                    "Skipping non-CmDsOfdmRxMer object: %s", type(obj).__name__
                )
                continue

            model: CmDsOfdmRxMerModel = obj.to_model()
            ch_id = cast(ChannelId, model.channel_id)

            if ch_id not in channel_data:
                channel_data[ch_id] = []

            channel_data[ch_id].append(model.values)
            channel_freqs[ch_id] = self._build_frequencies(model)

        # Build final models
        for ch_id, magnitudes in channel_data.items():
            self.logger.debug("Building ChannelHeatMapModel for Channel: %s", ch_id)

            timestamps: list[TimestampSec] = self._get_capture_times(
                ch_id, CmDsOfdmRxMer
            )
            frequencies: FrequencySeriesHz = channel_freqs.get(ch_id, [])

            heatmap_map[ch_id] = ChannelHeatMapModel(
                channel_id=ch_id,
                frequency=frequencies,
                timestamps=timestamps,
                values=magnitudes,
            )

        return heatmap_map

    def _analyze_ofdm_profile_perf_1_models(self) -> OfdmProfilePerf01Map:
        """
        Perform OFDM Profile Performance Analysis (Type 1).

        Integrates data from RxMER, Modulation Profile, and FEC Summary aggregators.

        Steps
        -----
        1. Aggregate temporal PNM data by channel.
        2. For each channel:
            - Compute average RxMER and Shannon limits.
            - Retrieve modulation profile analysis results via `mod_pro_agg.basic_analysis()`.
            - Align FEC summary totals.
        3. Build and return structured per-channel performance results.

        Returns
        -------
        OfdmProfilePerf01Map
            Mapping of ChannelId → ChannelOfdmProfilePerf01Model.
        """
        self.logger.info("Running OFDM Profile Performance Analysis (Type 1)")

        rxmer_agg = DsRxMerAggregator()
        mod_pro_agg = DsModulationProfileAggregator()
        fec_sum_agg = FecSummaryAggregator()
        models: OfdmProfilePerf01Map = {}

        # Step 1: aggregate PNM objects
        for _, obj in self._get_temporal_pnm_data():
            if isinstance(obj, CmDsOfdmRxMer):
                rxmer_agg.add(obj)
            elif isinstance(obj, CmDsOfdmModulationProfile):
                mod_pro_agg.add(obj)
            elif isinstance(obj, CmDsOfdmFecSummary):
                fec_sum_agg.add(obj)

        if self.logger.isEnabledFor(logging.INFO):
            self.logger.info(f"RxMER Aggregator Count: {rxmer_agg.length()}")
            self.logger.info(
                f"Modulation Profile Aggregator Count: {mod_pro_agg.length()}"
            )
            self.logger.info(f"FEC Summary Aggregator Count: {fec_sum_agg.length()}")

        # Step 2: analyze per channel
        for ch_id in rxmer_agg.get_channel_ids():
            mam = rxmer_agg.get_min_avg_max(ch_id)
            shannon_model = ShannonSeries(mam.avg).to_model()
            frequencies = rxmer_agg.get_frequencies(ch_id)

            # Perform basic modulation profile analysis for this channel
            mod_analysis_map = mod_pro_agg.basic_analysis(ch_id)
            mod_analysis_list = mod_analysis_map.get(ch_id, [])
            if not mod_analysis_list:
                self.logger.warning(
                    "No modulation analysis results for channel %s", ch_id
                )
                continue

            capture_times = sorted(rxmer_agg.get_capture_times(ch_id))
            if not capture_times:
                self.logger.warning("No RxMER captures for channel %s", ch_id)
                continue

            start, stop = TimeStamp(capture_times[0]), TimeStamp(capture_times[-1])
            fec_summary = fec_sum_agg.get_summary_totals(ch_id, start, stop)

            profile_entries = self._build_profile_entries(
                mod_analysis_list=mod_analysis_list,
                mam=mam,
                start=start,
                fec_summary=fec_summary,
            )

            models[ch_id] = ChannelOfdmProfilePerf01Model(
                channel_id=ch_id,
                frequency=frequencies,
                avg_mer=mam.avg,
                mer_shannon_limits=cast(FloatSeries, shannon_model.snr_db_min),
                profiles=profile_entries,
            )

        return models

    def _build_profile_entries(
        self,
        mod_analysis_list: list[DsModulationProfileAnalysisModel],
        mam: MinAvgMax,
        start: TimeStamp,
        fec_summary: FecSummaryTotalsModel,
    ) -> list[ProfileEntryModel]:
        profile_entries: list[ProfileEntryModel] = []
        for mod_analysis in mod_analysis_list:
            capture_time = CaptureTime(getattr(mod_analysis, "capture_time", start))
            profile_entries.extend(
                self._build_profile_entries_for_analysis(
                    capture_time=capture_time,
                    profiles=mod_analysis.profiles,
                    mam=mam,
                    fec_summary=fec_summary,
                )
            )
        return profile_entries

    def _build_profile_entries_for_analysis(
        self,
        capture_time: CaptureTime,
        profiles: list[ProfileAnalysisEntryModel],
        mam: MinAvgMax,
        fec_summary: FecSummaryTotalsModel,
    ) -> list[ProfileEntryModel]:
        entries: list[ProfileEntryModel] = []
        for profile_entry in profiles:
            pid = profile_entry.profile_id
            shannon_min = profile_entry.carrier_values.shannon_min_mer
            capacity_delta = [
                float(a - b) for a, b in zip(mam.avg, shannon_min, strict=False)
            ]
            fec_entry = next(
                (p for p in fec_summary.summary if p.profile_id == pid), None
            )
            fec_payload = (
                fec_summary
                if fec_entry is None
                else FecSummaryTotalsModel(
                    start=fec_summary.start,
                    end=fec_summary.end,
                    channel_id=fec_summary.channel_id,
                    summary=[fec_entry],
                )
            )

            entries.append(
                ProfileEntryModel(
                    capture_time=capture_time,
                    profile_id=pid,
                    profile_min_mer=shannon_min,
                    capacity_delta=capacity_delta,
                    fec_summary=fec_payload,
                )
            )
        return entries

    """Abstract Required methods"""

    def _process(self) -> None:
        """
        Process transactions into typed PNM objects and build a time-indexed view.

        Steps
        -----
        1) Fetch all TransactionCollectionModel items from the current TransactionCollection.
        2) Attempt to decode each payload (bytes) as one of:
            - CmDsOfdmRxMer
            - CmDsOfdmFecSummary
            - CmDsOfdmModulationProfile
            In that order; on failure, fall through to the next type.
        3) Store each successfully decoded object in a temporal mapping keyed
        by its capture_time (or INVALID_CAPTURE_TIME if missing).
        4) Produce a list `self._sorted_temporal_mapping` of (capture_time, obj) tuples,
        sorted by ascending capture_time, for downstream iteration.
        """
        self._is_process = True
        self.logger.info("Processing Multi-RxMER Analysis Report")

        # Convert Transactions to PNM RxMER Data
        tc = self.getTransactionCollection()
        tcms: list[TransactionCollectionModel] = tc.getTransactionCollectionModel()
        temporal_mapping: dict[
            CaptureTime, CmDsOfdmRxMer | CmDsOfdmFecSummary | CmDsOfdmModulationProfile
        ] = {}

        self.logger.info(f"TransactionCollectionModel Count: {len(tcms)}")

        # Groom data for general use due to various Analysis that is performed
        for count, tcm in enumerate(tcms):
            try:
                dorm = CmDsOfdmRxMer(tcm.data)
                capture_time: CaptureTime = (
                    dorm.getPnmHeaderModel().pnm_header.capture_time
                    or INVALID_CAPTURE_TIME
                )
                temporal_mapping[capture_time] = dorm
                model = dorm.to_model()
                self.register_models_for_json_archive_files(
                    model, [str(model.channel_id), "CmDsOfdmRxMer"]
                )
                continue

            except Exception as e:
                self.logger.debug(
                    f"PNM file {count} is not compatible with CmDsOfdmRxMer, skipping: {e}"
                )

            try:
                dofs = CmDsOfdmFecSummary(tcm.data)
                capture_time: CaptureTime = (
                    dofs.getPnmHeaderModel().pnm_header.capture_time
                    or INVALID_CAPTURE_TIME
                )
                temporal_mapping[capture_time] = dofs
                model = dofs.to_model()
                self.register_models_for_json_archive_files(
                    model, [str(model.channel_id), "CmDsOfdmFecSummary"]
                )
                continue

            except Exception as e:
                self.logger.debug(
                    f"PNM file {count} is not compatible with CmDsOfdmFecSummary, skipping: {e}"
                )

            try:
                domp = CmDsOfdmModulationProfile(tcm.data)
                capture_time: CaptureTime = (
                    domp.getPnmHeaderModel().pnm_header.capture_time
                    or INVALID_CAPTURE_TIME
                )
                temporal_mapping[capture_time] = domp
                model = domp.to_model()
                self.register_models_for_json_archive_files(
                    model, [str(model.channel_id), "CmDsOfdmModulationProfile"]
                )
                continue

            except Exception as e:
                self.logger.debug(
                    f"PNM file {count} is not compatible with CmDsOfdmModulationProfile, skipping: {e}"
                )

        # Create a sorted list of tuples based on capture_time (ascending)
        self._sorted_temporal_mapping = sorted(
            temporal_mapping.items(), key=lambda x: x[0]
        )

        self.logger.debug(
            f"Temporal mapping size={len(temporal_mapping)}, sorted entries={len(self._sorted_temporal_mapping)}"
        )

        self._dispatch_build()

    def create_csv(self, **kwargs: object) -> list[CSVManager]:
        """
        Build CSV outputs for supported analysis types.
        Currently implemented for MIN_AVG_MAX only.
        """
        self.logger.debug("Processing Multi-RxMER Analysis CSV Report")
        out: list[CSVManager] = []
        model = self.to_model()

        if self.analysis_type == MultiRxMerAnalysisType.MIN_AVG_MAX:
            data = cast(MinAvgMaxMap, model.data)

            for ch_id, ch_model in data.items():
                csv_mgr: CSVManager = self.csv_manager_factory()

                # Convert frequency (Hz) → kHz for readability and to match labeling.
                freq_hz = ch_model.frequency
                freq_khz = [f / 1_000.0 for f in freq_hz]

                csv_mgr.set_header(["channel_id", "frequency_khz", "min", "avg", "max"])

                for idx, f_khz in enumerate(freq_khz):
                    # Defensive indexing (lists should match by construction)
                    mn = ch_model.min[idx] if idx < len(ch_model.min) else None
                    av = ch_model.avg[idx] if idx < len(ch_model.avg) else None
                    mx = ch_model.max[idx] if idx < len(ch_model.max) else None
                    csv_mgr.insert_row([ch_id, f_khz, mn, av, mx])

                csv_fname = self.create_csv_fname(
                    tags=["rxmer_min_avg_max", f"{ch_id}"]
                )
                csv_mgr.set_path_fname(csv_fname)

                out.append(csv_mgr)

        elif self.analysis_type == MultiRxMerAnalysisType.OFDM_PROFILE_PERFORMANCE_1:
            data = cast(OfdmProfilePerf01Map, model.data)

            for ch_id, ch_model in data.items():
                ch_model = cast(ChannelOfdmProfilePerf01Model, ch_model)

                for profile_model in ch_model.profiles:
                    csv_mgr: CSVManager = self.csv_manager_factory()
                    header = [
                        "ProfileID",
                        "Frequency(Hz)",
                        "AvgMER(dB)",
                        "ProfileMin(dB)",
                        "CapacityDelta(Avg vs. ProfileMin)",
                        "FECTotal",
                        "FECCorrected",
                        "FECUncorrectable",
                    ]
                    csv_mgr.set_header(header)

                    pid = profile_model.profile_id
                    fec_e = (
                        profile_model.fec_summary.summary[0]
                        if profile_model.fec_summary.summary
                        else None
                    )
                    total = fec_e.summary.total_codewords if fec_e else 0
                    corr = fec_e.summary.corrected if fec_e else 0
                    uncor = fec_e.summary.uncorrectable if fec_e else 0

                    self._write_profile_perf_rows(
                        csv_mgr=csv_mgr,
                        profile_id=pid,
                        total=total,
                        corr=corr,
                        uncor=uncor,
                        frequencies=ch_model.frequency,
                        avg_mer=ch_model.avg_mer,
                        profile_min_mer=profile_model.profile_min_mer,
                        capacity_delta=profile_model.capacity_delta,
                    )

                    csv_fname = self.create_csv_fname(
                        tags=["ofdm_profile_perf_1", f"ch{ch_id}", f"pid{pid}"]
                    )
                    csv_mgr.set_path_fname(csv_fname)
                    out.append(csv_mgr)

        elif self.analysis_type == MultiRxMerAnalysisType.RXMER_HEAT_MAP:
            data = cast(HeatMapMap, model.data)

            for ch_id, ch_model in data.items():
                ch_model = cast(ChannelHeatMapModel, ch_model)
                csv_mgr: CSVManager = self.csv_manager_factory()

                # Build header: first column is capture time index, then frequency (Hz → kHz)
                freq_khz = [f / 1_000.0 for f in ch_model.frequency]
                header = ["CaptureTime"] + [str(f) for f in freq_khz]
                csv_mgr.set_header(header)

                # Each row contains: capture time + MER values for that time
                for ts, mag_series in zip(
                    ch_model.timestamps, ch_model.values, strict=False
                ):
                    csv_mgr.insert_row([ts] + mag_series)

                # Assign CSV filename
                csv_fname = self.create_csv_fname(
                    tags=["rxmer_ofdm_heat_map", f"{ch_id}"]
                )
                csv_mgr.set_path_fname(csv_fname)

                out.append(csv_mgr)

        return out

    def _write_profile_perf_rows(
        self,
        csv_mgr: CSVManager,
        profile_id: ProfileId,
        total: int,
        corr: int,
        uncor: int,
        frequencies: FrequencySeriesHz,
        avg_mer: FloatSeries,
        profile_min_mer: FloatSeries,
        capacity_delta: FloatSeries,
    ) -> None:
        for freq, avg_value, prof_lim, delta in zip(
            frequencies,
            avg_mer,
            profile_min_mer,
            capacity_delta,
            strict=False,
        ):
            csv_mgr.insert_row(
                [profile_id, freq, avg_value, prof_lim, delta, total, corr, uncor]
            )

    def create_matplot(self, **kwargs: object) -> list[MatplotManager]:
        """
        Build MatPlot PNG outputs for supported analysis types.
        Currently implemented for MIN_AVG_MAX only.
        """
        self.logger.debug("Processing Multi-RxMER Analysis MatPlot Report")
        out: list[MatplotManager] = []
        model = self.to_model()

        if self.analysis_type == MultiRxMerAnalysisType.MIN_AVG_MAX:
            data1 = cast(MinAvgMaxMap, model.data)

            for channel_id, ch_model in data1.items():
                freq_hz = cast(ArrayLike, ch_model.frequency)
                freq_khz = cast(ArrayLike, freq_hz)

                mn = cast(ArrayLike, ch_model.min)
                av = cast(ArrayLike, ch_model.avg)
                mx = cast(ArrayLike, ch_model.max)

                cfg = PlotConfig(
                    title=f"Min-Avg-Max RxMER · Channel: {channel_id}",
                    x=cast(ArrayLike, freq_khz),
                    y_multi=[mn, av, mx],
                    y_multi_label=["Min", "Avg", "Max"],
                    x_tick_mode="unit",
                    x_unit_from="hz",
                    x_unit_out="mhz",
                    x_tick_decimals=0,
                    xlabel_base="Frequency",
                    ylabel="dB",
                    grid=True,
                    legend=True,
                    transparent=False,
                    line_colors=[
                        "#FF5733",
                        "#3357FF",
                        "#33FF57",
                    ],
                    theme="dark",
                )

                multi = self.create_png_fname(
                    tags=[str(channel_id), "rxmer_min_avg_max"]
                )
                self.logger.debug(
                    "Creating MatPlot: %s for channel: %s", multi, channel_id
                )

                mat_mgr = MatplotManager(default_cfg=cfg)
                mat_mgr.plot_multi_line(filename=multi)

                out.append(mat_mgr)

        elif self.analysis_type == MultiRxMerAnalysisType.RXMER_HEAT_MAP:
            data2 = cast(HeatMapMap, model.data)

            for ch_id, ch_model in data2.items():
                ch_model = cast(ChannelHeatMapModel, ch_model)

                Z = np.asarray(ch_model.values, dtype=float)
                if Z.size == 0:
                    self.logger.warning(
                        "RXMER_HEAT_MAP: empty matrix for channel %s; skipping.", ch_id
                    )
                    continue

                x_hz = cast(ArrayLike, ch_model.frequency)
                y_ix = cast(ArrayLike, np.arange(Z.shape[0], dtype=float))

                try:
                    vmin = float(np.nanmin(Z))
                    vmax = float(np.nanmax(Z))
                except Exception:
                    vmin = None
                    vmax = None

                cfg = PlotConfig(
                    title=f"HeatMap RxMER · Channel: {ch_id}",
                    x=x_hz,
                    x_tick_mode="unit",
                    x_unit_from="hz",
                    x_unit_out="mhz",
                    x_tick_decimals=0,
                    xlabel_base="Frequency",
                    ylabel="Capture Index",
                    zlabel="MER (dB)",
                    grid=False,
                    legend=False,
                    transparent=False,
                    theme="dark",
                )

                png_name = self.create_png_fname(tags=[str(ch_id), "rxmer_heat_map"])

                mat_mgr = MatplotManager(default_cfg=cfg)
                mat_mgr.heatmap2d(
                    Z.tolist(),
                    png_name,
                    x=x_hz,
                    y=y_ix,
                    add_colorbar=True,
                    vmin=vmin,
                    vmax=vmax,
                )

                out.append(mat_mgr)

        elif self.analysis_type == MultiRxMerAnalysisType.OFDM_PROFILE_PERFORMANCE_1:
            data3 = cast(OfdmProfilePerf01Map, model.data)

            for ch_id, ch_model in data3.items():
                ch_model = cast(ChannelOfdmProfilePerf01Model, ch_model)

                if not ch_model.profiles:
                    self.logger.warning(
                        "OFDM_PROFILE_PERFORMANCE_1: no profiles for channel %s; skipping.",
                        ch_id,
                    )
                    continue

                freq_hz = cast(ArrayLike, ch_model.frequency)
                avg_mer = cast(ArrayLike, ch_model.avg_mer)

                for profile_model in ch_model.profiles:
                    pid = profile_model.profile_id
                    pmin = cast(ArrayLike, profile_model.profile_min_mer)
                    fec_e = (
                        profile_model.fec_summary.summary[0]
                        if profile_model.fec_summary.summary
                        else None
                    )
                    total = getattr(fec_e.summary, "total_codewords", 0) if fec_e else 0
                    corr = getattr(fec_e.summary, "corrected", 0) if fec_e else 0
                    uncor = getattr(fec_e.summary, "uncorrectable", 0) if fec_e else 0
                    fec_l = f"FEC(Total={total}, Corr={corr}, Uncorr={uncor})"

                    cfg = PlotConfig(
                        title=f"OFDM PROFILE PERFORMANCE 1 · Channel: {ch_id} · Profile: {pid}",
                        x=freq_hz,
                        y_multi=[avg_mer, pmin],
                        y_multi_label=[f"AvgMER (dB) {fec_l}", "ProfileMin (dB)"],
                        x_tick_mode="unit",
                        x_unit_from="hz",
                        x_unit_out="mhz",
                        x_tick_decimals=0,
                        xlabel_base="Frequency",
                        ylabel="Average MER (dB)",
                        grid=True,
                        legend=True,
                        transparent=False,
                        line_colors=["#3357FF", "#33FF57"],
                        theme="dark",
                    )

                    fname = self.create_png_fname(
                        tags=[f"{ch_id}", f"profile_{pid}", "ofdm_profile_perf_1"]
                    )
                    plotmgr = MatplotManager(default_cfg=cfg)
                    plotmgr.plot_multi_line(filename=fname)
                    out.append(plotmgr)

        return out

    """Helpers"""

    def _parse_rxmer_heatmap_series(self) -> None:
        pass

    def _build_frequencies(
        self, model: CmDsOfdmRxMerModel | FrequencySeriesHz | None
    ) -> FrequencySeriesHz:
        """
        Build absolute subcarrier center frequencies (Hz) for the RxMER series.
        """
        if isinstance(model, list):
            return model
        if model is None:
            return []

        active_idx = model.first_active_subcarrier_index
        spacing = model.subcarrier_spacing
        freq_zero = model.subcarrier_zero_frequency
        num_idx = len(model.values)

        start_freq = freq_zero + (spacing * active_idx)

        freqs: FrequencySeriesHz = cast(
            FrequencySeriesHz, [start_freq + (i * spacing) for i in range(num_idx)]
        )
        return freqs
# FILE: src/pypnm/api/routes/basic/fec_summary_analysis_rpt.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from typing import cast

from pydantic import Field

from pypnm.api.routes.basic.abstract.analysis_report import (
    AnalysisReport,
    AnalysisRptMatplotConfig,
)
from pypnm.api.routes.basic.abstract.base_models.common_analysis import CommonAnalysis
from pypnm.api.routes.common.classes.analysis.analysis import Analysis
from pypnm.api.routes.common.classes.analysis.model.schema import (
    OfdmFecSummaryAnalysisModel,
)
from pypnm.lib.csv.manager import CSVManager
from pypnm.lib.matplot.manager import MatplotManager, PlotConfig
from pypnm.lib.types import ArrayLike, ChannelId, IntSeries, ScalarValue


class FecSummaryAnalysisRptModel(CommonAnalysis):
    """
    CommonAnalysis wrapper for OFDM FEC Summary outputs.

    Attributes
    ----------
    parameters : OfdmFecSummaryAnalysisModel
        Structured FEC summary model produced by the analysis layer.
    """

    parameters: OfdmFecSummaryAnalysisModel = Field(
        ...,
        description="Structured OFDM FEC summary model (per-channel, per-profile codeword time series).",
    )


class FecSummaryAnalysisReport(AnalysisReport):
    """
    Report generator for OFDM FEC Summary analysis.

    Responsibilities
    ----------------
    - Emit one CSV per channel/profile with time-series codeword counters.
    - Emit one PNG per channel/profile with Total/Corrected/Uncorrected curves.
    """

    FNAME_TAG: str = "FecSummary"

    def __init__(
        self,
        analysis: Analysis,
        analysis_matplot_config: AnalysisRptMatplotConfig | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize report generator and internal result registry."""
        if analysis_matplot_config is None:
            analysis_matplot_config = AnalysisRptMatplotConfig()
        super().__init__(analysis, analysis_matplot_config)
        self.logger = logging.getLogger(f"{self.__class__.__name__}")
        self._results: dict[int, FecSummaryAnalysisRptModel] = {}

    @staticmethod
    def _as_seq(x: ScalarValue | Sequence[ScalarValue] | None) -> list[ScalarValue]:
        """
        Convert scalar or sequence of scalars into a list of ScalarValue.

        Notes
        -----
        - None         → []
        - list/tuple   → list(x)
        - other scalar → [x]
        """
        if x is None:
            return []
        if isinstance(x, (list, tuple)):
            return list(x)
        try:
            return list(x)
        except Exception:
            return [x]

    @staticmethod
    def _get(obj: object, *names: str) -> object | None:
        """
        Retrieve the first matching attribute or mapping key from a set of candidates.

        Parameters
        ----------
        obj : Any
            Source object or mapping.
        *names : str
            Candidate attribute or key names to probe in order.

        Returns
        -------
        Any
            Value of the first attribute/key found, otherwise None.
        """
        for n in names:
            if hasattr(obj, n):
                return getattr(obj, n)
            if isinstance(obj, Mapping) and n in obj:
                return obj[n]
        return None

    def _resolve_profile(self, profile_entry: object) -> str:
        """
        Resolve a human-readable profile identifier string.

        Parameters
        ----------
        profile_entry : Any
            Profile entry object or mapping with one of: profile, profile_id, id.

        Returns
        -------
        str
            Profile identifier coerced to string (integer string when possible).
        """
        p = self._get(profile_entry, "profile", "profile_id", "id")
        try:
            return str(int(p))
        except Exception:
            return str(p) if p is not None else "unknown"

    def _resolve_codewords(
        self,
        profile_entry: object,
    ) -> tuple[list[ScalarValue], IntSeries, IntSeries, IntSeries, dict[str, int]]:
        """
        Resolve timestamp and codeword counter series from schema variants.

        Parameters
        ----------
        profile_entry : Any
            Profile entry containing codeword time-series data in one of several
            supported field layouts.

        Returns
        -------
        Tuple[List[ScalarValue], IntSeries, IntSeries, IntSeries, Dict[str, int]]
            - List[ScalarValue] : Timestamps (epoch seconds or formatted labels).
            - IntSeries         : Total codewords per timestamp.
            - IntSeries         : Corrected codewords per timestamp.
            - IntSeries         : Uncorrected codewords per timestamp.
            - Dict[str, int]    : Shape summary for logging (keys: ts, tc, cc, uc).
        """
        cw = self._get(
            profile_entry, "codewords", "codeword_entries", "entries", "codeword"
        )
        shape: dict[str, int] = {}
        candidates = [cw, self._get(cw, "values"), self._get(cw, "data")]

        ts: list[ScalarValue] = []
        tc: IntSeries = []
        cc: IntSeries = []
        uc: IntSeries = []
        for node in candidates:
            if node is None:
                continue
            ts = self._as_seq(self._get(node, "timestamps", "timestamp"))
            tc = [
                int(v)
                for v in self._as_seq(
                    self._get(node, "total_codewords", "total", "totals")
                )
            ]
            cc = [int(v) for v in self._as_seq(self._get(node, "corrected"))]
            uc = [int(v) for v in self._as_seq(self._get(node, "uncorrected"))]
            if any((ts, tc, cc, uc)):
                break

        shape["ts"] = len(ts)
        shape["tc"] = len(tc)
        shape["cc"] = len(cc)
        shape["uc"] = len(uc)
        return ts, tc, cc, uc, shape

    def _log_preview(
        self,
        ch: ChannelId,
        profile: str,
        ts: Sequence[ScalarValue],
        tc: Sequence[int],
        cc: Sequence[int],
        uc: Sequence[int],
    ) -> None:
        """
        Log a short preview of the first few samples for a channel/profile series.

        Parameters
        ----------
        ch : ChannelId
            Channel identifier.
        profile : str
            Profile identifier.
        ts : Sequence[ScalarValue]
            Timestamp sequence.
        tc : Sequence[int]
            Total codeword counts.
        cc : Sequence[int]
            Corrected codeword counts.
        uc : Sequence[int]
            Uncorrected codeword counts.
        """

        def head(
            seq: Sequence[ScalarValue | int], k: int = 5
        ) -> list[ScalarValue | int]:
            return list(seq[:k])

        self.logger.debug(
            "Preview ch=%s prof=%s ts[:5]=%s total[:5]=%s corr[:5]=%s unc[:5]=%s",
            int(ch),
            profile,
            head(ts),
            head(tc),
            head(cc),
            head(uc),
        )

    def create_csv(self, **kwargs: object) -> list[CSVManager]:
        """
        Produce CSV files with per-timestamp codeword counters for each channel/profile.

        Returns
        -------
        list[CSVManager]
            Managers pointing at the generated CSV files.
        """
        mgr_out: list[CSVManager] = []
        for common_model in self.get_common_analysis_model():
            c_model = cast(FecSummaryAnalysisRptModel, common_model)
            channel_id: int = int(c_model.channel_id)
            analysis_model = c_model.parameters
            profiles = getattr(analysis_model, "profiles", []) or []

            for profile_entry in profiles:
                profile = self._resolve_profile(profile_entry)
                ts, tc, cc, uc, shape = self._resolve_codewords(profile_entry)
                n = min(len(ts), len(tc), len(cc), len(uc))
                self.logger.debug(
                    "CSV series lengths ch=%s prof=%s shape=%s n=%d",
                    channel_id,
                    profile,
                    shape,
                    n,
                )
                if n == 0:
                    self.logger.warning(
                        "No data for Channel %s, Profile %s (timestamps/counters empty).",
                        channel_id,
                        profile,
                    )
                    continue

                try:
                    csv_mgr: CSVManager = self.csv_manager_factory()
                    csv_mgr.set_header(
                        [
                            "ChannelID",
                            "Profile",
                            "Timestamp",
                            "TotalCodewords",
                            "Corrected",
                            "Uncorrected",
                        ]
                    )
                    csv_fname = self.create_csv_fname(
                        tags=[str(channel_id), profile, self.FNAME_TAG]
                    )
                    csv_mgr.set_path_fname(csv_fname)
                    self._append_csv_rows(
                        csv_mgr=csv_mgr,
                        channel_id=channel_id,
                        profile=profile,
                        ts=ts,
                        tc=tc,
                        cc=cc,
                        uc=uc,
                        count=n,
                    )
                    self._log_preview(channel_id, profile, ts, tc, cc, uc)
                    self.logger.debug(
                        "CSV created ch=%s prof=%s -> %s (rows=%d)",
                        channel_id,
                        profile,
                        csv_fname,
                        csv_mgr.get_row_count(),
                    )
                    mgr_out.append(csv_mgr)
                except Exception as exc:
                    self.logger.exception(
                        "Failed to create CSV for channel %s (profile %s): %s",
                        channel_id,
                        profile,
                        exc,
                    )
        return mgr_out

    def _append_csv_rows(
        self,
        csv_mgr: CSVManager,
        channel_id: int,
        profile: str,
        ts: Sequence[ScalarValue],
        tc: Sequence[int],
        cc: Sequence[int],
        uc: Sequence[int],
        count: int,
    ) -> None:
        for idx in range(count):
            csv_mgr.insert_row(
                [channel_id, profile, ts[idx], tc[idx], cc[idx], uc[idx]]
            )

    def create_matplot(self, **kwargs: object) -> list[MatplotManager]:
        """
        Produce PNG plots (Total/Corrected/Uncorrected) for each channel/profile.

        Notes
        -----
        - X axis ticks are hidden.
        - A single human-readable time range ("start → end") is used as the xlabel.

        Returns
        -------
        list[MatplotManager]
            Managers used to generate and reference plot outputs.
        """
        mgr_out: list[MatplotManager] = []
        for common_model in self.get_common_analysis_model():
            c_model = cast(FecSummaryAnalysisRptModel, common_model)
            ch_id: ChannelId = ChannelId(c_model.channel_id)
            analysis_model = c_model.parameters
            profiles = getattr(analysis_model, "profiles", []) or []

            for profile_entry in profiles:
                profile = self._resolve_profile(profile_entry)
                ts, tc, cc, uc, shape = self._resolve_codewords(profile_entry)
                n = min(len(ts), len(tc), len(cc), len(uc))
                self.logger.debug(
                    "Plot series lengths ch=%s prof=%s shape=%s n=%d",
                    int(ch_id),
                    profile,
                    shape,
                    n,
                )
                if n == 0:
                    self.logger.warning(
                        "No data for Channel %s, Profile %s (timestamps/counters empty).",
                        int(ch_id),
                        profile,
                    )
                    continue

                try:
                    cfg = PlotConfig(
                        title=f"FEC Summary · OFDM · Channel {int(ch_id)} · Profile ({profile})",
                        x=cast(ArrayLike, ts[:n]),
                        ylabel="Codeword Count",
                        y_multi=[
                            cast(ArrayLike, tc[:n]),
                            cast(ArrayLike, cc[:n]),
                            cast(ArrayLike, uc[:n]),
                        ],
                        y_multi_label=["Total", "Corrected", "Uncorrected"],
                        grid=True,
                        legend=True,
                        transparent=False,
                        theme=self.getAnalysisRptMatplotConfig().theme,
                        line_colors=["tab:blue", "tab:green", "tab:red"],
                        # ── X-axis time range label & tick suppression ──
                        x_ticks_visible=False,  # hide all x ticks/labels
                        x_time_labels="from_to",  # render "start → end" as xlabel
                        x_time_input_unit="s",  # timestamps are epoch seconds
                        x_time_format="%Y-%m-%d %H:%M",  # adjust as needed
                        xlabel_prefix="Time Range: ",  # optional prefix before start→end
                    )

                    mgr = MatplotManager(default_cfg=cfg)
                    png_path = self.create_png_fname(
                        tags=[str(int(ch_id)), profile, self.FNAME_TAG]
                    )
                    self._log_preview(ch_id, profile, ts, tc, cc, uc)
                    self.logger.debug(
                        "Creating MatPlot: %s ch=%s prof=%s",
                        png_path,
                        int(ch_id),
                        profile,
                    )
                    mgr.plot_multi_line(filename=png_path)
                    mgr_out.append(mgr)
                except Exception as exc:
                    self.logger.exception(
                        "Failed to create plot for channel %s (profile %s): %s",
                        int(ch_id),
                        profile,
                        exc,
                    )
        return mgr_out

    def _process(self) -> None:
        """
        Register CommonAnalysis wrappers for each OfdmFecSummaryAnalysisModel.

        Expected
        --------
        The analysis model list is `list[OfdmFecSummaryAnalysisModel]`.
        """
        models: list[OfdmFecSummaryAnalysisModel] = cast(
            list[OfdmFecSummaryAnalysisModel], self.get_analysis_model()
        )
        for model in models:
            channel_id: int = int(model.channel_id)
            a_model = FecSummaryAnalysisRptModel(
                channel_id=channel_id, parameters=model
            )
            self.register_common_analysis_model(channel_id, a_model)
# FILE: src/pypnm/api/routes/basic/modulation_profile_analysis_rpt.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any, TypeVar, cast

from pydantic import BaseModel, ConfigDict, Field

from pypnm.api.routes.basic.abstract.analysis_report import (
    AnalysisReport,
    AnalysisRptMatplotConfig,
)
from pypnm.api.routes.basic.abstract.base_models.common_analysis import CommonAnalysis
from pypnm.api.routes.common.classes.analysis.analysis import Analysis
from pypnm.lib.constants import INVALID_CHANNEL_ID, INVALID_PROFILE_ID
from pypnm.lib.csv.manager import CSVManager
from pypnm.lib.matplot.manager import MatplotManager, PlotConfig
from pypnm.lib.types import (
    ArrayLike,
    ChannelId,
    FloatSeries,
    FrequencyHz,
    FrequencySeriesHz,
    ProfileId,
    StringArray,
)


class ModulationProfileRptModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    profile_id: int = Field(..., description="Profile identifier")
    modulation: list[str] = Field(
        default_factory=list,
        description="Per-carrier modulation label (e.g., 'QAM256')",
    )
    bits_per_symbol: list[int] = Field(
        default_factory=list,
        description="Per-carrier bits per symbol (derived or provided)",
    )
    shannon_min_mer: list[float] = Field(
        default_factory=list, description="Per-carrier minimum MER per Shannon (dB)"
    )


class ModulationProfileParametersAnalysisRpt(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    profiles: list[ModulationProfileRptModel] = Field(
        default_factory=list, description="All profiles for a channel"
    )


class ModulationProfileAnalysisRptModel(CommonAnalysis):
    parameters: ModulationProfileParametersAnalysisRpt = Field(
        ..., description="Modulation profile parameters"
    )


class ModulationProfileReport(AnalysisReport):
    FNAME_TAG: str = "modulationprofile"

    def __init__(
        self,
        analysis: Analysis,
        analysis_matplot_config: AnalysisRptMatplotConfig | None = None,
        **kwargs: object,
    ) -> None:
        if analysis_matplot_config is None:
            analysis_matplot_config = AnalysisRptMatplotConfig()
        super().__init__(analysis, analysis_matplot_config)
        self.logger = logging.getLogger("ModulationProfileReport")
        self._results: dict[int, ModulationProfileAnalysisRptModel] = {}

    def create_csv(self, **kwargs: object) -> list[CSVManager]:
        """
        Stream validated models into CSVs. Assumes `_process()` already enforced.
        Emits one CSV per channel/profile pair.
        """
        csv_mgr_list: list[CSVManager] = []
        any_models = False

        for common_model in self.get_common_analysis_model():
            any_models = True
            model = cast(ModulationProfileAnalysisRptModel, common_model)
            channel_id: int = int(model.channel_id)
            freq: FrequencySeriesHz = cast(FrequencySeriesHz, model.raw_x)

            if not freq:
                self.logger.warning(
                    f"Channel {channel_id} has empty frequency array; skipping CSV."
                )
                continue

            try:
                header: list[str] = [
                    "ChannelID",
                    "ProfileID",
                    "Frequency_Hz",
                    "Modulation",
                    "BitsPerSymbol",
                    "ShannonMinMER_dB",
                ]

                for profile in model.parameters.profiles:
                    csv_mgr: CSVManager = self.csv_manager_factory()
                    csv_mgr.set_header(header)

                    csv_fname = self.create_csv_fname(
                        tags=[str(channel_id), str(profile.profile_id), self.FNAME_TAG]
                    )
                    csv_mgr.set_path_fname(csv_fname)

                    n = len(freq)
                    mod = self._align_len(profile.modulation, n, fill="UNKNOWN")
                    bps = self._align_len(profile.bits_per_symbol, n, fill=0)
                    mer = self._align_len(profile.shannon_min_mer, n, fill=float("nan"))

                    rows_written = self._append_profile_rows(
                        csv_mgr=csv_mgr,
                        channel_id=channel_id,
                        profile_id=profile.profile_id,
                        freq=freq,
                        mod=mod,
                        bps=bps,
                        mer=mer,
                    )

                    self.logger.info(
                        f"CSV rows for channel {channel_id} profile {profile.profile_id}: {rows_written}"
                    )
                    self.logger.info(
                        f"CSV created for channel {channel_id}: {csv_fname} (rows={csv_mgr.get_row_count()})"
                    )

                    csv_mgr_list.append(csv_mgr)

            except Exception as exc:
                self.logger.exception(
                    f"Failed to create CSV for channel {channel_id}: {exc}",
                    exc_info=True,
                )

        if not any_models:
            self.logger.info("No analysis data available; no CSVs created.")

        return csv_mgr_list

    def create_matplot(self) -> list[MatplotManager]:
        """
        Generate per-channel plots, one set per profile:
        1) Bits-per-symbol vs. Frequency
        2) Shannon Min MER vs. Frequency
        3) Modulation vs. Frequency with a preloaded M-QAM scale (linear spacing via log₂(M) positions,
            tick labels shown as M values: 4, 8, 16, 32, …, 4096)

        Notes
        -----
        - Frequency axis is formatted by Matplot using unit scaling (Hz → MHz) and zero decimals.
        - Theme is taken from AnalysisRptMatplotConfig (e.g., "dark" or "light").
        - The M-QAM axis uses evenly spaced positions at log₂(M) to avoid visually "log-like" spacing,
        while the visible tick labels are the true QAM orders (M).
        """
        out: list[MatplotManager] = []

        for common_model in self.get_common_analysis_model():
            model = cast(ModulationProfileAnalysisRptModel, common_model)
            channel_id: ChannelId = ChannelId(model.channel_id)
            freq: FrequencySeriesHz = cast(FrequencySeriesHz, model.raw_x)

            if not freq:
                self.logger.warning(
                    f"Channel {channel_id} has empty frequency array; skipping plots."
                )
                continue

            for profile in model.parameters.profiles:
                profile_id: ProfileId = ProfileId(profile.profile_id)

                # Align inputs to frequency length
                try:
                    n = len(freq)
                    bpsym: FloatSeries = self._align_len(
                        profile.bits_per_symbol, n, fill=0
                    )
                    min_mer: FloatSeries = self._align_len(
                        profile.shannon_min_mer, n, fill=float("nan")
                    )
                    mod_lbls: StringArray = self._align_len(
                        profile.modulation, n, fill="UNKNOWN"
                    )
                    mod_order: list[int] = [
                        self._derive_qam_order(lbl) for lbl in mod_lbls
                    ]
                except Exception as exc:
                    self.logger.exception(
                        f"Failed to align arrays for channel {channel_id} profile {profile_id}: {exc}",
                        exc_info=True,
                    )
                    continue

                # 1) Bits-per-symbol vs Frequency
                try:
                    bps_cfg = PlotConfig(
                        title=f"Bits-Per-Symbol vs Frequency — OFDM Ch {channel_id} · Profile {profile_id}",
                        x=cast(ArrayLike, freq),
                        y=cast(ArrayLike, bpsym),
                        ylabel="Bits per Symbol",
                        x_tick_mode="unit",
                        x_unit_from="hz",
                        x_unit_out="mhz",
                        x_tick_decimals=0,
                        xlabel_base="Frequency",
                        grid=True,
                        legend=False,
                        transparent=False,
                        theme=self.getAnalysisRptMatplotConfig().theme,
                    )

                    png_fname = self.create_png_fname(
                        tags=[str(channel_id), str(profile_id), "bps", self.FNAME_TAG]
                    )
                    self.logger.info(
                        f"Creating Bits-Per-Symbol plot: {png_fname} for channel: {channel_id}"
                    )
                    mplot_mgr = MatplotManager(default_cfg=bps_cfg)
                    mplot_mgr.plot_line(filename=png_fname)
                    out.append(mplot_mgr)
                except Exception as exc:
                    self.logger.exception(
                        f"Failed to create Bits-Per-Symbol plot for channel {channel_id} profile {profile_id}: {exc}",
                        exc_info=True,
                    )

                # 2) Shannon Min MER vs Frequency
                try:
                    mer_cfg = PlotConfig(
                        title=f"Shannon Min MER vs Frequency — OFDM Ch {channel_id} · Profile {profile_id}",
                        x=cast(ArrayLike, freq),
                        y=cast(ArrayLike, min_mer),
                        ylabel="Shannon Min MER (dB)",
                        x_tick_mode="unit",
                        x_unit_from="hz",
                        x_unit_out="mhz",
                        x_tick_decimals=0,
                        xlabel_base="Frequency",
                        grid=True,
                        legend=False,
                        transparent=False,
                        theme=self.getAnalysisRptMatplotConfig().theme,
                    )

                    png_fname = self.create_png_fname(
                        tags=[
                            str(channel_id),
                            str(profile_id),
                            "shannon",
                            self.FNAME_TAG,
                        ]
                    )
                    self.logger.info(
                        f"Creating Shannon Min MER plot: {png_fname} for channel: {channel_id}"
                    )
                    mplot_mgr = MatplotManager(default_cfg=mer_cfg)
                    mplot_mgr.plot_line(filename=png_fname)
                    out.append(mplot_mgr)
                except Exception as exc:
                    self.logger.exception(
                        f"Failed to create Shannon Min MER plot for channel {channel_id} profile {profile_id}: {exc}",
                        exc_info=True,
                    )

                # 3) Modulation vs Frequency with preloaded M-QAM scale (linear spacing via log₂(M), labels show M)
                try:
                    (
                        mod_bits,
                        y_ticks_bits,
                        y_labels_M,
                        max_bits_cap,
                    ) = self._build_modulation_plot_axes(mod_order)

                    mod_cfg = PlotConfig(
                        title=f"Modulation vs Frequency · OFDM · Channel ({channel_id}) · Profile ({profile_id})",
                        x=cast(ArrayLike, freq),
                        y=cast(ArrayLike, mod_bits),
                        ylabel="Modulation Order (M-QAM)",
                        x_tick_mode="unit",
                        x_unit_from="hz",
                        x_unit_out="mhz",
                        x_tick_decimals=0,
                        xlabel_base="Frequency",
                        y_ticks=y_ticks_bits,
                        y_tick_labels=y_labels_M,
                        ylim=(0.0, float(max_bits_cap)),
                        grid=True,
                        legend=False,
                        transparent=False,
                        theme=self.getAnalysisRptMatplotConfig().theme,
                    )

                    png_fname = self.create_png_fname(
                        tags=[
                            str(channel_id),
                            str(profile_id),
                            "modulation",
                            self.FNAME_TAG,
                        ]
                    )
                    self.logger.info(
                        f"Creating Modulation plot: {png_fname} for channel: {channel_id}"
                    )
                    mplot_mgr = MatplotManager(default_cfg=mod_cfg)
                    mplot_mgr.plot_line(filename=png_fname)
                    out.append(mplot_mgr)
                except Exception as exc:
                    self.logger.exception(
                        f"Failed to create Modulation plot for channel {channel_id} profile {profile_id}: {exc}",
                        exc_info=True,
                    )

        if not out:
            self.logger.info("No analysis data available; no plots created.")

        return out

    def _append_profile_rows(
        self,
        csv_mgr: CSVManager,
        channel_id: int,
        profile_id: int,
        freq: FrequencySeriesHz,
        mod: list[str],
        bps: FloatSeries,
        mer: FloatSeries,
    ) -> int:
        rows_written = 0
        for idx in range(len(freq)):
            csv_mgr.insert_row(
                [
                    channel_id,
                    profile_id,
                    freq[idx],
                    mod[idx],
                    int(bps[idx]),
                    float(mer[idx]),
                ]
            )
            rows_written += 1
        return rows_written

    def _build_modulation_plot_axes(
        self, mod_order: list[int]
    ) -> tuple[list[int], list[int], list[str], int]:
        from math import isfinite, log2

        mod_bits: list[int] = []
        for value in mod_order:
            if value and value > 0:
                try:
                    bits = log2(value)
                    mod_bits.append(int(bits) if isfinite(bits) else 0)
                except Exception:
                    mod_bits.append(0)
            else:
                mod_bits.append(0)

        ladder_M = [4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096]
        ladder_bits = [int(log2(item)) for item in ladder_M]

        max_bits_seen = max(mod_bits) if mod_bits else 8
        max_bits_cap = max(2, min(max_bits_seen, ladder_bits[-1]))

        y_ticks_bits = [bits for bits in ladder_bits if bits <= max_bits_cap]
        y_labels_M = [str(2**bits) for bits in y_ticks_bits]

        return mod_bits, y_ticks_bits, y_labels_M, max_bits_cap

    def _process(self) -> None:
        """
        Expected per-item shape (keys are case-sensitive):

        {
          "device_details": {...},
          "pnm_header": {...},
          "mac_address": "...",
          "channel_id": int,
          "frequency_unit": "Hz",
          "shannon_limit_unit": "dB",
          "profiles": [
            {
              "profile_id": int,
              "carrier_values": {
                "frequency": [...],           # List[float] (Hz)
                "modulation": [...],          # List[str]  (e.g., 'QAM256')
                "bits_per_symbol": [...],     # Optional[List[int]]
                "shannon_min_mer": [...]      # List[float] (dB)
              }
            },
            ...
          ]
        }
        """
        data_list: list[dict[str, Any]] = self.get_analysis_data() or []

        try:
            for _idx, data in enumerate(data_list):
                channel_id = ChannelId(data.get("channel_id", INVALID_CHANNEL_ID))
                profiles_in: list[dict[str, Any]] = data.get("profiles", [])

                freq_array: FrequencySeriesHz = []
                profile_models: list[ModulationProfileRptModel] = []

                for profile_entry in profiles_in:
                    cv: dict[str, Any] = profile_entry.get("carrier_values", {})
                    profile_id: int = int(
                        profile_entry.get("profile_id", INVALID_PROFILE_ID)
                    )

                    freqs: FrequencySeriesHz = list(
                        map(FrequencyHz, cv.get("frequency", []) or [])
                    )
                    mod: list[str] = list(map(str, cv.get("modulation", []) or []))
                    bps: list[int] = list(map(int, cv.get("bits_per_symbol", []) or []))
                    mer: list[float] = list(
                        map(float, cv.get("shannon_min_mer", []) or [])
                    )

                    if not bps and mod:
                        bps = [self._derive_bits_per_symbol(m) for m in mod]

                    if not freq_array and freqs:
                        freq_array = freqs

                    n = len(freq_array) if freq_array else len(freqs)
                    if n:
                        mod = self._align_len(mod, n, fill="UNKNOWN")
                        bps = self._align_len(bps, n, fill=0)
                        mer = self._align_len(mer, n, fill=float("nan"))

                    profile_models.append(
                        ModulationProfileRptModel(
                            profile_id=profile_id,
                            modulation=mod,
                            bits_per_symbol=bps,
                            shannon_min_mer=mer,
                        )
                    )

                params = ModulationProfileParametersAnalysisRpt(profiles=profile_models)

                model = ModulationProfileAnalysisRptModel(
                    channel_id=channel_id,
                    raw_x=freq_array,
                    raw_y=[0.0],
                    parameters=params,
                )

                self.register_common_analysis_model(channel_id, model)

        except Exception as exc:
            self.logger.exception(
                f"Failed to process Modulation Profile data: {exc}", exc_info=True
            )

    T = TypeVar("T")

    @staticmethod
    def _align_len(seq: Iterable[T] | list[T], n: int, *, fill: T) -> list[T]:
        """
        Force a sequence to length n using truncation or padding with `fill`.
        """
        lst = list(seq) if not isinstance(seq, list) else seq
        if n <= 0:
            return []
        if len(lst) >= n:
            return lst[:n]
        return lst + [fill] * (n - len(lst))

    @staticmethod
    def _derive_bits_per_symbol(mod_label: str) -> int:
        """
        Best-effort mapping from modulation label to bits/symbol. Accepts forms like 'QAM256', 'QAM-256', '256QAM', 'qam1024', etc.
        """
        if not mod_label:
            return 0
        s = mod_label.strip().upper().replace("-", "").replace("_", "")
        digits = "".join(ch for ch in s if ch.isdigit())
        if not digits:
            return 0
        try:
            order = int(digits)
            from math import isfinite, log2

            val = log2(order)
            return int(val) if isfinite(val) else 0
        except Exception:
            return 0

    @staticmethod
    def _derive_qam_order(mod_label: str) -> int:
        """
        Parse modulation label to return QAM order M (e.g., 'QAM256' -> 256). If the label is missing digits, returns 0.
        """
        if not mod_label:
            return 0
        s = mod_label.strip().upper().replace("-", "").replace("_", "")
        digits = "".join(ch for ch in s if ch.isdigit())
        if not digits:
            return 0
        try:
            return int(digits)
        except Exception:
            return 0
# FILE: src/pypnm/api/routes/common/classes/analysis/analysis.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from enum import Enum
from typing import Any, cast

import numpy as np

from pypnm.api.routes.advance.analysis.signal_analysis.detection.echo.echo_detector import (
    EchoDetector,
    EchoDetectorReport,
)
from pypnm.api.routes.advance.analysis.signal_analysis.detection.echo.type import (
    EchoDetectorType,
)
from pypnm.api.routes.common.classes.analysis.model.mod_profile_schema import (
    CarrierItemModel,
    CarrierValuesListModel,
    CarrierValuesModel,
    CarrierValuesSplitModel,
    ProfileAnalysisEntryModel,
)
from pypnm.api.routes.common.classes.analysis.model.process import (
    AnalysisProcessParameters,
)
from pypnm.api.routes.common.classes.analysis.model.schema import (
    BaseAnalysisModel,
    ChanEstCarrierModel,
    ConstellationDisplayAnalysisModel,
    DsChannelEstAnalysisModel,
    DsHistogramAnalysisModel,
    DsModulationProfileAnalysisModel,
    DsRxMerAnalysisModel,
    EchoDatasetModel,
    FecSummaryCodeWordModel,
    GrpDelayStatsModel,
    OfdmaUsPreEqCarrierModel,
    OfdmFecSummaryAnalysisModel,
    OfdmFecSummaryProfileModel,
    RegressionModel,
    RxMerCarrierValuesModel,
    UsOfdmaUsPreEqAnalysisModel,
)
from pypnm.api.routes.common.classes.analysis.model.spectrum_analyzer_schema import (
    DEFAULT_POINT_AVG,
    MagnitudeSeries,
    SpecAnaAnalysisResults,
    SpectrumAnalyzerAnalysisModel,
    WindowAverage,
)
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.docs.pnm.spectrumAnalyzer.schemas import SpecAnCapturePara
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cm_snmp_operation import Generate
from pypnm.docsis.data_type.sysDescr import SystemDescriptor
from pypnm.lib.constants import (
    CABLE_VF,
    INVALID_CHANNEL_ID,
    INVALID_PROFILE_ID,
    INVALID_SCHEMA_TYPE,
    INVALID_START_VALUE,
    SPEED_OF_LIGHT,
    CableType,
)
from pypnm.lib.file_processor import FileProcessor
from pypnm.lib.log_files import LogFile
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.qam.lut_mgr import QamLutManager
from pypnm.lib.qam.types import QamModulation
from pypnm.lib.signal_processing.averager import MovingAverage
from pypnm.lib.signal_processing.butterworth import (
    DEFAULT_BUTTERWORTH_ORDER,
    MagnitudeButterworthFilter,
)
from pypnm.lib.signal_processing.complex_array_ops import ComplexArrayOps
from pypnm.lib.signal_processing.group_delay import GroupDelay
from pypnm.lib.signal_processing.linear_regression import LinearRegression1D
from pypnm.lib.signal_processing.shan.series import Shannon, ShannonSeries
from pypnm.lib.types import (
    ArrayLike,
    ChannelId,
    ComplexArray,
    FloatSeries,
    FrequencyHz,
    FrequencySeriesHz,
    IntSeries,
    MacAddressStr,
    ProfileId,
)
from pypnm.pnm.data_type.DocsIf3CmSpectrumAnalysisCtrlCmd import WindowFunction
from pypnm.pnm.data_type.DsOfdmModulationType import DsOfdmModulationType
from pypnm.pnm.lib.signal_statistics import SignalStatistics, SignalStatisticsModel
from pypnm.pnm.parser.CmDsOfdmModulationProfile import (
    CmDsOfdmModulationProfile,
    ModulationOrderType,
    RangeModulationProfileSchemaModel,
    SkipModulationProfileSchemaModel,
)
from pypnm.pnm.parser.model.parser_rtn_models import (
    CmDsConstDispMeasModel,
    CmDsHistModel,
    CmDsOfdmChanEstimateCoefModel,
    CmDsOfdmFecSummaryModel,
    CmDsOfdmModulationProfileModel,
    CmDsOfdmRxMerModel,
    CmUsOfdmaPreEqModel,
)
from pypnm.pnm.parser.pnm_file_type import PnmFileType


class RxMerCarrierType(Enum):
    """
    RxMER carrier classification labels.

    Members
    -------
    EXCLUSION : str
        "0". Subcarriers marked as excluded (e.g., guard bands, PLC gaps).
    CLIPPED : str
        "1". Values clipped/saturated (e.g., 0.0 dB or 63.5 dB).
    NORMAL : str
        "2". Valid, non-clipped RxMER readings.
    """

    EXCLUSION = "0"
    CLIPPED = "1"
    NORMAL = "2"


# RxMER special sentinel values used for classification:
RXMER_EXCLUSION = 63.75
RXMER_CLIPPED_LOW = 0.0
RXMER_CLIPPED_HIGH = 63.5

# Constants for Signal Processing
CHAN_EST_BW_CUTOFF_FRACTION: float = 0.25


class AnalysisType(Enum):
    """
    Analysis mode selector.

    Notes
    -----
    BASIC
        Provides (frequency, magnitude) and selected meta-data depending on the
        detected PNM file type. Additional per-type metrics may be included
        (e.g., group delay, Shannon limits, histogram counts).
    """

    BASIC = 0


class Analysis:
    """Core analysis runner.

    This orchestrator normalizes the payload's ``data`` into a list of
    measurement dictionaries and dispatches to the appropriate analysis
    routine based on the inferred PNM file type. For echo detection, the
    provided ``cable_type`` controls the velocity factor used to convert
    echo time delays to physical distances.

    Parameters
    ----------
    analysis_type : AnalysisType
        Selected analysis mode (e.g., ``AnalysisType.BASIC``).
    msg_response : MessageResponse
        Wrapped transport of the measurement payload; must expose
        ``payload_to_dict()`` with a top-level ``"data"`` entry.
    cable_type : CableType, default CableType.RG6
        Cable type used by echo-detection analysis to determine the
        propagation velocity factor for distance calculations.

    """

    def __init__(
        self,
        analysis_type: AnalysisType,
        msg_response: MessageResponse,
        cable_type: CableType = CableType.RG6,
        skip_automatic_process: bool = False,
    ) -> None:
        self.logger = logging.getLogger(f"{self.__class__.__name__}")
        self.analysis_type: AnalysisType = analysis_type
        self.msg_response: MessageResponse = msg_response
        self._cable_type: CableType = cable_type
        payload: dict[int | str, Any] = msg_response.payload_to_dict() or {}
        _raw_data = payload.get("data", [])

        self._result_model: list[BaseAnalysisModel] = []
        self._processed_pnm_type: list[PnmFileType] = []
        self._skip_automatic_process = skip_automatic_process

        # Defining DataTypes
        self._analysis_para: AnalysisProcessParameters = AnalysisProcessParameters()

        if isinstance(_raw_data, Mapping):
            self.measurement_data: list[dict[str, Any]] = [dict(_raw_data)]
        elif isinstance(_raw_data, Sequence) and not isinstance(
            _raw_data, (str, bytes, bytearray)
        ):
            self.measurement_data = [dict(m) for m in _raw_data]
        else:
            self.measurement_data = []

        self._analysis_dict: list[dict[str, Any]] = []

        if self.logger.isEnabledFor(logging.DEBUG):
            self.save_message_response(self.msg_response)

        if not skip_automatic_process:
            self._process(self._analysis_para)

    def process(self, analysis_para: AnalysisProcessParameters) -> None:
        self._analysis_para = analysis_para
        self._process(analysis_para)

    def _process(self, analysis_para: AnalysisProcessParameters) -> None:
        """Iterate and dispatch analysis per measurement.

        For each normalized measurement, this method assembles the combined
        PNM file type string from the header fields and routes to the
        corresponding *basic* analysis handler.

        Notes
        -----
        Unknown or missing file types are logged; the measurement is
        serialized for troubleshooting via :class:`LogFile`.
        """

        for idx, measurement in enumerate(self.measurement_data):
            if (
                "pnm_file_type" in measurement
                and PnmFileType.CM_SPECTRUM_ANALYSIS_SNMP_AMP_DATA.name
                in measurement["pnm_file_type"]
            ):
                self.logger.debug("Processing SNMP Spectrum Analysis Data")

                pnm_file_type = PnmFileType.CM_SPECTRUM_ANALYSIS_SNMP_AMP_DATA.value
                if self.analysis_type == AnalysisType.BASIC:
                    self.logger.debug(
                        "Performing Basic Analysis on SNMP Spectrum Analysis Data"
                    )
                    self._basic_analysis(pnm_file_type, measurement, analysis_para)

                continue

            pnm_header: dict[str, Any] = measurement.get("pnm_header") or {}
            channel_id: int = measurement.get("channel_id", INVALID_CHANNEL_ID)

            self.logger.debug(f"PNM-HEADER[{idx}]: {pnm_header}")

            file_type = str(pnm_header.get("file_type", ""))
            file_ver = str(pnm_header.get("file_type_version", ""))
            pnm_file_type = f"{file_type}{file_ver}"

            if not pnm_file_type:
                self.logger.error("PNM FileType not Found")
                LogFile.write(
                    fname=f"unknown-pnm-filetype-{Generate.time_stamp()}.dict",
                    data=measurement,
                )
                pass

            if self.analysis_type == AnalysisType.BASIC:
                self.logger.debug(
                    f"Performing Basic Analysis on PNM: {pnm_file_type} on Channel: {channel_id}"
                )
                self._basic_analysis(pnm_file_type, measurement, analysis_para)

            else:
                self.logger.error(f"Unknown AnalysisType: {self.analysis_type}")
                raise

    def _basic_analysis(
        self,
        pnm_file_type: str,
        measurement: dict[str, Any],
        analysis_para: AnalysisProcessParameters,
    ) -> None:
        """
        Route to the appropriate BASIC analysis handler.

        Parameters
        ----------
        pnm_file_type : str
            Concatenated PNM file type identifier, e.g.
            ``PnmFileType.RECEIVE_MODULATION_ERROR_RATIO.value``.
        measurement : dict
            Single measurement dictionary. Expected keys vary by file type,
            but generally include:
                - ``pnm_header`` : dict with ``file_type`` and version
                - ``channel_id`` : int
                - ``device_details`` : dict
                - per-type fields such as subcarrier spacing, values, profiles, etc.

        Notes
        -----
        This method only dispatches. See the specific handlers for field
        expectations and returned structures:

        """
        # TODO: unify return type?
        # model:BaseAnalysisModel

        if pnm_file_type == PnmFileType.OFDM_CHANNEL_ESTIMATE_COEFFICIENT.value:
            self.logger.debug("Processing: OFDM_CHANNEL_ESTIMATE_COEFFICIENT")
            model = self.basic_analysis_ds_chan_est(measurement)
            self.__update_result_model(model)
            self.__update_result_dict(model.model_dump())
            self.__add_pnmType(PnmFileType.OFDM_CHANNEL_ESTIMATE_COEFFICIENT)

        elif pnm_file_type == PnmFileType.DOWNSTREAM_CONSTELLATION_DISPLAY.value:
            self.logger.debug("Processing: DOWNSTREAM_CONSTELLATION_DISPLAY")
            model = self.basic_analysis_ds_constellation_display(measurement)
            self.__update_result_model(model)
            self.__update_result_dict(model.model_dump())
            self.__add_pnmType(PnmFileType.DOWNSTREAM_CONSTELLATION_DISPLAY)

        elif pnm_file_type == PnmFileType.RECEIVE_MODULATION_ERROR_RATIO.value:
            self.logger.debug("Processing: RECEIVE_MODULATION_ERROR_RATIO")
            model = self.basic_analysis_rxmer(measurement)
            self.__update_result_model(model)
            self.__update_result_dict(model.model_dump())
            self.__add_pnmType(PnmFileType.RECEIVE_MODULATION_ERROR_RATIO)

        elif pnm_file_type == PnmFileType.DOWNSTREAM_HISTOGRAM.value:
            self.logger.debug("Processing: DOWNSTREAM_HISTOGRAM")
            model = self.basic_analysis_ds_histogram(measurement)
            self.__update_result_model(model)
            self.__update_result_dict(model.model_dump())
            self.__add_pnmType(PnmFileType.DOWNSTREAM_HISTOGRAM)

        elif pnm_file_type == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS.value:
            self.logger.debug("Processing: UPSTREAM_PRE_EQUALIZER_COEFFICIENTS")
            model = self.basic_analysis_us_ofdma_pre_equalization(measurement)
            self.__update_result_model(model)
            self.__update_result_dict(model.model_dump())
            self.__add_pnmType(PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS)

        elif (
            pnm_file_type
            == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE.value
        ):
            self.logger.debug(
                "Processing: UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE"
            )
            model = self.basic_analysis_us_ofdma_pre_equalization(measurement)
            self.__update_result_model(model)
            self.__update_result_dict(model.model_dump())
            self.__add_pnmType(
                PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE
            )

        elif pnm_file_type == PnmFileType.OFDM_FEC_SUMMARY.value:
            self.logger.debug("Processing: OFDM_FEC_SUMMARY")
            model = self.basic_analysis_ds_ofdm_fec_summary(measurement)
            self.__update_result_model(model)
            self.__update_result_dict(model.model_dump())
            self.__add_pnmType(PnmFileType.OFDM_FEC_SUMMARY)

        elif pnm_file_type == PnmFileType.SPECTRUM_ANALYSIS.value:
            self.logger.debug("Processing: SPECTRUM_ANALYSIS")
            model = self.basic_analysis_spectrum_analyzer(measurement, analysis_para)
            self.__update_result_model(model)
            self.__update_result_dict(model.model_dump())
            self.__add_pnmType(PnmFileType.SPECTRUM_ANALYSIS)

        elif pnm_file_type == PnmFileType.OFDM_MODULATION_PROFILE.value:
            self.logger.debug("Processing: OFDM_MODULATION_PROFILE")
            model = self.basic_analysis_ds_modulation_profile(measurement)
            self.__update_result_model(model)
            self.__update_result_dict(model.model_dump())
            self.__add_pnmType(PnmFileType.OFDM_MODULATION_PROFILE)

        elif pnm_file_type == PnmFileType.LATENCY_REPORT.value:
            self.logger.warning("Stub: Processing: LATENCY_REPORT")
            self.__add_pnmType(PnmFileType.LATENCY_REPORT)
            pass

        elif pnm_file_type == PnmFileType.CM_SPECTRUM_ANALYSIS_SNMP_AMP_DATA.value:
            self.logger.debug(
                "Processing: Basic Analysis -> CM_SPECTRUM_ANALYSIS_SNMP_AMP_DATA"
            )
            model = self.basic_analysis_spectrum_analyzer_snmp(
                measurement, analysis_para
            )
            self.__update_result_model(model)
            self.__update_result_dict(model.model_dump())
            self.__add_pnmType(PnmFileType.CM_SPECTRUM_ANALYSIS_SNMP_AMP_DATA)

        else:
            self.logger.error(f"Unknown PNM file type: ({pnm_file_type})")

    def get_pnm_type(self) -> list[PnmFileType]:
        return self._processed_pnm_type

    def get_results(
        self, full_dict: bool = True
    ) -> dict[str, Any] | list[dict[str, Any]]:
        """
        Return accumulated analysis results.

        Behavior
        --------
        - full_dict=True  -> always: {"analysis": [dict, dict, ...]}
        - full_dict=False -> if exactly one result: dict
                            else: {"analysis": [dict, dict, ...]}
        """
        results: list[dict[str, Any]] = self._analysis_dict

        if full_dict:
            return {"analysis": results}

        if len(results) == 1 and isinstance(results[0], dict):
            return results[0]

        return {"analysis": results}

    def get_model(self) -> BaseAnalysisModel | list[BaseAnalysisModel]:
        """Get the accumulated analysis results (typed models).

        Returns
        -------
        BaseAnalysisModel or list of BaseAnalysisModel
            The collected Pydantic models for analyses that produce them.
        """
        return self._result_model

    def get_dicts(self) -> list[dict[str, Any]]:
        return self._analysis_dict

    def save_message_response(self, msg_response: MessageResponse) -> None:
        """Persist the raw message response (debug aid).

        Parameters
        ----------
        msg_response : MessageResponse
            Source container that will be serialized to disk. The filename
            includes the MAC address (if present) and a timestamp.
        """
        msg_rsp_dict: dict[Any, Any] = msg_response.payload_to_dict()
        mac = msg_rsp_dict.get("mac_address")
        fname = f"{SystemConfigSettings().message_response_dir()}/{mac}_{Generate.time_stamp()}.msg"
        self.logger.debug(f"Saving Message Response: {fname}")

        fp = FileProcessor(fname)
        fp.write_file(msg_rsp_dict)
        fp.close()

    def __update_result_model(self, model: BaseAnalysisModel) -> None:
        """Append a typed analysis model to the results cache.

        Parameters
        ----------
        model : BaseAnalysisModel
            The model instance to record.
        """
        self._result_model.append(model)

    def __update_result_dict(self, model_dict: dict[str, Any]) -> None:
        """Append a plain-dict analysis result to the results cache.

        Parameters
        ----------
        model : dict
            The dictionary result to record.
        """
        self._analysis_dict.append(model_dict)

    def __add_pnmType(self, pft: PnmFileType) -> None:
        self._processed_pnm_type.append(pft)

    @classmethod
    def get_analysis_from_model(
        cls,
        model: BaseAnalysisModel,
        analysis_type: AnalysisType = AnalysisType.BASIC,
        cable_type: CableType = CableType.RG6,
    ) -> Analysis:
        """
        Construct an Analysis instance from an existing analysis model.

        The returned Analysis is equivalent to an already-processed BASIC analysis
        for a single measurement. The internal result caches are populated so that
        get_model(), get_results(), and get_dicts() can be used directly.

        Parameters
        ----------
        model : BaseAnalysisModel
            A concrete analysis model instance such as
            DsRxMerAnalysisModel, DsChannelEstAnalysisModel, etc.
        analysis_type : AnalysisType, default AnalysisType.BASIC
            Logical analysis mode to tag on the Analysis instance.
        cable_type : CableType, default CableType.RG6
            Cable type metadata retained on the Analysis instance.

        Returns
        -------
        Analysis
            An Analysis object whose result caches are populated from `model`.
        """
        # Infer the corresponding PNM file type from the model class
        pnm_type: PnmFileType | None
        if isinstance(model, DsChannelEstAnalysisModel):
            pnm_type = PnmFileType.OFDM_CHANNEL_ESTIMATE_COEFFICIENT
        elif isinstance(model, ConstellationDisplayAnalysisModel):
            pnm_type = PnmFileType.DOWNSTREAM_CONSTELLATION_DISPLAY
        elif isinstance(model, DsRxMerAnalysisModel):
            pnm_type = PnmFileType.RECEIVE_MODULATION_ERROR_RATIO
        elif isinstance(model, DsHistogramAnalysisModel):
            pnm_type = PnmFileType.DOWNSTREAM_HISTOGRAM
        elif isinstance(model, UsOfdmaUsPreEqAnalysisModel):
            pnm_type = PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS
        elif isinstance(model, OfdmFecSummaryAnalysisModel):
            pnm_type = PnmFileType.OFDM_FEC_SUMMARY
        elif isinstance(model, DsModulationProfileAnalysisModel):
            pnm_type = PnmFileType.OFDM_MODULATION_PROFILE
        else:
            pnm_type = None

        # Bypass __init__ so we don't need a MessageResponse; populate internals manually.
        analysis = object.__new__(cls)  # type: ignore[call-arg]

        analysis.logger = logging.getLogger(f"{cls.__name__}")
        analysis.analysis_type = analysis_type
        analysis.msg_response = None
        analysis._cable_type = cable_type
        analysis._skip_automatic_process = True
        analysis._analysis_para = AnalysisProcessParameters()

        # No raw measurement data when constructed from a model
        analysis.measurement_data = []

        # Populate result caches from the provided model
        analysis._result_model = [model]
        analysis._analysis_dict = (
            [model.model_dump()] if hasattr(model, "model_dump") else [dict(model)]
        )

        analysis._processed_pnm_type = [pnm_type] if pnm_type is not None else []

        return analysis

    # ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++#

    @classmethod
    def basic_analysis_rxmer(cls, measurement: dict[str, Any]) -> DsRxMerAnalysisModel:
        """
        Perform basic RxMER (Receive Modulation Error Ratio) analysis.

        Computes frequency per subcarrier, propagates magnitudes, and assigns a
        carrier status classification for each element (``EXCLUSION``, ``CLIPPED``,
        or ``NORMAL``). Also provides a simple regression line over the magnitudes
        and Shannon-series metadata.

        Parameters
        ----------
        measurement : dict
            Expected keys (subset):
                - ``channel_id`` : int
                - ``pnm_header`` : dict
                - ``device_details`` : dict
                - ``mac_address`` : str
                - ``subcarrier_spacing`` : int (Hz)
                - ``first_active_subcarrier_index`` : int
                - ``subcarrier_zero_frequency`` : int (Hz)
                - ``values`` : List[float] (RxMER in dB)

        Returns
        -------
        DsRxMerAnalysisModel
            Typed model with ``carrier_values.frequency``, ``carrier_values.magnitude``,
            and ``carrier_values.carrier_status`` aligned by index, plus regression
            and modulation statistics.

        Raises
        ------
        ValueError
            If required parameters are missing/negative, or lengths mismatch.
        """
        out: DsRxMerAnalysisModel

        channel_id: ChannelId = measurement.get("channel_id", INVALID_CHANNEL_ID)
        pnm_header = measurement.get("pnm_header", {})
        device_details = measurement.get("device_details", {})
        mac_address: MacAddressStr = measurement.get("mac_address", MacAddress.null())
        subcarrier_spacing: int = measurement.get("subcarrier_spacing", -1)
        first_active_subcarrier_index: int = measurement.get(
            "first_active_subcarrier_index", -1
        )
        subcarrier_zero_frequency: int = measurement.get(
            "subcarrier_zero_frequency", -1
        )
        values = measurement.get("values", [])

        if (
            first_active_subcarrier_index < 0
            or subcarrier_zero_frequency < 0
            or subcarrier_spacing < 0
        ):
            raise ValueError(
                f"Active index: {first_active_subcarrier_index} or "
                f"zero frequency: {subcarrier_zero_frequency} or "
                f"spacing: {subcarrier_spacing} ALL must be non-negative"
            )

        if not values:
            raise ValueError("No RxMER values provided in measurement.")

        base_freq = (
            subcarrier_spacing * first_active_subcarrier_index
        ) + subcarrier_zero_frequency
        freqs: FloatSeries = [
            base_freq + (i * subcarrier_spacing) for i in range(len(values))
        ]
        magnitudes: FloatSeries = values

        def classify(v: int) -> int:
            if v == RXMER_EXCLUSION:
                return int(RxMerCarrierType.EXCLUSION.value)
            elif v in (RXMER_CLIPPED_LOW, RXMER_CLIPPED_HIGH):
                return int(RxMerCarrierType.CLIPPED.value)
            else:
                return int(RxMerCarrierType.NORMAL.value)

        # carrier_status will be List[int]
        carrier_status: list[int] = [classify(v) for v in values]

        if not (len(freqs) == len(magnitudes) == len(carrier_status)):
            raise ValueError(
                f"Length mismatch detected: frequencies({len(freqs)}), "
                f"magnitudes({len(magnitudes)}), carrier_status({len(carrier_status)})"
            )

        ss = ShannonSeries(magnitudes)

        regession_model = RegressionModel(
            slope=cast(
                FloatSeries,
                LinearRegression1D(
                    cast(ArrayLike, magnitudes), cast(ArrayLike, freqs)
                ).regression_line(),
            )
        )

        csm: dict[str, Any] = {
            RxMerCarrierType.EXCLUSION.name.lower(): RxMerCarrierType.EXCLUSION.value,
            RxMerCarrierType.CLIPPED.name.lower(): RxMerCarrierType.CLIPPED.value,
            RxMerCarrierType.NORMAL.name.lower(): RxMerCarrierType.NORMAL.value,
        }

        cv = RxMerCarrierValuesModel(
            carrier_status_map=csm,
            carrier_count=len(freqs),
            magnitude=magnitudes,
            frequency=freqs,
            carrier_status=carrier_status,
        )

        out = DsRxMerAnalysisModel(
            device_details=device_details,
            pnm_header=pnm_header,
            channel_id=channel_id,
            mac_address=mac_address,
            subcarrier_spacing=subcarrier_spacing,
            first_active_subcarrier_index=first_active_subcarrier_index,
            subcarrier_zero_frequency=subcarrier_zero_frequency,
            carrier_values=cv,
            regression=regession_model,
            modulation_statistics=ss.to_model(),
        )

        return out

    @classmethod
    def basic_analysis_ds_chan_est(
        cls, measurement: dict[str, Any], cable_type: CableType = CableType.RG6
    ) -> DsChannelEstAnalysisModel:
        """
        Perform downstream channel-estimation analysis.

        Computes:
        - Per-subcarrier frequency axis (Hz)
        - Magnitude sequence (dB) from complex coefficients
        - Group delay (µs) from phase slope across subcarriers
        - Echo detection via IFFT of H(f) → h(t) with conservative thresholds

        Expected Keys (subset) in `measurement`
        ---------------------------------------
        channel_id : int
            Downstream channel ID.
        subcarrier_spacing : int
            Δf in Hz between subcarriers.
        first_active_subcarrier_index : int
            Index of the first active subcarrier relative to subcarrier 0.
        subcarrier_zero_frequency : int
            Frequency (Hz) of subcarrier 0.
        occupied_channel_bandwidth : int
            Occupied bandwidth for metadata.
        values : ComplexArray
            List of complex-like samples for H(f). [(re, im), ...] or [complex, ...].

        Returns
        -------
        DsChannelEstAnalysisModel
            Typed model with carrier values, signal statistics, and echo results.
        """
        log = logging.getLogger(f"{cls.__name__}")

        channel_id: ChannelId = measurement.get("channel_id", INVALID_CHANNEL_ID)
        subcarrier_spacing: FrequencyHz = measurement.get(
            "subcarrier_spacing", INVALID_START_VALUE
        )
        first_active_subcarrier_index: int = measurement.get(
            "first_active_subcarrier_index", INVALID_START_VALUE
        )
        subcarrier_zero_frequency: FrequencyHz = measurement.get(
            "subcarrier_zero_frequency", INVALID_START_VALUE
        )
        occupied_channel_bandwidth: FrequencyHz = measurement.get(
            "occupied_channel_bandwidth", INVALID_START_VALUE
        )

        if (
            (first_active_subcarrier_index < 0)
            or (subcarrier_zero_frequency < 0)
            or (subcarrier_spacing <= 0)
        ):
            raise ValueError(
                f"Active index: {first_active_subcarrier_index} or "
                f"zero frequency: {subcarrier_zero_frequency} or "
                f"spacing: {subcarrier_spacing} must be non-negative"
            )

        values: ComplexArray = measurement.get("values", [])
        if not values:
            raise ValueError(
                "No complex channel estimation values provided in measurement."
            )

        start_freq: FrequencyHz = cast(
            FrequencyHz,
            (subcarrier_spacing * first_active_subcarrier_index)
            + subcarrier_zero_frequency,
        )
        freqs: FrequencySeriesHz = cast(
            FrequencySeriesHz,
            [start_freq + (i * subcarrier_spacing) for i in range(len(values))],
        )

        gd = GroupDelay.from_channel_estimate(
            Hhat=values, df_hz=subcarrier_spacing, f0_hz=start_freq
        )
        gd_results = gd.to_result()

        cao = ComplexArrayOps(values)
        magnitudes_db_raw: FloatSeries = cao.to_list(cao.power_db())

        complex_arr = np.asarray(
            [
                complex(v[0], v[1])
                if not isinstance(v, complex)
                and isinstance(v, (list, tuple))
                and len(v) == 2
                else complex(v)
                for v in values
            ],
            dtype=np.complex128,
        )

        try:
            cutoff_hz: FrequencyHz = FrequencyHz(
                int(float(subcarrier_spacing) * CHAN_EST_BW_CUTOFF_FRACTION)
            )

            mag_filter = MagnitudeButterworthFilter.from_subcarrier_spacing(
                subcarrier_spacing_hz=FrequencyHz(subcarrier_spacing),
                cutoff_hz=cutoff_hz,
                order=DEFAULT_BUTTERWORTH_ORDER,
                zero_phase=True,
            )

            mag_result = mag_filter.apply(
                np.asarray(magnitudes_db_raw, dtype=np.float64)
            )
            magnitudes_db: FloatSeries = mag_result.filtered_values.tolist()
        except Exception:
            magnitudes_db = magnitudes_db_raw

        signal_stats_model: SignalStatisticsModel = SignalStatistics(
            magnitudes_db
        ).compute()

        group_delay_stats: GrpDelayStatsModel = GrpDelayStatsModel(
            group_delay_unit="microsecond",
            magnitude=ComplexArrayOps.to_list(gd_results.group_delay_us),
        )

        magn_linear = np.power(10.0, np.asarray(magnitudes_db, dtype=np.float64) / 20.0)
        phases = np.angle(complex_arr)
        H_smooth = magn_linear * np.exp(1j * phases)

        N = len(values)
        n_fft = 1 << (N - 1).bit_length()
        if n_fft < 1024:
            n_fft = 1024

        fs = float(N) * float(subcarrier_spacing)
        max_delay_s = 3.5e-6

        v = SPEED_OF_LIGHT * CABLE_VF.get(cable_type.name, 0.87)
        max_dist_m = 0.5 * v * max_delay_s
        i_stop = int(max_delay_s * fs)
        log.debug(
            "EchoDetector window: fs=%.3f Hz, n_fft=%d, i_stop=%d bins, max_delay=%.2fus, max_dist≈%.1f m",
            fs,
            n_fft,
            i_stop,
            max_delay_s * 1e6,
            max_dist_m,
        )

        det = EchoDetector(
            freq_data=H_smooth.tolist(),
            subcarrier_spacing_hz=float(subcarrier_spacing),
            n_fft=4096,
            cable_type=cable_type.name,
            channel_id=channel_id,
        )

        max_delay_s_used = 3.5e-6
        echo_report: EchoDetectorReport = det.multi_echo(
            threshold_mode="db_down",
            threshold_db_down=60.0,
            normalize_power=True,
            guard_bins=16,
            min_separation_s=8.0 / det.fs,
            max_delay_s=max_delay_s_used,
            max_peaks=3,
            include_time_response=False,
            direct_at_zero=True,
            window="hann",
        )

        i_stop = int(np.ceil(max_delay_s_used * det.fs))
        edge_guard = 8
        if echo_report.echoes:
            echo_report.echoes = [
                e for e in echo_report.echoes if (e.bin_index < (i_stop - edge_guard))
            ]

        echo_rpt = EchoDatasetModel(type=EchoDetectorType.IFFT, report=echo_report)

        carrier_values: ChanEstCarrierModel = ChanEstCarrierModel(
            carrier_count=len(freqs),
            frequency_unit="Hz",
            frequency=freqs,
            complex=values,
            complex_dimension=int(complex_arr.ndim),
            magnitudes=magnitudes_db,
            group_delay=group_delay_stats,
            occupied_channel_bandwidth=occupied_channel_bandwidth,
        )

        result_model: DsChannelEstAnalysisModel = DsChannelEstAnalysisModel(
            device_details=measurement.get("device_details", {}),
            pnm_header=measurement.get("pnm_header", {}),
            mac_address=measurement.get("mac_address", ""),
            channel_id=ChannelId(measurement.get("channel_id", INVALID_START_VALUE)),
            subcarrier_spacing=subcarrier_spacing,
            first_active_subcarrier_index=first_active_subcarrier_index,
            subcarrier_zero_frequency=subcarrier_zero_frequency,
            carrier_values=carrier_values,
            signal_statistics=signal_stats_model,
            echo=echo_rpt,
        )

        return result_model

    @classmethod
    def basic_analysis_ds_modulation_profile(
        cls, measurement: Mapping[str, Any], split_carriers: bool = True
    ) -> DsModulationProfileAnalysisModel:
        """
        Analyze the Downstream OFDM Modulation Profile and return a typed model.

        Parameters
        ----------
        measurement : Mapping[str, Any]
            Expected keys (subset):
            - subcarrier_spacing : int (Hz)
            - first_active_subcarrier_index : int
            - subcarrier_zero_frequency : int (Hz)
            - mac_address : str
            - channel_id : int
            - device_details : Mapping[str, Any] (optional passthrough)
            - pnm_header : Mapping[str, Any] (optional passthrough)
            - profiles : list of dicts:
                    {
                        "profile_id": int,
                        "schemes": list[SchemeModel-like]
                    }

            Each scheme item is one of:
            - schema_type = 0 (range):
                    {
                        "schema_type": 0,
                        "modulation_order": "qam_256" | "plc" | "exclusion" | "continuous_pilot" | ...,
                        "num_subcarriers": int
                    }
            - schema_type = 1 (skip):
                    {
                        "schema_type": 1,
                        "main_modulation_order": "...",
                        "skip_modulation_order": "...",
                        "num_subcarriers": int
                    }

        split_carriers : bool, default True
            Controls how per-carrier results are represented in the output:

            * True  → **split layout** (compact parallel arrays). Best for fast analytics,
                    vectorized ops, plotting, and storage efficiency.
            * False → **list layout** (verbose per-carrier records). Best for inspection/logging.

        Returns
        -------
        DsModulationProfileAnalysisModel

        Raises
        ------
        ValueError
            If spacing/indices/frequencies are invalid.
        """
        spacing: FrequencyHz = FrequencyHz(
            measurement.get("subcarrier_spacing", INVALID_START_VALUE)
        )
        active_index: int = int(
            measurement.get("first_active_subcarrier_index", INVALID_START_VALUE)
        )
        zero_freq: FrequencyHz = FrequencyHz(
            measurement.get("subcarrier_zero_frequency", INVALID_START_VALUE)
        )

        if active_index < 0 or zero_freq < 0 or spacing <= 0:
            raise ValueError(
                f"Invalid parameters: spacing={spacing}, active_index={active_index}, zero_freq={zero_freq}"
            )

        # Calculate Start Frequency
        start_freq = zero_freq + spacing * active_index

        out = DsModulationProfileAnalysisModel(
            device_details=measurement.get("device_details", {}),
            pnm_header=measurement.get("pnm_header", {}),
            mac_address=MacAddressStr(
                measurement.get("mac_address", MacAddress.null())
            ),
            channel_id=ChannelId(measurement.get("channel_id", INVALID_CHANNEL_ID)),
            frequency_unit="Hz",
            shannon_min_unit="dB",
            profiles=[],
        )

        for profile in measurement.get("profiles", []) or []:
            profile_id = ProfileId(profile.get("profile_id", INVALID_PROFILE_ID))
            schemes = profile.get("schemes", []) or []

            carrier_values = cls._build_carrier_values_from_mapping(
                schemes=schemes,
                start_freq=start_freq,
                spacing=spacing,
                split_carriers=split_carriers,
            )

            out.profiles.append(
                ProfileAnalysisEntryModel(
                    profile_id=profile_id,
                    carrier_values=carrier_values,
                )
            )

        return out

    @classmethod
    def _build_carrier_values_from_mapping(
        cls,
        schemes: list[dict[str, Any]],
        start_freq: FrequencyHz,
        spacing: FrequencyHz,
        split_carriers: bool,
    ) -> CarrierValuesModel:
        freq_list: FrequencySeriesHz = []
        mod_list: list[str] = []
        shan_list: list[float] = []
        carrier_items: list[CarrierItemModel] = []

        freq_ptr = start_freq
        for scheme in schemes:
            schema_type = int(scheme.get("schema_type", INVALID_SCHEMA_TYPE))

            if schema_type == CmDsOfdmModulationProfile.RANGE_MODULATION:
                mod_name: str = str(scheme.get("modulation_order"))
                count: int = int(scheme.get("num_subcarriers", 0))
            elif schema_type == CmDsOfdmModulationProfile.SKIP_MODULATION:
                mod_name = str(scheme.get("main_modulation_order"))
                count = int(scheme.get("num_subcarriers", 0))
            else:
                logging.warning(
                    f"basic_analysis_ds_modulation_profile() -> Unknown Schema: {schema_type}"
                )
                continue

            freq_ptr = cls._append_carriers(
                freq_ptr=freq_ptr,
                spacing=spacing,
                mod_name=mod_name,
                count=count,
                split_carriers=split_carriers,
                freq_list=freq_list,
                mod_list=mod_list,
                shan_list=shan_list,
                carrier_items=carrier_items,
            )

        return cls._build_carrier_values(
            split_carriers=split_carriers,
            freq_list=freq_list,
            mod_list=mod_list,
            shan_list=shan_list,
            carrier_items=carrier_items,
        )

    @classmethod
    def basic_analysis_us_ofdma_pre_equalization(
        cls, measurement: dict[str, Any]
    ) -> UsOfdmaUsPreEqAnalysisModel:
        """
        Perform Upstream OFDMA Pre-Equalization Analysis.

        Computes:
        - Per-subcarrier frequency axis (Hz)
        - Magnitude sequence (dB) from complex coefficients
        - Group delay (µs) from phase slope across subcarriers
        - IFFT-based echo detection over a constrained delay window
        - Complex samples passthrough
        - Signal statistics over the magnitude sequence

        Expected Keys (subset) in `measurement`
        ---------------------------------------
        channel_id : int
            Upstream OFDMA channel ID.
        subcarrier_spacing : int
            Δf in Hz between subcarriers.
        first_active_subcarrier_index : int
            Index of the first active subcarrier relative to subcarrier 0.
        subcarrier_zero_frequency : int
            Frequency (Hz) of subcarrier 0.
        occupied_channel_bandwidth : int
            Occupied bandwidth for metadata.
        values : ComplexArray
            List of complex-like samples for H(f). [(re, im), ...] or [complex, ...].

        Returns
        -------
        UsOfdmaUsPreEqAnalysisModel
            Typed model with carrier values, signal statistics, and echo results.
        """
        log = logging.getLogger(f"{cls.__name__}")

        channel_id: ChannelId = measurement.get("channel_id", INVALID_CHANNEL_ID)
        subcarrier_spacing: FrequencyHz = measurement.get(
            "subcarrier_spacing", INVALID_START_VALUE
        )
        first_active_subcarrier_index: int = measurement.get(
            "first_active_subcarrier_index", INVALID_START_VALUE
        )
        subcarrier_zero_frequency: FrequencyHz = measurement.get(
            "subcarrier_zero_frequency", INVALID_START_VALUE
        )
        occupied_channel_bandwidth: FrequencyHz = measurement.get(
            "occupied_channel_bandwidth", INVALID_START_VALUE
        )

        if (
            (first_active_subcarrier_index < 0)
            or (subcarrier_zero_frequency < 0)
            or (subcarrier_spacing <= 0)
        ):
            raise ValueError(
                f"Active index: {first_active_subcarrier_index} or "
                f"zero frequency: {subcarrier_zero_frequency} or "
                f"spacing: {subcarrier_spacing} must be non-negative"
            )

        values: ComplexArray = measurement.get("values", [])
        if not values:
            raise ValueError(
                "No complex pre-equalization values provided in measurement."
            )

        start_freq: FrequencyHz = cast(
            FrequencyHz,
            (subcarrier_spacing * first_active_subcarrier_index)
            + subcarrier_zero_frequency,
        )
        freqs: FrequencySeriesHz = cast(
            FrequencySeriesHz,
            [start_freq + (i * subcarrier_spacing) for i in range(len(values))],
        )

        gd = GroupDelay.from_channel_estimate(
            Hhat=values, df_hz=subcarrier_spacing, f0_hz=start_freq
        )
        gd_results = gd.to_result()

        cao = ComplexArrayOps(values)
        magnitudes_db_raw: FloatSeries = cao.to_list(cao.power_db())

        complex_arr = np.asarray(
            [
                complex(v[0], v[1])
                if (not isinstance(v, complex))
                and isinstance(v, (list, tuple))
                and len(v) == 2
                else complex(v)
                for v in values
            ],
            dtype=np.complex128,
        )

        try:
            cutoff_hz: FrequencyHz = FrequencyHz(
                int(float(subcarrier_spacing) * CHAN_EST_BW_CUTOFF_FRACTION)
            )

            mag_filter = MagnitudeButterworthFilter.from_subcarrier_spacing(
                subcarrier_spacing_hz=FrequencyHz(subcarrier_spacing),
                cutoff_hz=cutoff_hz,
                order=DEFAULT_BUTTERWORTH_ORDER,
                zero_phase=True,
            )

            mag_result = mag_filter.apply(
                np.asarray(magnitudes_db_raw, dtype=np.float64)
            )
            magnitudes_db: FloatSeries = mag_result.filtered_values.tolist()
        except Exception:
            magnitudes_db = magnitudes_db_raw

        signal_stats_model: SignalStatisticsModel = SignalStatistics(
            magnitudes_db
        ).compute()

        group_delay_stats: GrpDelayStatsModel = GrpDelayStatsModel(
            group_delay_unit="microsecond",
            magnitude=ComplexArrayOps.to_list(gd_results.group_delay_us),
        )

        magn_linear = np.power(10.0, np.asarray(magnitudes_db, dtype=np.float64) / 20.0)
        phases = np.angle(complex_arr)
        H_smooth = magn_linear * np.exp(1j * phases)

        N = len(values)
        n_fft = 1 << (N - 1).bit_length()
        if n_fft < 1024:
            n_fft = 1024

        fs = float(N) * float(subcarrier_spacing)
        max_delay_s_used = 3.5e-6

        cable_type_name = "RG6"
        v = SPEED_OF_LIGHT * CABLE_VF.get(cable_type_name, 0.87)
        max_dist_m = 0.5 * v * max_delay_s_used
        i_stop = int(max_delay_s_used * fs)
        log.debug(
            "US OFDMA Pre-Eq EchoDetector window: fs=%.3f Hz, n_fft=%d, i_stop=%d bins, "
            "max_delay=%.2fus, max_dist≈%.1f m",
            fs,
            n_fft,
            i_stop,
            max_delay_s_used * 1e6,
            max_dist_m,
        )

        det = EchoDetector(
            freq_data=H_smooth.tolist(),
            subcarrier_spacing_hz=float(subcarrier_spacing),
            n_fft=4096,
            cable_type=cable_type_name,
            channel_id=channel_id,
        )

        echo_report: EchoDetectorReport = det.multi_echo(
            threshold_mode="db_down",
            threshold_db_down=60.0,
            normalize_power=True,
            guard_bins=16,
            min_separation_s=8.0 / det.fs,
            max_delay_s=max_delay_s_used,
            max_peaks=3,
            include_time_response=False,
            direct_at_zero=True,
            window="hann",
        )

        i_stop = int(np.ceil(max_delay_s_used * det.fs))
        edge_guard = 8
        if echo_report.echoes:
            echo_report.echoes = [
                e for e in echo_report.echoes if (e.bin_index < (i_stop - edge_guard))
            ]

        echo_rpt = EchoDatasetModel(
            type=EchoDetectorType.IFFT,
            report=echo_report,
        )

        carrier_values: OfdmaUsPreEqCarrierModel = OfdmaUsPreEqCarrierModel(
            carrier_count=len(freqs),
            frequency_unit="Hz",
            frequency=freqs,
            complex=values,
            complex_dimension=int(complex_arr.ndim),
            magnitudes=magnitudes_db,
            group_delay=group_delay_stats,
            occupied_channel_bandwidth=occupied_channel_bandwidth,
        )

        result_model: UsOfdmaUsPreEqAnalysisModel = UsOfdmaUsPreEqAnalysisModel(
            device_details=measurement.get("device_details", {}),
            pnm_header=measurement.get("pnm_header", {}),
            mac_address=MacAddressStr(measurement.get("mac_address", "")),
            channel_id=ChannelId(channel_id),
            subcarrier_spacing=subcarrier_spacing,
            first_active_subcarrier_index=first_active_subcarrier_index,
            subcarrier_zero_frequency=subcarrier_zero_frequency,
            carrier_values=carrier_values,
            signal_statistics=signal_stats_model,
            echo=echo_rpt,
        )

        if log.isEnabledFor(logging.DEBUG):
            LogFile.write(
                f"UsOfdmaUsPreEqAnalysisModel_{result_model.mac_address}_{result_model.channel_id}.log",
                result_model,
            )

        return result_model

    @classmethod
    def basic_analysis_ds_constellation_display(
        cls, measurement: dict[str, Any]
    ) -> ConstellationDisplayAnalysisModel:
        """
        Build a minimal constellation analysis payload from a downstream OFDM
        measurement dictionary.

        CM Output Assumption
        --------------------
        The DOCSIS spec states the constellation display samples are provided as
        s2.13 **soft decisions scaled to ~unit average power** at the slicer input.
        Because your LUT hard points are likewise normalized, **do not rescale**
        the CM-provided soft points here.

        Parameters
        ----------
        measurement : dict
            Expected keys (subset):
            - ``samples`` : ComplexArray (list of [real, imag]) — required
            - ``pnm_header`` : dict
            - ``mac_address`` : str
            - ``channel_id`` : int
            - ``num_sample_symbols`` : int (defaults to len(samples))
            - ``actual_modulation_order`` : int | str (e.g., 256 or "QAM-256")

        Returns
        -------
        ConstellationDisplayAnalysisModel
            Typed model carrying device/header info, inferred QAM order,
            **hard** constellation points from the LUT, and the **unscaled soft**
            decision coordinates provided by the CM.

        Raises
        ------
        ValueError
            If ``samples`` is missing or empty.
        """
        samples: ComplexArray = measurement.get("samples") or []
        if not samples:
            raise ValueError(
                "measurement['samples'] is required and must be a non-empty ComplexArray."
            )

        # Map actual modulation order → QamModulation
        amo: int | str = measurement.get(
            "actual_modulation_order", DsOfdmModulationType.UNKNOWN
        )
        qm: QamModulation = QamModulation.from_DsOfdmModulationType(amo)

        # Hard points come from LUT (already normalized)
        hard = QamLutManager().get_hard_decisions(qm)

        # IMPORTANT: Do NOT rescale the CM soft decisions; they are already unit-power normalized (s2.13).
        soft = samples

        return ConstellationDisplayAnalysisModel(
            device_details=measurement.get("device_details", SystemDescriptor.empty()),
            pnm_header=measurement.get("pnm_header", {}),
            mac_address=measurement.get("mac_address", MacAddress.null()),
            channel_id=measurement.get("channel_id", INVALID_CHANNEL_ID),
            num_sample_symbols=measurement.get("num_sample_symbols", len(samples)),
            modulation_order=qm,  # QamModulation
            hard=hard,  # LUT hard points (normalized)
            soft=soft,  # CM soft decisions (already normalized) ← changed
        )

    @classmethod
    def basic_analysis_ds_histogram(
        cls, measurement: dict[str, Any]
    ) -> DsHistogramAnalysisModel:
        """
        Build a :class:`DsHistogramAnalysisModel` from a downstream histogram payload.

        Parameters
        ----------
        measurement : dict
            Expected keys (subset):
                - ``device_details`` : dict
                - ``pnm_header`` : dict
                - ``mac_address`` : str
                - ``channel_id`` : int
                - ``symmetry`` : int
                - ``dwell_count`` : int
                - ``hit_counts`` : List[int]

        Returns
        -------
        DsHistogramAnalysisModel
            Typed model with histogram metrics and metadata.
        """
        return DsHistogramAnalysisModel(
            device_details=measurement.get("device_details", SystemDescriptor.empty()),
            pnm_header=measurement.get("pnm_header", {}),
            mac_address=measurement.get("mac_address", MacAddress.null()),
            channel_id=measurement.get("channel_id", INVALID_CHANNEL_ID),
            symmetry=measurement.get("symmetry", -1),
            dwell_counts=measurement.get("dwell_count_values", []),
            hit_counts=measurement.get("hit_count_values", []),
        )

    @classmethod
    def basic_analysis_ds_ofdm_fec_summary(
        cls, measurement: dict[str, Any]
    ) -> OfdmFecSummaryAnalysisModel:
        """
        Build an OfdmFecSummaryAnalysisModel from a DS OFDM FEC summary payload.

        Accepts EITHER:
        - parser shape:   fec_summary_data[*].codeword_entries.{timestamp,total_codewords,corrected,uncorrectable}
        - analysis shape: profiles[*].codewords.{timestamps,total_codewords,corrected,uncorrected}

        Truncates to the shortest parallel length per profile and logs length issues.
        """
        log = logging.getLogger(getattr(cls, "__name__", "OfdmFecSummaryAnalysis"))

        # Prefer parser shape; fall back to analysis shape.
        raw_profiles = measurement.get("fec_summary_data")
        alt_profiles = measurement.get("profiles")

        profiles_src = (
            "fec_summary_data"
            if raw_profiles
            else ("profiles" if alt_profiles else None)
        )
        prof_iter = raw_profiles if raw_profiles is not None else (alt_profiles or [])

        if profiles_src is None:
            log.warning(
                "FEC Summary: no 'fec_summary_data' or 'profiles' in measurement; returning empty model."
            )
            return OfdmFecSummaryAnalysisModel(
                device_details=measurement.get("device_details", {}),
                pnm_header=measurement.get("pnm_header", {}),
                mac_address=measurement.get("mac_address", MacAddress.null()),
                channel_id=ChannelId(measurement.get("channel_id", INVALID_CHANNEL_ID)),
                profiles=[],
            )

        out_profiles: list[OfdmFecSummaryProfileModel] = []

        for idx, prof in enumerate(prof_iter):
            # Profile id + declared sets field name differs per shape.
            profile_id = ProfileId(
                prof.get("profile_id", prof.get("profile", INVALID_CHANNEL_ID))
            )
            declared_sets = int(prof.get("number_of_sets", 0))

            # Choose inner block by shape:
            # - parser shape:   codeword_entries.{timestamp, total_codewords, corrected, uncorrectable}
            # - analysis shape: codewords.{timestamps, total_codewords, corrected, uncorrected}
            cwe = prof.get("codeword_entries")
            if cwe is None:
                cwe = prof.get("codewords") or {}

            # Try both key spellings for timestamps
            ts_raw = cwe.get("timestamp")
            if ts_raw is None:
                ts_raw = cwe.get("timestamps")

            # Coerce to ints; be tolerant of None/empty lists
            ts_list = [int(x) for x in (ts_raw or [])]
            tot_list = [int(x) for x in (cwe.get("total_codewords") or [])]
            cor_list = [int(x) for x in (cwe.get("corrected") or [])]
            unc_list = [int(x) for x in (cwe.get("uncorrectable") or [])]

            n = (
                min(len(ts_list), len(tot_list), len(cor_list), len(unc_list))
                if any((ts_list, tot_list, cor_list, unc_list))
                else 0
            )

            if n and any(
                len(lst) != n for lst in (ts_list, tot_list, cor_list, unc_list)
            ):
                log.warning(
                    "FEC Summary: profile=%s (%s[%d]) series mismatch; truncating to %d "
                    "(ts=%d, total=%d, corrected=%d, uncorrectable=%d)",
                    profile_id,
                    profiles_src,
                    idx,
                    n,
                    len(ts_list),
                    len(tot_list),
                    len(cor_list),
                    len(unc_list),
                )
                ts_list, tot_list, cor_list, unc_list = (
                    ts_list[:n],
                    tot_list[:n],
                    cor_list[:n],
                    unc_list[:n],
                )

            if declared_sets and declared_sets != n:
                log.debug(
                    "FEC Summary: profile=%s declared number_of_sets=%d, computed=%d; using computed.",
                    profile_id,
                    declared_sets,
                    n,
                )

            # Helpful debug when n == 0 so you can see the shape that arrived
            if n == 0:
                log.debug(
                    "FEC Summary: profile=%s has no aligned data (src=%s[%d]); "
                    "lens ts/total/corr/unc = %d/%d/%d/%d; keys=%s",
                    profile_id,
                    profiles_src,
                    idx,
                    len(ts_list),
                    len(tot_list),
                    len(cor_list),
                    len(unc_list),
                    list(cwe.keys()),
                )

            cw = FecSummaryCodeWordModel(
                timestamps=ts_list,
                total_codewords=tot_list,
                corrected=cor_list,
                uncorrected=unc_list,
            )

            out_profiles.append(
                OfdmFecSummaryProfileModel(
                    profile=profile_id,
                    number_of_sets=n,
                    codewords=cw,
                )
            )

        # Optional top-level sanity
        declared_num_profiles = int(measurement.get("num_profiles", len(out_profiles)))
        if declared_num_profiles != len(out_profiles):
            log.debug(
                "FEC Summary: num_profiles declared=%d, parsed=%d",
                declared_num_profiles,
                len(out_profiles),
            )

        return OfdmFecSummaryAnalysisModel(
            device_details=measurement.get("device_details", {}),
            pnm_header=measurement.get("pnm_header", {}),
            mac_address=measurement.get("mac_address", MacAddress.null()),
            channel_id=ChannelId(measurement.get("channel_id", INVALID_CHANNEL_ID)),
            profiles=out_profiles,
        )

    @classmethod
    def basic_analysis_spectrum_analyzer(
        cls,
        measurement: dict[str, Any],
        analysis_parameters: AnalysisProcessParameters | None,
    ) -> SpectrumAnalyzerAnalysisModel:
        """
        Build SpectrumAnalyzerAnalysisModel from converted PNM measurement:
        """
        log = logging.getLogger(f"{cls.__name__}")
        # --- core params ---
        first_seg_cf = int(measurement.get("first_segment_center_frequency", 0))
        last_seg_cf = int(measurement.get("last_segment_center_frequency", 0))
        seg_span_hz = int(measurement.get("segment_frequency_span", 0))
        bins_per_seg = int(measurement.get("num_bins_per_segment", 0))
        enbw_hz = float(measurement.get("equivalent_noise_bandwidth", 0.0))
        noise_bw_khz = int(round(enbw_hz / 1_000.0)) if enbw_hz > 0.0 else 0

        wf_raw = int(measurement.get("window_function", WindowFunction.HANN.value))
        try:
            wf_enum: WindowFunction = WindowFunction(wf_raw)
        except Exception:
            wf_enum = WindowFunction.HANN

        bin_bw = int(measurement.get("bin_frequency_spacing", 0))
        if bin_bw <= 0 and seg_span_hz > 0 and bins_per_seg > 0:
            bin_bw = max(1, seg_span_hz // bins_per_seg)

        # --- segments & magnitudes ---
        segments = measurement.get("amplitude_bin_segments_float", [])
        num_segments = len(segments)
        if bins_per_seg <= 0 and num_segments:
            bins_per_seg = len(segments[0])

        # Normalize each segment length to bins_per_seg (clip/pad NaN)
        norm_segments: list[list[float]] = []
        for s in segments:
            if len(s) >= bins_per_seg:
                norm_segments.append([float(x) for x in s[:bins_per_seg]])
            else:
                pad = [float("nan")] * (bins_per_seg - len(s))
                norm_segments.append([float(x) for x in s] + pad)

        magnitudes: MagnitudeSeries = [x for seg in norm_segments for x in seg]

        # --- compute frequency axis across segments ---
        frequencies: FrequencySeriesHz = []
        if (
            num_segments > 0
            and bins_per_seg > 0
            and seg_span_hz > 0
            and bin_bw > 0
            and first_seg_cf > 0
        ):
            seg_step_hz = (
                (last_seg_cf - first_seg_cf) // (num_segments - 1)
                if num_segments > 1
                else 0
            )
            # start at center - span/2, align to bin center with +bin_bw/2
            seg0_start = first_seg_cf - (seg_span_hz // 2) + (bin_bw // 2)

            freqs: FrequencySeriesHz = []
            for s_idx in range(num_segments):
                start_hz = seg0_start + s_idx * seg_step_hz
                freqs.extend(int(start_hz + i * bin_bw) for i in range(bins_per_seg))
            frequencies = freqs

        # --- align lengths (trim to shortest) ---
        if frequencies and magnitudes and len(frequencies) != len(magnitudes):
            n = min(len(frequencies), len(magnitudes))
            frequencies = frequencies[:n]
            magnitudes = magnitudes[:n]
        if not frequencies or not magnitudes:
            frequencies, magnitudes = [], []

        # --- windowed average (same length) ---
        # TODO: Need to clean this up, need to move the DEFAULT to the Model in a better way
        if analysis_parameters:
            log.debug(
                "Spectrum Analyzer: applying moving average with parameters: %s",
                analysis_parameters,
            )
            window_points = analysis_parameters.moving_average.points
        else:
            log.warning(
                "Spectrum Analyzer: applying DEFAULT moving average: %s",
                DEFAULT_POINT_AVG,
            )
            window_points = DEFAULT_POINT_AVG

        try:
            ma = MovingAverage(max(1, window_points), mode="reflect")
            smoothed = ma.apply(magnitudes) if magnitudes else []
        except Exception:
            smoothed = list(magnitudes)

        if len(smoothed) != len(frequencies):
            smoothed = smoothed[: len(frequencies)]

        window_avg = WindowAverage(points=max(1, window_points), magnitudes=smoothed)

        results = SpecAnaAnalysisResults(
            bin_bandwidth=bin_bw,
            segment_length=bins_per_seg,
            frequencies=frequencies,
            magnitudes=magnitudes,
            window_average=window_avg,
        )

        capture_parameters: SpecAnCapturePara = SpecAnCapturePara(
            first_segment_center_freq=FrequencyHz(first_seg_cf),
            last_segment_center_freq=FrequencyHz(last_seg_cf),
            segment_freq_span=FrequencyHz(seg_span_hz),
            num_bins_per_segment=bins_per_seg,
            noise_bw=noise_bw_khz,
            window_function=wf_enum,
        )

        return SpectrumAnalyzerAnalysisModel(
            device_details=measurement.get("device_details", SystemDescriptor.empty()),
            pnm_header=measurement.get("pnm_header", {}),
            mac_address=measurement.get("mac_address", MacAddress.null()),
            channel_id=ChannelId(measurement.get("channel_id", 0)),
            capture_parameters=capture_parameters,
            signal_analysis=results,
        )

    @classmethod
    def basic_analysis_spectrum_analyzer_snmp(
        cls,
        measurement: dict[str, Any],
        analysis_parameters: AnalysisProcessParameters | None = None,
    ) -> SpectrumAnalyzerAnalysisModel:
        log = logging.getLogger(f"{cls.__name__}")

        freqs: FrequencySeriesHz = list(measurement.get("frequency", []) or [])
        mags: MagnitudeSeries = [
            float(x) for x in (measurement.get("amplitude", []) or [])
        ]

        if not freqs or not mags:
            raise ValueError(
                "Spectrum Analyzer (SNMP): 'frequency' and 'amplitude' must be non-empty."
            )
        if len(freqs) != len(mags):
            n = min(len(freqs), len(mags))
            log.warning(
                "Spectrum Analyzer (SNMP): len mismatch freq=%d amp=%d; truncating to %d",
                len(freqs),
                len(mags),
                n,
            )
            freqs, mags = freqs[:n], mags[:n]

        # Infer bin bandwidth from median positive Δf (robust to occasional glitches)
        try:
            if len(freqs) >= 2:
                diffs = np.diff(np.asarray(freqs, dtype=np.int64))
                pos_diffs = diffs[diffs > 0]
                bin_bw = int(np.median(pos_diffs)) if pos_diffs.size else int(diffs[0])
            else:
                bin_bw = 0
        except Exception:
            bin_bw = 0

        first_hz: int = int(freqs[0])
        last_hz: int = int(freqs[-1])
        span_hz: int = abs(last_hz - first_hz)
        bins: int = len(freqs)

        # Moving-average (windowed) smoothing
        if analysis_parameters:
            window_points = int(max(1, analysis_parameters.moving_average.points))
        else:
            window_points = int(max(1, DEFAULT_POINT_AVG))

        try:
            ma = MovingAverage(window_points, mode="reflect")
            smoothed = ma.apply(mags) if mags else []
        except Exception:
            smoothed = list(mags)

        if len(smoothed) != len(freqs):
            smoothed = smoothed[: len(freqs)]

        window_avg = WindowAverage(points=window_points, magnitudes=smoothed)

        # Build results (single-sweep flattened to one "segment")
        results = SpecAnaAnalysisResults(
            bin_bandwidth=bin_bw,
            segment_length=bins,
            frequencies=freqs,
            magnitudes=mags,
            window_average=window_avg,
        )

        # Endpoints only; no center calculation
        enbw_hz = float(measurement.get("equivalent_noise_bandwidth", 0.0))
        noise_bw_khz = int(round(enbw_hz / 1_000.0)) if enbw_hz > 0.0 else 0

        capture_parameters: SpecAnCapturePara = SpecAnCapturePara(
            first_segment_center_freq=FrequencyHz(first_hz),
            last_segment_center_freq=FrequencyHz(last_hz),
            segment_freq_span=FrequencyHz(span_hz),
            num_bins_per_segment=bins,
            noise_bw=noise_bw_khz,
            window_function=WindowFunction.HANN,
        )

        return SpectrumAnalyzerAnalysisModel(
            device_details=measurement.get("device_details", SystemDescriptor.empty()),
            pnm_header=measurement.get("pnm_header", {}),
            mac_address=measurement.get("mac_address", MacAddress.null()),
            channel_id=ChannelId(measurement.get("channel_id", 0)),
            capture_parameters=capture_parameters,
            signal_analysis=results,
        )

    # ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++#

    @classmethod
    def basic_analysis_rxmer_from_model(
        cls, model: CmDsOfdmRxMerModel
    ) -> DsRxMerAnalysisModel:
        """
        Perform basic RxMER analysis from a parsed :class:`CmDsOfdmRxMerModel`.

        This is the model-based counterpart to ``basic_analysis_rxmer(...)`` and builds
        a :class:`DsRxMerAnalysisModel` using typed fields instead of a raw measurement
        dictionary. It re-derives the frequency axis, carrier status classification, and
        regression line, while reusing metadata already normalized into the model.
        """
        channel_id: ChannelId = model.channel_id
        subcarrier_spacing: FrequencyHz = model.subcarrier_spacing
        first_active_subcarrier_index: int = model.first_active_subcarrier_index
        subcarrier_zero_frequency: FrequencyHz = model.subcarrier_zero_frequency

        if (
            (first_active_subcarrier_index < 0)
            or (subcarrier_zero_frequency < 0)
            or (subcarrier_spacing <= 0)
        ):
            raise ValueError(
                f"Active index: {first_active_subcarrier_index} or "
                f"zero frequency: {subcarrier_zero_frequency} or "
                f"spacing: {subcarrier_spacing} must be non-negative"
            )

        magnitudes: FloatSeries = model.values
        if not magnitudes:
            raise ValueError("No RxMER values provided in model.")

        base_freq: FrequencyHz = FrequencyHz(
            (subcarrier_spacing * first_active_subcarrier_index)
            + subcarrier_zero_frequency
        )
        freqs: FrequencySeriesHz = [
            FrequencyHz(base_freq + (i * subcarrier_spacing))
            for i in range(len(magnitudes))
        ]

        def classify(v: float) -> int:
            if v == RXMER_EXCLUSION:
                return int(RxMerCarrierType.EXCLUSION.value)
            if v in (RXMER_CLIPPED_LOW, RXMER_CLIPPED_HIGH):
                return int(RxMerCarrierType.CLIPPED.value)
            return int(RxMerCarrierType.NORMAL.value)

        carrier_status: IntSeries = [classify(v) for v in magnitudes]

        if not (len(freqs) == len(magnitudes) == len(carrier_status)):
            raise ValueError(
                f"Length mismatch detected: frequencies({len(freqs)}), "
                f"magnitudes({len(magnitudes)}), carrier_status({len(carrier_status)})"
            )

        regession_model = RegressionModel(
            slope=cast(
                FloatSeries,
                LinearRegression1D(
                    cast(ArrayLike, magnitudes), cast(ArrayLike, freqs)
                ).regression_line(),
            )
        )

        csm: dict[str, Any] = {
            RxMerCarrierType.EXCLUSION.name.lower(): RxMerCarrierType.EXCLUSION.value,
            RxMerCarrierType.CLIPPED.name.lower(): RxMerCarrierType.CLIPPED.value,
            RxMerCarrierType.NORMAL.name.lower(): RxMerCarrierType.NORMAL.value,
        }

        carrier_values = RxMerCarrierValuesModel(
            carrier_status_map=csm,
            carrier_count=len(freqs),
            magnitude=magnitudes,
            frequency=freqs,
            carrier_status=carrier_status,
        )

        return DsRxMerAnalysisModel(
            device_details=getattr(model, "device_details", {}),
            pnm_header=model.pnm_header.model_dump()
            if hasattr(model.pnm_header, "model_dump")
            else getattr(model, "pnm_header", {}),
            mac_address=MacAddressStr(getattr(model, "mac_address", MacAddress.null())),
            channel_id=channel_id,
            subcarrier_spacing=subcarrier_spacing,
            first_active_subcarrier_index=first_active_subcarrier_index,
            subcarrier_zero_frequency=subcarrier_zero_frequency,
            carrier_values=carrier_values,
            regression=regession_model,
            modulation_statistics=model.modulation_statistics,
        )

    @classmethod
    def basic_analysis_ds_chan_est_from_model(
        cls,
        model: CmDsOfdmChanEstimateCoefModel,
        cable_type: CableType = CableType.RG6,
    ) -> DsChannelEstAnalysisModel:
        """
        Model-based variant of downstream channel-estimation analysis.

        Mirrors `basic_analysis_ds_chan_est()` but accepts a parsed
        `CmDsOfdmChanEstimateCoefModel` instead of a raw measurement dict.

        Computes:
        - Per-subcarrier frequency axis (Hz)
        - Magnitude sequence (dB) from complex coefficients, with optional
          Butterworth low-pass smoothing across subcarriers
        - Group delay (µs) from phase slope across subcarriers
        - IFFT-based echo detection over a constrained delay window
        - Complex samples passthrough
        - Signal statistics over the (smoothed) magnitude sequence
        """
        log = logging.getLogger(f"{cls.__name__}")

        subcarrier_spacing: FrequencyHz = FrequencyHz(
            int(getattr(model, "subcarrier_spacing", INVALID_START_VALUE))
        )
        first_active_subcarrier_index: int = int(
            getattr(model, "first_active_subcarrier_index", INVALID_START_VALUE)
        )
        subcarrier_zero_frequency: FrequencyHz = cast(
            FrequencyHz,
            int(getattr(model, "subcarrier_zero_frequency", INVALID_START_VALUE)),
        )
        occupied_channel_bandwidth: FrequencyHz = cast(
            FrequencyHz, int(getattr(model, "occupied_channel_bandwidth", 0))
        )

        if (
            (first_active_subcarrier_index < 0)
            or (subcarrier_zero_frequency < 0)
            or (subcarrier_spacing <= 0)
        ):
            raise ValueError(
                f"Active index: {first_active_subcarrier_index} or "
                f"zero frequency: {subcarrier_zero_frequency} or "
                f"spacing: {subcarrier_spacing} must be non-negative"
            )

        values: ComplexArray = cast(ComplexArray, getattr(model, "values", []))
        if not values:
            raise ValueError("No complex channel estimation values provided in model.")

        start_freq: FrequencyHz = cast(
            FrequencyHz,
            (subcarrier_spacing * first_active_subcarrier_index)
            + subcarrier_zero_frequency,
        )
        freqs: FrequencySeriesHz = cast(
            FrequencySeriesHz,
            [start_freq + (i * subcarrier_spacing) for i in range(len(values))],
        )

        gd = GroupDelay.from_channel_estimate(
            Hhat=values, df_hz=subcarrier_spacing, f0_hz=start_freq
        )
        gd_results = gd.to_result()

        cao = ComplexArrayOps(values)
        magnitudes_db_raw: FloatSeries = cao.to_list(cao.power_db())

        complex_arr = np.asarray(
            [
                complex(v[0], v[1])
                if not isinstance(v, complex)
                and isinstance(v, (list, tuple))
                and len(v) == 2
                else complex(v)
                for v in values
            ],
            dtype=np.complex128,
        )

        try:
            cutoff_hz: FrequencyHz = FrequencyHz(
                int(float(subcarrier_spacing) * CHAN_EST_BW_CUTOFF_FRACTION)
            )

            mag_filter = MagnitudeButterworthFilter.from_subcarrier_spacing(
                subcarrier_spacing_hz=FrequencyHz(int(subcarrier_spacing)),
                cutoff_hz=cutoff_hz,
                order=DEFAULT_BUTTERWORTH_ORDER,
                zero_phase=True,
            )

            mag_result = mag_filter.apply(
                np.asarray(magnitudes_db_raw, dtype=np.float64)
            )
            magnitudes_db: FloatSeries = mag_result.filtered_values.tolist()
        except Exception:
            magnitudes_db = magnitudes_db_raw

        signal_stats_model: SignalStatisticsModel = SignalStatistics(
            magnitudes_db
        ).compute()

        group_delay_stats: GrpDelayStatsModel = GrpDelayStatsModel(
            group_delay_unit="microsecond",
            magnitude=ComplexArrayOps.to_list(gd_results.group_delay_us),
        )

        magn_linear = np.power(10.0, np.asarray(magnitudes_db, dtype=np.float64) / 20.0)
        phases = np.angle(complex_arr)
        H_smooth = magn_linear * np.exp(1j * phases)

        N = len(values)
        n_fft = 1 << (N - 1).bit_length()
        if n_fft < 1024:
            n_fft = 1024

        fs = float(N) * float(subcarrier_spacing)
        max_delay_s_used = 3.5e-6

        v = SPEED_OF_LIGHT * CABLE_VF.get(cable_type.name, 0.87)
        max_dist_m = 0.5 * v * max_delay_s_used
        i_stop = int(max_delay_s_used * fs)
        log.debug(
            "DS ChanEst (model) EchoDetector window: fs=%.3f Hz, n_fft=%d, i_stop=%d bins, "
            "max_delay=%.2fus, max_dist≈%.1f m, cable_type=%s",
            fs,
            n_fft,
            i_stop,
            max_delay_s_used * 1e6,
            max_dist_m,
            cable_type.name,
        )

        det = EchoDetector(
            freq_data=H_smooth.tolist(),
            subcarrier_spacing_hz=float(subcarrier_spacing),
            n_fft=4096,
            cable_type=cable_type.name,
            channel_id=cast(
                ChannelId, int(getattr(model, "channel_id", INVALID_CHANNEL_ID))
            ),
        )

        echo_report: EchoDetectorReport = det.multi_echo(
            threshold_mode="db_down",
            threshold_db_down=60.0,
            normalize_power=True,
            guard_bins=16,
            min_separation_s=8.0 / det.fs,
            max_delay_s=max_delay_s_used,
            max_peaks=3,
            include_time_response=False,
            direct_at_zero=True,
            window="hann",
        )

        i_stop = int(np.ceil(max_delay_s_used * det.fs))
        edge_guard = 8
        if echo_report.echoes:
            echo_report.echoes = [
                e for e in echo_report.echoes if (e.bin_index < (i_stop - edge_guard))
            ]

        echo_rpt = EchoDatasetModel(type=EchoDetectorType.IFFT, report=echo_report)

        carrier_values: ChanEstCarrierModel = ChanEstCarrierModel(
            carrier_count=len(freqs),
            frequency_unit="Hz",
            frequency=freqs,
            complex=values,
            complex_dimension=int(complex_arr.ndim),
            magnitudes=magnitudes_db,
            group_delay=group_delay_stats,
            occupied_channel_bandwidth=occupied_channel_bandwidth,
        )

        result_model: DsChannelEstAnalysisModel = DsChannelEstAnalysisModel(
            device_details=getattr(model, "device_details", {}),
            pnm_header=model.pnm_header.model_dump()
            if hasattr(model.pnm_header, "model_dump")
            else {},
            mac_address=cast(MacAddressStr, getattr(model, "mac_address", "")),
            channel_id=cast(
                ChannelId, int(getattr(model, "channel_id", INVALID_START_VALUE))
            ),
            subcarrier_spacing=subcarrier_spacing,
            first_active_subcarrier_index=first_active_subcarrier_index,
            subcarrier_zero_frequency=subcarrier_zero_frequency,
            carrier_values=carrier_values,
            signal_statistics=signal_stats_model,
            echo=echo_rpt,
        )

        return result_model

    @classmethod
    def basic_analysis_ds_modulation_profile_from_model(
        cls, model: CmDsOfdmModulationProfileModel, split_carriers: bool = True
    ) -> DsModulationProfileAnalysisModel:
        """
        Analyze a Downstream OFDM Modulation Profile using a parsed model
        from :class:`CmDsOfdmModulationProfile`.
        """
        spacing: int = int(model.subcarrier_spacing)
        active_index: int = int(model.first_active_subcarrier_index)
        zero_freq: int = int(model.subcarrier_zero_frequency)

        if active_index < 0 or zero_freq < 0 or spacing <= 0:
            raise ValueError(
                f"Invalid parameters: spacing={spacing}, active_index={active_index}, zero_freq={zero_freq}"
            )

        start_freq = zero_freq + spacing * active_index

        result = DsModulationProfileAnalysisModel(
            device_details={},
            pnm_header=model.pnm_header.model_dump()
            if hasattr(model.pnm_header, "model_dump")
            else {},
            mac_address=model.mac_address,
            channel_id=model.channel_id,
            frequency_unit="Hz",
            shannon_min_unit="dB",
            profiles=[],
        )

        for profile in model.profiles:
            profile_id = int(profile.profile_id)
            carrier_values = cls._build_carrier_values_from_models(
                schemes=profile.schemes,
                start_freq=start_freq,
                spacing=FrequencyHz(spacing),
                split_carriers=split_carriers,
            )

            result.profiles.append(
                ProfileAnalysisEntryModel(
                    profile_id=profile_id,
                    carrier_values=carrier_values,
                )
            )

        return result

    @classmethod
    def _build_carrier_values_from_models(
        cls,
        schemes: list[
            RangeModulationProfileSchemaModel | SkipModulationProfileSchemaModel
        ],
        start_freq: FrequencyHz,
        spacing: FrequencyHz,
        split_carriers: bool,
    ) -> CarrierValuesModel:
        freq_list: FrequencySeriesHz = []
        mod_list: list[str] = []
        shan_list: list[float] = []
        carrier_items: list[CarrierItemModel] = []

        freq_ptr = start_freq
        for scheme in schemes:
            if isinstance(scheme, RangeModulationProfileSchemaModel):
                mod_name = str(scheme.modulation_order)
                count = int(scheme.num_subcarriers)
            elif isinstance(scheme, SkipModulationProfileSchemaModel):
                mod_name = str(scheme.main_modulation_order)
                count = int(scheme.num_subcarriers)
            else:
                logging.warning(
                    f"Unknown modulation profile schema type: {getattr(scheme, 'schema_type', '?')}"
                )
                continue

            freq_ptr = cls._append_carriers(
                freq_ptr=freq_ptr,
                spacing=spacing,
                mod_name=mod_name,
                count=count,
                split_carriers=split_carriers,
                freq_list=freq_list,
                mod_list=mod_list,
                shan_list=shan_list,
                carrier_items=carrier_items,
            )

        return cls._build_carrier_values(
            split_carriers=split_carriers,
            freq_list=freq_list,
            mod_list=mod_list,
            shan_list=shan_list,
            carrier_items=carrier_items,
        )

    @classmethod
    def _append_carriers(
        cls,
        freq_ptr: FrequencyHz,
        spacing: FrequencyHz,
        mod_name: str,
        count: int,
        split_carriers: bool,
        freq_list: FrequencySeriesHz,
        mod_list: list[str],
        shan_list: list[float],
        carrier_items: list[CarrierItemModel],
    ) -> FrequencyHz:
        for _ in range(count):
            s_min = cls._resolve_shannon_min(mod_name)
            f_val = int(freq_ptr)

            if split_carriers:
                freq_list.append(f_val)
                mod_list.append(mod_name)
                shan_list.append(s_min)
            else:
                carrier_items.append(
                    CarrierItemModel(
                        frequency=f_val,
                        modulation=mod_name,
                        shannon_min_mer=s_min,
                    )
                )

            freq_ptr += spacing
        return freq_ptr

    @classmethod
    def _resolve_shannon_min(cls, mod_name: str) -> float:
        if mod_name in (
            ModulationOrderType.continuous_pilot.name,
            ModulationOrderType.exclusion.name,
        ):
            return 0.0
        if mod_name == ModulationOrderType.plc.name:
            return round(float(Shannon.bits_to_snr(4)), 2)
        return round(float(Shannon.snr_from_modulation(mod_name)), 2)

    @classmethod
    def _build_carrier_values(
        cls,
        split_carriers: bool,
        freq_list: FrequencySeriesHz,
        mod_list: list[str],
        shan_list: list[float],
        carrier_items: list[CarrierItemModel],
    ) -> CarrierValuesModel:
        if split_carriers:
            return CarrierValuesSplitModel(
                layout="split",
                frequency=freq_list,
                modulation=mod_list,
                shannon_min_mer=shan_list,
            )

        return CarrierValuesListModel(
            layout="list",
            carriers=carrier_items,
        )

    @classmethod
    def basic_analysis_ds_constellation_display_from_model(
        cls, model: CmDsConstDispMeasModel
    ) -> ConstellationDisplayAnalysisModel:
        """
        Build a constellation analysis payload from a parsed :class:`CmDsConstDispMeasModel`.

        This is the model-based counterpart to ``basic_analysis_ds_constellation_display(...)``.
        It interprets the parsed constellation capture (soft decisions, modulation order,
        and metadata) and returns a fully-typed :class:`ConstellationDisplayAnalysisModel`.

        CM Output Assumption
        --------------------
        DOCSIS defines the constellation display samples as s2.13 soft decisions that
        are already scaled to approximately unit average power at the slicer input.
        Because the LUT hard points are normalized in the same way, **no additional
        scaling is applied** to the soft samples here.

        Parameters
        ----------
        model : CmDsConstDispMeasModel
            Parsed constellation display measurement, including:
            - ``samples``                : ComplexArray of soft decisions
            - ``actual_modulation_order``: int modulation order (e.g., 256)
            - ``num_sample_symbols``     : number of captured symbols
            - common PNM header fields   : ``pnm_header``, ``mac_address``, ``channel_id``.

        Returns
        -------
        ConstellationDisplayAnalysisModel
            Typed model carrying device/header info, inferred QAM order, LUT-hard
            constellation points, and CM-provided soft decisions.

        Raises
        ------
        ValueError
            If ``model.samples`` is empty.
        """
        samples: ComplexArray = model.samples or []
        if not samples:
            raise ValueError(
                "CmDsConstDispMeasModel.samples must be a non-empty ComplexArray."
            )

        amo: int = int(getattr(model, "actual_modulation_order", 0))
        qm: QamModulation = QamModulation.from_DsOfdmModulationType(amo)

        hard: ComplexArray = QamLutManager().get_hard_decisions(qm)
        soft: ComplexArray = samples

        return ConstellationDisplayAnalysisModel(
            device_details=getattr(
                model, "device_details", SystemDescriptor.empty().to_dict()
            ),
            pnm_header=model.pnm_header.model_dump()
            if hasattr(model.pnm_header, "model_dump")
            else getattr(model, "pnm_header", {}),
            mac_address=MacAddressStr(getattr(model, "mac_address", MacAddress.null())),
            channel_id=ChannelId(getattr(model, "channel_id", INVALID_CHANNEL_ID)),
            num_sample_symbols=int(getattr(model, "num_sample_symbols", len(samples))),
            modulation_order=qm,
            hard=hard,
            soft=soft,
        )

    @classmethod
    def basic_analysis_ds_histogram_from_model(
        cls, model: CmDsHistModel
    ) -> DsHistogramAnalysisModel:
        """
        Build a :class:`DsHistogramAnalysisModel` from a parsed :class:`CmDsHistModel`.

        This is the model-based counterpart to ``basic_analysis_ds_histogram(...)``.
        It preserves the parsed symmetry flag, dwell counts, and hit counts, while
        normalizing PNM header and MAC/channel metadata into the canonical analysis
        model used by the API layer.

        Parameters
        ----------
        model : CmDsHistModel
            Parsed downstream histogram PNM payload, including:
            - ``pnm_header``               : :class:`PnmHeaderParameters`
            - ``mac_address``              : MAC address string
            - ``symmetry``                 : histogram symmetry indicator
            - ``dwell_count_values_length``: declared dwell-count length
            - ``dwell_count_values``       : dwell-count series
            - ``hit_count_values_length``  : declared hit-count length
            - ``hit_count_values``         : hit-count series

        Returns
        -------
        DsHistogramAnalysisModel
            Typed histogram analysis payload suitable for downstream consumers.
        """
        log = logging.getLogger(f"{cls.__name__}")

        dwell_counts = list(model.dwell_count_values or [])
        hit_counts = list(model.hit_count_values or [])

        if model.dwell_count_values_length and model.dwell_count_values_length != len(
            dwell_counts
        ):
            new_len = min(model.dwell_count_values_length, len(dwell_counts))
            log.warning(
                "DsHistogram: dwell_count length mismatch; declared=%d, actual=%d, truncating to %d",
                model.dwell_count_values_length,
                len(dwell_counts),
                new_len,
            )
            dwell_counts = dwell_counts[:new_len]

        if model.hit_count_values_length and model.hit_count_values_length != len(
            hit_counts
        ):
            new_len = min(model.hit_count_values_length, len(hit_counts))
            log.warning(
                "DsHistogram: hit_count length mismatch; declared=%d, actual=%d, truncating to %d",
                model.hit_count_values_length,
                len(hit_counts),
                new_len,
            )
            hit_counts = hit_counts[:new_len]

        return DsHistogramAnalysisModel(
            device_details=getattr(model, "device_details", {}),
            pnm_header=model.pnm_header.model_dump()
            if hasattr(model.pnm_header, "model_dump")
            else model.pnm_header,
            mac_address=model.mac_address or MacAddress.null(),
            channel_id=ChannelId(getattr(model, "channel_id", INVALID_CHANNEL_ID)),
            symmetry=model.symmetry,
            dwell_counts=dwell_counts,
            hit_counts=hit_counts,
        )

    @classmethod
    def basic_analysis_ds_ofdm_fec_summary_from_model(
        cls, model: CmDsOfdmFecSummaryModel
    ) -> OfdmFecSummaryAnalysisModel:
        """
        Build an :class:`OfdmFecSummaryAnalysisModel` from a parsed
        :class:`CmDsOfdmFecSummaryModel`.

        This is the model-based counterpart to ``basic_analysis_ds_ofdm_fec_summary(...)``.
        It maps the parser-facing structures:

        * :class:`OfdmFecSumDataModel`          → :class:`OfdmFecSummaryProfileModel`
        * :class:`OfdmFecSumCodeWordEntryModel` → :class:`FecSummaryCodeWordModel`

        while carrying forward common analysis metadata from ``CmDsOfdmFecSummaryModel``.

        Parameters
        ----------
        model : CmDsOfdmFecSummaryModel
            Canonical DOCSIS downstream OFDM FEC summary model, including:
            - ``pnm_header``       : :class:`PnmHeaderParameters`
            - ``channel_id``       : ChannelId
            - ``mac_address``      : MAC address string
            - ``summary_type``     : CM-OSSI summary type enum
            - ``num_profiles``     : declared profile count
            - ``fec_summary_data`` : list of :class:`OfdmFecSumDataModel` entries

        Returns
        -------
        OfdmFecSummaryAnalysisModel
            Normalized FEC summary analysis payload used by the API/plotting layers.
        """
        log = logging.getLogger(f"{cls.__name__}")

        profiles: list[OfdmFecSummaryProfileModel] = []

        for _idx, prof in enumerate(model.fec_summary_data or []):
            cwe = prof.codeword_entries

            cw = FecSummaryCodeWordModel(
                timestamps=list(cwe.timestamp),
                total_codewords=list(cwe.total_codewords),
                corrected=list(cwe.corrected),
                uncorrected=list(cwe.uncorrectable),
            )

            profiles.append(
                OfdmFecSummaryProfileModel(
                    profile=ProfileId(prof.profile_id),
                    number_of_sets=int(prof.number_of_sets),
                    codewords=cw,
                )
            )

        declared_num_profiles = int(model.num_profiles)
        if declared_num_profiles != len(profiles):
            log.debug(
                "FEC Summary (model): num_profiles declared=%d, parsed=%d",
                declared_num_profiles,
                len(profiles),
            )

        return OfdmFecSummaryAnalysisModel(
            device_details={},
            pnm_header=model.pnm_header.model_dump()
            if hasattr(model.pnm_header, "model_dump")
            else model.pnm_header,
            mac_address=MacAddressStr(model.mac_address or MacAddress.null()),
            channel_id=ChannelId(
                model.channel_id if model.channel_id is not None else INVALID_CHANNEL_ID
            ),
            profiles=profiles,
        )

    @classmethod
    def basic_analysis_us_ofdma_pre_equalization_from_model(
        cls, model: CmUsOfdmaPreEqModel
    ) -> UsOfdmaUsPreEqAnalysisModel:
        """
        Model-based variant of Upstream OFDMA Pre-Equalization Analysis.

        Mirrors `basic_analysis_us_ofdma_pre_equalization()` but accepts a parsed
        :class:`CmUsOfdmaPreEqModel` instead of a raw measurement dict.

        Computes:
        - Per-subcarrier frequency axis (Hz)
        - Magnitude sequence (dB) from complex coefficients, with optional
          Butterworth low-pass smoothing across subcarriers
        - Group delay (µs) from phase slope across subcarriers
        - IFFT-based echo detection over a constrained delay window
        - Complex samples passthrough
        - Signal statistics over the (smoothed) magnitude sequence
        """
        log = logging.getLogger(f"{cls.__name__}")

        subcarrier_spacing: FrequencyHz = FrequencyHz(
            int(getattr(model, "subcarrier_spacing", INVALID_START_VALUE))
        )
        first_active_subcarrier_index: int = int(
            getattr(model, "first_active_subcarrier_index", INVALID_START_VALUE)
        )
        subcarrier_zero_frequency: FrequencyHz = FrequencyHz(
            int(getattr(model, "subcarrier_zero_frequency", INVALID_START_VALUE))
        )
        occupied_channel_bandwidth: FrequencyHz = FrequencyHz(
            int(getattr(model, "occupied_channel_bandwidth", 0))
        )

        if (
            (first_active_subcarrier_index < 0)
            or (subcarrier_zero_frequency < 0)
            or (subcarrier_spacing <= 0)
        ):
            raise ValueError(
                f"Active index: {first_active_subcarrier_index} or "
                f"zero frequency: {subcarrier_zero_frequency} or "
                f"spacing: {subcarrier_spacing} must be non-negative"
            )

        values: ComplexArray = cast(ComplexArray, getattr(model, "values", []))
        if not values:
            raise ValueError("No complex pre-equalization values provided in model.")

        start_freq: FrequencyHz = FrequencyHz(
            (subcarrier_spacing * first_active_subcarrier_index)
            + subcarrier_zero_frequency
        )
        freqs: FrequencySeriesHz = cast(
            FrequencySeriesHz,
            [start_freq + (i * subcarrier_spacing) for i in range(len(values))],
        )

        gd = GroupDelay.from_channel_estimate(
            Hhat=values, df_hz=subcarrier_spacing, f0_hz=start_freq
        )
        gd_results = gd.to_result()

        cao = ComplexArrayOps(values)
        magnitudes_db_raw: FloatSeries = cao.to_list(cao.power_db())

        complex_arr = np.asarray(
            [
                complex(v[0], v[1])
                if (not isinstance(v, complex))
                and isinstance(v, (list, tuple))
                and len(v) == 2
                else complex(v)
                for v in values
            ],
            dtype=np.complex128,
        )

        try:
            cutoff_hz: FrequencyHz = FrequencyHz(
                int(float(subcarrier_spacing) * CHAN_EST_BW_CUTOFF_FRACTION)
            )

            mag_filter = MagnitudeButterworthFilter.from_subcarrier_spacing(
                subcarrier_spacing_hz=FrequencyHz(int(subcarrier_spacing)),
                cutoff_hz=cutoff_hz,
                order=DEFAULT_BUTTERWORTH_ORDER,
                zero_phase=True,
            )

            mag_result = mag_filter.apply(
                np.asarray(magnitudes_db_raw, dtype=np.float64)
            )
            magnitudes_db: FloatSeries = mag_result.filtered_values.tolist()
        except Exception:
            magnitudes_db = magnitudes_db_raw

        signal_stats_model: SignalStatisticsModel = SignalStatistics(
            magnitudes_db
        ).compute()

        group_delay_stats: GrpDelayStatsModel = GrpDelayStatsModel(
            group_delay_unit="microsecond",
            magnitude=ComplexArrayOps.to_list(gd_results.group_delay_us),
        )

        magn_linear = np.power(10.0, np.asarray(magnitudes_db, dtype=np.float64) / 20.0)
        phases = np.angle(complex_arr)
        H_smooth = magn_linear * np.exp(1j * phases)

        N = len(values)
        n_fft = 1 << (N - 1).bit_length()
        if n_fft < 1024:
            n_fft = 1024

        fs = float(N) * float(subcarrier_spacing)
        max_delay_s_used = 3.5e-6

        cable_type_name = "RG6"
        v = SPEED_OF_LIGHT * CABLE_VF.get(cable_type_name, 0.87)
        max_dist_m = 0.5 * v * max_delay_s_used
        i_stop = int(max_delay_s_used * fs)
        log.debug(
            "US OFDMA Pre-Eq (model) EchoDetector window: fs=%.3f Hz, n_fft=%d, i_stop=%d bins, "
            "max_delay=%.2fus, max_dist≈%.1f m",
            fs,
            n_fft,
            i_stop,
            max_delay_s_used * 1e6,
            max_dist_m,
        )

        det = EchoDetector(
            freq_data=H_smooth.tolist(),
            subcarrier_spacing_hz=float(subcarrier_spacing),
            n_fft=4096,
            cable_type=cable_type_name,
            channel_id=ChannelId(getattr(model, "channel_id", INVALID_CHANNEL_ID)),
        )

        echo_report: EchoDetectorReport = det.multi_echo(
            threshold_mode="db_down",
            threshold_db_down=60.0,
            normalize_power=True,
            guard_bins=16,
            min_separation_s=8.0 / det.fs,
            max_delay_s=max_delay_s_used,
            max_peaks=3,
            include_time_response=False,
            direct_at_zero=True,
            window="hann",
        )

        i_stop = int(np.ceil(max_delay_s_used * det.fs))
        edge_guard = 8
        if echo_report.echoes:
            echo_report.echoes = [
                e for e in echo_report.echoes if (e.bin_index < (i_stop - edge_guard))
            ]

        echo_rpt = EchoDatasetModel(
            type=EchoDetectorType.IFFT,
            report=echo_report,
        )

        carrier_values: OfdmaUsPreEqCarrierModel = OfdmaUsPreEqCarrierModel(
            carrier_count=len(freqs),
            frequency_unit="Hz",
            frequency=freqs,
            complex=values,
            complex_dimension=int(complex_arr.ndim),
            magnitudes=magnitudes_db,
            group_delay=group_delay_stats,
            occupied_channel_bandwidth=occupied_channel_bandwidth,
        )

        result_model: UsOfdmaUsPreEqAnalysisModel = UsOfdmaUsPreEqAnalysisModel(
            device_details=getattr(model, "device_details", {}),
            pnm_header=model.pnm_header.model_dump()
            if hasattr(model.pnm_header, "model_dump")
            else getattr(model, "pnm_header", {}),
            mac_address=MacAddressStr(getattr(model, "mac_address", MacAddress.null())),
            channel_id=ChannelId(getattr(model, "channel_id", INVALID_CHANNEL_ID)),
            subcarrier_spacing=subcarrier_spacing,
            first_active_subcarrier_index=first_active_subcarrier_index,
            subcarrier_zero_frequency=subcarrier_zero_frequency,
            carrier_values=carrier_values,
            signal_statistics=signal_stats_model,
            echo=echo_rpt,
        )

        if log.isEnabledFor(logging.DEBUG):
            LogFile.write(
                f"UsOfdmaUsPreEqAnalysisModel_{result_model.mac_address}_{result_model.channel_id}.log",
                result_model,
            )

        return result_model

    @classmethod
    def basic_analysis_echo_detection_ifft(
        cls,
        model: CmDsOfdmChanEstimateCoefModel,
        cable_type: CableType = CableType.RG6,
    ) -> EchoDetectorReport:
        """
        Run FFT/IFFT-based echo detection from a single Channel-Estimation snapshot.

        Overview
        --------
        Builds a time response h(t) from the complex channel-estimation spectrum H(f),
        identifies the direct path, then scans for echo peaks subject to a conservative
        threshold, guard region, and optional time-response attachment.

        Inputs (from model)
        -------------------
        values : ComplexArray
            List of complex-like samples for H(f). Accepted shapes:
            - [(re, im), ...] pairs or
            - [complex, ...]
        subcarrier_spacing : float
            Δf in Hz between OFDM subcarriers.
        channel_id : int
            Downstream channel ID, used for metadata only.

        Parameters
        ----------
        cable_type : CableType, default CableType.RG6
            Cable type to derive the velocity factor for distance conversion.

        Returns
        -------
        EchoDetectorReport
            Structured result including dataset metadata, direct-path info, an array
            of detected echoes (if any), and optional time-response block.

        Notes
        -----
        - n_fft is chosen as the next power of two ≥ N (min 1024) for finer time sampling.
        - Thresholding defaults to “dB-down” mode (70 dB below direct peak), with an
          automatic fallback to 80 dB if nothing is found.
        - Magnitude smoothing uses the same Butterworth pipeline as
          `basic_analysis_ds_chan_est()`, applied to |H(f)| before echo detection.
        """
        log = logging.getLogger(f"{cls.__name__}")

        values = cast(Sequence[complex | Sequence[float]], getattr(model, "values", []))
        if not values:
            raise ValueError(
                "Echo detection requires non-empty channel-estimation values."
            )

        df_hz = float(getattr(model, "subcarrier_spacing", 0.0))
        if df_hz <= 0.0:
            raise ValueError("Invalid subcarrier spacing for echo detection.")

        channel_id = cast(ChannelId, getattr(model, "channel_id", INVALID_CHANNEL_ID))

        # ── Optional Butterworth smoothing over |H(f)| in dB (same pattern as ds_chan_est) ──
        H = np.asarray(values, dtype=complex)
        freq_data_for_detector: Sequence[complex]

        try:
            cao = ComplexArrayOps(values)
            magnitudes_db_raw: FloatSeries = cao.to_list(cao.power_db())

            cutoff_hz: FrequencyHz = FrequencyHz(
                int(float(df_hz) * CHAN_EST_BW_CUTOFF_FRACTION)
            )

            mag_filter = MagnitudeButterworthFilter.from_subcarrier_spacing(
                subcarrier_spacing_hz=FrequencyHz(int(df_hz)),
                cutoff_hz=cutoff_hz,
            )

            mag_result = mag_filter.apply(
                np.asarray(magnitudes_db_raw, dtype=np.float64)
            )
            magnitudes_db_smooth = mag_result.filtered_values

            mag_lin = np.power(10.0, magnitudes_db_smooth / 20.0)
            H_phase = np.exp(1j * np.angle(H))
            H_filtered = mag_lin * H_phase

            freq_data_for_detector = H_filtered.tolist()

            log.debug(
                "Echo IFFT: applied Butterworth smoothing (df=%.3f Hz, cutoff=%.3f Hz, N=%d)",
                df_hz,
                float(cutoff_hz),
                H.shape[0],
            )
        except Exception as exc:
            log.debug(
                "Echo IFFT: Butterworth smoothing skipped due to error: %s; using raw values.",
                exc,
            )
            freq_data_for_detector = list(map(complex, H))

        # Choose IFFT length for finer time resolution
        N = len(freq_data_for_detector)
        n_fft = 1 << (N - 1).bit_length()
        if n_fft < 1024:
            n_fft = 1024

        # Detector
        det = EchoDetector(
            freq_data=freq_data_for_detector,
            subcarrier_spacing_hz=df_hz,
            n_fft=n_fft,
            cable_type=cable_type.name,
            channel_id=ChannelId(channel_id),
        )

        log.debug(
            "Init EchoDetector: N=%d, Δf=%.3f Hz, fs=%.3f Hz, n_fft=%d, cable=%s, chan=%s",
            N,
            df_hz,
            N * df_hz,
            n_fft,
            cable_type.name,
            str(channel_id),
        )

        # Conservative defaults, with auto-fallback if nothing exceeds threshold
        echo_report: EchoDetectorReport = det.multi_echo(
            threshold_mode="db_down",  # primary threshold strategy
            threshold_db_down=70.0,  # 70 dB below the direct path
            guard_bins=8,  # keep away from main-lobe skirt
            min_separation_s=0.0,  # allow closely spaced echoes if present
            max_delay_s=7.7e-6,  # ~1 km one-way at VF≈0.87
            max_peaks=5,  # cap number of echoes returned
            include_time_response=False,  # keep payload small by default
            direct_at_zero=True,  # recenter direct path to t=0
            window="hann",  # reduce sidelobes before IFFT
        )

        return echo_report
