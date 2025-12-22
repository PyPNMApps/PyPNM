# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import subprocess
import sys
from typing import List, Sequence, Tuple


Command = Tuple[str, Sequence[str]]


def _run_command(label: str, cmd: Sequence[str]) -> int:
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


def _build_commands(include_pyright: bool, pytest_args: Sequence[str]) -> List[Command]:
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
    commands: List[Command] = [
        ("secrets", ["./tools/security/scan-secrets.sh"]),
        ("enc-secrets", ["python", "./tools/security/scan-enc-secrets.py"]),
        ("macs", ["./tools/security/scan-mac-addresses.py", "--fail-on-found"]),
        ("headers", ["./tools/build/add-required-python-headers.py"]),
        ("ruff", ["ruff", "check", "src"]),
        ("pytest", ["pytest", *pytest_args]),
    ]

    if include_pyright:
        # Insert Pyright after Ruff but before pytest for faster feedback.
        commands.insert(3, ("pyright", ["pyright"]))

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
    6) pytest              - unit tests (pytest options from pyproject.toml).

    Optional Pyright
    ----------------
    To enable static type checking with Pyright, pass the flag:

        pypnm-software-qa-checker --with-pyright

    This will run an additional step:

    - pyright              - static type analysis using [tool.pyright] settings,
                             executed after Ruff but before pytest.

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

    pytest_args: List[str] = []
    qa_args: List[str] = raw_args

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
