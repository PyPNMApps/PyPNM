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


def _build_commands(
    include_pyright: bool, include_pylint: bool, pytest_args: list[str]
) -> list[Command]:
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
        ("headers", [python_cmd, "./tools/maintenance/add-required-python-headers.py"]),
        ("ruff", ["ruff", "check", "src"]),
    ]

    if include_pyright:
        # Insert Pyright after Ruff but before loop nesting and pytest for faster feedback.
        commands.append(("pyright", ["pyright"]))

    if include_pylint:
        commands.append(
            (
                "pylint",
                ["pylint", "--rcfile=.pylintrc", "src/pypnm/lib/db/transaction_repository.py"],
            )
        )

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
    4) headers             - ensure SPDX/license headers (./tools/maintenance/add-required-python-headers.py).
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

    Optional Pylint (Magic Values)
    ------------------------------
    To enable magic-value checks with Pylint, pass the flag:

        pypnm-software-qa-checker --with-pylint

    This runs the Pylint magic-value extension (R2004) using the
    .pylintrc configuration, after Ruff but before loop nesting.

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
    include_pylint = "--with-pylint" in qa_args
    filtered_qa_args = [a for a in qa_args if a not in {"--with-pyright", "--with-pylint"}]

    # Preserve a minimal sys.argv for any downstream libraries that inspect it.
    sys.argv = [sys.argv[0], *filtered_qa_args]

    commands = _build_commands(
        include_pyright=include_pyright,
        include_pylint=include_pylint,
        pytest_args=pytest_args,
    )

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
