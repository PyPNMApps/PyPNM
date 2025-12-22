#!/usr/bin/env python3
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

import argparse
import atexit
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Final


VERSION_FILE_PATH: Final[Path]           = Path("src/pypnm/version.py")
BUMP_SCRIPT_PATH: Final[Path]            = Path("tools/support") / "bump_version.py"
PYPROJECT_FILE_PATH: Final[Path]         = Path("pyproject.toml")
README_FILE_PATH: Final[Path]            = Path("README.md")
DOCS_ROOT: Final[Path]                   = Path("docs")
README_TAG_PATTERN: Final[re.Pattern[str]] = re.compile(r'TAG="v\d+\.\d+\.\d+\.\d+"')

VERSION_PART_SEPARATOR: Final[str]       = "."
EXPECTED_VERSION_PARTS: Final[int]       = 4

MAJOR_INDEX: Final[int]                  = 0
MINOR_INDEX: Final[int]                  = 1
MAINTENANCE_INDEX: Final[int]            = 2
BUILD_INDEX: Final[int]                  = 3

REPORT_DIR_NAME: Final[str]              = "release-reports"
REPORT_FILE_PREFIX: Final[str]           = "release-report"
REPORT_SECTIONS: Final[list[str]]        = [
    "Docs",
    "Docker",
    "K8s",
    "FastAPI",
    "REST",
    "PNM-Python",
    "Tools",
    "Install",
]
REPORT_HEADERS: Final[list[str]]         = ["Section", "Files Changed"]
INSTALL_PREFIXES: Final[list[str]]       = ["install.sh", "scripts/install", "deploy/"]
DOCKER_PREFIXES: Final[list[str]]        = ["docker/", "docker-compose", "docs/docker/"]
K8S_PREFIX: Final[str]                   = "docs/kubernetes/"


SUMMARY: dict[str, str] = {}
RELEASE_LOG_DIR: Path | None = None


def _print_banner() -> None:
    banner_path = Path(__file__).resolve().parent.parent / "banner.txt"
    if banner_path.is_file():
        print(banner_path.read_text(encoding="utf-8"))
        print()


def _init_release_logging() -> None:
    """Create a temporary directory for failed-command logs and announce it."""
    global RELEASE_LOG_DIR
    if RELEASE_LOG_DIR is None:
        RELEASE_LOG_DIR = Path(tempfile.mkdtemp(prefix="pypnm-release-logs-"))
        print(f"[release] Command failures will be logged under: {RELEASE_LOG_DIR}")


def _sanitize_label(label: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", label.strip().lower())
    return safe or "cmd"


def _default_label(cmd: list[str]) -> str:
    return Path(cmd[0]).name


def _log_command_failure(label: str, result: subprocess.CompletedProcess[str]) -> None:
    if RELEASE_LOG_DIR is None:
        return
    safe_label = _sanitize_label(label)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = RELEASE_LOG_DIR / f"{safe_label}-{timestamp}.log"
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    log_path.write_text(
        f"$ {' '.join(result.args if isinstance(result.args, (list, tuple)) else [str(result.args)])}\n\n"
        f"STDOUT:\n{stdout}\n\nSTDERR:\n{stderr}\n",
        encoding="utf-8",
    )
    print(f"[release] {label} failed; see {log_path}")


def _run(
    cmd: list[str],
    check: bool = True,
    *,
    label: str | None = None,
    capture_output: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess command, capturing output for logging on failure."""
    if capture_output:
        proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
    else:
        proc = subprocess.run(cmd, text=True, check=False)

    if proc.returncode != 0:
        if capture_output:
            _log_command_failure(label or _default_label(cmd), proc)
        if check:
            raise subprocess.CalledProcessError(
                proc.returncode,
                cmd,
                output=proc.stdout,
                stderr=proc.stderr,
            )
    return proc


# Simple status printer with color for TTY output
def _colorize(text: str, color: str) -> str:
    if not sys.stdout.isatty():
        return text
    codes = {
        "green": "\033[32m",
        "red": "\033[31m",
        "yellow": "\033[33m",
        "reset": "\033[0m",
    }
    return f"{codes.get(color, '')}{text}{codes['reset']}"


def _format_state(state: str) -> str:
    match state.lower():
        case "pass":
            return _colorize("PASS", "green")
        case "fail":
            return _colorize("FAIL", "red")
        case "skip":
            return _colorize("SKIP", "yellow")
        case _:
            return state.upper()


def _print_status(label: str, state: str) -> None:
    SUMMARY[label] = state
    print(f"{_format_state(state)} {label}")


def _print_release_summary() -> None:
    if not SUMMARY:
        return
    print("\nRelease step summary:")
    for label, state in SUMMARY.items():
        print(f" {_format_state(state)} {label}")
    if RELEASE_LOG_DIR:
        print(f"Failure logs (if any) stored in: {RELEASE_LOG_DIR}")


atexit.register(_print_release_summary)


def _ensure_clean_worktree() -> None:
    """Ensure the git working tree has no uncommitted changes."""
    result = _run(["git", "status", "--porcelain"], check=False, label="git-status")
    output = (result.stdout or "").strip()
    if output:
        print("ERROR: Working tree is not clean. Commit or stash changes first.", file=sys.stderr)
        sys.exit(1)


def _get_head_commit() -> str:
    result = _run(["git", "rev-parse", "HEAD"], label="git-rev-parse")
    return result.stdout.strip()


def _collect_commit_files(commit: str) -> list[str]:
    result = _run(["git", "show", "--pretty=format:", "--name-only", commit], label="git-show")
    paths = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
    return paths


def _classify_path(path: str) -> str:
    normalized = path.replace("\\", "/").lower()
    if normalized.startswith(K8S_PREFIX):
        return "K8s"
    if any(normalized.startswith(prefix) for prefix in DOCKER_PREFIXES):
        return "Docker"
    if normalized.startswith("docs/") or normalized == "readme.md":
        return "Docs"
    if "fastapi" in normalized:
        return "FastAPI"
    if "/rest" in normalized or "rest_" in normalized or "rest-" in normalized:
        return "REST"
    if normalized.startswith("src/pypnm/") or normalized == "pyproject.toml":
        return "PNM-Python"
    if normalized.startswith("tools/"):
        return "Tools"
    if any(normalized.startswith(prefix) for prefix in INSTALL_PREFIXES):
        return "Install"
    return "Other"


def _summarize_sections(paths: list[str]) -> dict[str, int]:
    counts = {section: 0 for section in REPORT_SECTIONS}
    counts["Other"] = 0
    for path in paths:
        section = _classify_path(path)
        if section in counts:
            counts[section] += 1
        else:
            counts["Other"] += 1
    return counts


def _render_table(counts: dict[str, int]) -> str:
    rows = [(section, str(counts.get(section, 0))) for section in REPORT_SECTIONS]
    if counts.get("Other", 0) > 0:
        rows.append(("Other", str(counts["Other"])))

    header_section, header_count = REPORT_HEADERS
    section_width = max(len(header_section), max(len(row[0]) for row in rows))
    count_width = max(len(header_count), max(len(row[1]) for row in rows))

    def line() -> str:
        return f"+{'-' * (section_width + 2)}+{'-' * (count_width + 2)}+"

    lines = [
        line(),
        f"| {header_section.ljust(section_width)} | {header_count.ljust(count_width)} |",
        line(),
    ]
    for section, count in rows:
        lines.append(f"| {section.ljust(section_width)} | {count.ljust(count_width)} |")
    lines.append(line())
    return "\n".join(lines)


def _render_markdown_table(counts: dict[str, int]) -> str:
    rows = [(section, str(counts.get(section, 0))) for section in REPORT_SECTIONS]
    if counts.get("Other", 0) > 0:
        rows.append(("Other", str(counts["Other"])))

    lines = [
        f"| {REPORT_HEADERS[0]} | {REPORT_HEADERS[1]} |",
        "| --- | --- |",
    ]
    for section, count in rows:
        lines.append(f"| {section} | {count} |")
    return "\n".join(lines)


def _write_release_report(
    commit: str,
    version: str,
    tag_name: str,
    branch: str,
    test_release: bool,
) -> Path:
    report_dir = Path(REPORT_DIR_NAME)
    report_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    report_path = report_dir / f"{REPORT_FILE_PREFIX}-{version}-{timestamp}.md"
    files = _collect_commit_files(commit)
    counts = _summarize_sections(files)
    mode = "test-release" if test_release else "release"

    report_path.write_text(
        "\n".join(
            [
                f"# PyPNM {mode} report",
                "",
                f"- Generated: {datetime.now().isoformat(timespec='seconds')}",
                f"- Branch: {branch}",
                f"- Source commit: `{commit}`",
                f"- Release version: `{version}`",
                f"- Release tag: `{tag_name}`",
                "",
                "## Change summary (last commit)",
                "",
                _render_markdown_table(counts),
                "",
            ]
        ),
        encoding="utf-8",
    )
    return report_path


def _ensure_virtualenv() -> None:
    """Ensure release is running inside a virtual environment."""
    if os.environ.get("VIRTUAL_ENV"):
        return
    if getattr(sys, "base_prefix", sys.prefix) != sys.prefix:
        return
    setup_cmd = (
        f"{sys.executable} -m venv .venv && "
        ". .venv/bin/activate && "
        "pip install -e '.[dev]'"
    )
    print(
        "ERROR: Release must run inside a Python virtual environment. "
        "Activate the venv (or create one) before running tools/release/release.py.",
        file=sys.stderr,
    )
    print("Suggested setup (copy/paste):", file=sys.stderr)
    print(f"  {setup_cmd}", file=sys.stderr)
    sys.exit(1)


def _ensure_pytest_available() -> None:
    """Ensure pytest is importable in the current environment."""
    try:
        import pytest  # noqa: F401
    except ModuleNotFoundError:
        print(
            "ERROR: pytest is not installed in the active Python environment. "
            "Install dev dependencies in the venv before running the release.",
            file=sys.stderr,
        )
        sys.exit(1)


def _checkout_and_pull(branch: str) -> None:
    """Checkout the target branch and fast-forward pull from origin."""
    _run(["git", "checkout", branch], label="git-checkout")
    _run(["git", "pull", "--ff-only"], label="git-pull")


def _read_current_version() -> str:
    """Read the current __version__ value from the version file."""
    if not VERSION_FILE_PATH.exists():
        print(f"ERROR: Version file not found: {VERSION_FILE_PATH}", file=sys.stderr)
        sys.exit(1)

    text = VERSION_FILE_PATH.read_text(encoding="utf-8")
    prefix = '__version__: str = "'
    start_index = text.find(prefix)
    if start_index < 0:
        print(
            f"ERROR: Could not find __version__ assignment in {VERSION_FILE_PATH}.",
            file=sys.stderr,
        )
        sys.exit(1)

    start_index = start_index + len(prefix)
    end_index = text.find('"', start_index)
    if end_index < 0:
        print(
            f"ERROR: Unterminated __version__ string in {VERSION_FILE_PATH}.",
            file=sys.stderr,
        )
        sys.exit(1)

    return text[start_index:end_index]


def _read_pyproject_version() -> str:
    """Read the [project].version value from pyproject.toml."""
    if not PYPROJECT_FILE_PATH.exists():
        print(f"ERROR: pyproject.toml not found: {PYPROJECT_FILE_PATH}", file=sys.stderr)
        sys.exit(1)

    text = PYPROJECT_FILE_PATH.read_text(encoding="utf-8")
    lines = text.splitlines()
    in_project_section = False

    for line in lines:
        stripped = line.strip()
        if stripped == "[project]":
            in_project_section = True
            continue

        if in_project_section and stripped.startswith("[") and stripped.endswith("]"):
            break

        if in_project_section and stripped.startswith("version") and "=" in stripped and '"' in stripped:
            first_quote = line.find('"')
            second_quote = line.find('"', first_quote + 1)
            if first_quote == -1 or second_quote == -1:
                print(
                    f"ERROR: Malformed [project].version line in {PYPROJECT_FILE_PATH}: {line!r}",
                    file=sys.stderr,
                )
                sys.exit(1)
            return line[first_quote + 1 : second_quote]

    print(
        f"ERROR: Could not find [project].version in {PYPROJECT_FILE_PATH}.",
        file=sys.stderr,
    )
    sys.exit(1)


def _validate_version_string(version: str) -> None:
    """Validate that the version string matches MAJOR.MINOR.MAINTENANCE.BUILD."""
    parts = version.split(VERSION_PART_SEPARATOR)
    if len(parts) != EXPECTED_VERSION_PARTS:
        print(
            f"ERROR: Version '{version}' has {len(parts)} parts, expected {EXPECTED_VERSION_PARTS}.",
            file=sys.stderr,
        )
        sys.exit(1)

    if not all(part.isdigit() for part in parts):
        print(
            f"ERROR: Invalid version '{version}'. Expected numeric MAJOR.MINOR.MAINTENANCE.BUILD.",
            file=sys.stderr,
        )
        sys.exit(1)


def _compute_next_version(current_version: str, mode: str) -> str:
    """Compute the next version string by incrementing the requested component."""
    _validate_version_string(current_version)
    parts_str = current_version.split(VERSION_PART_SEPARATOR)
    parts_int = [int(part) for part in parts_str]

    match mode:
        case "major":
            parts_int[MAJOR_INDEX]       = parts_int[MAJOR_INDEX] + 1
            parts_int[MINOR_INDEX]       = 0
            parts_int[MAINTENANCE_INDEX] = 0
            parts_int[BUILD_INDEX]       = 0
        case "minor":
            parts_int[MINOR_INDEX]       = parts_int[MINOR_INDEX] + 1
            parts_int[MAINTENANCE_INDEX] = 0
            parts_int[BUILD_INDEX]       = 0
        case "maintenance":
            parts_int[MAINTENANCE_INDEX] = parts_int[MAINTENANCE_INDEX] + 1
            parts_int[BUILD_INDEX]       = 0
        case "build":
            parts_int[BUILD_INDEX]       = parts_int[BUILD_INDEX] + 1
        case _:
            print(f"ERROR: Unsupported next mode '{mode}'.", file=sys.stderr)
            sys.exit(1)

    return VERSION_PART_SEPARATOR.join(str(part) for part in parts_int)


def _bump_version(new_version: str) -> None:
    """Invoke tools/bump_version.py to update the version string."""
    if not BUMP_SCRIPT_PATH.exists():
        print(f"ERROR: Version bump script not found: {BUMP_SCRIPT_PATH}", file=sys.stderr)
        sys.exit(1)

    _run([sys.executable, str(BUMP_SCRIPT_PATH), new_version], label="bump-version")


def _restore_previous_version(previous_version: str, tag_prefix: str) -> None:
    """Restore version files back to the previous version after a test release."""
    print(f"Restoring version files to {previous_version}...")
    _bump_version(previous_version)
    _update_readme_tag(f"{tag_prefix}{previous_version}")


def _update_readme_tag(new_tag: str) -> None:
    """Rewrite TAG placeholders to the new release tag in README and docs."""
    paths = [README_FILE_PATH]
    if DOCS_ROOT.exists():
        paths.extend([p for p in DOCS_ROOT.rglob("*.md") if p.is_file()])

    for path in paths:
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            continue

        updated_text, count = README_TAG_PATTERN.subn(f'TAG="{new_tag}"', text)
        if count == 0:
            continue

        path.write_text(updated_text, encoding="utf-8")
        print(f"Updated TAG placeholders in {path} to {new_tag}")


def _run_tests() -> None:
    """Run the test suite before finalizing the release."""
    _ensure_pytest_available()
    print("Running tests (pytest)...")
    result = _run([sys.executable, "-m", "pytest"], check=False, label="pytest")
    if result.returncode != 0:
        print("ERROR: pytest failed. Aborting release.", file=sys.stderr)
        _print_status("Tests", "fail")
        sys.exit(result.returncode)
    _print_status("Tests", "pass")


def _run_repo_hygiene_checks() -> None:
    """Run pre-release hygiene checks (secrets, MAC address scans, etc.)."""
    checks: list[tuple[str, list[str]]] = [
        ("Secret scan", ["./tools/security/scan-secrets.sh"]),
        ("MAC scan", ["./tools/security/scan-mac-addresses.py", "--fail-on-found"]),
    ]
    print("Running repository hygiene checks...")
    for label, cmd in checks:
        script_path = Path(cmd[0])
        if script_path.suffix in {".sh", ".py"} and not script_path.exists():
            print(f"{label}: {script_path} not found, skipping.")
            _print_status(label, "skip")
            continue
        result = _run(cmd, check=False, label=label)
        if result.returncode != 0:
            print(f"ERROR: {label} failed. Aborting release.", file=sys.stderr)
            _print_status(label, "fail")
            sys.exit(result.returncode)
        _print_status(label, "pass")


def _prime_sudo_session() -> None:
    """Run sudo -v once so later sudo invocations do not re-prompt."""
    if shutil.which("sudo") is None:
        return
    print("Priming sudo credentials (sudo -v)...")
    result = _run(["sudo", "-v"], check=False, label="sudo-validate", capture_output=False)
    if result.returncode != 0:
        print("ERROR: Unable to validate sudo credentials. Aborting release.", file=sys.stderr)
        _print_status("sudo-validate", "fail")
        sys.exit(result.returncode)
    _print_status("sudo-validate", "pass")


def _run_mkdocs_strict() -> None:
    """Build mkdocs site in strict mode to catch broken links before release."""
    if not Path("mkdocs.yml").exists():
        print("mkdocs.yml not found; skipping mkdocs strict build.")
        _print_status("MkDocs", "skip")
        return

    print("Building docs with mkdocs --strict ...")
    result = _run(["mkdocs", "build", "--strict"], check=False, label="mkdocs")
    if result.returncode != 0:
        print("ERROR: mkdocs build failed. Aborting release.", file=sys.stderr)
        _print_status("MkDocs", "fail")
        sys.exit(result.returncode)
    _print_status("MkDocs", "pass")


def _commit_version_bump(new_version: str) -> None:
    """Commit the version bump change (includes README/docs tag updates)."""
    add_paths = [
        str(VERSION_FILE_PATH),
        str(PYPROJECT_FILE_PATH),
        str(README_FILE_PATH),
    ]

    # Add docs in case TAG placeholders were updated there
    if DOCS_ROOT.exists():
        add_paths.append(str(DOCS_ROOT))

    _run(["git", "add", *add_paths], label="git-add")
    _run(["git", "commit", "-m", f"Release {new_version}"], label="git-commit")


def _create_tag(new_version: str, tag_prefix: str) -> str:
    """Create an annotated git tag for the release."""
    tag_name = f"{tag_prefix}{new_version}"
    _run(["git", "tag", "-a", tag_name, "-m", f"Release {new_version}"], label="git-tag")
    return tag_name


def _push_branch_and_tag(branch: str, tag_name: str) -> None:
    """Push the branch and tag to the origin remote."""
    _run(["git", "push", "origin", branch], label="git-push-branch")
    _run(["git", "push", "origin", tag_name], label="git-push-tag")


def main() -> None:
    """Automate a release: bump version, run tests, commit, tag, and push.

    Typical flows
    -------------
    1) Let the script compute the next maintenance version:
       tools/release/release.py

    2) Let the script compute the next version by mode:
       tools/release/release.py --next minor
       tools/release/release.py --next major
       tools/release/release.py --next maintenance
       tools/release/release.py --next build

    3) Release an explicit version:
       tools/release/release.py --version 0.2.1.0

    4) Show what would happen without changing anything:
       tools/release/release.py --next maintenance --dry-run
       tools/release/release.py --dry-run
    """
    _print_banner()
    parser = argparse.ArgumentParser(
        description=(
            "Automate a PyPNM release: compute or apply a version using tools/bump_version.py, "
            "run tests, commit, tag, and push."
        )
    )
    parser.add_argument(
        "--version",
        help="Explicit release version in MAJOR.MINOR.MAINTENANCE.BUILD format (e.g. 0.1.0.0).",
    )
    parser.add_argument(
        "--next",
        choices=["major", "minor", "maintenance", "build"],
        help="Compute the next version from the current one (default: maintenance if omitted).",
    )
    parser.add_argument(
        "--branch",
        default="main",
        help="Branch to release from (default: main). Use 'stable' when ready.",
    )
    parser.add_argument(
        "--tag-prefix",
        default="v",
        help="Prefix for git tag names (default: 'v', e.g. v0.1.0.0).",
    )
    parser.add_argument(
        "--skip-tests",
        action="store_true",
        help="Skip running pytest before committing and tagging.",
    )
    parser.add_argument(
        "--skip-docker-test",
        action="store_true",
        help="Skip local docker build/smoke preflight (tools/local/local_container_build.sh).",
    )
    parser.add_argument(
        "--skip-k8s-test",
        action="store_true",
        help="Skip local Kubernetes smoke test (tools/local/local_kubernetes_smoke.sh).",
    )
    parser.add_argument(
        "--test-release",
        action="store_true",
        help="Run locally without commit/tag/push, then restore the prior version.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show planned actions without modifying anything.",
    )

    args = parser.parse_args()
    explicit_version: str | None = args.version
    next_mode: str | None        = args.next
    branch: str                  = args.branch
    tag_prefix: str              = args.tag_prefix
    skip_tests: bool             = args.skip_tests
    skip_docker: bool            = args.skip_docker_test
    skip_k8s: bool               = args.skip_k8s_test
    dry_run: bool                = args.dry_run
    test_release: bool           = args.test_release

    current_version   = _read_current_version()
    pyproject_version = _read_pyproject_version()

    if current_version != pyproject_version:
        print(
            "ERROR: Version mismatch between src/pypnm/version.py "
            f"({current_version}) and pyproject.toml [project].version "
            f"({pyproject_version}). Run tools/bump_version.py or fix manually.",
            file=sys.stderr,
        )
        sys.exit(1)

    if explicit_version is not None and next_mode is not None:
        print("ERROR: --version and --next cannot be used together.", file=sys.stderr)
        sys.exit(1)

    if explicit_version is not None:
        new_version = explicit_version
        _validate_version_string(new_version)
    else:
        mode       = next_mode or "maintenance"
        new_version = _compute_next_version(current_version, mode)

    if new_version == current_version:
        print(f"No change: version is already {current_version}.")
        sys.exit(0)

    if dry_run:
        print("Dry run: the following actions would be performed:")
        print("  1) Ensure git working tree is clean")
        print(f"  2) Checkout branch '{branch}' and pull with --ff-only")
        print(f"  3) Update version {current_version} -> {new_version} via tools/bump_version.py")
        print(f"  4) Update README/docs TAG placeholders to {tag_prefix}{new_version}")
        print("  5) Run repository hygiene checks (secrets/macs)")
        if not skip_tests:
            print("  6) Run pytest")
        if not skip_docker:
            print("  7) Run local docker preflight (tools/local/local_container_build.sh --smoke)")
        if not skip_k8s:
            print("  8) Run local Kubernetes smoke test (tools/local/local_kubernetes_smoke.sh)")
        print(f"  9) Build docs with mkdocs --strict")
        if test_release:
            print(" 10) Skip commit/tag/push (test-only)")
            print(f" 11) Restore version files back to {current_version}")
        else:
            print(f" 10) Commit version bump: 'Release {new_version}'")
            print(f" 11) Create annotated tag '{tag_prefix}{new_version}'")
            print(f" 12) Push branch '{branch}' and tag to origin")
        sys.exit(0)

    _ensure_virtualenv()

    if explicit_version is None:
        print(f"Current version: {current_version}")
        print(f"Planned version bump: {current_version} -> {new_version}")
        answer = input("Proceed with release? [y/N]: ").strip().lower()
        if answer not in ("y", "yes"):
            print("Aborted: release was not confirmed.")
            sys.exit(1)

    _init_release_logging()
    if not skip_docker or not skip_k8s:
        _prime_sudo_session()

    _ensure_clean_worktree()
    if not test_release:
        _checkout_and_pull(branch)

    report_commit = _get_head_commit()

    print(f"Bumping version: {current_version} -> {new_version}")
    _bump_version(new_version)
    _update_readme_tag(f"{tag_prefix}{new_version}")

    _run_repo_hygiene_checks()

    if not skip_tests:
        _run_tests()
    else:
        _print_status("Tests", "skip")

    if not skip_docker:
        print("Running local docker preflight (tools/local/local_container_build.sh --smoke)...")
        cmd = ["./tools/local/local_container_build.sh", "--smoke"]
        result = _run(cmd, check=False, label="docker-smoke")
        if result.returncode != 0:
            # Attempt sudo fallback if permission denied is suspected
            err_text = (result.stderr or "") + "\n" + (result.stdout or "")
            if "permission denied" in err_text.lower():
                print("Docker preflight failed; retrying with sudo...")
                result = _run(["sudo"] + cmd, check=False, label="docker-smoke-sudo")
        if result.returncode != 0:
            print("ERROR: local docker preflight failed. Aborting release.", file=sys.stderr)
            print("If this is a Docker permission issue, add your user to the docker group and re-login:")
            print("  sudo usermod -aG docker $USER")
            _print_status("Docker preflight", "fail")
            sys.exit(result.returncode)
        _print_status("Docker preflight", "pass")
    else:
        _print_status("Docker preflight", "skip")

    if not skip_k8s:
        print("Running local Kubernetes smoke test (tools/local/local_kubernetes_smoke.sh)...")
        cmd = ["./tools/local/local_kubernetes_smoke.sh"]
        result = _run(cmd, check=False, label="k8s-smoke")
        if result.returncode != 0:
            err_text = (result.stderr or "") + "\n" + (result.stdout or "")
            if "permission denied" in err_text.lower():
                print("Kubernetes smoke test failed; retrying with sudo...")
                result = _run(["sudo"] + cmd, check=False, label="k8s-smoke-sudo")
        if result.returncode != 0:
            print("ERROR: local Kubernetes smoke test failed. Aborting release.", file=sys.stderr)
            err_text = (result.stderr or "") + "\n" + (result.stdout or "")
            if "missing required command: kind" in err_text.lower() or "missing required command: kubectl" in err_text.lower():
                print("Hint: install kind + kubectl with:")
                print("  ./tools/k8s/pypnm_kind_vm_bootstrap.sh")
                print("Also ensure Docker is running: sudo systemctl start docker")
            _print_status("Kubernetes smoke", "fail")
            sys.exit(result.returncode)
        _print_status("Kubernetes smoke", "pass")
    else:
        _print_status("Kubernetes smoke", "skip")

    _run_mkdocs_strict()

    if test_release:
        print("Skipping commit/tag/push (--test-release set).")
        _restore_previous_version(current_version, tag_prefix)
        _print_status("Commit", "skip")
        _print_status("Tag", "skip")
        _print_status("Push", "skip")
        return

    _commit_version_bump(new_version)
    tag_name = _create_tag(new_version, tag_prefix)
    _push_branch_and_tag(branch, tag_name)

    report_path = _write_release_report(report_commit, new_version, tag_name, branch, test_release)
    counts = _summarize_sections(_collect_commit_files(report_commit))
    print("\nRelease change summary (last commit):")
    print(_render_table(counts))
    print(f"Release report saved to {report_path}")
    _print_status("Release report", "pass")

    print(f"Release {new_version} completed on branch '{branch}' with tag '{tag_name}'.")


if __name__ == "__main__":
    main()
