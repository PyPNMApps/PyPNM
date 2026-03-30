# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SEED_SCRIPT = REPO_ROOT / "scripts" / "seed-fastapi-worker-profile.py"
START_SCRIPT = REPO_ROOT / "scripts" / "start-fastapi-service.sh"


def test_seed_fastapi_worker_profile_writes_expected_env_file(tmp_path: Path) -> None:
    output_path = tmp_path / "pypnm-serve.env"

    result = subprocess.run(
        [
            sys.executable,
            str(SEED_SCRIPT),
            "--write",
            str(output_path),
            "--cpu-count",
            "8",
            "--memory-gib",
            "8",
        ],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    assert "Wrote PyPNM worker profile" in result.stdout
    content = output_path.read_text()
    assert "PYPNM_SERVE_CPU_COUNT=8" in content
    assert "PYPNM_SERVE_TOTAL_MEMORY_GIB=8.0" in content
    assert "PYPNM_SERVE_WORKERS=2" in content
    assert "PYPNM_SERVE_LIMIT_MAX_REQUESTS=1000" in content


def test_start_fastapi_service_uses_profile_defaults_when_missing_flags(tmp_path: Path) -> None:
    profile_path = tmp_path / "pypnm-serve.env"
    profile_path.write_text(
        "PYPNM_SERVE_WORKERS=2\n"
        "PYPNM_SERVE_LIMIT_MAX_REQUESTS=1000\n",
    )

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    args_path = tmp_path / "pypnm-args.txt"
    fake_pypnm = fake_bin / "pypnm"
    fake_pypnm.write_text(
        "#!/usr/bin/env bash\n"
        "printf '%s\\n' \"$@\" > \"$PYPNM_TEST_ARGS_FILE\"\n",
    )
    fake_pypnm.chmod(fake_pypnm.stat().st_mode | stat.S_IEXEC)

    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    env["PYPNM_SERVE_ENV_FILE"] = str(profile_path)
    env["PYPNM_TEST_ARGS_FILE"] = str(args_path)

    subprocess.run(
        [str(START_SCRIPT), "--host", "0.0.0.0"],
        cwd=REPO_ROOT,
        check=True,
        env=env,
    )

    assert args_path.read_text().splitlines() == [
        "serve",
        "--host",
        "0.0.0.0",
        "--workers",
        "2",
        "--limit-max-requests",
        "1000",
    ]


def test_start_fastapi_service_preserves_explicit_flags(tmp_path: Path) -> None:
    profile_path = tmp_path / "pypnm-serve.env"
    profile_path.write_text(
        "PYPNM_SERVE_WORKERS=2\n"
        "PYPNM_SERVE_LIMIT_MAX_REQUESTS=1000\n",
    )

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    args_path = tmp_path / "pypnm-args.txt"
    fake_pypnm = fake_bin / "pypnm"
    fake_pypnm.write_text(
        "#!/usr/bin/env bash\n"
        "printf '%s\\n' \"$@\" > \"$PYPNM_TEST_ARGS_FILE\"\n",
    )
    fake_pypnm.chmod(fake_pypnm.stat().st_mode | stat.S_IEXEC)

    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    env["PYPNM_SERVE_ENV_FILE"] = str(profile_path)
    env["PYPNM_TEST_ARGS_FILE"] = str(args_path)

    subprocess.run(
        [
            str(START_SCRIPT),
            "--workers",
            "4",
            "--limit-max-requests",
            "2000",
        ],
        cwd=REPO_ROOT,
        check=True,
        env=env,
    )

    assert args_path.read_text().splitlines() == [
        "serve",
        "--workers",
        "4",
        "--limit-max-requests",
        "2000",
    ]
