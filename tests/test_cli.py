# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from argparse import Namespace
from pathlib import Path

from pypnm import cli


def _serve_args(**overrides: object) -> Namespace:
    base = {
        "host": "127.0.0.1",
        "port": 8000,
        "ssl": False,
        "cert": "./certs/cert.pem",
        "key": "./certs/key.pem",
        "mute_tags": "",
        "mute_tags_hard": False,
        "log_level": "info",
        "workers": None,
        "limit_max_requests": None,
        "no_access_log": False,
        "reload": False,
        "reload_dirs": [],
        "reload_includes": ["*.py"],
        "reload_excludes": ["*.pyc", "*__pycache__*", "*.tmp", "*.log"],
        "run_background": False,
        "background_log_file": "",
        "background_pidfile": "",
    }
    base.update(overrides)
    return Namespace(**base)


def test_run_serve_passes_limit_max_requests(monkeypatch) -> None:
    recorded: dict[str, object] = {}

    def fake_uvicorn_run(**kwargs: object) -> None:
        recorded.update(kwargs)

    monkeypatch.setattr(cli, "_sanitize_pythonpath_for_serve", lambda: None)
    monkeypatch.setattr(cli.uvicorn, "run", fake_uvicorn_run)
    monkeypatch.setattr(
        cli,
        "detect_worker_profile",
        lambda: cli.WorkerProfile(cpu_count=4, total_memory_gib=16.0, workers=2, limit_max_requests=1000),
    )

    exit_code = cli._run_serve(_serve_args(workers=2, limit_max_requests=1000))

    assert exit_code == cli.SUCCESS_EXIT_CODE
    assert recorded["limit_max_requests"] == 1000
    assert recorded["workers"] == 2


def test_run_serve_rejects_negative_limit_max_requests(monkeypatch) -> None:
    uvicorn_called = False

    def fake_uvicorn_run(**_kwargs: object) -> None:
        nonlocal uvicorn_called
        uvicorn_called = True

    monkeypatch.setattr(cli, "_sanitize_pythonpath_for_serve", lambda: None)
    monkeypatch.setattr(cli.uvicorn, "run", fake_uvicorn_run)

    exit_code = cli._run_serve(_serve_args(limit_max_requests=-1))

    assert exit_code == cli.EXIT_CODE_USAGE
    assert uvicorn_called is False


def test_run_serve_logs_seeded_runtime_profile(monkeypatch, capsys) -> None:
    recorded: dict[str, object] = {}

    def fake_uvicorn_run(**kwargs: object) -> None:
        recorded.update(kwargs)

    monkeypatch.setattr(cli, "_sanitize_pythonpath_for_serve", lambda: None)
    monkeypatch.setattr(cli.uvicorn, "run", fake_uvicorn_run)
    profile_path = Path("/tmp/pypnm-runtime/pypnm-serve.env")
    monkeypatch.setenv("PYPNM_SERVE_ENV_FILE", str(profile_path))
    monkeypatch.setattr(
        cli,
        "load_seeded_profile",
        lambda _path: cli.WorkerProfile(cpu_count=8, total_memory_gib=16.0, workers=4, limit_max_requests=2000),
    )

    exit_code = cli._run_serve(_serve_args())
    captured = capsys.readouterr()

    assert exit_code == cli.SUCCESS_EXIT_CODE
    assert recorded["workers"] == 4
    assert recorded["limit_max_requests"] == 2000
    assert (
        f"[INFO] Auto-selected FastAPI runtime profile: workers=4 limit_max_requests=2000 profile={profile_path}"
        in captured.out
    )


def test_run_serve_logs_effective_reload_worker_profile(monkeypatch, capsys) -> None:
    recorded: dict[str, object] = {}

    def fake_uvicorn_run(**kwargs: object) -> None:
        recorded.update(kwargs)

    monkeypatch.setattr(cli, "_sanitize_pythonpath_for_serve", lambda: None)
    monkeypatch.setattr(cli.uvicorn, "run", fake_uvicorn_run)
    monkeypatch.setattr(
        cli,
        "detect_worker_profile",
        lambda: cli.WorkerProfile(cpu_count=8, total_memory_gib=16.0, workers=4, limit_max_requests=2000),
    )

    exit_code = cli._run_serve(_serve_args(workers=4, limit_max_requests=2000, reload=True))
    captured = capsys.readouterr()

    assert exit_code == cli.SUCCESS_EXIT_CODE
    assert recorded["workers"] == cli.DEFAULT_WORKERS
    assert recorded["limit_max_requests"] == 2000
    assert (
        "[INFO] FastAPI runtime profile: workers=1 limit_max_requests=2000 source=explicit_cli"
        in captured.out
    )


def test_run_serve_auto_selects_hardware_profile_when_no_seed_exists(monkeypatch, capsys) -> None:
    recorded: dict[str, object] = {}

    def fake_uvicorn_run(**kwargs: object) -> None:
        recorded.update(kwargs)

    monkeypatch.setattr(cli, "_sanitize_pythonpath_for_serve", lambda: None)
    monkeypatch.setattr(cli.uvicorn, "run", fake_uvicorn_run)
    monkeypatch.setattr(cli, "load_seeded_profile", lambda _path: None)
    monkeypatch.setattr(
        cli,
        "detect_worker_profile",
        lambda: cli.WorkerProfile(cpu_count=8, total_memory_gib=32.0, workers=4, limit_max_requests=2000),
    )

    exit_code = cli._run_serve(_serve_args())
    captured = capsys.readouterr()

    assert exit_code == cli.SUCCESS_EXIT_CODE
    assert recorded["workers"] == 4
    assert recorded["limit_max_requests"] == 2000
    assert (
        "[INFO] FastAPI runtime profile: workers=4 limit_max_requests=2000 source=hardware_auto"
        in captured.out
    )


def test_run_serve_background_launches_detached_child(monkeypatch) -> None:
    monkeypatch.setattr(cli, "_sanitize_pythonpath_for_serve", lambda: None)
    called: dict[str, object] = {}

    def _fake_launch_background_serve(**kwargs: object) -> int:
        called.update(kwargs)
        return cli.SUCCESS_EXIT_CODE

    uvicorn_called = {"value": False}

    def fake_uvicorn_run(**_kwargs: object) -> None:
        uvicorn_called["value"] = True

    monkeypatch.setattr(cli, "launch_background_serve", _fake_launch_background_serve)
    monkeypatch.setattr(cli.uvicorn, "run", fake_uvicorn_run)
    monkeypatch.setattr(cli.SystemConfigSettings, "runtime_dir", classmethod(lambda cls: "/tmp/pypnm-runtime"))

    exit_code = cli._run_serve(
        _serve_args(
            run_background=True,
            background_log_file="/tmp/pypnm.log",
            background_pidfile="/tmp/pypnm.pid",
        )
    )

    assert exit_code == cli.SUCCESS_EXIT_CODE
    assert uvicorn_called["value"] is False
    assert called["module_name"] == "pypnm.cli"
    assert called["app_slug"] == "pypnm"
    assert called["runtime_dir"] == "/tmp/pypnm-runtime"
    assert called["log_file"] == "/tmp/pypnm.log"
    assert called["pidfile"] == "/tmp/pypnm.pid"


def test_run_serve_background_rejects_reload(monkeypatch) -> None:
    uvicorn_called = {"value": False}

    def fake_uvicorn_run(**_kwargs: object) -> None:
        uvicorn_called["value"] = True

    monkeypatch.setattr(cli.uvicorn, "run", fake_uvicorn_run)

    exit_code = cli._run_serve(_serve_args(run_background=True, reload=True))

    assert exit_code == cli.EXIT_CODE_USAGE
    assert uvicorn_called["value"] is False
