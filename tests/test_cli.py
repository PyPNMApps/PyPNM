# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from argparse import Namespace

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
        "workers": 2,
        "limit_max_requests": 1000,
        "no_access_log": False,
        "reload": False,
        "reload_dirs": [],
        "reload_includes": ["*.py"],
        "reload_excludes": ["*.pyc", "*__pycache__*", "*.tmp", "*.log"],
    }
    base.update(overrides)
    return Namespace(**base)


def test_run_serve_passes_limit_max_requests(monkeypatch) -> None:
    recorded: dict[str, object] = {}

    def fake_uvicorn_run(**kwargs: object) -> None:
        recorded.update(kwargs)

    monkeypatch.setattr(cli, "_sanitize_pythonpath_for_serve", lambda: None)
    monkeypatch.setattr(cli.uvicorn, "run", fake_uvicorn_run)

    exit_code = cli._run_serve(_serve_args())

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
