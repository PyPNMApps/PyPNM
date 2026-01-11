# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")


REPO_ROOT = Path(__file__).resolve().parents[1]
DEV_COMPOSE_PATH = REPO_ROOT / "docker-compose.yml"
RELEASE_COMPOSE_PATH = (
    REPO_ROOT / "deploy" / "docker" / "compose" / "docker-compose.yml"
)
DOCKERFILE_PATH = REPO_ROOT / "Dockerfile"
ENTRYPOINT_PATH = REPO_ROOT / "docker" / "entrypoint.sh"


def load_yaml(path: Path) -> dict:
    assert path.exists(), f"Missing compose file at {path}"
    return yaml.safe_load(path.read_text())


def test_compose_has_expected_service_structure() -> None:
    compose = load_yaml(DEV_COMPOSE_PATH)
    services = compose.get("services")
    assert isinstance(services, dict), "docker-compose.yml must define services"

    service = services.get("pypnm-api")
    assert service, "docker-compose.yml must define the pypnm-api service"

    build = service.get("build")
    assert build and build.get("context") == ".", (
        "Compose build context should be repo root"
    )
    assert build.get("dockerfile") == "Dockerfile", (
        "Compose should use the root Dockerfile"
    )

    build_args = build.get("args") or {}
    assert build_args.get("PYTHON_VERSION") == "3.12", (
        "Compose should pin the Python version"
    )

    ports = service.get("ports") or []
    assert any(port in ("8000:8000", "${PYPNM_PORT:-8000}:8000") for port in ports), (
        "API port mapping must expose 8000"
    )

    expected_volumes = {
        "pypnm_config": "/app/config",
        "pypnm_logs": "/app/logs",
        "pypnm_data": "/app/.data",
        "pypnm_output": "/app/output",
    }
    declared_volumes = compose.get("volumes") or {}
    service_volumes = service.get("volumes") or []

    for volume_name, mount_point in expected_volumes.items():
        assert volume_name in declared_volumes, (
            f"Named volume {volume_name} must be declared at top level"
        )
        expected_mount = f"{volume_name}:{mount_point}"
        assert expected_mount in service_volumes, (
            f"Service must mount {volume_name} to {mount_point}"
        )

    healthcheck = service.get("healthcheck")
    assert healthcheck, "Compose service needs a healthcheck for CI smoke tests"
    assert healthcheck.get("retries", 0) >= 1, "Healthcheck must retry at least once"
    assert service.get("restart") == "unless-stopped"


def test_release_compose_uses_ghcr_and_named_volumes() -> None:
    compose = load_yaml(RELEASE_COMPOSE_PATH)
    service = compose["services"]["pypnm-api"]

    image = service.get("image", "")
    assert image.startswith("ghcr.io/PyPNMApps/pypnm:"), (
        "Release compose must pull from ghcr.io/PyPNMApps/pypnm"
    )

    env_file = service.get("env_file") or []
    assert ".env" in env_file, "Release compose should read variables from .env"

    bind_mounts = [
        volume for volume in service.get("volumes", []) if isinstance(volume, dict)
    ]
    assert any(
        mount.get("target") == "/app/config/system.json" and mount.get("read_only")
        for mount in bind_mounts
    ), "Release compose must mount config/system.json as read-only"


def test_dockerfile_and_entrypoint_expectations() -> None:
    dockerfile_text = DOCKERFILE_PATH.read_text()
    entrypoint_text = ENTRYPOINT_PATH.read_text()

    assert "ARG PYTHON_VERSION" in dockerfile_text
    assert 'ENTRYPOINT ["/app/entrypoint.sh"]' in dockerfile_text
    assert "uvicorn" in dockerfile_text and "pypnm.api.main:app" in dockerfile_text

    assert "DEFAULT_CONFIG" in entrypoint_text
    assert "gosu" in entrypoint_text, "Entrypoint should drop privileges via gosu"
    assert "CONFIG_DIR" in entrypoint_text and "LOG_DIR" in entrypoint_text, (
        "Entrypoint must prepare config/log directories"
    )
