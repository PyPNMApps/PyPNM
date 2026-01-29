## Agent Review Bundle Summary
- Goal: Update contact email to pypnm.docsis@gmail.com.
- Changes: Replace legacy Outlook address in metadata and docs.
- Files: pyproject.toml; SECURITY.md; README.md
- Tests: python3 -m compileall src; ruff check src; ruff format --check . (fails: repo drift); pytest -q
- Notes: ruff format --check . reports many files would be reformatted; pytest skips hardware integration tests (PNM_CM_IT).

# FILE: pyproject.toml
# SPDX-License-Identifier: Apache-2.0

[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name            = "pypnm-docsis"
version         = "1.1.1.0"
description     = "DOCSIS 3.x/4.0 Proactive Network Maintenance Toolkit"
readme          = "README.md"
requires-python = ">=3.10"
license         = "Apache-2.0"

authors = [
  { name = "Maurice Garcia", email = "pypnm.docsis@gmail.com" }
]

classifiers = [
  "Programming Language :: Python :: 3",
  "Programming Language :: Python :: 3 :: Only",
  "Programming Language :: Python :: 3.10",
  "Programming Language :: Python :: 3.11",
  "Programming Language :: Python :: 3.12",
  "Programming Language :: Python :: 3.13",
  "Operating System :: OS Independent",
  "Framework :: FastAPI",
  "Topic :: System :: Networking",
  "Typing :: Typed",
]

license-files = ["LICENSE", "NOTICE"]

dependencies = [
  "fastapi==0.115.12",
  "uvicorn[standard]==0.34.2",
  "python-multipart>=0.0.20",
  "numpy==2.2.6",
  "scipy==1.15.1",
  "pydantic>=2.12.4,<2.13",
  "pysmi==1.6.1",
  "pysnmp==7.1.17",
  "python-dotenv>=1.0.0",
  "requests==2.32.3",
  "pandas==2.2.3",
  "paramiko==3.5.1",
  "tftpy==0.8.5",
  "matplotlib==3.10.8",
  "typing-extensions>=4.10.0",
]

[project.optional-dependencies]
dev = [
  "pytest>=8.0.0",
  "pytest-cov>=5.0.0",
  "pytest-asyncio>=0.23.5",
  "black>=24.0.0",
  "pydantic-settings>=2.6.0",
  "ruff>=0.14.7",
  "pycycle>=0.0.8",
  "pyright>=1.1.407",
  "pyyaml>=6.0.2",
]
docs = [
  "mkdocs>=1.6",
  "mkdocs-material>=9.5",
  "pymdown-extensions>=10.8",
]
reports = []

[project.urls]
Homepage    = "https://www.pypnm.io"
Repository  = "https://github.com/PyPNMApps/PyPNM"
Bug-Tracker = "https://github.com/PyPNMApps/PyPNM/issues"
Documentation = "https://www.pypnm.io"

[project.scripts]
pypnm      = "pypnm.cli:main"
docs-serve = "mkdocs.__main__:serve"
docs-build = "mkdocs.__main__:build"
pypnm-software-qa-checker  = "pypnm.tools.qa_checker:main"

[tool.setuptools]
package-dir = { "" = "src" }
include-package-data = true

[tool.setuptools.packages.find]
where   = ["src"]
include = ["pypnm*"]

[tool.setuptools.package-data]
"pypnm" = [
  "settings/*.json",
  "py.typed",
]

[tool.pytest.ini_options]
minversion   = "8.0"
pythonpath   = ["src"]
testpaths    = ["tests"]
addopts      = "-ra -q --strict-markers --tb=short -m 'not cm_it'"
asyncio_mode = "auto"
log_cli = true
log_cli_level = "INFO"
log_cli_format = "%(levelname)s %(name)s:%(lineno)d | %(message)s"
log_cli_date_format = "%H:%M:%S"
markers = [
  "asyncio: mark test as asyncio-based (requires pytest-asyncio)",
  "cm_it: cable modem integration tests (enable with -m cm_it)",
  "slow: slow tests",
  "net: network-required tests",
  "pnm: PNM file parsing tests",
]
filterwarnings = [
  "ignore:getReadersFromUrls is deprecated:DeprecationWarning:pysnmp",
  "ignore:smiV1Relaxed is deprecated:DeprecationWarning:pysnmp",
  "ignore:.*getReadersFromUrls.*:DeprecationWarning:pysmi.reader.url",
  "ignore:.*addSources.*:DeprecationWarning:pysnmp.smi.compiler",
  "ignore:.*addSearchers.*:DeprecationWarning:pysnmp.smi.compiler",
  "ignore:.*addBorrowers.*:DeprecationWarning:pysnmp.smi.compiler",
]

[tool.coverage.run]
branch = true
source = ["pypnm"]

[tool.coverage.report]
show_missing = true
skip_covered = true

[tool.black]
line-length = 100
target-version = ["py310"]

[tool.ruff]
src            = ["src"]
target-version = "py310"
exclude        = [
  "tools",
  "src/pypnm/lib/matplot/manager.py",
  "src/pypnm/lib/csv/manager.py",
  "src/pypnm/api/routes/common/extended/common_messaging_service.py",
  "src/pypnm/api/routes/common/extended/common_measure_service.py",
  "src/pypnm/examples/",
]

[tool.ruff.lint]
# Common, high-signal rulesets:
# F   = Pyflakes (real errors)
# E,W = pycodestyle
# I   = import sorting
# B   = flake8-bugbear
# UP  = pyupgrade
#
# Ignore:
# E501 - https://docs.astral.sh/ruff/rules/line-too-long/
# B006 - https://docs.astral.sh/ruff/rules/mutable-argument-default/
#
# ---------------------------------------------------------------------------
# Ruff Roadmap (do NOT enable by default; turn on gradually when ready)
# ---------------------------------------------------------------------------
# Phase 1 (current):
#   - Focus on correctness + core style only.
#   - Enabled rule families:
#       F, E, W, I, B, UP
#
# Phase 2 (optional): Naming rules
#   - Add N (pep8-naming) when public API naming is stable.
#   - This enforces conventional names for functions, classes, etc.
#   - Example change (for later, DO NOT UNCOMMENT YET):
#       select = ["F", "E", "W", "I", "B", "UP", "N"]
#
# Phase 3 (optional): Type-annotation rules
#   - Add ANN to enforce more consistent type hints once F/E/W noise is low.
#   - You can selectively ignore strict ANN codes if needed (e.g., ANN101/ANN102).
#   - Example (for later):
#       select = ["F", "E", "W", "I", "B", "UP", "ANN"]
#       ignore = ["E501", "B006", "ANN101", "ANN102"]
#
# Phase 4 (optional): Simplification & performance hints
#   - Enable SIM (flake8-simplify) to flag redundant or over-complicated logic.
#   - Enable PERF to catch obvious performance footguns in hot paths.
#   - Recommended approach:
#       - First, run ad-hoc from CLI without adding to select:
#           ruff check src --select SIM,PERF
#       - Fix only the diagnostics you agree with.
#   - If you like the results, you can later extend select:
#       select = ["F", "E", "W", "I", "B", "UP", "N", "ANN", "SIM", "PERF"]
#
# Packs to generally avoid for PyPNM (unless explicitly desired later):
#   - D (pydocstyle): conflicts with custom docstring rules.
#   - C90 / PL (mccabe / pylint families): very noisy, low signal for this project.

select = ["F", "E", "W", "I", "B", "UP", "ANN", "SIM", "PERF"]
ignore = [
  "E501",
  "B006"
]

[tool.pyright]
pythonVersion = "3.10"
pythonPlatform = "Linux"

include = ["src"]
exclude = [
  "tools",
  "src/pypnm/examples/",
  "**/__pycache__",
]

# VSCode + .env venv
venvPath = "."
venv = ".env"

reportMissingImports = "warning"
reportMissingTypeStubs = "warning"
typeCheckingMode = "basic"

# FILE: SECURITY.md
# Security Policy

This document describes how security issues in the PyPNM project are handled. It is intended for users, contributors, and operators who discover or suspect a vulnerability in the code, configuration, or release artifacts.

## Supported Versions

PyPNM is under active development. At this time, security fixes are generally provided for:

- The latest release on the `main` branch
- The most recent tagged release, when applicable

Older releases may not receive security fixes. If you are running an older version and discover a vulnerability, please test against the latest version and include that information when reporting the issue.

## Reporting a Vulnerability

If you believe you have found a security vulnerability in PyPNM, any of its dependencies, or related release artifacts (containers, example configs, scripts), please notify the maintainer privately.

### Preferred Contact

- Email: `pypnm.docsis@gmail.com`

When reporting, include as much detail as possible so the issue can be reproduced and evaluated:

- A description of the suspected vulnerability
- Steps to reproduce the issue
- The impact you believe it may have
- The environment details:
  - PyPNM version (commit hash or tag)
  - Python version
  - Operating system and architecture
- Any relevant configuration details (sanitize or anonymize sensitive values)

### What Not To Do

- Do not open public GitHub issues or pull requests that contain exploit details, stack traces with sensitive data, or real credentials.
- Do not share real SNMP communities, API keys, passwords, or private IP addresses in any public location.
- Do not test discovered vulnerabilities against systems or networks you do not own or have explicit permission to test.

## Handling Process

When a security report is received, the general process is:

1. **Acknowledgement**  
   The maintainer will acknowledge receipt of the report as soon as reasonably possible.

2. **Triage and Verification**  
   The issue will be reviewed to confirm whether it is a valid security concern, to understand impact, scope, and affected components.

3. **Fix Development**  
   If the issue is confirmed, a fix or mitigation will be developed. In some cases this may include updates to dependencies, container images, or documentation.

4. **Release and Advisory**  
   Once a fix is ready, a new release may be published and, if necessary, a security advisory created through GitHub or the project documentation. Reporters will be notified of the outcome.

5. **Post-Resolution Review**  
   When appropriate, build and review additional safeguards (for example, additional tests, configuration hardening, or CI checks) to prevent regressions.

## Scope

Security reports are especially welcome for issues related to:

- Remote code execution, privilege escalation, or arbitrary file access in PyPNM services
- Authentication, authorization, or access control bypass in the FastAPI interface
- Leakage of secrets (SNMP communities, encryption keys, access tokens) through logs, endpoints, or generated artifacts
- Insecure default configurations that could lead to exposure when using recommended example settings
- Vulnerabilities introduced by dependencies (for example, high or critical CVEs)

The following are generally **out of scope** for security reporting, unless they directly lead to a concrete security impact:

- General performance problems
- Non-sensitive information leaks (for example, error messages without sensitive content)
- Denial-of-service scenarios that require unrealistic or abusive local access

If you are unsure whether something qualifies, you are encouraged to report it privately anyway. It is better to over-report potential issues than to overlook a real vulnerability.

## Responsible Disclosure

The PyPNM project follows a responsible disclosure approach:

- Please report vulnerabilities privately first and allow reasonable time for analysis and remediation before public disclosure.
- The maintainer will work with you to coordinate timelines for any public announcement, if warranted.
- If you intend to publish your findings, please mention this in your initial report so timelines can be discussed.

## Development and Hardening Practices

To reduce the likelihood of security issues, the project adopts the following general practices:

- Avoid committing secrets to the repository; use local configuration files and environment variables instead.
- Use secret-scanning tools (such as gitleaks and TruffleHog) before making repositories public or cutting releases.
- Keep dependencies up to date and monitor vulnerability advisories.
- Prefer least-privilege access for any external services or credentials used in examples or automation.
- Treat all user-provided input as untrusted when designing new APIs or features.

If you have suggestions for improving the security posture of PyPNM (for example, hardening configuration defaults, recommended deployment patterns, or CI checks), you are welcome to share them via a non-public security report or a regular GitHub issue if they do not disclose sensitive information.

# FILE: README.md
<p align="center">
  <a href="docs/index.md">
    <picture>
      <source srcset="docs/images/logo/pypnm-dark-mode-hp.png"
              media="(prefers-color-scheme: dark)" />
      <img src="docs/images/logo/pypnm-light-mode-hp.png"
           alt="PyPNM Logo"
           width="200"
           style="border-radius: 24px;" />
    </picture>
  </a>
</p>

# PyPNM - Proactive Network Maintenance Toolkit

[![PyPNM Version](https://img.shields.io/github/v/tag/PyPNMApps/PyPNM?label=PyPNM&sort=semver)](https://github.com/PyPNMApps/PyPNM/tags)
[![PyPI - Version](https://img.shields.io/pypi/v/pypnm-docsis.svg)](https://pypi.org/project/pypnm-docsis/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/pypnm-docsis.svg)](https://pypi.org/project/pypnm-docsis/)
[![Daily Build](https://github.com/PyPNMApps/PyPNM/actions/workflows/daily-build.yml/badge.svg?branch=main)](https://github.com/PyPNMApps/PyPNM/actions/workflows/daily-build.yml)
[![macOS CI](https://github.com/PyPNMApps/PyPNM/actions/workflows/macos-ci.yml/badge.svg?branch=main)](https://github.com/PyPNMApps/PyPNM/actions/workflows/macos-ci.yml)
![CodeQL](https://github.com/PyPNMApps/PyPNM/actions/workflows/codeql.yml/badge.svg)
[![PyPI Install Check](https://github.com/PyPNMApps/PyPNM/actions/workflows/pypi-install-check.yml/badge.svg?branch=main)](https://github.com/PyPNMApps/PyPNM/actions/workflows/pypi-install-check.yml)
[![Kubernetes (kind)](https://github.com/PyPNMApps/PyPNM/actions/workflows/kubernetes-kind.yml/badge.svg?branch=main)](https://github.com/PyPNMApps/PyPNM/actions/workflows/kubernetes-kind.yml)
[![GHCR Publish](https://github.com/PyPNMApps/PyPNM/actions/workflows/publish-ghcr.yml/badge.svg)](https://github.com/PyPNMApps/PyPNM/actions/workflows/publish-ghcr.yml)
[![Dockerized](https://img.shields.io/badge/GHCR-latest-2496ED?logo=docker&logoColor=white&label=Docker)](https://github.com/PyPNMApps/PyPNM/pkgs/container/pypnm)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04%20%7C%2024.04%20LTS-E95420?logo=ubuntu&logoColor=white)](https://github.com/PyPNMApps/PyPNM)

PyPNM is a DOCSIS 3.x/4.0 Proactive Network Maintenance toolkit for engineers who want repeatable, scriptable visibility into modem health. It can run purely as a Python library or as a FastAPI web service for real-time dashboards and offline analysis workflows.

## Table of contents

- [Choose your path](#choose-your-path)
- [Kubernetes | Docker](#kubernetes--docker)
  - [Docker](#docker-deploy)
  - [Kubernetes (kind)](#k8s-deploy)
- [Key Features](#key-features)
- [Prerequisites](#prerequisites)
  - [Operating Systems](#operating-systems)
  - [Shell Dependencies](#shell-dependencies)
- [Getting Started](#getting-started)
  - [Install From PyPI (Library Only)](#install-from-pypi-library-only)
  - [1) Clone](#1-clone)
  - [2) Install](#2-install)
  - [3) Activate The Virtual Environment](#3-activate-the-virtual-environment)
  - [4) Configure System Settings](#4-configure-system-settings)
  - [5) Run The FastAPI Service Launcher](#5-run-the-fastapi-service-launcher)
  - [6) (Optional) Serve The Documentation](#6-optional-serve-the-documentation)
  - [7) Explore The API](#7-explore-the-api)
- [Documentation](#documentation)
- [Gallery](docs/gallery/index.md)
- [SNMP Notes](#snmp-notes)
- [CableLabs Specifications & MIBs](#cablelabs-specifications--mibs)
- [PNM Architecture & Guidance](#pnm-architecture--guidance)
- [License](#license)
- [Maintainer](#maintainer)

## Choose your path

| Path | Description |
| --- | --- |
| [Kubernetes deploy (kind)](#k8s-deploy) | Run PyPNM in a local kind cluster (GHCR image). |
| [Docker deploy](#docker-deploy) | Install and run the containerized PyPNM service. |
| [Use PyPNM as a library](#install-from-pypi-library-only) | Install `pypnm-docsis` into an existing Python environment. |
| [Run the full platform](#1-clone) | Clone the repo and use the full FastAPI + tooling stack. |

## Kubernetes | Docker

<a id="docker-deploy"></a>
### Docker (Recommended) - [Install Docker](docs/docker/install-docker.md) | [Install PyPNM Container](docs/docker/install.md) | [Commands](docs/docker/commands.md)

Fast install (helper script; latest release auto-detected):

```bash
TAG="v1.1.1.0"
PORT=8080

curl -fsSLo install-pypnm-docker-container.sh \
  https://raw.githubusercontent.com/PyPNMApps/PyPNM/main/scripts/install-pypnm-docker-container.sh

chmod +x install-pypnm-docker-container.sh

sudo ./install-pypnm-docker-container.sh --tag ${TAG} --port ${PORT}
```

If Docker isn’t on your host yet, follow the [Install Docker prerequisites](docs/docker/install-docker.md) guide first.

More Docker options and compose workflows: [PyPNM Docker Installation](docs/docker/install.md) and [Developer Workflow](docs/docker/commands.md#developer-workflow).

<a id="k8s-deploy"></a>
### Kubernetes (kind) dev clusters

Kubernetes quick links:
- [Install kind](docs/kubernetes/kind-install.md)
- [Deploy PyPNM](docs/kubernetes/pypnm-deploy.md)
- [kind + FreeLens (VM)](docs/kubernetes/kind-freelens.md)

We continuously test the manifests with a kind-based CI smoke test (`Kubernetes (kind)` badge above). Follow the [kind quickstart](docs/kubernetes/quickstart.md) or the [detailed deployment guide](docs/kubernetes/pypnm-deploy.md) to run PyPNM inside a local single-node cluster; multi-node scenarios are not covered yet (see [pros/cons](docs/kubernetes/pros-cons.md)).

Script-only deployment (no repo clone) is documented in [PyPNM deploy](docs/kubernetes/pypnm-deploy.md#script-only-deploy-no-repo-clone).

## Prerequisites

### Operating systems

Linux, validated on:

- Ubuntu 22.04 LTS
- Ubuntu 24.04 LTS

Other modern Linux distributions may work but are not yet part of the test matrix.

### Shell dependencies

From a fresh system, install Git:

```bash
sudo apt update
sudo apt install -y git
```

Python and remaining dependencies are handled by the installer.

## Getting started

### Install from PyPI (library only)

If you only need the library, install from PyPI:

  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  python -m pip install --upgrade pip
  pip install pypnm-docsis
  ```

Uninstall and cleanup:

  ```bash
  pip uninstall pypnm-docsis
  rm -f ~/.ssh/pypnm_secrets.key
  ```

## FastAPI Service and Development

### 1) Clone

  ```bash
  git clone https://github.com/PyPNMApps/PyPNM.git
  cd PyPNM
```

### 2) Install

Run the installer:

  ```bash
  ./install.sh
  ```

Common flags (use as needed):

| Flag | Purpose |
|------|---------|
| `--development` | Installs Docker Engine + kind/kubectl. See [Development Install](docs/install/development.md). |
| `--clean`       | Removes prior install artifacts (venv/build/dist/cache) before installing. Preserves data and system configuration. |
| `--purge-cache` | Clears pip cache after activating the venv (use with `--clean` when troubleshooting stale installs). |
| `--pnm-file-retrieval-setup` | Launches `tools/pnm/pnm_file_retrieval_setup.py` after install. See the [PNM File Retrieval Overview](docs/topology/index.md). |
| `--demo-mode`   | Seeds demo data/paths for offline exploration. See the [demo mode guide](./demo/README.md). |
| `--production`  | Reverts demo-mode changes and restores your previous `system.json` backup. |

Installer extras: adds shell aliases when available; source your rc file once to pick them up.

### 3) Activate the virtual environment

If you used the installer defaults, activate the `.env` environment:

  ```bash
  source .env/bin/activate
  ```

### 4) Configure system settings

System configuration lives in [deploy/docker/config/system.json](https://github.com/PyPNMApps/PyPNM/blob/main/deploy/docker/config/system.json).

- [Config menu](docs/system/menu.md): `source ~/.bashrc && config-menu`
- [System Configuration Reference](docs/system/system-config.md): field-by-field descriptions and defaults
If you installed with `--pnm-file-retrieval-setup`, it runs automatically and backs up `system.json` first.

### 5) [Run the FastAPI service launcher](docs/system/pypnm-cli.md)

HTTP (default: `http://127.0.0.1:8000`):

  ```bash
  pypnm
  ```

Development hot-reload:

  ```bash
  pypnm --reload
  ```

### 6) (Optional) Serve the documentation

HTTP (default: `http://127.0.0.1:8001`):

  ```bash
  mkdocs serve
  ```

### 7) Explore the API

Installed services and docs are available at the following URLs:

| Git Clone | Docker |
|-----------|--------|
| [FastAPI Swagger UI](http://localhost:8000/docs)  | [FastAPI Swagger UI](http://localhost:8080/docs)  |
| [FastAPI ReDoc](http://localhost:8000/redoc)      | [FastAPI ReDoc](http://localhost:8080/redoc)      |
| [MkDocs docs](http://localhost:8001)              | [MkDocs docs](http://localhost:8081)              |

## Recommendations

Postman is a great tool for testing the FastAPI endpoints:
- [Download Postman](https://www.postman.com/downloads/)

## Documentation

- [Docs hub](./docs/index.md) - task-based entry point (install, configure, operate, contribute).
- [FastAPI reference](./docs/api/fast-api/index.md) - Endpoint details and request/response schemas.
- [Python API reference](./docs/api/python/index.md) - Importable helpers and data models.

## SNMP notes

- SNMPv2c is supported  
- SNMPv3 is currently stubbed and not yet supported

## CableLabs specifications & MIBs

- [CM-SP-MULPIv3.1](https://www.cablelabs.com/specifications/CM-SP-MULPIv3.1)  
- [CM-SP-CM-OSSIv3.1](https://www.cablelabs.com/specifications/CM-SP-CM-OSSIv3.1)  
- [CM-SP-MULPIv4.0](https://www.cablelabs.com/specifications/CM-SP-MULPIv4.0)  
- [CM-SP-CM-OSSIv4.0](https://www.cablelabs.com/specifications/CM-SP-CM-OSSIv4.0)  
- [DOCSIS MIBs](https://mibs.cablelabs.com/MIBs/DOCSIS/)

## PNM architecture & guidance

- [CM-TR-PMA](https://www.cablelabs.com/specifications/CM-TR-PMA)  
- [CM-GL-PNM-HFC](https://www.cablelabs.com/specifications/CM-GL-PNM-HFC)  
- [CM-GL-PNM-3.1](https://www.cablelabs.com/specifications/CM-GL-PNM-3.1)

## License

[`Apache License 2.0`](./LICENSE) and [`NOTICE`](./NOTICE)

## Next steps

- Review [PNM topology options](docs/topology/index.md) to decide how captures will move through your network.
- Follow the [System Configuration guide](docs/system/system-config.md) to tailor `system.json` for your lab.
- Explore [system tools](docs/system/menu.md) and [operational scripts](docs/tools/index.md) for day-to-day automation.

## Maintainer

Maurice Garcia

- [Email](mailto:pypnm.docsis@gmail.com)  
- [LinkedIn](https://www.linkedin.com/in/mauricemgarcia/)
