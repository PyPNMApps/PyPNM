## Agent Review Bundle Summary
- Goal:
- Changes:
- Files:
- Tests:
- Notes:

### Summary
Implemented the M2 DB schema manager with connection handling, idempotent schema apply, seed rows, and a health check, added SQLite coverage for schema init, and updated docs plus dependency wiring to reflect the DB bootstrap behavior. Adjusted FastAPI parameter defaults to satisfy lint and kept schema assets as the authoritative DDL source.

### Modified Files
- docs/system/system-config.md
- pyproject.toml
- src/pypnm/api/routes/advance/common/abstract/service.py
- src/pypnm/api/routes/docs/pnm/files/router.py
- src/pypnm/lib/db/db_schema_manager.py
- src/pypnm/lib/db/model/db_health_model.py
- tests/test_db_schema_manager.py

### Commands Executed And Results
- `python3 -m compileall src` → pass
- `pytest` → pass (514 passed, 3 skipped)
- `ruff check .` → pass
- `ruff format --diff src/pypnm/api/routes/docs/pnm/files/router.py src/pypnm/lib/db/db_schema_manager.py src/pypnm/lib/db/model/db_health_model.py` → reported formatting changes prior to manual fixes
- `ruff format --check .` → pass

### Tests
- `pytest` → pass (514 passed, 3 skipped)
- `ruff` → pass (`ruff check .`, `ruff format --check .`)
- `python3 -m compileall src` → pass

### Notes / Warnings
- pytest emits expected log warnings/errors from existing tests; no deprecation warnings observed.

### Remaining TODOs / Follow-Ups
- None

# FILE: docs/system/system-config.md
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 Maurice Garcia -->

# System Configuration Reference

Canonical Structure And Field Semantics For `system.json`.

* **Config file**: [`src/pypnm/settings/system.json`](https://github.com/PyPNMApps/PyPNM/blob/main/src/pypnm/settings/system.json)
* **ConfigManager class**: [`src/pypnm/config/config_manager.py`](https://github.com/PyPNMApps/PyPNM/blob/main/src/pypnm/config/config_manager.py)
* **PnmConfigManager class**: [`src/pypnm/config/pnm_config_manager.py`](https://github.com/PyPNMApps/PyPNM/blob/main/src/pypnm/config/pnm_config_manager.py)

## Table Of Contents

* [1. FastApiRequestDefault](#1-fastapirequestdefault)
* [2. SNMP](#2-snmp)
* [3. PnmBulkDataTransfer](#3-pnmbulkdatatransfer)
* [4. PnmFileRetrieval](#4-pnmfileretrieval)
* [5. Database](#5-database)
* [6. Logging](#6-logging)
* [7. TestMode](#7-testmode)
* [Loading Configuration](#loading-configuration)

## 1. FastApiRequestDefault

Default Parameters For REST Requests To The FastAPI Service.

```json
"FastApiRequestDefault": {
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "ip_address": "192.168.0.100"
}
```

| Field       | Type   | Description                       |
| ----------- | ------ | --------------------------------- |
| mac_address | string | Default device MAC address.       |
| ip_address  | string | Default device IP (IPv4 or IPv6). |

## 2. SNMP

Global SNMP Settings, Including Version-Specific Options.

```json
"SNMP": {
  "timeout": 2,
  "version": {
    "2c": {
      "enable": true,
      "retries": 3,
      "read_community": "public",
      "write_community": "private"
    },
    "3": {
      "enable": false,
      "retries": 3,
      "username": "user",
      "securityLevel": "authPriv",
      "authProtocol": "SHA",
      "authPassword": "pass",
      "privProtocol": "AES",
      "privPassword": "privpass"
    }
  }
}
```

**Top-Level**

| Field   | Type   | Description                                  |
| ------- | ------ | -------------------------------------------- |
| timeout | number | Per-request timeout (seconds).               |
| version | object | Container for v2c/v3 configuration versions. |

**SNMP v2c**

| Field           | Type    | Description                     |
| --------------- | ------- | ------------------------------- |
| enable          | boolean | Enable v2c operations.          |
| retries         | number  | Retry count on timeout/failure. |
| read_community  | string  | Community for GET/WALK.         |
| write_community | string  | Community for SET.              |

**SNMP v3**

| Field         | Type    | Description                                  |
| ------------- | ------- | -------------------------------------------- |
| enable        | boolean | Enable v3 operations.                        |
| retries       | number  | Retry count on timeout/failure.              |
| username      | string  | Security name.                               |
| securityLevel | string  | `noAuthNoPriv`, `authNoPriv`, or `authPriv`. |
| authProtocol  | string  | For example `MD5`, `SHA`.                    |
| authPassword  | string  | Required when `auth*` is used.               |
| privProtocol  | string  | For example `DES`, `AES`.                    |
| privPassword  | string  | Required when `*Priv` is used.               |

## 3. PnmBulkDataTransfer

Transport Parameters For CM-Generated Files (for example, RxMER, FEC Summary) Sent To A Server.

```json
"PnmBulkDataTransfer": {
  "method": "tftp",
  "tftp": {
    "ip_v4": "192.168.0.10",
    "ip_v6": "::1",
    "remote_dir": ""
  },
  "http": {
    "base_url": "http://files.example.com/",
    "port": 80
  },
  "https": {
    "base_url": "https://files.example.com/",
    "port": 443
  }
}
```

| Field   | Type   | Description                                                |
| ------- | ------ | ---------------------------------------------------------- |
| method  | string | Preferred bulk method: `tftp`, `http`, or `https`.         |
| tftp.*  | object | TFTP targets for IPv4/IPv6 plus optional remote directory. |
| http.*  | object | HTTP base URL and port for file delivery.                  |
| https.* | object | HTTPS base URL and port for file delivery.                 |

## 4. PnmFileRetrieval

Local Storage Layout And Remote Retrieval Methods.

Related Guide: [File Transfer Methods](pnm-file-retrieval/index.md)

Runtime DB location policy: SQLite DB files live under `.data/db/` (demo uses `demo/.data/db/`), while Postgres is external and does not create a local DB file.

```json
"PnmFileRetrieval": {
  "pnm_dir": ".data/pnm",
  "csv_dir": ".data/csv",
  "json_dir": ".data/json",
  "xlsx_dir": ".data/xlsx",
  "png_dir": ".data/png",
  "archive_dir": ".data/archive",
  "msg_rsp_dir": ".data/msg_rsp",
  "transaction_db": ".data/db/transactions.json",
  "capture_group_db": ".data/db/capture_group.json",
  "session_group_db": ".data/db/session_group.json",
  "operation_db": ".data/db/operation_capture.json",
  "json_transaction_db": ".data/db/json_transactions.json",
  "retries": 5,
  "retrieval_method": {
    "method": "local",
    "methods": {
      "local": {
        "src_dir": "/srv/tftp"
      },
      "tftp": {
        "host": "localhost",
        "port": 69,
        "timeout": 5,
        "remote_dir": ""
      },
      "ftp": {
        "host": "localhost",
        "port": 21,
        "tls": false,
        "timeout": 5,
        "user": "user",
        "password_enc": "",
        "remote_dir": "/srv/tftp"
      },
      "sftp": {
        "host": "localhost",
        "port": 22,
        "user": "user",
        "password_enc": "",
        "private_key_path": "",
        "remote_dir": "/srv/tftp"
      },
      "http": {
        "base_url": "http://STUB/",
        "port": 80
      },
      "https": {
        "base_url": "https://STUB/",
        "port": 443
      }
    }
  }
}
```

`password_enc` is the preferred password field for file retrieval methods. Plaintext `password` is supported only as a legacy fallback and is deprecated.

**Directories And Databases**

| Field               | Type   | Description                                  |
| ------------------- | ------ | -------------------------------------------- |
| pnm_dir             | string | Local storage for raw PNM binaries.          |
| csv_dir             | string | Local storage for derived CSVs.              |
| json_dir            | string | Local storage for derived JSON.              |
| xlsx_dir            | string | Local storage for Excel reports.             |
| png_dir             | string | Local storage for generated PNGs.            |
| archive_dir         | string | Local storage for analysis ZIP archives.     |
| msg_rsp_dir         | string | Local storage for message/response metadata. |
| transaction_db      | string | JSON ledger of file transactions.            |
| capture_group_db    | string | JSON map of grouped transactions.            |
| session_group_db    | string | JSON map of session groups.                  |
| operation_db        | string | JSON map of operation to capture group.      |
| json_transaction_db | string | JSON map of JSON transaction metadata.       |

**Retrieval Settings**

| Field                                  | Type   | Description                                                           |
| -------------------------------------- | ------ | --------------------------------------------------------------------- |
| retrieval_method.method                 | string | Active retrieval method: `local`, `tftp`, `ftp`, `sftp`, `http`, `https`. |
| retrieval_method.methods.local.src_dir  | string | Source directory to watch/copy from when using `local`.               |
| retrieval_method.methods.tftp.*         | object | TFTP host/port/timeout and remote directory.                          |
| retrieval_method.methods.ftp.*          | object | FTP connection, credentials, and remote directory.                    |
| retrieval_method.methods.sftp.*         | object | SFTP connection and remote directory.                                 |
| retrieval_method.methods.http.*         | object | HTTP base URL and port.                                               |
| retrieval_method.methods.https.*        | object | HTTPS base URL and port.                                              |
| retries                                | number | Max attempts per retrieval operation.                                 |

> The legacy key name `retrival_method` is accepted for backward compatibility.

## 5. Database

Database Backend Selection And Connection Settings.

```json
"Database": {
  "backend": "sqlite",
  "sqlite": {
    "path": ".data/db/pypnm.sqlite3"
  },
  "postgres": {
    "dsn": ""
  }
}
```

Backend selection is set at install time (SQLite default; Postgres recommended for multi-worker deployments). Set `PYPNM_DB_BACKEND` to override the backend selection (`sqlite` or `postgres`). SQLite stores its DB file under `.data/db/` (demo uses `demo/.data/db/`), while Postgres is external and does not create a local DB file. For Postgres, supply the DSN via `PYPNM_DB_POSTGRES_DSN` to avoid storing plaintext credentials in tracked JSON files. Blank strings for required values are invalid when the backend is active.

On startup, PyPNM applies the schema for the selected backend and seeds the canonical `UNKNOWN` sysDescr row and the default artifact store entry.

DB backend migration is in progress; legacy ledger keys remain until Phase M6.

## 6. Logging

Application Logging Options.

```json
"logging": {
  "log_level": "INFO",
  "log_dir": "logs",
  "log_filename": "pypnm.log"
}
```

| Field        | Type   | Description                                 |
| ------------ | ------ | ------------------------------------------- |
| log_level    | string | `DEBUG`, `INFO`, `WARN`, or `ERROR`.        |
| log_dir      | string | Directory for log files.                    |
| log_filename | string | Log filename (created under `log_dir`).     |

## 7. TestMode

Global And Class-Specific Test-Mode Controls.

```json
"TestMode": {
  "global": {
    "mode": {
      "enable": true
    }
  },
  "class_name": {
    "DsScQamChannelSpectrumAnalyzer": {
      "mode": {
        "enable": true
      }
    }
  }
}
```

| Field                          | Type    | Description                                            |
| ------------------------------ | ------- | ------------------------------------------------------ |
| global.mode.enable             | boolean | Enable or disable global test mode.                    |
| class_name.<Class>.mode.enable | boolean | Per-class override for test mode, keyed by class name. |

## Loading Configuration

Typical Access Pattern Using The Manager Abstractions.

```python
from pypnm.config.config_manager import ConfigManager
from pypnm.config.pnm_config_manager import PnmConfigManager

cfg = ConfigManager()

mac = cfg.get("FastApiRequestDefault", "mac_address")
ip  = cfg.get("FastApiRequestDefault", "ip_address")

pnm_cfg = PnmConfigManager()
tftp_v4 = pnm_cfg.get("PnmBulkDataTransfer", "tftp")["ip_v4"]
```

# FILE: pyproject.toml
# SPDX-License-Identifier: Apache-2.0

[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name            = "pypnm-docsis"
version         = "1.0.20.0"
description     = "DOCSIS 3.x/4.0 Proactive Network Maintenance Toolkit"
readme          = "README.md"
requires-python = ">=3.10"
license         = "Apache-2.0"

authors = [
  { name = "Maurice Garcia", email = "mgarcia01752@outlook.com" }
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
  "psycopg[binary]==3.2.3",
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

# FILE: src/pypnm/api/routes/advance/common/abstract/service.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from typing import TypeVar

from pypnm.api.routes.advance.common.capture_service import AbstractCaptureService
from pypnm.api.routes.advance.common.operation_state import OperationState
from pypnm.lib.types import GroupId, OperationId

T = TypeVar("T", bound=AbstractCaptureService)


class AbstractService:
    """
    Base router class managing the lifecycle of capture service instances.

    Responsibilities:
        - Instantiate and start capture services using load_service().
        - Store service instances keyed by operation ID in an internal registry.
        - Provide get_service() for retrieving active services in route handlers.

    Attributes:
        _service_store (Dict[str, AbstractCaptureService]):
            Registry mapping operation IDs to service instances.
    """

    # Maintain singleton mapping of operation_id to service instances
    __SERVICE_STORE: dict[OperationId, AbstractCaptureService] = {}

    def __init__(self) -> None:
        """
        Initialize the internal service registry.
        """
        self._service_store: dict[OperationId, AbstractCaptureService] = {}
        self.logger = logging.getLogger(self.__class__.__name__)

    async def updateServiceStore(
        self, operation_id: OperationId, service: AbstractCaptureService
    ) -> None:
        """
        Update the internal service registry with a new or modified service instance.

        Args:
            operation_id (OperationId): The unique ID of the operation.
            service (AbstractCaptureService): The service instance to register.

        Returns:
            None
        """
        self.__SERVICE_STORE[operation_id] = service

    async def loadService(
        self, service_cls: type[T], *args: object, **kwargs: object
    ) -> tuple[GroupId, OperationId]:
        """
        Instantiate, start, and register a capture service.

        Args:
            service_cls (Type[T]): Capture service class to instantiate.
            *args: Positional args for the service constructor.
            **kwargs: Keyword args for the service constructor.

        Returns:
            Tuple[GroupId, OperationId]: (group_id, operation_id) returned by service.start().

        Raises:
            Exception: Propagates errors from instantiation or startup.

        Supported Service Types:
            - MultiRxMerService
            - MultiChannelEstimationService
            - MultiRxMer_Ofdm_Performance_1_Service

        """
        service: T = service_cls(*args, **kwargs)
        group_id, operation_id = await service.start()
        self._service_store[operation_id] = service
        return group_id, operation_id

    def getService(self, operation_id: OperationId) -> AbstractCaptureService:
        """
        Retrieve a previously loaded service by its operation ID.

        Args:
            operation_id (str): The ID returned by load_service().

        Returns:
            AbstractCaptureService: The associated service instance.

        Raises:
            KeyError: If no service exists for the given operation ID.
        """
        try:
            return self._service_store[operation_id]
        except KeyError as err:
            raise KeyError(
                f"No service loaded for operation_id '{operation_id}'"
            ) from err

    def getActiveServices(self) -> dict[OperationId, AbstractCaptureService]:
        """
        Retrieve all currently active services.

        Returns:
            Dict[OperationId, AbstractCaptureService]: Mapping of operation IDs to service instances.
        """
        self.logger.info(
            f"Retrieving active services. Current store: {self._service_store.keys()}"
        )

        active_services: dict[OperationId, AbstractCaptureService] = {}

        for operation_id in self._service_store:
            self.logger.info(f"Active service: operation_id={operation_id}")
            if (
                self._service_store[operation_id].status()["state"]
                == OperationState.RUNNING
            ):
                self.logger.info(f"Service {operation_id} is running")
                active_services[operation_id] = self._service_store[operation_id]

        return active_services

# FILE: src/pypnm/api/routes/docs/pnm/files/router.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from typing import cast

from fastapi import APIRouter, File, Path, Query, UploadFile
from fastapi.responses import FileResponse, JSONResponse

from pypnm.api.routes.common.classes.common_endpoint_classes.common.enum import (
    OutputType,
)
from pypnm.api.routes.docs.pnm.files.schemas import (
    AnalysisJsonResponse,
    FileAnalysisRequest,
    FileQueryRequest,
    FileQueryResponse,
    HexDumpResponse,
    MacAddressSystemDescriptorResponse,
    UploadFileResponse,
)
from pypnm.api.routes.docs.pnm.files.service import PnmFileService
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE
from pypnm.lib.mac_address import MacAddress, MacAddressFormat
from pypnm.lib.types import FileName, MacAddressStr, OperationId, TransactionId


class PnmFileManager:
    """
    REST API router for managing PNM test files.

    Endpoints:
    - Search files by MAC or criteria
    - Push/upload new test file
    - Analyze an uploaded or retrieved file
    """

    DEFAULT_HEXDUMP_BYTES_PER_LINE = 16

    def __init__(self) -> None:
        self.logger = logging.getLogger(f"PnmFileManager.{self.__class__.__name__}")
        self.router = APIRouter(
            prefix="/docs/pnm/files",
            tags=["PNM File Manager"],
        )
        self._add_routes()

    def _add_routes(self) -> None:
        default_mac_address = (
            MacAddress(SystemConfigSettings.default_mac_address())
            .to_mac_format(fmt=MacAddressFormat.COLON)
            .lower()
        )

        @self.router.get(
            "/getMacAddresses/",
            response_model=MacAddressSystemDescriptorResponse,
            summary="Get All Registered MAC Addresses With PNM Files",
            responses=FAST_API_RESPONSE,
        )
        def get_mac_addresses() -> MacAddressSystemDescriptorResponse:  # noqa: B008
            """
            **Retrieve All Registered MAC Addresses With Uploaded PNM Files**

            Returns a list of all DOCSIS cable modem MAC addresses that have associated
            telemetry capture files stored in the PyPNM transaction database.

            Each MAC address represents a unique cable modem that has undergone
            telemetry data collection.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/file-manager/file-manager-api.md#1-get-all-registered-mac-addresses-with-pnm-files)
            """
            return PnmFileService().get_mac_addresses()

        search_files_mac_param = Path(
            description=(
                f"MAC address of the cable modem, default: **{default_mac_address}**"
            ),
        )

        @self.router.get(
            "/searchFiles/{mac_address}",
            response_model=FileQueryResponse,
            summary="Search For PNM Files Via Mac Address",
            responses=FAST_API_RESPONSE,
        )
        def search_files(
            mac_address: MacAddressStr = search_files_mac_param,
        ) -> FileQueryResponse:  # noqa: B008
            """
            **Search Uploaded PNM Files By MAC Address**

            Returns all registered telemetry capture files associated with a given DOCSIS cable modem.

            Each file represents a measurement such as RxMER, constellation, pre-equalization taps,
            or spectrum scan, and can be downloaded or analyzed via other endpoints.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/file-manager/file-manager-api.md#1-search-files-by-mac-address)
            """
            request = FileQueryRequest(mac_address=mac_address)
            result = PnmFileService().search_files(request)
            return result

        download_transaction_id_param = Path(
            description="Transaction ID of the file to download"
        )

        @self.router.get(
            "/download/transactionID/{transaction_id}",
            response_class=FileResponse,
            summary="Download A PNM File By Transaction ID",
            responses=FAST_API_RESPONSE,
        )
        def download_file_via_transaction_id(
            transaction_id: TransactionId = download_transaction_id_param,
        ) -> FileResponse:  # noqa: B008
            """
            **Download PNM Measurement File By Transaction ID**

            Retrieves the raw binary file generated during a telemetry capture session.
            Used for offline inspection, reprocessing, or historical archiving.

            Note:
            Depending on your browser and SwaggerUI behavior, the file may either download
            automatically or require clicking the returned link.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/file-manager/file-manager-api.md#2-download-file-by-transaction-id)
            """
            return PnmFileService().get_file_by_transaction_id(transaction_id)

        download_mac_param = Path(
            ..., description="MAC address of the file to download"
        )

        @self.router.get(
            "/download/macAddress/{mac_address}",
            response_class=FileResponse,
            summary="Download A PNM File By MAC Address",
            responses=FAST_API_RESPONSE,
        )
        def download_file_via_mac_address(
            mac_address: MacAddressStr = download_mac_param,
        ) -> FileResponse:  # noqa: B008
            """
            **Download PNM Measurement File By Transaction ID**

            Retrieves the raw binary file generated during a telemetry capture session.
            Used for offline inspection, reprocessing, or historical archiving.

            Note:
            Depending on your browser and SwaggerUI behavior, the file may either download
            automatically or require clicking the returned link.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/file-manager/file-manager-api.md#3-download-files-by-mac-address-zip-archive)
            """
            return PnmFileService().get_file_by_mac_address(mac_address)

        download_operation_id_param = Path(
            ..., description="Operation ID of the file to download"
        )

        @self.router.get(
            "/download/operationID/{operation_id}",
            response_class=FileResponse,
            summary="Download A PNM File By Operation ID",
            responses=FAST_API_RESPONSE,
        )
        def download_file_via_operationID(
            operation_id: OperationId = download_operation_id_param,
        ) -> FileResponse:  # noqa: B008
            """
            **Download PNM Measurement File By Operation ID**

            Retrieves the raw binary file generated during a telemetry capture session.
            Used for offline inspection, reprocessing, or historical archiving.

            Note:
            Depending on your browser and SwaggerUI behavior, the file may either download
            automatically or require clicking the returned link.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/file-manager/file-manager-api.md#4-download-files-by-operation-id-zip-archive)
            """
            return PnmFileService().get_file_by_operation_id(operation_id)

        upload_file_param = File(
            description="Raw PNM capture file (e.g., RxMER, constellation, histogram, spectrum)",
        )

        @self.router.post(
            "/upload",
            response_model=UploadFileResponse,
            summary="Upload A PNM File",
            responses=FAST_API_RESPONSE,
        )
        async def upload_file(
            file: UploadFile = upload_file_param,
        ) -> JSONResponse:  # noqa: B008
            """
            **Upload A PNM Binary File Into The PyPNM Transaction Database**

            This endpoint accepts a PNM capture file as multipart/form-data and stores
            it under a new transaction record.

            The server will:
            - Persist the file to the configured PNM directory.
            - Inspect the PNM header to identify the file type.
            - Map the file type to a logical PNM test (DocsPnmCmCtlTest).
            - Register a transaction entry with a placeholder null MAC address
              (to be backfilled later from the file contents).

            The response returns the generated transaction_id and echoes the stored filename.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/file-manager/file-manager-api.md#5-upload-pnm-file)

            """
            content = await file.read()
            result = PnmFileService().upload_file(
                filename=cast(FileName, file.filename), data=content
            )
            return JSONResponse(content=result.model_dump())

        @self.router.post(
            "/getAnalysis",
            response_model=AnalysisJsonResponse,
            summary="Analyze a PNM File Via Transaction ID",
            responses=FAST_API_RESPONSE,
        )
        def get_analysis_via_transaction_id(
            request: FileAnalysisRequest,
        ) -> AnalysisJsonResponse | FileResponse | JSONResponse:
            """
            **Analysis Of A PNM File**

            Launches an analysis routine based on the specified transactionID and requested
            analysis type. The backend will resolve the PNM file associated with the transactionID,
            inspect its header, and route it to the appropriate analysis pipeline.

            Supported Uploaded PNM File Types:
            - RxMER per subcarrier
            - Channel Estimation Coefficients
            - Constellation Diagram
            - Downstream Histogram
            - OFDMA Pre-equalization
            - Fec Summary
            - Modulation Profile

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/file-manager/file-manager-api.md#6-analyze-pnm-file-via-transaction-id)
            """
            PnmFileService().get_analysis(request)

            output_type = request.analysis.output.type

            if output_type == OutputType.JSON:
                analysis_result, file_type = PnmFileService().get_analysis(request)
                return AnalysisJsonResponse(
                    mac_address=analysis_result.mac_address,
                    pnm_file_type=file_type.name,
                    status="success",
                    analysis=analysis_result.model_dump(),
                )

            elif output_type == OutputType.ARCHIVE:
                return PnmFileService().get_archive(request)

            return JSONResponse(content="Not implemented yet")

        hexdump_transaction_id_param = Path(
            ..., description="Transaction ID of the PNM file to hexdump"
        )

        @self.router.get(
            "/getHexdump/transactionID/{transaction_id}",
            response_model=HexDumpResponse,
            summary="Hexdump Of A PNM File By Transaction ID",
            responses=FAST_API_RESPONSE,
        )
        def get_hexdump_via_transaction_id(
            transaction_id: TransactionId = hexdump_transaction_id_param,  # noqa: B008
            bytes_per_line: int | None = Query(
                default=None,
                description="Optional bytes-per-line for hexdump; if omitted, the service default is used.",
            ),
        ) -> HexDumpResponse:
            """
            **Hexdump Of A PNM File**

            Generates a hexadecimal dump of the raw binary contents of a PNM file
            associated with the specified transactionID.

            This is useful for low-level inspection, debugging, or forensic analysis
            of the file structure and data.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/file-manager/file-manager-api.md#7-hexdump-of-a-pnm-file-via-transaction-id)
            """
            hexdump_result = PnmFileService().get_hexdump_by_transaction_id(
                transaction_id=transaction_id,
                bytes_per_line=bytes_per_line if bytes_per_line is not None else 0,
            )
            return hexdump_result


# Required for auto-discovery via dynamic router loading
router = PnmFileManager().router

# FILE: src/pypnm/lib/db/db_schema_manager.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING, TypeAlias

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.model.db_health_model import DatabaseHealthModel
from pypnm.lib.types import DatabaseBackend, DatabaseDsn, DatabasePath

if TYPE_CHECKING:
    from psycopg import Connection as PsycopgConnection
else:
    PsycopgConnection = object

DbConnection: TypeAlias = sqlite3.Connection | PsycopgConnection

SCHEMA_VERSION: int = 1
SCHEMA_META_ID: int = 1
UNKNOWN_SYSDESCR_HASH: str = "UNKNOWN"
DEFAULT_ARTIFACT_STORE_NAME: str = "default"
DEFAULT_ARTIFACT_STORE_ROOT: str = ".data/pnm"

_SQLITE_DDL_FILE: str = "schema_sqlite.sql"
_POSTGRES_DDL_FILE: str = "schema_postgres.sql"

_REQUIRED_TABLES: tuple[str, ...] = (
    "schema_meta",
    "system_description_dim",
    "device_details",
    "transaction_records",
    "capture_groups",
    "capture_group_transactions",
    "operation_captures",
    "artifact_stores",
    "file_artifacts",
    "transaction_artifacts",
)


class DatabaseSchemaManager:
    """
    Initialize and validate the DB schema for the selected backend.
    """

    def __init__(
        self,
        backend: DatabaseBackend,
        sqlite_path: DatabasePath,
        postgres_dsn: DatabaseDsn,
    ) -> None:
        self._backend = backend
        self._sqlite_path = sqlite_path
        self._postgres_dsn = postgres_dsn
        self.logger = logging.getLogger(f"{self.__class__.__name__}")

    @classmethod
    def from_system_config(cls) -> DatabaseSchemaManager:
        """
        Build a schema manager using SystemConfigSettings.
        """
        return cls(
            SystemConfigSettings.database_backend(),
            SystemConfigSettings.database_sqlite_path(),
            SystemConfigSettings.database_postgres_dsn(),
        )

    @classmethod
    def from_overrides(
        cls,
        backend: DatabaseBackend,
        sqlite_path: DatabasePath,
        postgres_dsn: DatabaseDsn,
    ) -> DatabaseSchemaManager:
        """
        Build a schema manager using explicit backend overrides.
        """
        return cls(backend, sqlite_path, postgres_dsn)

    def connect(self) -> DbConnection:
        """
        Open a DB connection for the configured backend.
        """
        match self._backend:
            case DatabaseBackend.SQLITE:
                return self._connect_sqlite()
            case DatabaseBackend.POSTGRES:
                return self._connect_postgres()
        raise ValueError(f"Unsupported Database backend: {self._backend}")

    def initialize_schema(self) -> None:
        """
        Apply schema DDL and seed required rows idempotently.
        """
        connection = self.connect()
        try:
            self._apply_schema(connection)
            self._seed_unknown_sysdescr(connection)
            self._seed_default_artifact_store(connection)
            self._ensure_schema_version(connection)
        finally:
            connection.close()

    def health_check(self) -> DatabaseHealthModel:
        """
        Run a schema health check and return a diagnostic model.
        """
        connection = self.connect()
        try:
            table_names = self._fetch_table_names(connection)
            missing_tables = [
                table for table in _REQUIRED_TABLES if table not in table_names
            ]
            schema_version = self._fetch_schema_version(connection)
            unknown_sysdescr_present = self._has_unknown_sysdescr(connection)
            default_store_present = self._has_default_artifact_store(connection)
            ok = (
                not missing_tables
                and schema_version == SCHEMA_VERSION
                and unknown_sysdescr_present
                and default_store_present
            )
            details = self._health_details(
                schema_version,
                missing_tables,
                unknown_sysdescr_present,
                default_store_present,
            )
            return DatabaseHealthModel(
                backend=self._backend,
                schema_version=schema_version,
                missing_tables=missing_tables,
                unknown_sysdescr_present=unknown_sysdescr_present,
                default_artifact_store_present=default_store_present,
                ok=ok,
                details=details,
            )
        finally:
            connection.close()

    def _connect_sqlite(self) -> sqlite3.Connection:
        db_path = self._resolve_sqlite_db_path()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(db_path)
        connection.execute("PRAGMA foreign_keys = ON;")
        return connection

    def _connect_postgres(self) -> PsycopgConnection:
        dsn = str(self._postgres_dsn).strip()
        if not dsn:
            raise ValueError("Database.postgres.dsn cannot be blank")
        try:
            import psycopg
        except ImportError as exc:
            raise RuntimeError(
                "psycopg is required for Postgres backend support"
            ) from exc
        return psycopg.connect(dsn)

    def _apply_schema(self, connection: DbConnection) -> None:
        ddl_sql = self._load_schema_sql()
        match self._backend:
            case DatabaseBackend.SQLITE:
                sqlite_conn = connection
                sqlite_conn.executescript(ddl_sql)
                sqlite_conn.commit()
            case DatabaseBackend.POSTGRES:
                pg_conn = connection
                with pg_conn.cursor() as cursor:
                    cursor.execute(ddl_sql)
                pg_conn.commit()

    def _seed_unknown_sysdescr(self, connection: DbConnection) -> None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                sqlite_conn = connection
                sqlite_conn.execute(
                    """
                    INSERT OR IGNORE INTO system_description_dim (
                        hw_rev, vendor, bootr, sw_rev, model,
                        sysdescr_json, sysdescr_hash, is_unknown
                    )
                    VALUES (
                        'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN',
                        '{}', ?, 1
                    );
                    """,
                    (UNKNOWN_SYSDESCR_HASH,),
                )
                sqlite_conn.commit()
            case DatabaseBackend.POSTGRES:
                pg_conn = connection
                with pg_conn.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO system_description_dim (
                            hw_rev, vendor, bootr, sw_rev, model,
                            sysdescr_json, sysdescr_hash, is_unknown
                        )
                        VALUES (
                            'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN',
                            '{}'::jsonb, %s, TRUE
                        )
                        ON CONFLICT (sysdescr_hash) DO NOTHING;
                        """,
                        (UNKNOWN_SYSDESCR_HASH,),
                    )
                pg_conn.commit()

    def _seed_default_artifact_store(self, connection: DbConnection) -> None:
        root_path = self._normalize_root_path(SystemConfigSettings.pnm_dir())
        match self._backend:
            case DatabaseBackend.SQLITE:
                sqlite_conn = connection
                sqlite_conn.execute(
                    """
                    INSERT OR IGNORE INTO artifact_stores (store_name, root_path)
                    VALUES (?, ?);
                    """,
                    (DEFAULT_ARTIFACT_STORE_NAME, root_path),
                )
                sqlite_conn.commit()
            case DatabaseBackend.POSTGRES:
                pg_conn = connection
                with pg_conn.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO artifact_stores (store_name, root_path)
                        VALUES (%s, %s)
                        ON CONFLICT (store_name) DO NOTHING;
                        """,
                        (DEFAULT_ARTIFACT_STORE_NAME, root_path),
                    )
                pg_conn.commit()

    def _ensure_schema_version(self, connection: DbConnection) -> None:
        schema_version = self._fetch_schema_version(connection)
        if schema_version != SCHEMA_VERSION:
            raise RuntimeError(
                f"Unsupported schema_version={schema_version}; expected {SCHEMA_VERSION}"
            )

    def _fetch_table_names(self, connection: DbConnection) -> set[str]:
        match self._backend:
            case DatabaseBackend.SQLITE:
                sqlite_conn = connection
                cursor = sqlite_conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table';"
                )
                return {row[0] for row in cursor.fetchall()}
            case DatabaseBackend.POSTGRES:
                pg_conn = connection
                with pg_conn.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT table_name
                        FROM information_schema.tables
                        WHERE table_schema = 'public';
                        """
                    )
                    return {row[0] for row in cursor.fetchall()}
        return set()

    def _fetch_schema_version(self, connection: DbConnection) -> int:
        match self._backend:
            case DatabaseBackend.SQLITE:
                sqlite_conn = connection
                cursor = sqlite_conn.execute(
                    "SELECT schema_version FROM schema_meta WHERE schema_meta_id = ?;",
                    (SCHEMA_META_ID,),
                )
                row = cursor.fetchone()
                if row:
                    return int(row[0])
            case DatabaseBackend.POSTGRES:
                pg_conn = connection
                with pg_conn.cursor() as cursor:
                    cursor.execute(
                        "SELECT schema_version FROM schema_meta WHERE schema_meta_id = %s;",
                        (SCHEMA_META_ID,),
                    )
                    row = cursor.fetchone()
                    if row:
                        return int(row[0])
        return 0

    def _has_unknown_sysdescr(self, connection: DbConnection) -> bool:
        match self._backend:
            case DatabaseBackend.SQLITE:
                sqlite_conn = connection
                cursor = sqlite_conn.execute(
                    "SELECT 1 FROM system_description_dim WHERE sysdescr_hash = ?;",
                    (UNKNOWN_SYSDESCR_HASH,),
                )
                return cursor.fetchone() is not None
            case DatabaseBackend.POSTGRES:
                pg_conn = connection
                with pg_conn.cursor() as cursor:
                    cursor.execute(
                        "SELECT 1 FROM system_description_dim WHERE sysdescr_hash = %s;",
                        (UNKNOWN_SYSDESCR_HASH,),
                    )
                    return cursor.fetchone() is not None
        return False

    def _has_default_artifact_store(self, connection: DbConnection) -> bool:
        match self._backend:
            case DatabaseBackend.SQLITE:
                sqlite_conn = connection
                cursor = sqlite_conn.execute(
                    "SELECT 1 FROM artifact_stores WHERE store_name = ?;",
                    (DEFAULT_ARTIFACT_STORE_NAME,),
                )
                return cursor.fetchone() is not None
            case DatabaseBackend.POSTGRES:
                pg_conn = connection
                with pg_conn.cursor() as cursor:
                    cursor.execute(
                        "SELECT 1 FROM artifact_stores WHERE store_name = %s;",
                        (DEFAULT_ARTIFACT_STORE_NAME,),
                    )
                    return cursor.fetchone() is not None
        return False

    def _health_details(
        self,
        schema_version: int,
        missing_tables: list[str],
        unknown_sysdescr_present: bool,
        default_store_present: bool,
    ) -> str:
        if missing_tables:
            return f"Missing tables: {', '.join(missing_tables)}"
        if schema_version != SCHEMA_VERSION:
            return f"Schema version mismatch: {schema_version}"
        if not unknown_sysdescr_present:
            return "Missing UNKNOWN sysDescr seed row"
        if not default_store_present:
            return "Missing default artifact store row"
        return "Schema healthy"

    def _resolve_sqlite_db_path(self) -> Path:
        path = Path(str(self._sqlite_path))
        if path.is_absolute():
            return path
        return self._resolve_app_root() / path

    def _normalize_root_path(self, root_path: str) -> str:
        path = Path(root_path)
        if not path.is_absolute():
            return root_path
        app_root = self._resolve_app_root()
        if app_root in path.parents:
            return str(path.relative_to(app_root))
        self.logger.warning(
            "Artifact store root_path is absolute; portable paths are recommended: %s",
            root_path,
        )
        return root_path

    def _load_schema_sql(self) -> str:
        ddl_dir = self._resolve_ddl_dir()
        ddl_file = (
            _SQLITE_DDL_FILE
            if self._backend == DatabaseBackend.SQLITE
            else _POSTGRES_DDL_FILE
        )
        ddl_path = ddl_dir / ddl_file
        return ddl_path.read_text(encoding="utf-8")

    def _resolve_ddl_dir(self) -> Path:
        candidates = [Path(__file__).resolve(), Path.cwd().resolve()]
        for candidate in candidates:
            for parent in [candidate] + list(candidate.parents):
                ddl_dir = parent / "docs" / "design" / "db"
                if ddl_dir.is_dir():
                    return ddl_dir
        raise FileNotFoundError("Unable to locate docs/design/db for DDL assets")

    def _resolve_app_root(self) -> Path:
        cwd = Path.cwd().resolve()
        for parent in [cwd] + list(cwd.parents):
            if (parent / "pyproject.toml").is_file():
                return parent
        return cwd

# FILE: src/pypnm/lib/db/model/db_health_model.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pydantic import BaseModel, Field

from pypnm.lib.types import DatabaseBackend


class DatabaseHealthModel(BaseModel):
    """
    Database health status for schema diagnostics.
    """

    backend: DatabaseBackend = Field(..., description="Database backend under test")
    schema_version: int = Field(
        ..., description="Detected schema version (0 when missing)"
    )
    missing_tables: list[str] = Field(
        default_factory=list, description="Required tables that are missing"
    )
    unknown_sysdescr_present: bool = Field(
        ..., description="Whether the canonical UNKNOWN sysDescr row exists"
    )
    default_artifact_store_present: bool = Field(
        ..., description="Whether the default artifact store row exists"
    )
    ok: bool = Field(..., description="True when schema is healthy and complete")
    details: str = Field("", description="Diagnostic summary")

# FILE: tests/test_db_schema_manager.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import cast

from pypnm.lib.db.db_schema_manager import (
    DEFAULT_ARTIFACT_STORE_NAME,
    SCHEMA_VERSION,
    UNKNOWN_SYSDESCR_HASH,
    DatabaseSchemaManager,
)
from pypnm.lib.types import DatabaseBackend, DatabaseDsn, DatabasePath

SCHEMA_META_ID: int = 1
EXPECTED_UNKNOWN_COUNT: int = 1


def test_sqlite_schema_init_and_health(tmp_path: Path) -> None:
    db_path = tmp_path / "pypnm_schema.sqlite3"
    sqlite_path = cast(DatabasePath, str(db_path))
    postgres_dsn = cast(DatabaseDsn, "")
    manager = DatabaseSchemaManager.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )

    manager.initialize_schema()
    manager.initialize_schema()

    health = manager.health_check()
    assert health.ok is True
    assert health.schema_version == SCHEMA_VERSION
    assert health.missing_tables == []
    assert health.unknown_sysdescr_present is True
    assert health.default_artifact_store_present is True

    connection = sqlite3.connect(db_path)
    try:
        cursor = connection.execute(
            "SELECT schema_version FROM schema_meta WHERE schema_meta_id = ?;",
            (SCHEMA_META_ID,),
        )
        row = cursor.fetchone()
        assert row is not None
        assert int(row[0]) == SCHEMA_VERSION

        cursor = connection.execute(
            "SELECT COUNT(1) FROM system_description_dim WHERE sysdescr_hash = ?;",
            (UNKNOWN_SYSDESCR_HASH,),
        )
        row = cursor.fetchone()
        assert row is not None
        assert int(row[0]) == EXPECTED_UNKNOWN_COUNT

        cursor = connection.execute(
            "SELECT root_path FROM artifact_stores WHERE store_name = ?;",
            (DEFAULT_ARTIFACT_STORE_NAME,),
        )
        row = cursor.fetchone()
        assert row is not None
        assert str(row[0]).strip() != ""
    finally:
        connection.close()
