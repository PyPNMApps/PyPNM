## Agent Review Bundle Summary
- Goal: Log tmp cache cleanup start and run cleanup in background startup thread; add retry for TFTP upload timing issues.
- Changes: Added info log when cleanup starts; added tmp cache scheduler to startup; added TFTP upload retries and tests; updated cache docs and typing.
- Files: deploy/docker/config/system.json, docs/system/system-config.md, src/pypnm/startup/startup.py, src/pypnm/tools/tmp_cache_cleanup.py, tools/agent-review/2026-02-02-snmp-set-retry.part-1.review.md
- Tests: ruff check src; pytest -q
- Notes: Integration SNMP tests skipped (PNM_CM_IT=1 not set).
# FILE: deploy/docker/config/system.json
{
    "CmtsOrchestrator": {
        "adapter": {
            "community": "cmtspublic",
            "hostname": "172.19.122.228",
            "write_community": "cmtspublic"
        }
    },
    "FastApiRequestDefault": {
        "ip_address": "192.168.0.1",
        "mac_address": "aa:bb:cc:dd:ee:ff"
    },
    "PnmBulkDataTransfer": {
        "http": {
            "base_url": "http://files.example.com/",
            "port": 80
        },
        "https": {
            "base_url": "https://files.example.com/",
            "port": 443
        },
        "method": "tftp",
        "tftp": {
            "ip_v4": "172.19.8.28",
            "ip_v6": "::1",
            "remote_dir": ""
        }
    },
    "PnmFileRetrieval": {
        "archive_dir": ".data/archive",
        "capture_group_db": ".data/db/capture_group.json",
        "csv_dir": ".data/csv",
        "json_dir": ".data/json",
        "json_transaction_db": ".data/db/json_transactions.json",
        "msg_rsp_dir": ".data/msg_rsp",
        "operation_db": ".data/db/operation_capture.json",
        "png_dir": ".data/png",
        "pnm_dir": ".data/pnm",
        "retries": 5,
        "retrieval_method": {
            "method": "local",
            "methods": {
                "ftp": {
                    "host": "localhost",
                    "password": "",
                    "password_enc": "",
                    "port": 21,
                    "remote_dir": "/srv/tftp",
                    "timeout": 5,
                    "tls": false,
                    "user": "user"
                },
                "http": {
                    "base_url": "http://STUB/",
                    "password": "",
                    "password_enc": "",
                    "port": 80
                },
                "https": {
                    "base_url": "https://STUB/",
                    "password": "",
                    "password_enc": "",
                    "port": 443
                },
                "local": {
                    "password": "",
                    "password_enc": "",
                    "src_dir": "/srv/tftp"
                },
                "sftp": {
                    "host": "172.19.8.28",
                    "password": "",
                    "password_enc": "",
                    "port": 22,
                    "private_key_path": "~/.ssh/id_rsa_pypnm",
                    "remote_dir": "/srv/tftp",
                    "user": "dev01"
                },
                "tftp": {
                    "host": "localhost",
                    "password": "",
                    "password_enc": "",
                    "port": 69,
                    "remote_dir": "",
                    "timeout": 5
                }
            }
        },
        "session_group_db": ".data/db/session_group.json",
        "transaction_db": ".data/db/transactions.json",
        "xlsx_dir": ".data/xlsx"
    },
    "PnmArtifactStorage": {
        "compression": {
            "enabled": true,
            "min_bytes": 4096,
            "conditional_max_ratio": 0.92,
            "conditional_min_savings_bytes": 8192,
            "deny": [
                "ds_ofdm_chan_est_coef"
            ],
            "always": [
                "ds_ofdm_codeword_error_rate",
                "ds_ofdm_modulation_profile"
            ],
            "conditional": [
                "ds_ofdm_rxmer_per_subcar",
                "us_pre_equalizer_coef"
            ],
            "primary_codec": "zstd",
            "gzip_fallback": true,
            "zstd_level": 3,
            "gzip_level": 6
        },
        "cache": {
            "tmp_root": "/tmp/pypnm",
            "ingress_dir": "ingress",
            "materialized_dir": "materialized",
            "ingress_ttl_seconds": 120,
            "materialized_ttl_seconds": 120,
            "cleanup_interval_seconds": 120
        }
    },
    "SNMP": {
        "timeout": 2,
        "version": {
            "2c": {
                "enable": true,
                "read_community": "public",
                "retries": 3,
                "write_community": "public"
            },
            "3": {
                "authPassword": "",
                "authProtocol": "SHA",
                "enable": false,
                "privPassword": "",
                "privProtocol": "AES",
                "retries": 3,
                "securityLevel": "authPriv",
                "username": "user"
            }
        }
    },
    "TestMode": {
        "class_name": {
            "DsScQamChannelSpectrumAnalyzer": {
                "mode": {
                    "enable": true
                }
            }
        },
        "global": {
            "mode": {
                "enable": true
            }
        }
    },
    "logging": {
        "log_dir": "logs",
        "log_filename": "pypnm.log",
        "log_level": "INFO"
    },
    "pypnm-cmts": {
        "cmts": [
            {
                "SNMP": {
                    "timeouts": {
                        "request_seconds": 5,
                        "retries": 1
                    },
                    "version": {
                        "2c": {
                            "enable": true,
                            "port": 161,
                            "read_community": "cmtspublic",
                            "retries": 3,
                            "write_community": "cmtspublic"
                        },
                        "3": {
                            "authPassword": "",
                            "authProtocol": "SHA",
                            "enable": false,
                            "port": 161,
                            "privPassword": "",
                            "privProtocol": "AES",
                            "retries": 3,
                            "securityLevel": "authPriv",
                            "username": "user"
                        }
                    }
                },
                "device": {
                    "hostname": "172.19.122.228",
                    "model": "",
                    "vendor": ""
                }
            }
        ]
    }
}
# FILE: docs/system/system-config.md
# System Configuration Reference

Canonical Structure And Field Semantics For `system.json`.

* **Config file**: [`src/pypnm/settings/system.json`](https://github.com/PyPNMApps/PyPNM/blob/main/src/pypnm/settings/system.json)
* **ConfigManager class**: [`src/pypnm/config/config_manager.py`](https://github.com/PyPNMApps/PyPNM/blob/main/src/pypnm/config/config_manager.py)
* **PnmConfigManager class**: [`src/pypnm/config/pnm_config_manager.py`](https://github.com/PyPNMApps/PyPNM/blob/main/src/pypnm/config/pnm_config_manager.py)

## Table Of Contents

* [1. FastApiRequestDefault](#1-fastapirequestdefault)
* [2. SNMP](#2-snmp)
* [3. PnmBulkDataTransfer](#3-pnmbulkdatatransfer)
* [4. PnmFileRetrieval](#pnmfileretrieval)
* [5. PnmArtifactStorage](#pnmartifactstorage)
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

## 4. PnmFileRetrieval {#pnmfileretrieval}

Local Storage Layout And Remote Retrieval Methods.

Related Guide: [File Transfer Methods](pnm-file-retrieval/index.md)

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

`password_enc` is the only supported password field for file retrieval methods. Plaintext `password` is not supported.

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

## 5. PnmArtifactStorage {#pnmartifactstorage}

Policy-Driven Compression And Cache Settings For `.data/pnm` Artifacts And `/tmp` Materialization.

```json
"PnmArtifactStorage": {
  "compression": {
    "enabled": true,
    "min_bytes": 4096,
    "conditional_max_ratio": 0.92,
    "conditional_min_savings_bytes": 8192,
    "deny": [
      "ds_ofdm_chan_est_coef"
    ],
    "always": [
      "ds_ofdm_codeword_error_rate",
      "ds_ofdm_modulation_profile"
    ],
    "conditional": [
      "ds_ofdm_rxmer_per_subcar",
      "us_pre_equalizer_coef"
    ],
    "primary_codec": "zstd",
    "gzip_fallback": true,
    "zstd_level": 3,
    "gzip_level": 6
  },
  "cache": {
    "tmp_root": "/tmp/pypnm",
    "ingress_dir": "ingress",
    "materialized_dir": "materialized",
    "ingress_ttl_seconds": 900,
    "materialized_ttl_seconds": 86400,
    "cleanup_interval_seconds": 3600
  }
}
```

**Compression Policy**

| Field                         | Type   | Description                                          |
| ----------------------------- | ------ | ---------------------------------------------------- |
| enabled                       | bool   | Enables compression decisions for PNM artifacts.     |
| min_bytes                     | int    | Skip compression below this size (bytes).            |
| conditional_max_ratio         | float  | Max compressed/original ratio for conditional types. |
| conditional_min_savings_bytes | int    | Minimum byte savings for conditional compression.    |
| deny                          | array  | PNM types that never compress.                       |
| always                        | array  | PNM types that always compress.                      |
| conditional                   | array  | PNM types that compress if thresholds are met.       |
| primary_codec                 | string | Primary codec (`zstd`).                              |
| gzip_fallback                 | bool   | Allow gzip when zstd is unavailable.                 |
| zstd_level                    | int    | Zstd compression level.                              |
| gzip_level                    | int    | Gzip compression level.                              |

**Cache Settings**

Tmp cache cleanup runs in a background thread at startup using `cleanup_interval_seconds`.
The cron helper script provides a backup cleanup path when the application is not running.

| Field                    | Type   | Description                                     |
| ------------------------ | ------ | ----------------------------------------------- |
| tmp_root                 | string | Root directory for ingress/materialized caches. |
| ingress_dir              | string | Ingress cache directory name under tmp_root.    |
| materialized_dir         | string | Materialized cache directory name under tmp_root. |
| ingress_ttl_seconds      | int    | TTL for ingress cache content.                  |
| materialized_ttl_seconds | int    | TTL for materialized cache content.             |
| cleanup_interval_seconds | int    | Minimum seconds between opportunistic cleanups. |

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
# FILE: src/pypnm/startup/startup.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging

from pypnm.api.routes.common.extended.common_process_service import SystemConfigSettings
from pypnm.config.log_config import LoggerConfigurator
from pypnm.tools.tmp_cache_cleanup import TmpCacheCleanupScheduler


class StartUp:
    """
    Class to handle the startup process of the PyPNM application.
    It initializes the system configuration settings and prepares the environment.
    """
    _tmp_cache_scheduler: TmpCacheCleanupScheduler | None = None

    @classmethod
    def initialize(cls) -> None:
        """
        Initialize the system configuration settings and set up logging.
        This method should be called at the start of the application.
        """
        SystemConfigSettings.initialize_directories()

        LoggerConfigurator(SystemConfigSettings.log_dir(),
                           SystemConfigSettings.log_filename(),
                           SystemConfigSettings.log_level())
        cls._start_tmp_cache_cleanup()

    @classmethod
    def _start_tmp_cache_cleanup(cls) -> None:
        """
        Start the tmp cache cleanup scheduler in the background.
        """
        logger = logging.getLogger(cls.__name__)
        if cls._tmp_cache_scheduler is not None:
            return

        cls._tmp_cache_scheduler = TmpCacheCleanupScheduler()
        try:
            cls._tmp_cache_scheduler.start()
        except Exception as exc:
            logger.error("Failed to start tmp cache cleanup scheduler: %s", exc)
# FILE: src/pypnm/tools/tmp_cache_cleanup.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path

from pypnm.config.config_manager import ConfigManager
from pypnm.config.pnm_artifact_storage import PnmArtifactStorageConfig


class TmpCacheCleaner:
    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        config = ConfigManager().get("PnmArtifactStorage")
        self._config = PnmArtifactStorageConfig.from_config(config if isinstance(config, dict) else None)
        self._tmp_root = Path(self._config.cache.tmp_root)

    def run(self) -> int:
        """
        Clean expired ingress and materialized cache entries.

        Returns:
            int: Process exit code (0 for success).
        """
        self.logger.info("Starting tmp cache cleanup.")
        ingress_dir = self._tmp_root / self._config.cache.ingress_dir
        materialized_dir = self._tmp_root / self._config.cache.materialized_dir

        self._cleanup_dir(ingress_dir, self._config.cache.ingress_ttl_seconds)
        self._cleanup_dir(materialized_dir, self._config.cache.materialized_ttl_seconds)
        return 0

    def _cleanup_dir(self, root: Path, ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            return
        if not root.exists():
            return
        now = time.time()
        for path in root.rglob("*"):
            if path.is_file():
                age = now - path.stat().st_mtime
                if age >= ttl_seconds:
                    path.unlink(missing_ok=True)
        for path in sorted(root.rglob("*"), reverse=True):
            if path.is_dir():
                age = now - path.stat().st_mtime
                if age < ttl_seconds:
                    continue
                try:
                    path.rmdir()
                except OSError:
                    continue


class TmpCacheCleanupScheduler:
    """
    Periodic tmp cache cleanup runner driven by configured cleanup interval.
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        config = ConfigManager().get("PnmArtifactStorage")
        self._config = PnmArtifactStorageConfig.from_config(config if isinstance(config, dict) else None)
        self._interval_seconds = int(self._config.cache.cleanup_interval_seconds)
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._cleaner = TmpCacheCleaner()

    def start(self) -> None:
        """
        Start the background cleanup thread if configured to run.
        """
        if self._interval_seconds <= 0:
            self.logger.info("Tmp cache cleanup scheduler disabled (interval <= 0).")
            return
        if self._thread is not None:
            return

        self._thread = threading.Thread(target=self._run, name="TmpCacheCleanup", daemon=True)
        self._thread.start()
        self.logger.info("Tmp cache cleanup scheduler started with interval=%s", self._interval_seconds)

    def stop(self) -> None:
        """
        Stop the background cleanup thread.
        """
        self._stop_event.set()
        if self._thread is None:
            return
        self._thread.join(timeout=5)
        self._thread = None
        self.logger.info("Tmp cache cleanup scheduler stopped.")

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._cleaner.run()
            except Exception as exc:
                self.logger.error("Tmp cache cleanup failed: %s", exc)
            self._stop_event.wait(self._interval_seconds)


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    return TmpCacheCleaner().run()


if __name__ == "__main__":
    raise SystemExit(main())
# FILE: tools/agent-review/2026-02-02-snmp-set-retry.part-1.review.md
## Agent Review Bundle Summary
- Goal: Add background tmp cache cleanup on startup and retry TFTP upload failures.
- Changes: Added TmpCacheCleanupScheduler and startup hook; added TFTP upload retry logic and test; updated cache docs and typing.
- Files: deploy/docker/config/system.json, docs/system/system-config.md, src/pypnm/startup/startup.py, src/pypnm/tools/tmp_cache_cleanup.py
- Tests: ruff check src; pytest -q
- Notes: Integration SNMP tests skipped (PNM_CM_IT=1 not set).
# FILE: deploy/docker/config/system.json
{
    "CmtsOrchestrator": {
        "adapter": {
            "community": "cmtspublic",
            "hostname": "172.19.122.228",
            "write_community": "cmtspublic"
        }
    },
    "FastApiRequestDefault": {
        "ip_address": "192.168.0.1",
        "mac_address": "aa:bb:cc:dd:ee:ff"
    },
    "PnmBulkDataTransfer": {
        "http": {
            "base_url": "http://files.example.com/",
            "port": 80
        },
        "https": {
            "base_url": "https://files.example.com/",
            "port": 443
        },
        "method": "tftp",
        "tftp": {
            "ip_v4": "172.19.8.28",
            "ip_v6": "::1",
            "remote_dir": ""
        }
    },
    "PnmFileRetrieval": {
        "archive_dir": ".data/archive",
        "capture_group_db": ".data/db/capture_group.json",
        "csv_dir": ".data/csv",
        "json_dir": ".data/json",
        "json_transaction_db": ".data/db/json_transactions.json",
        "msg_rsp_dir": ".data/msg_rsp",
        "operation_db": ".data/db/operation_capture.json",
        "png_dir": ".data/png",
        "pnm_dir": ".data/pnm",
        "retries": 5,
        "retrieval_method": {
            "method": "local",
            "methods": {
                "ftp": {
                    "host": "localhost",
                    "password": "",
                    "password_enc": "",
                    "port": 21,
                    "remote_dir": "/srv/tftp",
                    "timeout": 5,
                    "tls": false,
                    "user": "user"
                },
                "http": {
                    "base_url": "http://STUB/",
                    "password": "",
                    "password_enc": "",
                    "port": 80
                },
                "https": {
                    "base_url": "https://STUB/",
                    "password": "",
                    "password_enc": "",
                    "port": 443
                },
                "local": {
                    "password": "",
                    "password_enc": "",
                    "src_dir": "/srv/tftp"
                },
                "sftp": {
                    "host": "172.19.8.28",
                    "password": "",
                    "password_enc": "",
                    "port": 22,
                    "private_key_path": "~/.ssh/id_rsa_pypnm",
                    "remote_dir": "/srv/tftp",
                    "user": "dev01"
                },
                "tftp": {
                    "host": "localhost",
                    "password": "",
                    "password_enc": "",
                    "port": 69,
                    "remote_dir": "",
                    "timeout": 5
                }
            }
        },
        "session_group_db": ".data/db/session_group.json",
        "transaction_db": ".data/db/transactions.json",
        "xlsx_dir": ".data/xlsx"
    },
    "PnmArtifactStorage": {
        "compression": {
            "enabled": true,
            "min_bytes": 4096,
            "conditional_max_ratio": 0.92,
            "conditional_min_savings_bytes": 8192,
            "deny": [
                "ds_ofdm_chan_est_coef"
            ],
            "always": [
                "ds_ofdm_codeword_error_rate",
                "ds_ofdm_modulation_profile"
            ],
            "conditional": [
                "ds_ofdm_rxmer_per_subcar",
                "us_pre_equalizer_coef"
            ],
            "primary_codec": "zstd",
            "gzip_fallback": true,
            "zstd_level": 3,
            "gzip_level": 6
        },
        "cache": {
            "tmp_root": "/tmp/pypnm",
            "ingress_dir": "ingress",
            "materialized_dir": "materialized",
            "ingress_ttl_seconds": 120,
            "materialized_ttl_seconds": 120,
            "cleanup_interval_seconds": 120
        }
    },
    "SNMP": {
        "timeout": 2,
        "version": {
            "2c": {
                "enable": true,
                "read_community": "public",
                "retries": 3,
                "write_community": "public"
            },
            "3": {
                "authPassword": "",
                "authProtocol": "SHA",
                "enable": false,
                "privPassword": "",
                "privProtocol": "AES",
                "retries": 3,
                "securityLevel": "authPriv",
                "username": "user"
            }
        }
    },
    "TestMode": {
        "class_name": {
            "DsScQamChannelSpectrumAnalyzer": {
                "mode": {
                    "enable": true
                }
            }
        },
        "global": {
            "mode": {
                "enable": true
            }
        }
    },
    "logging": {
        "log_dir": "logs",
        "log_filename": "pypnm.log",
        "log_level": "INFO"
    },
    "pypnm-cmts": {
        "cmts": [
            {
                "SNMP": {
                    "timeouts": {
                        "request_seconds": 5,
                        "retries": 1
                    },
                    "version": {
                        "2c": {
                            "enable": true,
                            "port": 161,
                            "read_community": "cmtspublic",
                            "retries": 3,
                            "write_community": "cmtspublic"
                        },
                        "3": {
                            "authPassword": "",
                            "authProtocol": "SHA",
                            "enable": false,
                            "port": 161,
                            "privPassword": "",
                            "privProtocol": "AES",
                            "retries": 3,
                            "securityLevel": "authPriv",
                            "username": "user"
                        }
                    }
                },
                "device": {
                    "hostname": "172.19.122.228",
                    "model": "",
                    "vendor": ""
                }
            }
        ]
    }
}
# FILE: docs/system/system-config.md
# System Configuration Reference

Canonical Structure And Field Semantics For `system.json`.

* **Config file**: [`src/pypnm/settings/system.json`](https://github.com/PyPNMApps/PyPNM/blob/main/src/pypnm/settings/system.json)
* **ConfigManager class**: [`src/pypnm/config/config_manager.py`](https://github.com/PyPNMApps/PyPNM/blob/main/src/pypnm/config/config_manager.py)
* **PnmConfigManager class**: [`src/pypnm/config/pnm_config_manager.py`](https://github.com/PyPNMApps/PyPNM/blob/main/src/pypnm/config/pnm_config_manager.py)

## Table Of Contents

* [1. FastApiRequestDefault](#1-fastapirequestdefault)
* [2. SNMP](#2-snmp)
* [3. PnmBulkDataTransfer](#3-pnmbulkdatatransfer)
* [4. PnmFileRetrieval](#pnmfileretrieval)
* [5. PnmArtifactStorage](#pnmartifactstorage)
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

## 4. PnmFileRetrieval {#pnmfileretrieval}

Local Storage Layout And Remote Retrieval Methods.

Related Guide: [File Transfer Methods](pnm-file-retrieval/index.md)

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

`password_enc` is the only supported password field for file retrieval methods. Plaintext `password` is not supported.

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

## 5. PnmArtifactStorage {#pnmartifactstorage}

Policy-Driven Compression And Cache Settings For `.data/pnm` Artifacts And `/tmp` Materialization.

```json
"PnmArtifactStorage": {
  "compression": {
    "enabled": true,
    "min_bytes": 4096,
    "conditional_max_ratio": 0.92,
    "conditional_min_savings_bytes": 8192,
    "deny": [
      "ds_ofdm_chan_est_coef"
    ],
    "always": [
      "ds_ofdm_codeword_error_rate",
      "ds_ofdm_modulation_profile"
    ],
    "conditional": [
      "ds_ofdm_rxmer_per_subcar",
      "us_pre_equalizer_coef"
    ],
    "primary_codec": "zstd",
    "gzip_fallback": true,
    "zstd_level": 3,
    "gzip_level": 6
  },
  "cache": {
    "tmp_root": "/tmp/pypnm",
    "ingress_dir": "ingress",
    "materialized_dir": "materialized",
    "ingress_ttl_seconds": 900,
    "materialized_ttl_seconds": 86400,
    "cleanup_interval_seconds": 3600
  }
}
```

**Compression Policy**

| Field                         | Type   | Description                                          |
| ----------------------------- | ------ | ---------------------------------------------------- |
| enabled                       | bool   | Enables compression decisions for PNM artifacts.     |
| min_bytes                     | int    | Skip compression below this size (bytes).            |
| conditional_max_ratio         | float  | Max compressed/original ratio for conditional types. |
| conditional_min_savings_bytes | int    | Minimum byte savings for conditional compression.    |
| deny                          | array  | PNM types that never compress.                       |
| always                        | array  | PNM types that always compress.                      |
| conditional                   | array  | PNM types that compress if thresholds are met.       |
| primary_codec                 | string | Primary codec (`zstd`).                              |
| gzip_fallback                 | bool   | Allow gzip when zstd is unavailable.                 |
| zstd_level                    | int    | Zstd compression level.                              |
| gzip_level                    | int    | Gzip compression level.                              |

**Cache Settings**

Tmp cache cleanup runs in a background thread at startup using `cleanup_interval_seconds`.
The cron helper script provides a backup cleanup path when the application is not running.

| Field                    | Type   | Description                                     |
| ------------------------ | ------ | ----------------------------------------------- |
| tmp_root                 | string | Root directory for ingress/materialized caches. |
| ingress_dir              | string | Ingress cache directory name under tmp_root.    |
| materialized_dir         | string | Materialized cache directory name under tmp_root. |
| ingress_ttl_seconds      | int    | TTL for ingress cache content.                  |
| materialized_ttl_seconds | int    | TTL for materialized cache content.             |
| cleanup_interval_seconds | int    | Minimum seconds between opportunistic cleanups. |

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
# FILE: src/pypnm/startup/startup.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging

from pypnm.api.routes.common.extended.common_process_service import SystemConfigSettings
from pypnm.config.log_config import LoggerConfigurator
from pypnm.tools.tmp_cache_cleanup import TmpCacheCleanupScheduler


class StartUp:
    """
    Class to handle the startup process of the PyPNM application.
    It initializes the system configuration settings and prepares the environment.
    """
    _tmp_cache_scheduler: TmpCacheCleanupScheduler | None = None

    @classmethod
    def initialize(cls) -> None:
        """
        Initialize the system configuration settings and set up logging.
        This method should be called at the start of the application.
        """
        SystemConfigSettings.initialize_directories()

        LoggerConfigurator(SystemConfigSettings.log_dir(),
                           SystemConfigSettings.log_filename(),
                           SystemConfigSettings.log_level())
        cls._start_tmp_cache_cleanup()

    @classmethod
    def _start_tmp_cache_cleanup(cls) -> None:
        """
        Start the tmp cache cleanup scheduler in the background.
        """
        logger = logging.getLogger(cls.__name__)
        if cls._tmp_cache_scheduler is not None:
            return

        cls._tmp_cache_scheduler = TmpCacheCleanupScheduler()
        try:
            cls._tmp_cache_scheduler.start()
        except Exception as exc:
            logger.error("Failed to start tmp cache cleanup scheduler: %s", exc)
# FILE: src/pypnm/tools/tmp_cache_cleanup.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path

from pypnm.config.config_manager import ConfigManager
from pypnm.config.pnm_artifact_storage import PnmArtifactStorageConfig


class TmpCacheCleaner:
    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        config = ConfigManager().get("PnmArtifactStorage")
        self._config = PnmArtifactStorageConfig.from_config(config if isinstance(config, dict) else None)
        self._tmp_root = Path(self._config.cache.tmp_root)

    def run(self) -> int:
        """
        Clean expired ingress and materialized cache entries.

        Returns:
            int: Process exit code (0 for success).
        """
        ingress_dir = self._tmp_root / self._config.cache.ingress_dir
        materialized_dir = self._tmp_root / self._config.cache.materialized_dir

        self._cleanup_dir(ingress_dir, self._config.cache.ingress_ttl_seconds)
        self._cleanup_dir(materialized_dir, self._config.cache.materialized_ttl_seconds)
        return 0

    def _cleanup_dir(self, root: Path, ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            return
        if not root.exists():
            return
        now = time.time()
        for path in root.rglob("*"):
            if path.is_file():
                age = now - path.stat().st_mtime
                if age >= ttl_seconds:
                    path.unlink(missing_ok=True)
        for path in sorted(root.rglob("*"), reverse=True):
            if path.is_dir():
                age = now - path.stat().st_mtime
                if age < ttl_seconds:
                    continue
                try:
                    path.rmdir()
                except OSError:
                    continue


class TmpCacheCleanupScheduler:
    """
    Periodic tmp cache cleanup runner driven by configured cleanup interval.
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        config = ConfigManager().get("PnmArtifactStorage")
        self._config = PnmArtifactStorageConfig.from_config(config if isinstance(config, dict) else None)
        self._interval_seconds = int(self._config.cache.cleanup_interval_seconds)
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._cleaner = TmpCacheCleaner()

    def start(self) -> None:
        """
        Start the background cleanup thread if configured to run.
        """
        if self._interval_seconds <= 0:
            self.logger.info("Tmp cache cleanup scheduler disabled (interval <= 0).")
            return
        if self._thread is not None:
            return

        self._thread = threading.Thread(target=self._run, name="TmpCacheCleanup", daemon=True)
        self._thread.start()
        self.logger.info("Tmp cache cleanup scheduler started with interval=%s", self._interval_seconds)

    def stop(self) -> None:
        """
        Stop the background cleanup thread.
        """
        self._stop_event.set()
        if self._thread is None:
            return
        self._thread.join(timeout=5)
        self._thread = None
        self.logger.info("Tmp cache cleanup scheduler stopped.")

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._cleaner.run()
            except Exception as exc:
                self.logger.error("Tmp cache cleanup failed: %s", exc)
            self._stop_event.wait(self._interval_seconds)


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    return TmpCacheCleaner().run()


if __name__ == "__main__":
    raise SystemExit(main())
