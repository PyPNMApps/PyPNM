## Agent Review Bundle Summary
- Goal: Flatten ingress cache layout so files are stored directly under the ingress dir.
- Changes: Removed transaction subdirectories in ingress paths; adjusted ingress lookup and tests; documented flat ingress layout.
- Files: docs/system/system-config.md, src/pypnm/pnm/lib/pnm_artifact_store.py, tests/test_pnm_artifact_store.py
- Tests: ruff check src; pytest -q
- Notes: Integration SNMP tests skipped (PNM_CM_IT=1 not set).
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
Ingress cache files are stored flat under the ingress directory (no transaction subdirectories).

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
# FILE: src/pypnm/pnm/lib/pnm_artifact_store.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from pypnm.api.routes.common.classes.file_capture.types import CompressionMetadataModel
from pypnm.config.config_manager import ConfigManager
from pypnm.config.pnm_artifact_storage import PnmArtifactStorageConfig
from pypnm.lib.compression.manager import CompressionManager
from pypnm.lib.system_call.manager import SystemCall
from pypnm.lib.types import FileNameStr, PathLike, TransactionId


@dataclass(frozen=True)
class ArtifactCommitResult:
    stored_filename: FileNameStr
    stored_path: Path
    compression: dict[str, object] | None
    size_before: int
    size_after: int


class PnmArtifactStore:
    """
    Manage at-rest compression and materialized caches for PNM artifacts.
    """

    _STAMP_SUFFIX = ".stamp.json"

    def __init__(self, config: PnmArtifactStorageConfig | None = None, pnm_dir: PathLike | None = None) -> None:
        """
        Initialize artifact storage with compression and cache configuration.

        Parameters
        ----------
        config:
            Optional explicit artifact storage configuration. When omitted,
            the config is loaded from the system configuration.
        pnm_dir:
            Optional override for the durable PNM storage root.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self._config = config or self._load_config()
        self._pnm_dir = Path(pnm_dir) if pnm_dir is not None else Path(self._load_pnm_dir())
        self._compression_manager = CompressionManager(SystemCall())
        self._tmp_root = Path(self._config.cache.tmp_root)
        self._ingress_dir = self._tmp_root / self._config.cache.ingress_dir
        self._materialized_dir = self._tmp_root / self._config.cache.materialized_dir
        self._last_cleanup = 0.0

        self._pnm_dir.mkdir(parents=True, exist_ok=True)
        self._ingress_dir.mkdir(parents=True, exist_ok=True)
        self._materialized_dir.mkdir(parents=True, exist_ok=True)

    def ingress_path(self, filename: FileNameStr, transaction_id: TransactionId | None = None) -> Path:
        """
        Return a writable ingress path for a capture file.

        Parameters
        ----------
        filename:
            Target filename for the ingress copy (normalized to raw filename).
        transaction_id:
            Optional transaction ID (ignored; ingress is a flat directory).

        Returns
        -------
        Path
            Filesystem path where callers can write the ingress artifact.
        """
        self._ingress_dir.mkdir(parents=True, exist_ok=True)
        return self._ingress_dir / self._normalize_ingress_name(filename)

    def ingress_candidate_path(self, filename: FileNameStr, transaction_id: TransactionId | None = None) -> Path:
        """
        Return the expected ingress path without creating directories.

        Parameters
        ----------
        filename:
            Target filename for the ingress copy (normalized to raw filename).
        transaction_id:
            Optional transaction ID (ignored; ingress is a flat directory).

        Returns
        -------
        Path
            Expected ingress location for the artifact.
        """
        return self._ingress_dir / self._normalize_ingress_name(filename)

    def find_ingress_by_filename(self, filename: FileNameStr) -> Path | None:
        """
        Search ingress cache for a filename, returning a unique match.

        Parameters
        ----------
        filename:
            Filename to search for (normalized to raw filename).

        Returns
        -------
        Path | None
            Matching ingress path when exactly one file is found; otherwise None.
        """
        target = self._normalize_ingress_name(filename)
        matches = list(self._ingress_dir.glob(target))
        if len(matches) == 1:
            return matches[0]
        return None

    @staticmethod
    def _normalize_ingress_name(filename: FileNameStr) -> str:
        name = Path(str(filename)).name
        if name.endswith(".zst"):
            return name[:-4]
        if name.endswith(".gz"):
            return name[:-3]
        return name

    def commit_ingress_file(
        self,
        pnm_type: str,
        ingress_path: Path,
        original_filename: FileNameStr,
    ) -> ArtifactCommitResult:
        """
        Commit an ingress file into the durable store with compression policy.

        Parameters
        ----------
        pnm_type:
            PNM type string used to evaluate compression policy.
        ingress_path:
            Filesystem path of the ingress artifact to commit.
        original_filename:
            Original filename used to derive the stored filename.

        Returns
        -------
        ArtifactCommitResult
            Commit metadata including stored filename, sizes, and compression info.
        """
        self._maybe_cleanup()

        if not ingress_path.is_file():
            raise FileNotFoundError(f"Ingress file not found: {ingress_path}")

        size_before = ingress_path.stat().st_size
        if not self._config.compression.enabled:
            return self._commit_raw(ingress_path, original_filename, size_before)

        if size_before < self._config.compression.min_bytes:
            return self._commit_raw(ingress_path, original_filename, size_before)

        policy = self._config.compression
        action = self._compression_action(pnm_type)

        if action == "deny":
            return self._commit_raw(ingress_path, original_filename, size_before)

        codec = self._compression_manager.select_codec(policy.primary_codec, policy.gzip_fallback)
        if codec is None:
            return self._commit_raw(ingress_path, original_filename, size_before)

        compressed_path = self._pnm_dir / f"{Path(str(original_filename)).name}.{codec}"
        tmp_path = self._pnm_dir / f".{compressed_path.name}.tmp"

        level = policy.zstd_level if codec == "zst" else policy.gzip_level
        self._compression_manager.compress(codec, ingress_path, tmp_path, level)

        size_after = tmp_path.stat().st_size
        ratio = size_after / size_before if size_before else 1.0
        savings = size_before - size_after

        if (
            action == "conditional"
            and ratio > policy.conditional_max_ratio
            and savings < policy.conditional_min_savings_bytes
        ):
            tmp_path.unlink(missing_ok=True)
            return self._commit_raw(ingress_path, original_filename, size_before)

        os.replace(tmp_path, compressed_path)

        compression = CompressionMetadataModel(
            is_compressed=True,
            codec="zstd" if codec == "zst" else "gzip",
            level=policy.zstd_level if codec == "zst" else policy.gzip_level,
            size_before=size_before,
            size_after=size_after,
        )
        return ArtifactCommitResult(
            stored_filename=FileNameStr(compressed_path.name),
            stored_path=compressed_path,
            compression=compression.model_dump(),
            size_before=size_before,
            size_after=size_after,
        )

    def resolve_physical_path(self, filename: FileNameStr, compression: dict[str, object] | None) -> Path:
        """
        Resolve the on-disk artifact path using filename and compression metadata.

        Parameters
        ----------
        filename:
            Stored filename as recorded in the transaction record.
        compression:
            Compression metadata dict, when available.

        Returns
        -------
        Path
            Best-effort resolved physical path on disk.
        """
        base = Path(str(filename)).name
        if compression and compression.get("is_compressed") is True:
            codec = self._codec_from_filename(base, compression)
            if codec == "zst":
                name = base if base.endswith(".zst") else f"{base}.zst"
                candidate = self._pnm_dir / name
                if candidate.is_file():
                    return candidate
            if codec == "gz":
                name = base if base.endswith(".gz") else f"{base}.gz"
                candidate = self._pnm_dir / name
                if candidate.is_file():
                    return candidate
            candidate = self._pnm_dir / base
            if candidate.is_file():
                return candidate

        raw_path = self._pnm_dir / base
        if raw_path.is_file():
            return raw_path

        zstd_path = self._pnm_dir / f"{base}.zst"
        if zstd_path.is_file():
            return zstd_path

        gzip_path = self._pnm_dir / f"{base}.gz"
        if gzip_path.is_file():
            return gzip_path

        return raw_path

    def materialize(
        self,
        transaction_id: TransactionId,
        filename: FileNameStr,
        compression: dict[str, object] | None,
    ) -> Path:
        """
        Provide a raw file path, materializing compressed artifacts into cache.

        Parameters
        ----------
        transaction_id:
            Transaction identifier for scoping the materialized cache path.
        filename:
            Stored filename as recorded in the transaction record.
        compression:
            Compression metadata dict, when available.

        Returns
        -------
        Path
            Path to a raw artifact, either the durable store or materialized cache.
        """
        self._maybe_cleanup()

        physical_path = self.resolve_physical_path(filename, compression)
        codec = self._codec_from_filename(physical_path.name, compression)
        if codec is None:
            return physical_path

        materialized_path = self._materialized_path(transaction_id, physical_path)
        stamp_path = Path(f"{materialized_path}{self._STAMP_SUFFIX}")

        if self._stamp_valid(stamp_path, physical_path, codec, materialized_path):
            return materialized_path

        self.logger.warning(
            "Uncompressed cache miss for transaction %s; raw file not cached, decompressing %s",
            transaction_id,
            physical_path,
        )
        materialized_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = materialized_path.with_name(f".{materialized_path.name}.tmp")

        self._compression_manager.decompress(codec, physical_path, tmp_path)

        os.replace(tmp_path, materialized_path)
        self._write_stamp(stamp_path, physical_path, codec)
        return materialized_path

    def read_bytes(
        self,
        transaction_id: TransactionId,
        filename: FileNameStr,
        compression: dict[str, object] | None,
    ) -> bytes:
        """
        Read artifact bytes, materializing into cache as needed.

        Parameters
        ----------
        transaction_id:
            Transaction identifier for cache scoping.
        filename:
            Stored filename as recorded in the transaction record.
        compression:
            Compression metadata dict, when available.

        Returns
        -------
        bytes
            Raw artifact bytes.
        """
        materialized = self.materialize(transaction_id, filename, compression)
        return materialized.read_bytes()

    def _load_config(self) -> PnmArtifactStorageConfig:
        """
        Load artifact storage configuration from system config.
        """
        config = ConfigManager().get("PnmArtifactStorage")
        return PnmArtifactStorageConfig.from_config(config if isinstance(config, dict) else None)

    def _load_pnm_dir(self) -> PathLike:
        """
        Load the configured PNM storage directory.
        """
        config = ConfigManager().get("PnmFileRetrieval", "pnm_dir")
        if isinstance(config, str) and config.strip():
            return config
        return ".data/pnm"

    def _compression_action(self, pnm_type: str) -> str:
        """
        Resolve the compression policy action for a PNM type.
        """
        policy = self._config.compression
        if pnm_type in policy.deny:
            return "deny"
        if pnm_type in policy.always:
            return "always"
        if pnm_type in policy.conditional:
            return "conditional"
        return "deny"

    @staticmethod
    def _raw_compression_metadata(size: int) -> CompressionMetadataModel:
        """
        Build compression metadata for uncompressed artifacts.
        """
        return CompressionMetadataModel(
            is_compressed=False,
            codec="none",
            level=0,
            size_before=size,
            size_after=size,
        )

    def _commit_raw(
        self,
        ingress_path: Path,
        original_filename: FileNameStr,
        size_before: int,
    ) -> ArtifactCommitResult:
        """
        Persist an uncompressed artifact into the durable store.
        """
        dest_path = self._pnm_dir / Path(str(original_filename)).name
        tmp_path = self._pnm_dir / f".{dest_path.name}.tmp"
        shutil.copy2(ingress_path, tmp_path)
        os.replace(tmp_path, dest_path)
        compression = self._raw_compression_metadata(size_before)
        return ArtifactCommitResult(
            stored_filename=FileNameStr(dest_path.name),
            stored_path=dest_path,
            compression=compression.model_dump(),
            size_before=size_before,
            size_after=size_before,
        )

    def _codec_from_filename(self, filename: str, compression: dict[str, object] | None) -> str | None:
        """
        Detect codec from metadata and filename extension.
        """
        if compression and compression.get("is_compressed") is True:
            codec = compression.get("codec")
            if isinstance(codec, str):
                if filename.endswith(".zst") and codec != "zstd":
                    self.logger.warning("Compression metadata codec '%s' conflicts with .zst extension", codec)
                if filename.endswith(".gz") and codec != "gzip":
                    self.logger.warning("Compression metadata codec '%s' conflicts with .gz extension", codec)
                return "zst" if codec == "zstd" else "gz" if codec == "gzip" else None
        if filename.endswith(".zst"):
            return "zst"
        if filename.endswith(".gz"):
            return "gz"
        return None

    def _is_compressed(self, compression: dict[str, object] | None, filename: str) -> bool:
        """
        Determine whether a file is compressed based on metadata or extension.
        """
        if compression and compression.get("is_compressed") is True:
            return True
        return filename.endswith(".zst") or filename.endswith(".gz")

    def _materialized_path(self, transaction_id: TransactionId, source_path: Path) -> Path:
        """
        Build the cache path for a materialized artifact copy.
        """
        digest = hashlib.sha256(str(source_path).encode()).hexdigest()[:12]
        name = source_path.name
        if name.endswith(".zst"):
            name = name[:-4]
        elif name.endswith(".gz"):
            name = name[:-3]
        return self._materialized_dir / str(transaction_id) / digest / name

    def _write_stamp(self, stamp_path: Path, source_path: Path, codec: str) -> None:
        """
        Write a cache stamp describing the source artifact.
        """
        payload = {
            "source_path": str(source_path),
            "source_mtime": source_path.stat().st_mtime,
            "source_size": source_path.stat().st_size,
            "codec": codec,
        }
        stamp_path.write_text(json.dumps(payload))

    def _stamp_valid(self, stamp_path: Path, source_path: Path, codec: str, materialized_path: Path) -> bool:
        """
        Validate a materialized cache stamp against the source artifact.
        """
        if not stamp_path.is_file() or not materialized_path.is_file():
            return False
        try:
            data = json.loads(stamp_path.read_text())
        except Exception:
            return False
        if data.get("source_path") != str(source_path):
            return False
        if data.get("source_mtime") != source_path.stat().st_mtime:
            return False
        if data.get("source_size") != source_path.stat().st_size:
            return False
        return data.get("codec") == codec

    def _maybe_cleanup(self) -> None:
        """
        Run cache cleanup on a configured cadence.
        """
        now = time.time()
        interval = self._config.cache.cleanup_interval_seconds
        if now - self._last_cleanup < interval:
            return
        self._cleanup_dir(self._ingress_dir, self._config.cache.ingress_ttl_seconds)
        self._cleanup_dir(self._materialized_dir, self._config.cache.materialized_ttl_seconds)
        self._last_cleanup = now

    def _cleanup_dir(self, root: Path, ttl_seconds: int) -> None:
        """
        Remove expired files and empty directories under a cache root.
        """
        if ttl_seconds <= 0:
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
# FILE: tests/test_pnm_artifact_store.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import os
import time
from pathlib import Path

from pypnm.config.pnm_artifact_storage import (
    ArtifactCacheConfig,
    ArtifactCompressionPolicyConfig,
    PnmArtifactStorageConfig,
)
from pypnm.lib.types import FileNameStr, TransactionId
from pypnm.pnm.lib.pnm_artifact_store import PnmArtifactStore


def _build_config(tmp_root: Path, min_bytes: int) -> PnmArtifactStorageConfig:
    return PnmArtifactStorageConfig(
        compression=ArtifactCompressionPolicyConfig(
            enabled=True,
            min_bytes=min_bytes,
            conditional_max_ratio=0.92,
            conditional_min_savings_bytes=8192,
            deny=[],
            always=["test_type"],
            conditional=[],
            primary_codec="gzip",
            gzip_fallback=False,
            zstd_level=3,
            gzip_level=6,
        ),
        cache=ArtifactCacheConfig(
            tmp_root=str(tmp_root),
            ingress_dir="ingress",
            materialized_dir="materialized",
            ingress_ttl_seconds=900,
            materialized_ttl_seconds=86400,
            cleanup_interval_seconds=0,
        ),
    )


def test_commit_ingress_file_gzip_compresses(tmp_path: Path) -> None:
    cfg = _build_config(tmp_path / "tmp", min_bytes=0)
    pnm_dir = tmp_path / "pnm"
    store = PnmArtifactStore(config=cfg, pnm_dir=pnm_dir)

    txn_id = TransactionId("tx1")
    ingress = store.ingress_path(FileNameStr("test.bin"), txn_id)
    ingress.write_bytes(b"0" * 10000)

    result = store.commit_ingress_file("test_type", ingress, FileNameStr("test.bin"))
    assert str(result.stored_filename).endswith(".gz")
    assert result.compression is not None
    assert result.compression.get("is_compressed") is True
    assert result.size_after < result.size_before


def test_commit_ingress_file_min_bytes_skips_compression(tmp_path: Path) -> None:
    cfg = _build_config(tmp_path / "tmp", min_bytes=20000)
    pnm_dir = tmp_path / "pnm"
    store = PnmArtifactStore(config=cfg, pnm_dir=pnm_dir)

    ingress = store.ingress_path(FileNameStr("test.bin"), TransactionId("tx2"))
    ingress.write_bytes(b"1" * 10000)

    result = store.commit_ingress_file("test_type", ingress, FileNameStr("test.bin"))
    assert str(result.stored_filename).endswith("test.bin")
    assert result.compression is not None
    assert result.compression.get("is_compressed") is False


def test_materialize_decompresses_gzip(tmp_path: Path) -> None:
    cfg = _build_config(tmp_path / "tmp", min_bytes=0)
    pnm_dir = tmp_path / "pnm"
    store = PnmArtifactStore(config=cfg, pnm_dir=pnm_dir)

    txn_id = TransactionId("tx3")
    ingress = store.ingress_path(FileNameStr("test.bin"), txn_id)
    payload = b"abc" * 5000
    ingress.write_bytes(payload)

    result = store.commit_ingress_file("test_type", ingress, FileNameStr("test.bin"))
    materialized = store.materialize(txn_id, result.stored_filename, result.compression)

    assert materialized.read_bytes() == payload


def test_resolve_physical_path_prefers_raw_when_missing_compressed(tmp_path: Path) -> None:
    cfg = _build_config(tmp_path / "tmp", min_bytes=0)
    pnm_dir = tmp_path / "pnm"
    store = PnmArtifactStore(config=cfg, pnm_dir=pnm_dir)

    raw_path = pnm_dir / "raw.bin"
    raw_path.write_bytes(b"raw")

    compression = {
        "is_compressed": True,
        "codec": "zstd",
        "level": 3,
        "size_before": 3,
        "size_after": 2,
    }
    resolved = store.resolve_physical_path(FileNameStr("raw.bin"), compression)
    assert resolved == raw_path


def test_cleanup_dir_keeps_recent_empty_dirs(tmp_path: Path) -> None:
    cfg = _build_config(tmp_path / "tmp", min_bytes=0)
    pnm_dir = tmp_path / "pnm"
    store = PnmArtifactStore(config=cfg, pnm_dir=pnm_dir)

    recent = store.ingress_path(FileNameStr("recent.bin"), TransactionId("recent"))
    recent.write_bytes(b"r")

    old_file = store.ingress_path(FileNameStr("old.bin"), TransactionId("old"))
    old_file.write_bytes(b"o")
    old_time = time.time() - 1000
    os.utime(old_file, (old_time, old_time))

    store._cleanup_dir(store._ingress_dir, ttl_seconds=900)

    assert recent.exists()
    assert not old_file.exists()
