## Agent Review Bundle Summary
- Goal: Remove runtime references to capture_group/operation JSON ledgers and mark legacy config keys as deprecated/ignored in docs and config warnings.
- Changes: Added one-time deprecation warnings for capture_group_db and operation_db, removed ledger paths from example config and docs, and updated M4 burndown wording to avoid JSON ledger file references.
- Files: src/pypnm/config/system_config_settings.py; src/pypnm/examples/settings/system.json; docs/system/system-config.md; docs/issues/index.md; docs/design/db/database-backend-burndown.md.
- Tests: python3 -m compileall src; ruff check .; ruff format --check .; pytest -q (596 passed, 9 skipped).
- Notes: Skips due to PYPNM_DB_POSTGRES_DSN unset and PNM_CM_IT integration tests disabled.

# FILE: src/pypnm/config/system_config_settings.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import cast

from pydantic import ValidationError

from pypnm.config.config_manager import ConfigManager
from pypnm.config.database_settings import (
    DEFAULT_POSTGRES_DSN,
    DEFAULT_SQLITE_DB_PATH,
    POSTGRES_DSN_ENV_VAR,
    DatabaseSettings,
)
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.secret.crypto_manager import SecretCryptoError, SecretCryptoManager
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    FileNameStr,
    InetAddressStr,
    IPv4Str,
    IPv6Str,
    MacAddressStr,
    SnmpReadCommunity,
    SnmpWriteCommunity,
)


class SystemConfigSettings:
    """Provides dynamically reloaded system configuration via class properties."""

    _cfg = ConfigManager()
    _logger = logging.getLogger("SystemConfigSettings")
    _deprecated_ledger_warned: set[str] = set()

    _DEFAULT_IP_ADDRESS: InetAddressStr = cast(InetAddressStr, "192.168.0.100")
    _DEFAULT_SNMP_RETRIES: int = 5
    _DEFAULT_SNMP_TIMEOUT: int = 2
    _DEFAULT_FILE_RETRIEVAL_RETRIES: int = 5
    _DEFAULT_HTTP_PORT: int = 80
    _DEFAULT_HTTPS_PORT: int = 443
    _DEFAULT_TFTP_PORT: int = 69
    _DEFAULT_FTP_PORT: int = 21
    _DEFAULT_SFTP_PORT: int = 22
    _DEFAULT_SCP_PORT: int = 22
    _DEFAULT_LOG_LEVEL: str = "INFO"
    _DEFAULT_LOG_DIR: str = "logs"
    _DEFAULT_LOG_FILENAME: str = "pypnm.log"
    _DEFAULT_SNMP_READ_COMMUNITY: str = "public"
    _DEFAULT_SNMP_WRITE_COMMUNITY: str = ""
    _DEFAULT_PNM_DIR: str = ".data/pnm"
    _DEFAULT_CSV_DIR: str = ".data/csv"
    _DEFAULT_JSON_DIR: str = ".data/json"
    _DEFAULT_XLSX_DIR: str = ".data/xlsx"
    _DEFAULT_PNG_DIR: str = ".data/png"
    _DEFAULT_ARCHIVE_DIR: str = ".data/archive"
    _DEFAULT_MSG_RSP_DIR: str = ".data/msg_rsp"
    _DEFAULT_DB_BACKEND: DatabaseBackend = DatabaseBackend.SQLITE
    _DEFAULT_SQLITE_DB_PATH: DatabasePath = DEFAULT_SQLITE_DB_PATH
    _DEFAULT_POSTGRES_DSN: DatabaseDsn = DEFAULT_POSTGRES_DSN
    _POSTGRES_DSN_ENV_VAR: str = POSTGRES_DSN_ENV_VAR
    _DB_BACKEND_ENV_VAR: str = "PYPNM_DB_BACKEND"

    _ENCRYPTED_TOKEN_PREFIX: str = "ENC["

    _PRIMARY_RETRIEVAL_METHOD_KEY: str = "retrieval_method"
    _LEGACY_RETRIEVAL_METHOD_KEY: str = "retrival_method"

    @classmethod
    def _config_path(cls, *path: str) -> str:
        """Return dotted path for logging."""
        return ".".join(path)

    @classmethod
    def _postgres_dsn_env_override(cls) -> str:
        value = os.getenv(cls._POSTGRES_DSN_ENV_VAR, "")
        return value.strip()

    @classmethod
    def _db_backend_env_override(cls) -> str:
        value = os.getenv(cls._DB_BACKEND_ENV_VAR, "")
        normalized = value.strip().lower()
        if normalized == "":
            return ""
        if normalized in (DatabaseBackend.SQLITE.value, DatabaseBackend.POSTGRES.value):
            return normalized
        cls._logger.error(
            "Invalid %s value '%s'; expected sqlite or postgres",
            cls._DB_BACKEND_ENV_VAR,
            value,
        )
        return ""

    @classmethod
    def _peek_str(cls, *path: str) -> str:
        value = cls._cfg.get(*path)
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        return str(value)

    @classmethod
    def _peek_str_fallback(
        cls, primary: tuple[str, ...], legacy: tuple[str, ...]
    ) -> str:
        value = cls._cfg.get(*primary)
        if value is not None:
            if isinstance(value, str):
                return value
            return str(value)
        return cls._peek_str(*legacy)

    @classmethod
    def _maybe_decrypt(cls, value: str, *path: str) -> str:
        text = value.strip()
        if text == "":
            return ""
        if not text.startswith(cls._ENCRYPTED_TOKEN_PREFIX):
            return text
        try:
            return SecretCryptoManager.decrypt_password(text)
        except SecretCryptoError as exc:
            cls._logger.error(
                "Failed to decrypt configuration value for '%s': %s",
                cls._config_path(*path),
                exc,
            )
            return ""

    @classmethod
    def _get_password_value(cls, require: bool, *method_path: str) -> str:
        password_enc = cls._peek_str(*method_path, "password_enc")
        if password_enc.strip() != "":
            decrypted = cls._maybe_decrypt(password_enc, *method_path, "password_enc")
            if decrypted != "":
                return decrypted
            if require:
                return ""

        password = cls._peek_str(*method_path, "password")
        if password.strip() == "":
            if require:
                cls._logger.error(
                    "Missing configuration value for '%s'; expected password or password_enc",
                    cls._config_path(*method_path, "password"),
                )
            return ""

        cls._logger.warning(
            "Using legacy plaintext password for '%s'; prefer password_enc",
            cls._config_path(*method_path, "password"),
        )
        return cls._maybe_decrypt(password, *method_path, "password")

    @classmethod
    def _get_password_value_fallback(
        cls, require: bool, primary: tuple[str, ...], legacy: tuple[str, ...]
    ) -> str:
        password_enc = cls._peek_str_fallback(
            primary + ("password_enc",), legacy + ("password_enc",)
        )
        if password_enc.strip() != "":
            decrypted = cls._maybe_decrypt(password_enc, *(primary + ("password_enc",)))
            if decrypted != "":
                return decrypted
            if require:
                return ""

        password = cls._peek_str_fallback(
            primary + ("password",), legacy + ("password",)
        )
        if password.strip() == "":
            if require:
                cls._logger.error(
                    "Missing configuration value for '%s'; expected password or password_enc",
                    cls._config_path(*(primary + ("password",))),
                )
            return ""

        cls._logger.warning(
            "Using legacy plaintext password for '%s'; prefer password_enc",
            cls._config_path(*(primary + ("password",))),
        )
        return cls._maybe_decrypt(password, *(primary + ("password",)))

    @classmethod
    def _get_str(cls, default: str, *path: str) -> str:
        value = cls._cfg.get(*path)
        if value is None:
            cls._logger.error(
                "Missing configuration value for '%s'; using default '%s'",
                cls._config_path(*path),
                default,
            )
            return default
        if not isinstance(value, str):
            coerced = str(value)
            cls._logger.error(
                "Non-string configuration value for '%s': %r; using coerced '%s'",
                cls._config_path(*path),
                value,
                coerced,
            )
            return coerced
        if value == "":
            cls._logger.error(
                "Empty configuration value for '%s'; using default '%s'",
                cls._config_path(*path),
                default,
            )
            return default
        return value

    @classmethod
    def _get_str_fallback(
        cls, default: str, primary: tuple[str, ...], legacy: tuple[str, ...]
    ) -> str:
        value = cls._cfg.get(*primary)
        if value is not None:
            if isinstance(value, str) and value != "":
                return value
            if not isinstance(value, str):
                coerced = str(value)
                cls._logger.error(
                    "Non-string configuration value for '%s': %r; using coerced '%s'",
                    cls._config_path(*primary),
                    value,
                    coerced,
                )
                return coerced
            if value == "":
                legacy_value = cls._cfg.get(*legacy)
                if legacy_value is not None:
                    if not isinstance(legacy_value, str):
                        coerced = str(legacy_value)
                        cls._logger.error(
                            "Non-string configuration value for '%s': %r; using coerced '%s'",
                            cls._config_path(*primary),
                            legacy_value,
                            coerced,
                        )
                        return coerced
                    if legacy_value != "":
                        return legacy_value
                cls._logger.error(
                    "Empty configuration value for '%s'; using default '%s'",
                    cls._config_path(*primary),
                    default,
                )
                return default

        legacy_value = cls._cfg.get(*legacy)
        if legacy_value is None:
            cls._logger.error(
                "Missing configuration value for '%s'; using default '%s'",
                cls._config_path(*primary),
                default,
            )
            return default
        if not isinstance(legacy_value, str):
            coerced = str(legacy_value)
            cls._logger.error(
                "Non-string configuration value for '%s': %r; using coerced '%s'",
                cls._config_path(*primary),
                legacy_value,
                coerced,
            )
            return coerced
        if legacy_value == "":
            cls._logger.error(
                "Empty configuration value for '%s'; using default '%s'",
                cls._config_path(*primary),
                default,
            )
            return default
        return legacy_value

    @classmethod
    def _get_str_allow_empty(cls, default: str, *path: str) -> str:
        value = cls._cfg.get(*path)
        if value is None:
            return default
        if not isinstance(value, str):
            coerced = str(value)
            cls._logger.error(
                "Non-string configuration value for '%s': %r; using coerced '%s'",
                cls._config_path(*path),
                value,
                coerced,
            )
            return coerced
        return value

    @classmethod
    def _get_str_fallback_allow_empty(
        cls, default: str, primary: tuple[str, ...], legacy: tuple[str, ...]
    ) -> str:
        value = cls._cfg.get(*primary)
        if value is not None:
            if isinstance(value, str):
                return value
            coerced = str(value)
            cls._logger.error(
                "Non-string configuration value for '%s': %r; using coerced '%s'",
                cls._config_path(*primary),
                value,
                coerced,
            )
            return coerced

        legacy_value = cls._cfg.get(*legacy)
        if legacy_value is None:
            return default
        if not isinstance(legacy_value, str):
            coerced = str(legacy_value)
            cls._logger.error(
                "Non-string configuration value for '%s': %r; using coerced '%s'",
                cls._config_path(*primary),
                legacy_value,
                coerced,
            )
            return coerced
        return legacy_value

    @classmethod
    def _get_int(cls, default: int, *path: str) -> int:
        value = cls._cfg.get(*path)
        if value is None:
            cls._logger.error(
                "Missing configuration value for '%s'; using default %d",
                cls._config_path(*path),
                default,
            )
            return default
        try:
            return int(value)
        except (TypeError, ValueError):
            cls._logger.error(
                "Invalid integer configuration value for '%s': %r; using default %d",
                cls._config_path(*path),
                value,
                default,
            )
            return default

    @classmethod
    def _get_int_fallback(
        cls, default: int, primary: tuple[str, ...], legacy: tuple[str, ...]
    ) -> int:
        value = cls._cfg.get(*primary)
        if value is not None:
            try:
                return int(value)
            except (TypeError, ValueError):
                cls._logger.error(
                    "Invalid integer configuration value for '%s': %r; using default %d",
                    cls._config_path(*primary),
                    value,
                    default,
                )
                return default

        legacy_value = cls._cfg.get(*legacy)
        if legacy_value is None:
            cls._logger.error(
                "Missing configuration value for '%s'; using default %d",
                cls._config_path(*primary),
                default,
            )
            return default
        try:
            return int(legacy_value)
        except (TypeError, ValueError):
            cls._logger.error(
                "Invalid integer configuration value for '%s': %r; using default %d",
                cls._config_path(*primary),
                legacy_value,
                default,
            )
            return default

    @classmethod
    def _get_bool(cls, default: bool, *path: str) -> bool:
        value = cls._cfg.get(*path)
        if isinstance(value, bool):
            return value
        if value is None:
            cls._logger.error(
                "Missing configuration value for '%s'; using default %s",
                cls._config_path(*path),
                default,
            )
            return default

        text = str(value).strip().lower()
        if text in ("1", "true", "yes", "on"):
            return True
        if text in ("0", "false", "no", "off"):
            return False

        cls._logger.error(
            "Invalid boolean configuration value for '%s': %r; using default %s",
            cls._config_path(*path),
            value,
            default,
        )
        return default

    @classmethod
    def _get_bool_fallback(
        cls, default: bool, primary: tuple[str, ...], legacy: tuple[str, ...]
    ) -> bool:
        value = cls._cfg.get(*primary)
        if isinstance(value, bool):
            return value
        if value is None:
            legacy_value = cls._cfg.get(*legacy)
            if isinstance(legacy_value, bool):
                return legacy_value
            if legacy_value is None:
                cls._logger.error(
                    "Missing configuration value for '%s'; using default %s",
                    cls._config_path(*primary),
                    default,
                )
                return default
            text = str(legacy_value).strip().lower()
            if text in ("1", "true", "yes", "on"):
                return True
            if text in ("0", "false", "no", "off"):
                return False
            cls._logger.error(
                "Invalid boolean configuration value for '%s': %r; using default %s",
                cls._config_path(*primary),
                legacy_value,
                default,
            )
            return default

        text = str(value).strip().lower()
        if text in ("1", "true", "yes", "on"):
            return True
        if text in ("0", "false", "no", "off"):
            return False

        cls._logger.error(
            "Invalid boolean configuration value for '%s': %r; using default %s",
            cls._config_path(*primary),
            value,
            default,
        )
        return default

    @classmethod
    def database_settings(cls) -> DatabaseSettings:
        data: dict[str, object] = {}

        backend_value = cls._cfg.get("Database", "backend")
        if backend_value is not None:
            data["backend"] = str(backend_value).strip()
        env_backend = cls._db_backend_env_override()
        if env_backend != "":
            data["backend"] = env_backend

        sqlite_value = cls._cfg.get("Database", "sqlite", "path")
        if sqlite_value is None:
            sqlite_path = str(cls._DEFAULT_SQLITE_DB_PATH)
        else:
            sqlite_path = str(sqlite_value)
        data["sqlite"] = {"path": sqlite_path}

        postgres_value = cls._cfg.get("Database", "postgres", "dsn")
        if postgres_value is None:
            postgres_dsn = str(cls._DEFAULT_POSTGRES_DSN)
        else:
            postgres_dsn = str(postgres_value)

        env_override = cls._postgres_dsn_env_override()
        if env_override != "":
            postgres_dsn = env_override
        data["postgres"] = {"dsn": postgres_dsn}

        return DatabaseSettings.model_validate(data)

    @classmethod
    def database_backend(cls) -> DatabaseBackend:
        try:
            return cls.database_settings().backend
        except ValidationError as exc:
            cls._logger.error("Invalid Database configuration: %s", exc)
            return cls._DEFAULT_DB_BACKEND

    @classmethod
    def database_sqlite_path(cls) -> DatabasePath:
        try:
            return cls.database_settings().sqlite.path
        except ValidationError as exc:
            cls._logger.error("Invalid Database configuration: %s", exc)
            return cls._DEFAULT_SQLITE_DB_PATH

    @classmethod
    def database_postgres_dsn(cls) -> DatabaseDsn:
        try:
            return cls.database_settings().postgres.dsn
        except ValidationError as exc:
            cls._logger.error("Invalid Database configuration: %s", exc)
            return cls._DEFAULT_POSTGRES_DSN

    @classmethod
    def get_config_path(cls) -> str:
        return cls._cfg.get_config_path()

    @classmethod
    def default_mac_address(cls) -> MacAddressStr:
        mac = cls._cfg.get("FastApiRequestDefault", "mac_address")
        if not mac:
            cls._logger.error(
                "Missing configuration value for '%s'; using MacAddress.null()",
                cls._config_path("FastApiRequestDefault", "mac_address"),
            )
            return cast(MacAddressStr, MacAddress.null())
        return cast(MacAddressStr, mac)

    @classmethod
    def default_ip_address(cls) -> InetAddressStr:
        return cast(
            InetAddressStr,
            cls._get_str(
                cls._DEFAULT_IP_ADDRESS, "FastApiRequestDefault", "ip_address"
            ),
        )

    # SNMP v2 settings
    @classmethod
    def snmp_enable(cls) -> bool:
        return cls._get_bool(True, "SNMP", "version", "2c", "enable")

    @classmethod
    def snmp_retries(cls) -> int:
        return cls._get_int(
            cls._DEFAULT_SNMP_RETRIES, "SNMP", "version", "2c", "retries"
        )

    @classmethod
    def snmp_read_community(cls) -> SnmpReadCommunity:
        value = cls._cfg.get("SNMP", "version", "2c", "read_community")
        if value is not None:
            if isinstance(value, str) and value.strip() != "":
                return cast(SnmpReadCommunity, value)
            if not isinstance(value, str):
                coerced = str(value)
                cls._logger.error(
                    "Non-string configuration value for '%s': %r; using coerced '%s'",
                    cls._config_path("SNMP", "version", "2c", "read_community"),
                    value,
                    coerced,
                )
                return cast(SnmpReadCommunity, coerced)
        legacy = cls._cfg.get("SNMP", "version", "2c", "community")
        if legacy is not None:
            if isinstance(legacy, str) and legacy.strip() != "":
                return cast(SnmpReadCommunity, legacy)
            if not isinstance(legacy, str):
                coerced = str(legacy)
                cls._logger.error(
                    "Non-string configuration value for '%s': %r; using coerced '%s'",
                    cls._config_path("SNMP", "version", "2c", "community"),
                    legacy,
                    coerced,
                )
                return cast(SnmpReadCommunity, coerced)
        return cast(
            SnmpReadCommunity,
            cls._get_str(
                cls._DEFAULT_SNMP_READ_COMMUNITY,
                "SNMP",
                "version",
                "2c",
                "read_community",
            ),
        )

    @classmethod
    def snmp_write_community(cls) -> SnmpWriteCommunity:
        value = cls._cfg.get("SNMP", "version", "2c", "write_community")
        if value is not None:
            if isinstance(value, str) and value.strip() != "":
                return cast(SnmpWriteCommunity, value)
            if not isinstance(value, str):
                coerced = str(value)
                cls._logger.error(
                    "Non-string configuration value for '%s': %r; using coerced '%s'",
                    cls._config_path("SNMP", "version", "2c", "write_community"),
                    value,
                    coerced,
                )
                return cast(SnmpWriteCommunity, coerced)
        return cast(
            SnmpWriteCommunity,
            cls._get_str(
                cls._DEFAULT_SNMP_WRITE_COMMUNITY,
                "SNMP",
                "version",
                "2c",
                "write_community",
            ),
        )

    # SNMP v3 settings

    @classmethod
    def snmp_v3_enable(cls) -> bool:
        return cls._get_bool(False, "SNMP", "version", "3", "enable")

    @classmethod
    def snmp_v3_username(cls) -> str:
        if not cls.snmp_v3_enable():
            return ""
        return cls._get_str("", "SNMP", "version", "3", "username")

    @classmethod
    def snmp_v3_security_level(cls) -> str:
        if not cls.snmp_v3_enable():
            return ""
        return cls._get_str("", "SNMP", "version", "3", "securityLevel")

    @classmethod
    def snmp_v3_auth_protocol(cls) -> str:
        if not cls.snmp_v3_enable():
            return ""
        return cls._get_str("", "SNMP", "version", "3", "authProtocol")

    @classmethod
    def snmp_v3_auth_password(cls) -> str:
        if not cls.snmp_v3_enable():
            return ""
        value = cls._get_str("", "SNMP", "version", "3", "authPassword")
        return cls._maybe_decrypt(value, "SNMP", "version", "3", "authPassword")

    @classmethod
    def snmp_v3_priv_protocol(cls) -> str:
        if not cls.snmp_v3_enable():
            return ""
        return cls._get_str("", "SNMP", "version", "3", "privProtocol")

    @classmethod
    def snmp_v3_priv_password(cls) -> str:
        if not cls.snmp_v3_enable():
            return ""
        value = cls._get_str("", "SNMP", "version", "3", "privPassword")
        return cls._maybe_decrypt(value, "SNMP", "version", "3", "privPassword")

    # SNMP general settings
    @classmethod
    def snmp_timeout(cls) -> int:
        return cls._get_int(cls._DEFAULT_SNMP_TIMEOUT, "SNMP", "timeout")

    # Bulk data transfer settings
    @classmethod
    def bulk_transfer_method(cls) -> str:
        return cls._get_str("", "PnmBulkDataTransfer", "method")

    @classmethod
    def bulk_tftp_ip_v4(cls) -> IPv4Str:
        return cast(
            IPv4Str,
            cls._get_str("", "PnmBulkDataTransfer", "tftp", "ip_v4"),
        )

    @classmethod
    def bulk_tftp_ip_v6(cls) -> IPv6Str:
        return cast(
            IPv6Str,
            cls._get_str("", "PnmBulkDataTransfer", "tftp", "ip_v6"),
        )

    @classmethod
    def bulk_tftp_remote_dir(cls) -> str:
        return cls._get_str_allow_empty("", "PnmBulkDataTransfer", "tftp", "remote_dir")

    @classmethod
    def bulk_http_base_url(cls) -> str:
        return cls._get_str("", "PnmBulkDataTransfer", "http", "base_url")

    @classmethod
    def bulk_http_port(cls) -> int:
        return cls._get_int(
            cls._DEFAULT_HTTP_PORT, "PnmBulkDataTransfer", "http", "port"
        )

    @classmethod
    def bulk_https_base_url(cls) -> str:
        return cls._get_str("", "PnmBulkDataTransfer", "https", "base_url")

    @classmethod
    def bulk_https_port(cls) -> int:
        return cls._get_int(
            cls._DEFAULT_HTTPS_PORT, "PnmBulkDataTransfer", "https", "port"
        )

    # PNM file retrieval/storage settings
    @classmethod
    def save_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_PNM_DIR, "PnmFileRetrieval", "pnm_dir")

    @classmethod
    def pnm_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_PNM_DIR, "PnmFileRetrieval", "pnm_dir")

    @classmethod
    def csv_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_CSV_DIR, "PnmFileRetrieval", "csv_dir")

    @classmethod
    def json_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_JSON_DIR, "PnmFileRetrieval", "json_dir")

    @classmethod
    def xlsx_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_XLSX_DIR, "PnmFileRetrieval", "xlsx_dir")

    @classmethod
    def png_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_PNG_DIR, "PnmFileRetrieval", "png_dir")

    @classmethod
    def archive_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_ARCHIVE_DIR, "PnmFileRetrieval", "archive_dir")

    @classmethod
    def message_response_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_MSG_RSP_DIR, "PnmFileRetrieval", "msg_rsp_dir")

    @classmethod
    def transaction_db(cls) -> str:
        return cls._get_str("", "PnmFileRetrieval", "transaction_db")

    @classmethod
    def capture_group_db(cls) -> str:
        return cls._get_str("", "PnmFileRetrieval", "capture_group_db")

    @classmethod
    def session_group_db(cls) -> str:
        return cls._get_str("", "PnmFileRetrieval", "session_group_db")

    @classmethod
    def operation_db(cls) -> str:
        return cls._get_str("", "PnmFileRetrieval", "operation_db")

    @classmethod
    def json_db(cls) -> str:
        return cls._get_str("", "PnmFileRetrieval", "json_transaction_db")

    @classmethod
    def file_retrieval_retries(cls) -> int:
        return cls._get_int(
            cls._DEFAULT_FILE_RETRIEVAL_RETRIES, "PnmFileRetrieval", "retries"
        )

    @classmethod
    def retrieval_method(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "method")
        legacy = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "method")

        return cls._get_str_fallback("", primary, legacy)

    # Local method
    @classmethod
    def local_src_dir(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "local",
            "src_dir",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "local",
            "src_dir",
        )
        return cls._get_str_fallback("", primary, legacy)

    # TFTP method
    @classmethod
    def tftp_host(cls) -> InetAddressStr:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "tftp",
            "host",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "tftp",
            "host",
        )
        return InetAddressStr(cls._get_str_fallback("", primary, legacy))

    @classmethod
    def tftp_port(cls) -> int:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "tftp",
            "port",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "tftp",
            "port",
        )
        return cls._get_int_fallback(cls._DEFAULT_TFTP_PORT, primary, legacy)

    @classmethod
    def tftp_timeout(cls) -> int:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "tftp",
            "timeout",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "tftp",
            "timeout",
        )
        return cls._get_int_fallback(cls._DEFAULT_SNMP_TIMEOUT, primary, legacy)

    @classmethod
    def tftp_remote_dir(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "tftp",
            "remote_dir",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "tftp",
            "remote_dir",
        )
        return cls._get_str_fallback_allow_empty("", primary, legacy)

    # FTP method
    @classmethod
    def ftp_host(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "ftp",
            "host",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "ftp",
            "host",
        )
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def ftp_port(cls) -> int:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "ftp",
            "port",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "ftp",
            "port",
        )
        return cls._get_int_fallback(cls._DEFAULT_FTP_PORT, primary, legacy)

    @classmethod
    def ftp_use_tls(cls) -> bool:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "ftp",
            "tls",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "ftp",
            "tls",
        )
        return cls._get_bool_fallback(False, primary, legacy)

    @classmethod
    def ftp_timeout(cls) -> int:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "ftp",
            "timeout",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "ftp",
            "timeout",
        )
        return cls._get_int_fallback(cls._DEFAULT_SNMP_TIMEOUT, primary, legacy)

    @classmethod
    def ftp_user(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "ftp",
            "user",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "ftp",
            "user",
        )
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def ftp_password(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "ftp",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "ftp",
        )
        return cls._get_password_value_fallback(
            True,
            primary,
            legacy,
        )

    @classmethod
    def ftp_remote_dir(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "ftp",
            "remote_dir",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "ftp",
            "remote_dir",
        )
        return cls._get_str_fallback_allow_empty("", primary, legacy)

    # SCP method
    @classmethod
    def scp_host(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "scp",
            "host",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "scp",
            "host",
        )
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def scp_port(cls) -> int:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "scp",
            "port",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "scp",
            "port",
        )
        return cls._get_int_fallback(cls._DEFAULT_SCP_PORT, primary, legacy)

    @classmethod
    def scp_user(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "scp",
            "user",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "scp",
            "user",
        )
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def scp_password(cls) -> str:
        private_key_path_primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "scp",
            "private_key_path",
        )
        private_key_path_legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "scp",
            "private_key_path",
        )
        private_key_path = cls._peek_str_fallback(
            private_key_path_primary, private_key_path_legacy
        ).strip()
        require = private_key_path == ""

        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "scp",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "scp",
        )

        return cls._get_password_value_fallback(
            require,
            primary,
            legacy,
        )

    @classmethod
    def scp_private_key_path(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "scp",
            "private_key_path",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "scp",
            "private_key_path",
        )
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def scp_remote_dir(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "scp",
            "remote_dir",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "scp",
            "remote_dir",
        )
        return cls._get_str_fallback_allow_empty("", primary, legacy)

    # SFTP method
    @classmethod
    def sftp_host(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "sftp",
            "host",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "sftp",
            "host",
        )
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def sftp_port(cls) -> int:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "sftp",
            "port",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "sftp",
            "port",
        )
        return cls._get_int_fallback(cls._DEFAULT_SFTP_PORT, primary, legacy)

    @classmethod
    def sftp_user(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "sftp",
            "user",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "sftp",
            "user",
        )
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def sftp_password(cls) -> str:
        private_key_path_primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "sftp",
            "private_key_path",
        )
        private_key_path_legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "sftp",
            "private_key_path",
        )
        private_key_path = cls._peek_str_fallback(
            private_key_path_primary, private_key_path_legacy
        ).strip()
        require = private_key_path == ""

        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "sftp",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "sftp",
        )

        return cls._get_password_value_fallback(
            require,
            primary,
            legacy,
        )

    @classmethod
    def sftp_private_key_path(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "sftp",
            "private_key_path",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "sftp",
            "private_key_path",
        )
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def sftp_remote_dir(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "sftp",
            "remote_dir",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "sftp",
            "remote_dir",
        )
        return cls._get_str_fallback_allow_empty("", primary, legacy)

    # HTTP method
    @classmethod
    def http_base_url(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "http",
            "base_url",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "http",
            "base_url",
        )
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def http_port(cls) -> int:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "http",
            "port",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "http",
            "port",
        )
        return cls._get_int_fallback(cls._DEFAULT_HTTP_PORT, primary, legacy)

    # HTTPS method
    @classmethod
    def https_base_url(cls) -> str:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "https",
            "base_url",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "https",
            "base_url",
        )
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def https_port(cls) -> int:
        primary = (
            "PnmFileRetrieval",
            cls._PRIMARY_RETRIEVAL_METHOD_KEY,
            "methods",
            "https",
            "port",
        )
        legacy = (
            "PnmFileRetrieval",
            cls._LEGACY_RETRIEVAL_METHOD_KEY,
            "methods",
            "https",
            "port",
        )
        return cls._get_int_fallback(cls._DEFAULT_HTTPS_PORT, primary, legacy)

    # Logging
    @classmethod
    def log_level(cls) -> str:
        return cls._get_str(cls._DEFAULT_LOG_LEVEL, "logging", "log_level")

    @classmethod
    def log_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_LOG_DIR, "logging", "log_dir")

    @classmethod
    def log_filename(cls) -> FileNameStr:
        return cls._get_str(cls._DEFAULT_LOG_FILENAME, "logging", "log_filename")

    @classmethod
    def initialize_directories(cls) -> None:
        """
        Create necessary directories if they do not exist.
        """
        cls._warn_deprecated_ledger_paths()
        directories = [
            cls.pnm_dir(),
            cls.csv_dir(),
            cls.json_dir(),
            cls.xlsx_dir(),
            cls.png_dir(),
            cls.archive_dir(),
            cls.message_response_dir(),
            cls.log_dir(),
        ]
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)

    @classmethod
    def _warn_deprecated_ledger_paths(cls) -> None:
        cls._warn_deprecated_ledger_key("transaction_db")
        cls._warn_deprecated_ledger_key("capture_group_db")
        cls._warn_deprecated_ledger_key("operation_db")
        cls._warn_deprecated_ledger_key("json_transaction_db")

    @classmethod
    def _warn_deprecated_ledger_key(cls, key: str) -> None:
        if key in cls._deprecated_ledger_warned:
            return
        value = cls._cfg.get("PnmFileRetrieval", key)
        if value is None:
            return
        if isinstance(value, str):
            if value == "":
                return
            configured = value
        else:
            configured = str(value)
            if configured == "":
                return
        cls._logger.warning(
            "Configuration key 'PnmFileRetrieval.%s' is deprecated and ignored at runtime; remove it from system.json",
            key,
        )
        cls._deprecated_ledger_warned.add(key)

    @classmethod
    def reload(cls) -> None:
        """
        Reload the configuration settings.
        """
        cls._cfg.reload()
        cls.initialize_directories()

# FILE: src/pypnm/examples/settings/system.json
{
    "FastApiRequestDefault": {
        "mac_address": "aa:bb:cc:dd:ee:ff",
        "ip_address": "192.168.0.1"
    },
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
    },
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
    },
    "PnmFileRetrieval": {
        "pnm_dir": ".data/pnm",
        "csv_dir": ".data/csv",
        "json_dir": ".data/json",
        "xlsx_dir": ".data/xlsx",
        "png_dir": ".data/png",
        "archive_dir": ".data/archive",
        "msg_rsp_dir": ".data/msg_rsp",
        "session_group_db": ".data/db/session_group.json",
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
                    "user": "test",
                    "password_enc": "",
                    "remote_dir": "/srv/tftp"
                },
                "sftp": {
                    "host": "localhost",
                    "port": 22,
                    "user": "test",
                    "password_enc": "",
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
    },
    "Database": {
        "backend": "sqlite",
        "sqlite": {
            "path": ".data/db/pypnm.sqlite3"
        },
        "postgres": {
            "dsn": ""
        }
    },
    "logging": {
        "log_level": "INFO",
        "log_dir": "logs",
        "log_filename": "pypnm.log"
    },
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
  "session_group_db": ".data/db/session_group.json",
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
Deprecated JSON ledger keys are ignored at runtime; metadata persistence is DB-backed.

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
| transaction_db      | string | Deprecated and ignored at runtime; remove from config.      |
| capture_group_db    | string | Deprecated and ignored at runtime; remove from config.      |
| session_group_db    | string | Legacy JSON map of session groups (migration only).        |
| operation_db        | string | Deprecated and ignored at runtime; remove from config.      |
| json_transaction_db | string | Deprecated and ignored at runtime; remove from config.      |

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

# FILE: docs/issues/index.md
# Reporting Issues

If you encounter a bug or unexpected behavior while using PyPNM, please report it
so we can investigate and resolve the issue. This document outlines the steps to
create a support bundle that captures the necessary data for debugging.

[REPORTING ISSUES](reporting-issues.md)

## Support Bundle Script

PyPNM includes a support bundle script that collects relevant logs, database
entries, and configuration files related to your issue. This script helps
sanitize sensitive information before sharing it with the PyPNM support team.

[Support Bundle Builder](support-bundle.md)

## FAQ

### Multi-capture results return 404 with legacy operation capture ledger

Runtime no longer reads legacy operation-capture ledgers after the DB cutover,
so legacy keys are not accepted by live endpoints. Use the offline migrator or
re-run the capture workflow on a DB-backed build to populate the
operation-to-group mapping in the database.

### Session group mappings missing after upgrade

Runtime no longer reads `session_group.json`; session groups are DB-backed. Use
the offline migrator (`python -m pypnm.tools.migrate_session_groups --input
PATH`) or re-run the session workflow to repopulate the DB.

### Transaction records store an unexpected MAC address value

The canonical MAC address stored in `transaction_records` is a lowercase string.
Earlier builds could persist a non-string value when `PnmFileTransaction.insert`
was passed a callable. Upgrade to a build with the fix and re-run captures to
refresh affected entries.

# FILE: docs/design/db/database-backend-burndown.md
# PyPNM DB Backend Refactor Burndown (With ToC)

## Table Of Contents

- [Overview](#overview)
- [Recent Status Update (2026-01-11)](#recent-status-update-2026-01-11)
- [Phase 7.7 Burndown Tracker (Updated 2026-01-11)](#phase-77-burndown-tracker-updated-2026-01-11)
- [Open Issues From Review Bundles (Updated 2026-01-11)](#open-issues-from-review-bundles-updated-2026-01-11)
- [Locked Decisions (Selection Summary)](#locked-decisions-selection-summary)
- [Milestones](#milestones)
- [Phase 0 · Guardrails And Release Hygiene (M0)](#phase-0--guardrails-and-release-hygiene-m0)
- [Phase 1 · Install-Time Backend Selection And Config Contract (M1)](#phase-1--install-time-backend-selection-and-config-contract-m1)
- [Phase 2 · Schema Introduction And DB Abstraction Layer (M2)](#phase-2--schema-introduction-and-db-abstraction-layer-m2)
- [Phase 3 · Transactions Migration (DB-Backed Transactions) (M3)](#phase-3--transactions-migration-db-backed-transactions-m3)
- [Phase 4 · Capture Group And Operation Migration (DB-Backed Capture Groups) (M4)](#phase-4--capture-group-and-operation-migration-db-backed-capture-groups-m4)
- [Phase 5 · Artifact Linkage (Filesystem References) (M5)](#phase-5--artifact-linkage-filesystem-references-m5)
- [Phase 6 · Remove Ledger JSON Design And Code (M6)](#phase-6--remove-ledger-json-design-and-code-m6)
- [Phase 7 · Pytest And GitHub Actions Migration (M7)](#phase-7--pytest-and-github-actions-migration-m7)
- [Cross-Cutting Requirements](#cross-cutting-requirements)
- [Suggested Codex Tracking Rules](#suggested-codex-tracking-rules)

## Overview

This burndown converts PyPNM from JSON ledger persistence under `.data/db/*.json` to a DB-backed persistence layer with install-time backend selection:

- SQLite (local file under `.data/db/pypnm.sqlite3`)
- PostgreSQL (external service)

Binary artifacts remain filesystem-based. The DB stores metadata and references via `artifact_stores`, `file_artifacts`, and `transaction_artifacts`.

PyPNM owns backend selection at install time. PyPNM-CMTS inherits this selection through PyPNM and must not implement a separate DB selection mechanism.

Concurrency note (design constraint carried into implementation and docs):

- SQLite is supported and recommended for single-process / single-writer deployments (PyPNM standalone, labs, demos).
- Postgres is recommended when PyPNM is used as a dependency in PyPNM-CMTS, or whenever multiple workers/processes may access the DB concurrently.

DB-only cutover policy (current intent):

- Runtime persistence is DB-only once a given domain has landed in DB form (transactions in M3; capture groups/ops in M4; artifacts in M5).
- JSON ledgers become legacy-only for migrated domains:
  - Not written by runtime once the DB write paths land for that domain.
  - Not read by runtime endpoints once DB read paths land for that domain.
  - Optional offline migrator may exist, but is not part of runtime behavior.

## Recent Status Update (2026-01-11)

Work completed since the last burndown sync (per Agent Review Bundles and the current codebase snapshot):

- **M2 complete (schema init + DB abstraction layer):**
  - Schema assets maintained as authoritative:
    - `docs/design/db/schema_sqlite.sql`
    - `docs/design/db/schema_postgres.sql`
  - Schema apply/init is idempotent and invoked from startup.
  - Seeds `UNKNOWN` sysDescr row idempotently.
  - Seeds default `artifact_stores` rows idempotently (at least the primary/prod default).

- **M3 complete (transactions and JSON export artifacts are DB-backed; legacy ledgers removed from runtime):**
  - Introduced repository helpers for sysDescr/device_details dimensions and transaction_records.
  - Wired `PnmFileTransaction` reads/writes to DB while preserving legacy payload shapes.
  - Updated file manager reads (`search_files`, `get_mac_addresses`) to query DB-backed repositories.
  - Updated tests to seed DB transactions and added repository unit coverage for:
    - sysDescr de-duplication
    - device_details de-duplication
    - deterministic listing and ordering (timestamp + transaction_id tie-break)

- **M4 is now in progress (repositories exist; cutover tasks remain):**
  - DB repositories for capture groups and operation→capture group linkage exist.
  - A compatibility layer exists for legacy column naming differences (operation_id vs operation_capture_id).
  - Remaining work is primarily cutover enforcement: stop runtime reads/writes of the capture/operation JSON ledgers and shift remaining endpoints/services fully to DB.

- `install.sh`
  - DB backend selection runs before `pytest` so tests execute against the selected backend contract.
  - Added `--db-install-sqlite` and `--db-install-postgres`, plus an interactive prompt when no flag is provided (defaults to SQLite in non-interactive/CI).
  - Added Postgres DSN prompt with password redaction (passwords are not persisted into `system.json`).
  - Fixed DSN redaction backreference and aligned DSN env-var warning logic to `POSTGRES_DSN_ENV_VAR` via indirect expansion.

- `docs/system/system-config.md`
  - Updated `PnmFileRetrieval` heading/anchor for GitHub compatibility.
  - Documented runtime DB location policy and recommended env var usage for Postgres DSNs.

Out-of-scope but in-flight (separate hygiene workstream): Ruff baseline cleanup (125 remaining issues after `ruff check . --fix`, including `PnmParsers` undefined name).

## Phase 7.7 Burndown Tracker (Updated 2026-01-11)

This tracker is a near-term hygiene lane that should remain compatible with the DB migration. It is not a replacement for the DB cutover milestones.

### Recent Completions

- Unified operation workflow payload shape:
  - Dual-status support (legacy `status` string + canonical `service_status`)
  - Centralized workflow schemas via re-exports
  - Registry status responses aligned to shared `time_remaining` contract
- Multi-capture registry status endpoints aligned to `time_remaining` contract:
  - Multi-RxMER `/advance/multiRxMer/status` (POST)
  - Multi-ChannelEstimation `/advance/multiChannelEstimation/status` (POST)
  - Safe coercion and default fallback when missing/invalid
- Docs updated:
  - `docs/api/fast-api/multi/capture-operation.md` updated to reflect unified payload shape
- Tests added/updated:
  - Operation workflow dual-status tests
  - Multi-RxMER + Multi-ChannelEstimation registry `time_remaining` behavior tests
  - Transaction repository unit tests and multi-capture result tests seeded via DB
- Verification complete:
  - `python3 -m compileall src` pass
  - `ruff check .` pass
  - `ruff format --check .` pass
  - `pytest -q` pass (583 passed, 4 skipped)

### Remaining Phase 7.7 TODOs (Open Items)

1) Address `PytestConfigWarning` related to `asyncio_mode` configuration
   - Goal: eliminate warning via explicit pytest config (no runtime impact, but hygiene blocker)

2) Final “legacy-key hygiene” scan
   - Goal: confirm no remaining deprecated/legacy keys or payload fields are being written or relied upon unintentionally
   - Scope: operation/capture records, workflow responses, and multi-capture start/status/result payloads

### Validation Gate (Must Stay Green)

- `python3 -m compileall src`
- `ruff check .`
- `ruff format --check .`
- `pytest -q`
- Optional (when enabled): SNMP integration tests via `PNM_CM_IT`
- Optional (when enabled): Postgres schema init via `PYPNM_DB_POSTGRES_DSN`

## Open Issues From Review Bundles (Updated 2026-01-11)

These are implementation follow-ups that are not blocked by the milestone plan but should be addressed during M4/M5 hardening.

1) Potential bug in `PnmFileTransaction.insert()`
   - Risk: passing `cable_modem.get_mac_address` (callable) instead of invoking it.
   - Requirement: ensure an actual MAC value is used consistently (normalized to lowercase).

2) Transaction ID generation hardening (keep the 16-char prefix contract)
   - Current: sha256(filename + timestamp) with truncation.
   - Improve: add higher-resolution time (e.g., `time.time_ns()`), plus MAC and/or test type.

3) Magic-number cleanup
   - Example: DEFAULT_HEXDUMP_BYTES_PER_LINE = 16 defined inside a function.
   - Requirement: promote to a named constant.

4) Refactor long if/elif chains to `match/case`
   - Target: `PnmFileService.__get_analysis()` (behavior unchanged).

5) Strict typing improvement
   - Target: `_RepositoryBase._from_system_config` should return `Self` (or an equivalent strict typing approach).

## Locked Decisions (Selection Summary)

This burndown must implement (and keep consistent with the design doc) the locked decision set:

`1A, 2B+2.1B, 3B, 4A(SQLite)+4C(Postgres when PyPNM-CMTS/multi-worker), 5C+5.1A, 6B+6.1A, 7B, 8A`

Implications that must remain explicit in tasks and acceptance criteria:

- PyPNM owns backend selection and schema init; PyPNM-CMTS is a consumer only.
- `install.sh` defaults to SQLite and prompts when no flag is provided.
- Postgres secrets must be supported via env var overrides; `pypnm/pypnm` is dev/CI only.
- Schema apply is idempotent from shipped DDL assets; seeds UNKNOWN sysDescr and artifact store rows.
- SQLite is for single-writer; Postgres is recommended for multi-worker and PyPNM-CMTS.
- DB stores portable app-root relative paths; runtime resolution builds absolute paths.
- CI must validate SQLite and Postgres (Postgres via service container; not “allowed failure”).
- JSON ledgers are deprecated; removal is tracked explicitly in M6 (do not introduce new ledger features).

## Milestones

Status guidance:

- Complete: done and validated.
- In progress: started, partials landed.
- Not started: planned.

Milestone status (as of 2026-01-11):

- M0: In progress (docs updated; packaging/docker hygiene still open)
- M1: In progress (installer selection landed; config template + settings accessors still open)
- M2: Complete (DB schema init + backend-aware connection path landed; schema manager in use)
- M3: Complete (transactions and JSON export artifacts are DB-backed; legacy ledger paths are not used at runtime)
- M4: In progress (capture groups + operation linkage repositories exist; JSON ledger cutover and endpoint wiring still open)
- M5: Not started (artifact linkage; DB becomes authoritative for path resolution)
- M6: Not started (delete ledger code paths and ledger docs)
- M7: Partially done (Postgres CI job plumbing landed; full DB-backed test suite + ledger removal assertions pending)

## Phase 0 · Guardrails And Release Hygiene (M0)

### Goal

Prevent DB/data leakage into releases and formalize runtime data placement.

### Tasks

- [ ] Add `.data/` and `demo/.data/` to `.gitignore` and confirm no tracked data remains.
- [ ] Ensure Python packaging excludes runtime data:
  - [ ] Exclude `.data/**` and `demo/.data/**` from sdist/wheel.
  - [ ] Confirm build config does not include runtime paths.
- [ ] Ensure Docker build excludes runtime data:
  - [ ] `.dockerignore` includes `.data/`, `demo/.data/`, `*.sqlite3`, `*.db`.
  - [ ] Dockerfiles do not `COPY` `.data/` or demo datasets into images.
- [x] Document runtime DB location rules:
  - [x] SQLite path under `.data/db/`
  - [x] Postgres external (no local DB file)
- [x] Add doc note: demo uses isolated root (`demo/`) and isolated DB.

### Acceptance Criteria

- [ ] Building sdist/wheel does not contain `.data/` or any DB files.
- [ ] Docker images do not contain `.data/` contents.
- [x] Docs state the runtime DB location policy clearly.

## Phase 1 · Install-Time Backend Selection And Config Contract (M1)

### Goal

Make DB backend selection a first-class install-time choice owned by PyPNM and visible in docs.

### Tasks

- [x] Extend `install.sh`:
  - [x] Support `--db-install-postgres`
  - [x] Support `--db-install-sqlite`
  - [x] Add interactive prompt if no flag provided (default: SQLite)
  - [x] Add install-time warning text:
    - [x] SQLite is recommended for standalone PyPNM / single-writer
    - [x] Postgres is recommended for PyPNM-CMTS and/or multi-worker/multi-process
  - [x] Add a Postgres config prompt path when Postgres is selected:
    - [x] Allow DSN entry OR discrete fields that render into a DSN
    - [x] Host / port / database / user / password / ssl mode
    - [x] Ensure password can be provided via env var override (no plaintext requirement in JSON)
    - [x] Ensure passwords are not persisted into `system.json` (DSN redaction + field-based DSN omits password)

- [ ] Add config keys to `settings/system.json.template` (and demo template if used):
  - [ ] `Database.backend` = `sqlite` | `postgres`
  - [ ] `Database.sqlite.path` default `.data/db/pypnm.sqlite3`
  - [ ] Postgres connection settings:
    - [ ] Support `Database.postgres.dsn`
    - [ ] Optional discrete settings for UX (installer can populate DSN)
  - [ ] Support environment variable overrides for secrets (do not require plaintext passwords in tracked JSON)

- [ ] Add `SystemConfigSettings` accessors for DB settings.

- [x] Ensure docs explicitly describe:
  - [x] Install-time backend selection mechanism
  - [x] SQLite vs Postgres recommendation (single-writer vs multi-worker)
  - [ ] PyPNM-CMTS inherits backend (no separate selection)

- [ ] Add pytest coverage for config defaults and validation (missing/blank handling).

### Notes: Postgres Credentials Policy

- Development defaults like `pypnm/pypnm` are acceptable for local dev and CI only.
- Do not recommend these credentials for production.
- Prefer environment variables or a local `.env` file for passwords and DSNs.
- Do not commit `.env` or populated DB settings containing real credentials.

### Acceptance Criteria

- [x] Fresh install can select backend via flag or prompt.
- [ ] Config settings are available via `SystemConfigSettings`.
- [ ] Tests cover selection and default behavior.

## Phase 2 · Schema Introduction And DB Abstraction Layer (M2)

### Goal

Introduce both schemas and a stable DB API that hides backend differences.

### Tasks

- [x] Ensure schema assets exist and are treated as authoritative:
  - [x] `docs/design/db/schema_postgres.sql`
  - [x] `docs/design/db/schema_sqlite.sql`

- [x] Implement DB connection layer in PyPNM:
  - [x] SQLite connection opens with `PRAGMA foreign_keys = ON`
  - [x] SQLite enables WAL + sets a busy timeout (to reduce transient contention)
  - [x] Postgres connection opens via DSN (minimum) or discrete settings
  - [x] Minimal connection factory based on `Database.backend`

- [x] Implement schema apply/init (idempotent, using shipped DDL assets):
  - [x] Apply DDL idempotently on startup/install
  - [x] Seed canonical `UNKNOWN` sysDescr row idempotently
  - [x] Seed default `artifact_stores` row idempotently:
    - [x] prod store: `.data/pnm`
    - [ ] demo store: `demo/.data/pnm` (only if demo enabled/used)

- [x] Add “DB health” check function for diagnostics:
  - [x] Connect, verify required tables exist, verify `UNKNOWN` row exists
  - [x] Verify schema version compatibility (`schema_meta.schema_version`)

- [x] Add pytest coverage:
  - [x] SQLite: init creates tables and seed rows (pure unit test)
  - [x] Postgres: init path is wired; CI runs minimal integration

### Acceptance Criteria

- [x] PyPNM can initialize DB schema for SQLite reliably.
- [x] Postgres path is implemented and can be exercised with integration tests.
- [x] `UNKNOWN` sysDescr exists after init.
- [x] Schema version mismatch fails fast with an actionable error.

## Phase 3 · Transactions Migration (DB-Backed Transactions) (M3)

### Goal

Replace the legacy JSON transaction ledger with DB-backed `transaction_records` plus de-dup dimensions, and update endpoint read paths.

Cutover note:

- Runtime must stop writing and reading legacy JSON transaction ledgers once DB-backed transactions are enabled.
- Other legacy ledgers remain until M4.

### Tasks

- [x] Implement repository/service layer:
  - [x] `SystemDescriptionRepository` (upsert by hash)
  - [x] `DeviceDetailsRepository` (upsert by hash, FK sysDescr)
  - [x] `TransactionRepository` (insert/get/list/search)

- [x] Enforce safeguards:
  - [x] MAC normalization in app (lowercase)
  - [x] Rely on DB CHECK constraints for MAC format enforcement

- [x] Update transaction creation/read code to use DB:
  - [x] Stop writing legacy JSON transaction ledgers
  - [x] Preserve external API shapes as needed by current services/endpoints

- [x] Track JSON export artifacts in DB (file_artifacts + transaction_artifacts; no JSON ledger)

- [x] Update file-manager endpoints to query DB (no JSON ledger traversal):
  - [x] `getMacAddresses`
  - [x] `searchFiles/{mac_address}`
  - [x] `download/transactionID/{transaction_id}` resolves filename via DB record (artifact linkage becomes authoritative in M5)

- [x] Add pytest coverage:
  - [x] Insert transaction creates dims (sysDescr/device details)
  - [x] De-dup sysDescr across multiple transactions
  - [x] De-dup device details across multiple transactions
  - [x] Endpoint-compatible query behavior (service-level tests)

### Acceptance Criteria

- [x] Captures produce DB rows instead of writing legacy JSON ledgers.
- [x] File manager flows can fetch transactions from DB (no JSON ledger traversal for transactions).
- [x] There is no runtime write/read path that touches legacy JSON ledgers.
- [x] JSON export artifacts are tracked in DB without JSON ledger files.

## Phase 4 · Capture Group And Operation Migration (DB-Backed Capture Groups) (M4)

### Goal

Move multi-capture and operation tracking to DB, updating operation-based endpoints.

Cutover note:

- This phase stops runtime writes to capture-group and operation ledgers.
- Once complete, operation status/result endpoints must resolve via DB-backed repositories.

### Tasks

- [x] Implement `CaptureGroupRepository`:
  - [x] Create capture group
  - [x] Add ordered transaction membership (`position`)
  - [x] Load capture group with ordered transactions

- [x] Implement `OperationCaptureRepository`:
  - [x] Create operation capture linking to capture group
  - [x] Resolve operation capture -> capture group -> ordered transaction list
  - [x] Support legacy schema compatibility (`operation_id` vs `operation_capture_id`) without branching call sites

- [ ] Update existing grouping/operation services to use DB end-to-end:
  - [ ] Stop writing legacy capture-group ledgers
  - [ ] Stop writing legacy operation-capture ledgers
  - [ ] Stop reading capture/operation ledgers from runtime paths
  - [ ] Ensure multi-capture start/status/result endpoints resolve operation/group via DB only

- [ ] Update file-manager endpoint behavior:
  - [ ] `download/operationID/{operation_id}` resolves op -> group -> ordered tx list via DB

- [ ] Add pytest coverage:
  - [ ] Position uniqueness within group
  - [ ] Operation capture references group correctly
  - [ ] Endpoint path resolution uses DB (service-level tests)
  - [ ] Explicit assertion: no runtime read/write of capture/operation JSON ledgers

### Acceptance Criteria

- [ ] Multi-capture workflows no longer use JSON ledger files.
- [ ] Operation workflows resolve through DB (no JSON traversal).
- [ ] There is no runtime write path that touches capture/operation ledger JSON.

## Phase 5 · Artifact Linkage (Filesystem References) (M5)

### Goal

Make file linkage explicit via `artifact_stores`, `file_artifacts`, and `transaction_artifacts` so file resolution is DB-driven.

### Tasks

- [ ] Implement repositories:
  - [ ] `ArtifactStoreRepository`:
    - [ ] Ensure a default store exists (prod)
    - [ ] Ensure demo store exists when demo mode is used

  - [ ] `FileArtifactRepository`:
    - [ ] Insert/upsert file artifacts (sha256 + relative path)
    - [ ] Store `relative_path` relative to artifact store root
    - [ ] Capture `size_bytes` and optional `mime_type`

  - [ ] `TransactionArtifactRepository`:
    - [ ] Link transaction to artifact via `role`

- [ ] Update capture flow:
  - [ ] On capture success, write artifact row and link to transaction (`role=pnm_raw`)

- [ ] Update upload flow:
  - [ ] Create transaction using `UNKNOWN` sysDescr when sysDescr is missing
  - [ ] Store artifact linkage to uploaded file (`role=pnm_uploaded_raw`)

- [ ] Update file-manager service methods to resolve through artifact linkage:
  - [ ] `get_pnm_path_for_transaction()` resolves by role preference:
    - [ ] Prefer `pnm_raw`
    - [ ] Fallback `pnm_uploaded_raw`
  - [ ] Keep `transaction_records.filename` for readability/back-compat, but do not treat it as authoritative

- [ ] Add pytest coverage:
  - [ ] Resolve absolute paths from `app_root + store.root_path + artifact.relative_path`
  - [ ] Demo root isolation (`demo/.data/...` paths)
  - [ ] ZIP archive generation for MAC and operation uses DB-linked artifacts

### Acceptance Criteria

- [ ] Transactions resolve to binaries without any legacy settings JSON linkage.
- [ ] Demo and prod are isolated by data root and DB.
- [ ] Endpoints resolve files via DB artifact linkage exclusively.

## Phase 6 · Remove Ledger JSON Design And Code (M6)

### Goal

Delete ledger JSON code paths and remove ledger JSON design from documentation, replacing it with DB backend documentation.

### Tasks

- [ ] Remove JSON ledger creation paths:
  - [ ] Stop creating `.data/db/*.json` ledgers in capture flows
  - [ ] Remove any remaining ledger read code paths

- [ ] Remove or deprecate config keys related to ledgers:
  - [ ] `transaction_db`, `capture_group_db`, `operation_db`, `json_transaction_db`

- [ ] Remove or repurpose ledger modules:
  - [ ] Remove `pypnm/lib/db/json_transaction.py` if no longer needed
  - [ ] Remove/retire any code paths that still materialize ledger JSON in memory

- [ ] Documentation cleanup (explicit requirement):
  - [ ] Remove/replace all doc references to:
    - [ ] legacy JSON ledger paths for transactions, capture groups, and operations
  - [ ] Update file-manager docs to state DB-backed persistence for transactions/groups/operations
  - [ ] Ensure diagrams and examples reflect DB-backed persistence and artifact linkage

- [ ] MkDocs + tooling support for Mermaid (if not already satisfied in the repo):
  - [ ] Update `mkdocs.yml` to render Mermaid fences (Material: `pymdownx.superfences`)
  - [ ] Add the Mermaid plugin dependency to the docs extras in `pyproject.toml` (avoid redundant deps)

- [ ] Final hygiene scan:
  - [ ] Ensure no `.data/` artifacts are tracked or packaged

### Acceptance Criteria

- [ ] No code path depends on JSON ledgers at runtime.
- [ ] Docs and examples reflect DB backend design (no ledger design remains as “current”).
- [ ] Release artifacts contain no DB data.

## Phase 7 · Pytest And GitHub Actions Migration (M7)

### Goal

Ensure all tests and GitHub workflows pass with the new DB layer, removing ledger assumptions and validating Postgres support.

### Tasks

- [ ] Pytest refactor:
  - [ ] Locate and update/remove any tests that read/write `.data/db/*.json`
  - [ ] Replace ledger fixtures with DB fixtures (SQLite by default)
  - [ ] Add DB test utilities:
    - [ ] Temporary SQLite DB per test (or per module) under `tmp_path`
    - [ ] Schema init helper (idempotent DDL apply)
    - [ ] Seed helper for artifact stores and `UNKNOWN` sysDescr
  - [ ] Convert endpoint-level tests (if present) to use DB-backed services (no JSON)

- [ ] GitHub Actions refactor (required for DB backend release confidence):
  - [ ] Add a DB backend test matrix:
    - [ ] SQLite job (required)
    - [x] Postgres job (required; not “allowed failure”)
  - [x] Postgres service container job:
    - [x] Use `postgres` service with `POSTGRES_USER=pypnm`, `POSTGRES_PASSWORD=pypnm`, `POSTGRES_DB=pypnm`
    - [x] Provide DSN via env var to tests (no committed secrets)
    - [x] Apply schema during test setup (idempotent)
  - [ ] Ensure tests remain hermetic:
    - [ ] No external CMTS/SNMP dependencies in CI

- [ ] Developer documentation:
  - [x] Document what backends CI validates
  - [x] Document how to run Postgres tests locally (docker compose recommended)
  - [x] Document DSN override via environment variables

### Acceptance Criteria

- [ ] `pytest` passes locally for SQLite with DB-backed services.
- [ ] GitHub Actions passes with SQLite in the DB-backed test path.
- [x] Postgres path is validated in CI with a service container.

## Cross-Cutting Requirements

### PyPNM-CMTS Contract

- [ ] PyPNM-CMTS must not select a different backend than PyPNM.
- [ ] All DB interactions in PyPNM-CMTS must occur through PyPNM APIs only.

### Runtime Cutover Rule

- [ ] Runtime must not fall back to JSON ledger reads once DB read paths exist for that domain.
- [ ] Any legacy ledger handling must be isolated to an offline migrator tool (optional) and must not be required for normal runtime.

### Docker And K8 Notes

- [ ] SQLite: require a persistent volume mount for `.data/` and single-writer deployment.
- [ ] Postgres: require DSN secrets/config; stateless PyPNM containers.

### Testing

- [ ] Every phase adds pytest coverage for new/changed behavior.
- [ ] Tests must not require external CMTS or live SNMP.
- [ ] Treat deprecation warnings as failures.

## Suggested Codex Tracking Rules

Codex should maintain a running checklist aligned to these phases:

- Current phase and status
- Files changed in the phase
- Tests added and executed
- CI workflow impacts validated
- Deferred items (with rationale)

## Phase 2 · Schema Introduction And DB Abstraction Layer (M2) Status Block

- Status: Complete (schema assets authoritative, startup idempotent schema init, connection factory, health check, seeds for UNKNOWN sysDescr and default artifact store)
- Verified gates: compileall, ruff check, ruff format --check, pytest all green in the latest bundle
- Known deltas: demo artifact store seeding only required if demo mode is actively supported; otherwise defer to M5/demo hardening
- Next dependencies: M4 cutover enforcement (eliminate capture/operation JSON ledger runtime usage), then M5 artifact linkage as the authoritative file resolver
