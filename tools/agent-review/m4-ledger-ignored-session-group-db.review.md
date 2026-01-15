## Agent Review Bundle Summary
- Goal:
- Changes:
- Files:
- Tests:
- Notes:

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
        cls._warn_deprecated_ledger_key("transaction_db")
        return ""

    @classmethod
    def capture_group_db(cls) -> str:
        cls._warn_deprecated_ledger_key("capture_group_db")
        return ""

    @classmethod
    def session_group_db(cls) -> str:
        cls._warn_deprecated_ledger_key("session_group_db")
        return ""

    @classmethod
    def operation_db(cls) -> str:
        cls._warn_deprecated_ledger_key("operation_db")
        return ""

    @classmethod
    def json_db(cls) -> str:
        cls._warn_deprecated_ledger_key("json_transaction_db")
        return ""

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
        cls._warn_deprecated_ledger_key("session_group_db")
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

# FILE: tests/test_system_config_settings.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from pydantic import ValidationError

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import DatabaseBackend


class FakeConfigManager:
    def __init__(self, data: dict[str, object] | None = None) -> None:
        self._data: dict[str, object] = data or {}
        self.reload_called: bool = False

    def get(self, *path: str) -> object | None:
        key = ".".join(path)
        return self._data.get(key)

    def set(self, value: object, *path: str) -> None:
        key = ".".join(path)
        self._data[key] = value

    def reload(self) -> None:
        self.reload_called = True


@pytest.fixture(autouse=True)
def _reset_cfg(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Ensure each test starts with a fresh FakeConfigManager.
    """
    fake = FakeConfigManager()
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)


def test_default_mac_address_from_config(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeConfigManager({"FastApiRequestDefault.mac_address": "aa:bb:cc:dd:ee:ff"})
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    mac = SystemConfigSettings.default_mac_address()
    assert mac == "aa:bb:cc:dd:ee:ff"


def test_default_mac_address_missing_uses_null_and_logs_error(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake = FakeConfigManager()
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    logger_name = "SystemConfigSettings"
    with caplog.at_level(logging.ERROR, logger=logger_name):
        mac = SystemConfigSettings.default_mac_address()

    assert mac == MacAddress.null()
    assert (
        "Missing configuration value for 'FastApiRequestDefault.mac_address'"
        in caplog.text
    )


def test_default_ip_address_uses_config_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeConfigManager({"FastApiRequestDefault.ip_address": "10.0.0.5"})
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    ip = SystemConfigSettings.default_ip_address()
    assert ip == "10.0.0.5"


def test_default_ip_address_missing_falls_back_to_default_and_logs(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake = FakeConfigManager()
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    logger_name = "SystemConfigSettings"
    with caplog.at_level(logging.ERROR, logger=logger_name):
        ip = SystemConfigSettings.default_ip_address()

    assert ip == "192.168.0.100"
    assert (
        "Missing configuration value for 'FastApiRequestDefault.ip_address'"
        in caplog.text
    )


def test_snmp_enable_boolean_and_string_handling(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Direct boolean True
    fake = FakeConfigManager({"SNMP.version.2c.enable": True})
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)
    assert SystemConfigSettings.snmp_enable() is True

    # String false
    fake2 = FakeConfigManager({"SNMP.version.2c.enable": "false"})
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake2)
    assert SystemConfigSettings.snmp_enable() is False

    # Invalid value falls back to default True and logs
    fake3 = FakeConfigManager({"SNMP.version.2c.enable": "not-a-bool"})
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake3)

    logger_name = "SystemConfigSettings"
    with caplog.at_level(logging.ERROR, logger=logger_name):
        value = SystemConfigSettings.snmp_enable()

    assert value is True
    assert (
        "Invalid boolean configuration value for 'SNMP.version.2c.enable'"
        in caplog.text
    )


def test_snmp_retries_int_conversion_and_defaults(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Valid integer string
    fake = FakeConfigManager({"SNMP.version.2c.retries": "7"})
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)
    assert SystemConfigSettings.snmp_retries() == 7

    # Missing => default 5 with log
    fake2 = FakeConfigManager()
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake2)

    logger_name = "SystemConfigSettings"
    with caplog.at_level(logging.ERROR, logger=logger_name):
        retries_missing = SystemConfigSettings.snmp_retries()

    assert retries_missing == 5
    assert "Missing configuration value for 'SNMP.version.2c.retries'" in caplog.text

    # Invalid => default 5 with log
    fake3 = FakeConfigManager({"SNMP.version.2c.retries": "not-an-int"})
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake3)

    with caplog.at_level(logging.ERROR, logger=logger_name):
        retries_invalid = SystemConfigSettings.snmp_retries()

    assert retries_invalid == 5
    assert (
        "Invalid integer configuration value for 'SNMP.version.2c.retries'"
        in caplog.text
    )


def test_database_backend_defaults_to_sqlite_when_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeConfigManager()
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    backend = SystemConfigSettings.database_backend()
    assert backend == DatabaseBackend.SQLITE


def test_database_settings_env_override_for_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeConfigManager({"Database.backend": "sqlite"})
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)
    monkeypatch.setenv("PYPNM_DB_BACKEND", "postgres")
    monkeypatch.setenv(
        "PYPNM_DB_POSTGRES_DSN", "postgresql://pypnm@localhost:5432/pypnm"
    )

    settings = SystemConfigSettings.database_settings()
    assert settings.backend == DatabaseBackend.POSTGRES


def test_database_settings_rejects_invalid_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeConfigManager({"Database.backend": "oracle"})
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    with pytest.raises(ValidationError):
        SystemConfigSettings.database_settings()


def test_database_settings_rejects_blank_sqlite_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeConfigManager({"Database.sqlite.path": ""})
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    with pytest.raises(ValidationError):
        SystemConfigSettings.database_settings()


def test_database_settings_env_override_for_postgres_dsn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeConfigManager(
        {
            "Database.backend": "postgres",
            "Database.postgres.dsn": "",
        }
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)
    monkeypatch.setenv(
        "PYPNM_DB_POSTGRES_DSN", "postgresql://pypnm@localhost:5432/pypnm"
    )

    settings = SystemConfigSettings.database_settings()
    assert settings.postgres.dsn == "postgresql://pypnm@localhost:5432/pypnm"


def test_database_settings_blank_postgres_dsn_without_env_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeConfigManager(
        {
            "Database.backend": "postgres",
            "Database.postgres.dsn": "",
        }
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    with pytest.raises(ValidationError):
        SystemConfigSettings.database_settings()


def test_log_settings_with_defaults_and_overrides(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Override all three logging keys
    fake = FakeConfigManager(
        {
            "logging.log_level": "DEBUG",
            "logging.log_dir": "/var/log/pypnm",
            "logging.log_filename": "custom.log",
        }
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    assert SystemConfigSettings.log_level() == "DEBUG"
    assert SystemConfigSettings.log_dir() == "/var/log/pypnm"
    assert SystemConfigSettings.log_filename() == "custom.log"

    # Missing keys => defaults with error logs
    fake2 = FakeConfigManager()
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake2)

    logger_name = "SystemConfigSettings"
    with caplog.at_level(logging.ERROR, logger=logger_name):
        level = SystemConfigSettings.log_level()
        log_dir = SystemConfigSettings.log_dir()
        fname = SystemConfigSettings.log_filename()

    assert level == "INFO"
    assert log_dir == "logs"
    assert fname == "pypnm.log"

    text = caplog.text
    assert "Missing configuration value for 'logging.log_level'" in text
    assert "Missing configuration value for 'logging.log_dir'" in text
    assert "Missing configuration value for 'logging.log_filename'" in text


def test_initialize_directories_creates_expected_default_dirs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """
    Use defaults and change CWD so .data/* and logs/ are created under tmp_path.
    """
    fake = FakeConfigManager()
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    monkeypatch.chdir(tmp_path)

    SystemConfigSettings.initialize_directories()

    # Defaults from SystemConfigSettings
    base = tmp_path
    expected_dirs = [
        base / ".data" / "pnm",
        base / ".data" / "csv",
        base / ".data" / "json",
        base / ".data" / "xlsx",
        base / ".data" / "png",
        base / ".data" / "archive",
        base / ".data" / "msg_rsp",
        base / "logs",
    ]

    for d in expected_dirs:
        assert d.is_dir(), f"Expected directory to exist: {d}"


def test_reload_calls_config_reload_and_initializes_directories(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fake = FakeConfigManager()
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)
    monkeypatch.chdir(tmp_path)

    SystemConfigSettings.reload()

    # reload() must have been called on the underlying ConfigManager
    assert fake.reload_called is True

    # And directories should be initialized as in the previous test
    base = tmp_path
    assert (base / ".data" / "pnm").is_dir()
    assert (base / "logs").is_dir()


def test_deprecated_ledger_keys_warn_once_and_ignore(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake = FakeConfigManager(
        {
            "PnmFileRetrieval.transaction_db": "legacy-transaction",
            "PnmFileRetrieval.capture_group_db": "legacy-capture-group",
            "PnmFileRetrieval.session_group_db": "legacy-session-group",
            "PnmFileRetrieval.operation_db": "legacy-operation",
            "PnmFileRetrieval.json_transaction_db": "legacy-json",
        }
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)
    monkeypatch.setattr(SystemConfigSettings, "_deprecated_ledger_warned", set())
    monkeypatch.chdir(tmp_path)

    logger_name = "SystemConfigSettings"
    with caplog.at_level(logging.WARNING, logger=logger_name):
        SystemConfigSettings.initialize_directories()

        assert SystemConfigSettings.transaction_db() == ""
        assert SystemConfigSettings.capture_group_db() == ""
        assert SystemConfigSettings.session_group_db() == ""
        assert SystemConfigSettings.operation_db() == ""
        assert SystemConfigSettings.json_db() == ""

        assert SystemConfigSettings.transaction_db() == ""
        assert SystemConfigSettings.capture_group_db() == ""
        assert SystemConfigSettings.session_group_db() == ""
        assert SystemConfigSettings.operation_db() == ""
        assert SystemConfigSettings.json_db() == ""

    expected_keys = [
        "transaction_db",
        "capture_group_db",
        "session_group_db",
        "operation_db",
        "json_transaction_db",
    ]
    for key in expected_keys:
        expected = (
            f"Configuration key 'PnmFileRetrieval.{key}' is deprecated and ignored "
            "at runtime; remove it from system.json"
        )
        assert caplog.text.count(expected) == 1


def test_scp_settings_use_config_values(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeConfigManager(
        {
            "PnmFileRetrieval.retrieval_method.methods.scp.host": "scp-host",
            "PnmFileRetrieval.retrieval_method.methods.scp.port": "2222",
            "PnmFileRetrieval.retrieval_method.methods.scp.user": "scpuser",
            "PnmFileRetrieval.retrieval_method.methods.scp.password": "scppass",
            "PnmFileRetrieval.retrieval_method.methods.scp.private_key_path": "/home/test/.ssh/id_rsa_scp",
            "PnmFileRetrieval.retrieval_method.methods.scp.remote_dir": "/srv/tftp",
        }
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    assert SystemConfigSettings.scp_host() == "scp-host"
    assert SystemConfigSettings.scp_port() == 2222
    assert SystemConfigSettings.scp_user() == "scpuser"
    assert SystemConfigSettings.scp_password() == "scppass"
    assert SystemConfigSettings.scp_private_key_path() == "/home/test/.ssh/id_rsa_scp"
    assert SystemConfigSettings.scp_remote_dir() == "/srv/tftp"


def test_scp_port_and_private_key_defaults_and_logs(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake = FakeConfigManager(
        {
            "PnmFileRetrieval.retrieval_method.methods.scp.host": "localhost",
        }
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    logger_name = "SystemConfigSettings"
    with caplog.at_level(logging.ERROR, logger=logger_name):
        port = SystemConfigSettings.scp_port()
        key_path = SystemConfigSettings.scp_private_key_path()

    assert port == 22
    assert key_path == ""

    text = caplog.text
    assert (
        "Missing configuration value for 'PnmFileRetrieval.retrieval_method.methods.scp.port'"
        in text
    )
    assert (
        "Missing configuration value for 'PnmFileRetrieval.retrieval_method.methods.scp.private_key_path'"
        in text
    )


def test_sftp_settings_use_config_values(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeConfigManager(
        {
            "PnmFileRetrieval.retrieval_method.methods.sftp.host": "sftp-host",
            "PnmFileRetrieval.retrieval_method.methods.sftp.port": "2223",
            "PnmFileRetrieval.retrieval_method.methods.sftp.user": "sftpuser",
            "PnmFileRetrieval.retrieval_method.methods.sftp.password": "sftppass",
            "PnmFileRetrieval.retrieval_method.methods.sftp.private_key_path": "/home/test/.ssh/id_rsa_sftp",
            "PnmFileRetrieval.retrieval_method.methods.sftp.remote_dir": "/srv/tftp-sftp",
        }
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    assert SystemConfigSettings.sftp_host() == "sftp-host"
    assert SystemConfigSettings.sftp_port() == 2223
    assert SystemConfigSettings.sftp_user() == "sftpuser"
    assert SystemConfigSettings.sftp_password() == "sftppass"
    assert SystemConfigSettings.sftp_private_key_path() == "/home/test/.ssh/id_rsa_sftp"
    assert SystemConfigSettings.sftp_remote_dir() == "/srv/tftp-sftp"


def test_sftp_port_and_private_key_defaults_and_logs(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake = FakeConfigManager(
        {
            "PnmFileRetrieval.retrieval_method.methods.sftp.host": "localhost",
        }
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    logger_name = "SystemConfigSettings"
    with caplog.at_level(logging.ERROR, logger=logger_name):
        port = SystemConfigSettings.sftp_port()
        key_path = SystemConfigSettings.sftp_private_key_path()

    assert port == 22
    assert key_path == ""

    text = caplog.text
    assert (
        "Missing configuration value for 'PnmFileRetrieval.retrieval_method.methods.sftp.port'"
        in text
    )
    assert (
        "Missing configuration value for 'PnmFileRetrieval.retrieval_method.methods.sftp.private_key_path'"
        in text
    )


def test_snmp_read_community_defaults_to_public(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeConfigManager()
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    assert SystemConfigSettings.snmp_read_community() == "public"


def test_snmp_write_community_defaults_to_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeConfigManager()
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    assert SystemConfigSettings.snmp_write_community() == ""


def test_snmp_read_community_falls_back_to_legacy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeConfigManager({"SNMP.version.2c.community": "legacy"})
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    assert SystemConfigSettings.snmp_read_community() == "legacy"


def test_snmp_read_community_prefers_explicit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeConfigManager(
        {
            "SNMP.version.2c.read_community": "read",
            "SNMP.version.2c.community": "legacy",
        }
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    assert SystemConfigSettings.snmp_read_community() == "read"


def test_snmp_write_community_does_not_use_legacy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeConfigManager({"SNMP.version.2c.community": "legacy"})
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    assert SystemConfigSettings.snmp_write_community() == ""


def test_snmp_write_community_uses_explicit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeConfigManager({"SNMP.version.2c.write_community": "private"})
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    assert SystemConfigSettings.snmp_write_community() == "private"

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
Deprecated JSON ledger keys are ignored at runtime; session groups are DB-backed and legacy JSON maps are supported only via the offline migrator.

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
| session_group_db    | string | Deprecated and ignored at runtime; use the offline migrator for legacy session-group JSON. |
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

DB backend migration is in progress; legacy ledger keys are retained for migration tooling and ignored at runtime.

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
