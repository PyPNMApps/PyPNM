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
    _cfg        = ConfigManager()
    _logger     = logging.getLogger("SystemConfigSettings")

    _DEFAULT_IP_ADDRESS: InetAddressStr      = cast(InetAddressStr, "192.168.0.100")
    _DEFAULT_SNMP_RETRIES: int              = 5
    _DEFAULT_SNMP_TIMEOUT: int              = 2
    _DEFAULT_FILE_RETRIEVAL_RETRIES: int    = 5
    _DEFAULT_HTTP_PORT: int                 = 80
    _DEFAULT_HTTPS_PORT: int                = 443
    _DEFAULT_TFTP_PORT: int                 = 69
    _DEFAULT_FTP_PORT: int                  = 21
    _DEFAULT_SFTP_PORT: int                 = 22
    _DEFAULT_SCP_PORT: int                  = 22
    _DEFAULT_LOG_LEVEL: str                 = "INFO"
    _DEFAULT_LOG_DIR: str                   = "logs"
    _DEFAULT_LOG_FILENAME: str              = "pypnm.log"
    _DEFAULT_SNMP_READ_COMMUNITY: str       = "public"
    _DEFAULT_SNMP_WRITE_COMMUNITY: str      = ""
    _DEFAULT_PNM_DIR: str                   = ".data/pnm"
    _DEFAULT_CSV_DIR: str                   = ".data/csv"
    _DEFAULT_JSON_DIR: str                  = ".data/json"
    _DEFAULT_XLSX_DIR: str                  = ".data/xlsx"
    _DEFAULT_PNG_DIR: str                   = ".data/png"
    _DEFAULT_ARCHIVE_DIR: str               = ".data/archive"
    _DEFAULT_MSG_RSP_DIR: str               = ".data/msg_rsp"
    _DEFAULT_DB_BACKEND: DatabaseBackend    = DatabaseBackend.SQLITE
    _DEFAULT_SQLITE_DB_PATH: DatabasePath   = DEFAULT_SQLITE_DB_PATH
    _DEFAULT_POSTGRES_DSN: DatabaseDsn      = DEFAULT_POSTGRES_DSN
    _POSTGRES_DSN_ENV_VAR: str              = POSTGRES_DSN_ENV_VAR
    _DB_BACKEND_ENV_VAR: str               = "PYPNM_DB_BACKEND"

    _ENCRYPTED_TOKEN_PREFIX: str            = "ENC["

    _PRIMARY_RETRIEVAL_METHOD_KEY: str      = "retrieval_method"
    _LEGACY_RETRIEVAL_METHOD_KEY: str       = "retrival_method"

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
    def _peek_str_fallback(cls, primary: tuple[str, ...], legacy: tuple[str, ...]) -> str:
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
    def _get_password_value_fallback(cls, require: bool, primary: tuple[str, ...], legacy: tuple[str, ...]) -> str:
        password_enc = cls._peek_str_fallback(primary + ("password_enc",), legacy + ("password_enc",))
        if password_enc.strip() != "":
            decrypted = cls._maybe_decrypt(password_enc, *(primary + ("password_enc",)))
            if decrypted != "":
                return decrypted
            if require:
                return ""

        password = cls._peek_str_fallback(primary + ("password",), legacy + ("password",))
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
    def _get_str_fallback(cls, default: str, primary: tuple[str, ...], legacy: tuple[str, ...]) -> str:
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
    def _get_str_fallback_allow_empty(cls, default: str, primary: tuple[str, ...], legacy: tuple[str, ...]) -> str:
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
    def _get_int_fallback(cls, default: int, primary: tuple[str, ...], legacy: tuple[str, ...]) -> int:
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
    def _get_bool_fallback(cls, default: bool, primary: tuple[str, ...], legacy: tuple[str, ...]) -> bool:
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
            cls._get_str(cls._DEFAULT_IP_ADDRESS, "FastApiRequestDefault", "ip_address"),
        )

    # SNMP v2 settings
    @classmethod
    def snmp_enable(cls) -> bool:
        return cls._get_bool(True, "SNMP", "version", "2c", "enable")

    @classmethod
    def snmp_retries(cls) -> int:
        return cls._get_int(cls._DEFAULT_SNMP_RETRIES, "SNMP", "version", "2c", "retries")



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
            cls._get_str(cls._DEFAULT_SNMP_READ_COMMUNITY, "SNMP", "version", "2c", "read_community"),
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
            cls._get_str(cls._DEFAULT_SNMP_WRITE_COMMUNITY, "SNMP", "version", "2c", "write_community"),
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
        return cls._get_int(cls._DEFAULT_HTTP_PORT, "PnmBulkDataTransfer", "http", "port")

    @classmethod
    def bulk_https_base_url(cls) -> str:
        return cls._get_str("", "PnmBulkDataTransfer", "https", "base_url")

    @classmethod
    def bulk_https_port(cls) -> int:
        return cls._get_int(cls._DEFAULT_HTTPS_PORT, "PnmBulkDataTransfer", "https", "port")

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
        return cls._get_int(cls._DEFAULT_FILE_RETRIEVAL_RETRIES, "PnmFileRetrieval", "retries")

    @classmethod
    def retrieval_method(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "method")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "method")

        return cls._get_str_fallback("", primary, legacy)

    # Local method
    @classmethod
    def local_src_dir(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "local", "src_dir")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "local", "src_dir")
        return cls._get_str_fallback("", primary, legacy)

    # TFTP method
    @classmethod
    def tftp_host(cls) -> InetAddressStr:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "tftp", "host")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "tftp", "host")
        return InetAddressStr(cls._get_str_fallback("", primary, legacy))

    @classmethod
    def tftp_port(cls) -> int:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "tftp", "port")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "tftp", "port")
        return cls._get_int_fallback(cls._DEFAULT_TFTP_PORT, primary, legacy)

    @classmethod
    def tftp_timeout(cls) -> int:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "tftp", "timeout")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "tftp", "timeout")
        return cls._get_int_fallback(cls._DEFAULT_SNMP_TIMEOUT, primary, legacy)

    @classmethod
    def tftp_remote_dir(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "tftp", "remote_dir")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "tftp", "remote_dir")
        return cls._get_str_fallback_allow_empty("", primary, legacy)

    # FTP method
    @classmethod
    def ftp_host(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "host")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "host")
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def ftp_port(cls) -> int:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "port")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "port")
        return cls._get_int_fallback(cls._DEFAULT_FTP_PORT, primary, legacy)

    @classmethod
    def ftp_use_tls(cls) -> bool:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "tls")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "tls")
        return cls._get_bool_fallback(False, primary, legacy)

    @classmethod
    def ftp_timeout(cls) -> int:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "timeout")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "timeout")
        return cls._get_int_fallback(cls._DEFAULT_SNMP_TIMEOUT, primary, legacy)

    @classmethod
    def ftp_user(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "user")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "user")
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def ftp_password(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "ftp")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "ftp")
        return cls._get_password_value_fallback(
            True,
            primary,
            legacy,
        )

    @classmethod
    def ftp_remote_dir(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "remote_dir")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "remote_dir")
        return cls._get_str_fallback_allow_empty("", primary, legacy)

    # SCP method
    @classmethod
    def scp_host(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "scp", "host")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "scp", "host")
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def scp_port(cls) -> int:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "scp", "port")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "scp", "port")
        return cls._get_int_fallback(cls._DEFAULT_SCP_PORT, primary, legacy)

    @classmethod
    def scp_user(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "scp", "user")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "scp", "user")
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def scp_password(cls) -> str:
        private_key_path_primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "scp", "private_key_path")
        private_key_path_legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "scp", "private_key_path")
        private_key_path         = cls._peek_str_fallback(private_key_path_primary, private_key_path_legacy).strip()
        require                  = private_key_path == ""

        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "scp")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "scp")

        return cls._get_password_value_fallback(
            require,
            primary,
            legacy,
        )

    @classmethod
    def scp_private_key_path(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "scp", "private_key_path")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "scp", "private_key_path")
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def scp_remote_dir(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "scp", "remote_dir")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "scp", "remote_dir")
        return cls._get_str_fallback_allow_empty("", primary, legacy)

    # SFTP method
    @classmethod
    def sftp_host(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "host")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "host")
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def sftp_port(cls) -> int:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "port")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "port")
        return cls._get_int_fallback(cls._DEFAULT_SFTP_PORT, primary, legacy)

    @classmethod
    def sftp_user(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "user")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "user")
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def sftp_password(cls) -> str:
        private_key_path_primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "private_key_path")
        private_key_path_legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "private_key_path")
        private_key_path         = cls._peek_str_fallback(private_key_path_primary, private_key_path_legacy).strip()
        require                  = private_key_path == ""

        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "sftp")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "sftp")

        return cls._get_password_value_fallback(
            require,
            primary,
            legacy,
        )

    @classmethod
    def sftp_private_key_path(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "private_key_path")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "private_key_path")
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def sftp_remote_dir(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "remote_dir")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "remote_dir")
        return cls._get_str_fallback_allow_empty("", primary, legacy)

    # HTTP method
    @classmethod
    def http_base_url(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "http", "base_url")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "http", "base_url")
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def http_port(cls) -> int:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "http", "port")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "http", "port")
        return cls._get_int_fallback(cls._DEFAULT_HTTP_PORT, primary, legacy)

    # HTTPS method
    @classmethod
    def https_base_url(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "https", "base_url")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "https", "base_url")
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def https_port(cls) -> int:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "https", "port")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "https", "port")
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
    def reload(cls) -> None:
        """
        Reload the configuration settings.
        """
        cls._cfg.reload()
        cls.initialize_directories()
