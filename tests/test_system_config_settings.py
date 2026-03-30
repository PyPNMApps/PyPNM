# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pytest

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.mac_address import MacAddress


class FakeConfigManager:
    def __init__(self, data: dict[str, Any] | None = None) -> None:
        self._data: dict[str, Any] = data or {}
        self.reload_called: bool = False

    def get(self, *path: str) -> Any | None:
        key = ".".join(path)
        return self._data.get(key)

    def set(self, value: Any, *path: str) -> None:
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
    fake = FakeConfigManager(
        {"FastApiRequestDefault.mac_address": "aa:bb:cc:dd:ee:ff"}
    )
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
    fake = FakeConfigManager(
        {"FastApiRequestDefault.ip_address": "10.0.0.5"}
    )
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
    fake = FakeConfigManager(
        {"SNMP.version.2c.enable": True}
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)
    assert SystemConfigSettings.snmp_enable() is True

    # String false
    fake2 = FakeConfigManager(
        {"SNMP.version.2c.enable": "false"}
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake2)
    assert SystemConfigSettings.snmp_enable() is False

    # Invalid value falls back to default True and logs
    fake3 = FakeConfigManager(
        {"SNMP.version.2c.enable": "not-a-bool"}
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake3)

    logger_name = "SystemConfigSettings"
    with caplog.at_level(logging.ERROR, logger=logger_name):
        value = SystemConfigSettings.snmp_enable()

    assert value is True
    assert "Invalid boolean configuration value for 'SNMP.version.2c.enable'" in caplog.text


def test_snmp_retries_int_conversion_and_defaults(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Valid integer string
    fake = FakeConfigManager(
        {"SNMP.version.2c.retries": "7"}
    )
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
    fake3 = FakeConfigManager(
        {"SNMP.version.2c.retries": "not-an-int"}
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake3)

    with caplog.at_level(logging.ERROR, logger=logger_name):
        retries_invalid = SystemConfigSettings.snmp_retries()

    assert retries_invalid == 5
    assert "Invalid integer configuration value for 'SNMP.version.2c.retries'" in caplog.text


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
        base / ".data" / "runtime",
        base / "logs",
    ]

    for d in expected_dirs:
        assert d.is_dir(), f"Expected directory to exist: {d}"


def test_runtime_dir_uses_config_value(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeConfigManager(
        {"PnmFileRetrieval.runtime_dir": "/var/lib/pypnm/runtime"}
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    assert SystemConfigSettings.runtime_dir() == "/var/lib/pypnm/runtime"


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
    assert "Missing configuration value for 'PnmFileRetrieval.retrieval_method.methods.scp.port'" in text
    assert "Missing configuration value for 'PnmFileRetrieval.retrieval_method.methods.scp.private_key_path'" in text


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
    assert "Missing configuration value for 'PnmFileRetrieval.retrieval_method.methods.sftp.port'" in text
    assert "Missing configuration value for 'PnmFileRetrieval.retrieval_method.methods.sftp.private_key_path'" in text


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
    fake = FakeConfigManager(
        {"SNMP.version.2c.community": "legacy"}
    )
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
    fake = FakeConfigManager(
        {"SNMP.version.2c.community": "legacy"}
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    assert SystemConfigSettings.snmp_write_community() == ""


def test_snmp_write_community_uses_explicit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeConfigManager(
        {"SNMP.version.2c.write_community": "private"}
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    assert SystemConfigSettings.snmp_write_community() == "private"
