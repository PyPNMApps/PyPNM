# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import os
from typing import Any

import pytest
from cryptography.fernet import Fernet

from pypnm.lib.secret.crypto_manager import SecretCryptoManager


@pytest.fixture(autouse=True)
def _ensure_test_secret_key(monkeypatch: pytest.MonkeyPatch) -> None:
    key = os.getenv("PYPNM_SECRET_KEY", "").strip()
    if key == "":
        monkeypatch.setenv("PYPNM_SECRET_KEY", Fernet.generate_key().decode("utf-8"))


def _get_methods(cfg: dict[str, Any]) -> dict[str, Any]:
    return (
        cfg.get("PnmFileRetrieval", {}).get("retrieval_method", {}).get("methods", {})
    )


def test_encryptor_moves_password_to_password_enc_and_roundtrips() -> None:
    cfg: dict[str, Any] = {
        "PnmFileRetrieval": {
            "retrieval_method": {
                "methods": {
                    "ftp": {"host": "ftp-host", "user": "u", "password": "p"},
                    "sftp": {"host": "sftp-host", "user": "u", "password": "p"},
                },
            },
        },
    }

    out = SecretCryptoManager.encrypt_system_config_secrets(cfg)

    methods = _get_methods(out)

    ftp = methods["ftp"]
    assert "password" not in ftp
    assert isinstance(ftp.get("password_enc", ""), str)
    assert ftp["password_enc"].startswith("ENC[")
    assert SecretCryptoManager.decrypt_password(ftp["password_enc"]) == "p"

    sftp = methods["sftp"]
    assert "password" not in sftp
    assert isinstance(sftp.get("password_enc", ""), str)
    assert sftp["password_enc"].startswith("ENC[")
    assert SecretCryptoManager.decrypt_password(sftp["password_enc"]) == "p"


def test_encryptor_encrypts_plain_password_enc_and_removes_password_field() -> None:
    cfg: dict[str, Any] = {
        "PnmFileRetrieval": {
            "retrieval_method": {
                "methods": {
                    "sftp": {
                        "host": "sftp-host",
                        "user": "u",
                        "password": "p",
                        "password_enc": "p",
                    },
                },
            },
        },
    }

    out = SecretCryptoManager.encrypt_system_config_secrets(cfg)

    sftp = _get_methods(out)["sftp"]
    assert "password" not in sftp
    assert isinstance(sftp.get("password_enc", ""), str)
    assert sftp["password_enc"].startswith("ENC[")
    assert SecretCryptoManager.decrypt_password(sftp["password_enc"]) == "p"


def test_encryptor_keeps_empty_password_enc_but_never_keeps_password_key() -> None:
    cfg: dict[str, Any] = {
        "PnmFileRetrieval": {
            "retrieval_method": {
                "methods": {
                    "ftp": {"host": "ftp-host", "user": "u", "password": ""},
                },
            },
        },
    }

    out = SecretCryptoManager.encrypt_system_config_secrets(cfg)

    ftp = _get_methods(out)["ftp"]
    assert "password" not in ftp
    assert ftp.get("password_enc", "") == ""
