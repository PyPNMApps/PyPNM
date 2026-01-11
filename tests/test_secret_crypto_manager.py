# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import base64
import os
from pathlib import Path

import pytest
from _pytest.monkeypatch import MonkeyPatch

try:
    from pypnm.lib.secret.crypto_manager import SecretCryptoError, SecretCryptoManager
except ModuleNotFoundError as exc:
    raise ModuleNotFoundError(
        "Failed to import SecretCryptoManager. Update the import path in this test file to match your module location."
    ) from exc


KEY_ENV_NAME = SecretCryptoManager.DEFAULT_ENV_VAR_NAME
PASSWORD_CLEAR = "sftp_password_123!"
PASSWORD_CLEAR_2 = "another_password_456!"
INVALID_TOKEN_PREFIX = "BAD[v1]:abc"
INVALID_TOKEN_MISSING_DELIM = "ENC[v1]abc"
INVALID_TOKEN_EMPTY_VERSION = "ENC[]:abc"
INVALID_TOKEN_EMPTY_PAYLOAD = "ENC[v1]:"


def _set_home(monkeypatch: MonkeyPatch, home: Path) -> None:
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))


def test_generate_key_b64_validates() -> None:
    key_b64 = SecretCryptoManager.generate_key_b64()
    SecretCryptoManager.validate_key_b64(key_b64)


def test_validate_key_b64_rejects_empty() -> None:
    with pytest.raises(SecretCryptoError):
        SecretCryptoManager.validate_key_b64("")


def test_validate_key_b64_rejects_invalid_base64() -> None:
    with pytest.raises(SecretCryptoError):
        SecretCryptoManager.validate_key_b64("this-is-not-base64!!!")


def test_validate_key_b64_rejects_wrong_decoded_size() -> None:
    raw = b"abc"
    key_b64 = base64.urlsafe_b64encode(raw).decode("utf-8")

    with pytest.raises(SecretCryptoError):
        SecretCryptoManager.validate_key_b64(key_b64)


def test_build_and_parse_token_round_trip() -> None:
    token = SecretCryptoManager.build_token(payload="payload", version="v1")
    parsed = SecretCryptoManager.parse_token(token)

    assert parsed.version == "v1"
    assert parsed.payload == "payload"


def test_parse_token_rejects_bad_prefix() -> None:
    with pytest.raises(SecretCryptoError):
        SecretCryptoManager.parse_token(INVALID_TOKEN_PREFIX)


def test_parse_token_rejects_missing_delimiter() -> None:
    with pytest.raises(SecretCryptoError):
        SecretCryptoManager.parse_token(INVALID_TOKEN_MISSING_DELIM)


def test_parse_token_rejects_empty_version() -> None:
    with pytest.raises(SecretCryptoError):
        SecretCryptoManager.parse_token(INVALID_TOKEN_EMPTY_VERSION)


def test_parse_token_rejects_empty_payload() -> None:
    with pytest.raises(SecretCryptoError):
        SecretCryptoManager.parse_token(INVALID_TOKEN_EMPTY_PAYLOAD)


def test_default_key_path_uses_home(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    _set_home(monkeypatch, tmp_path)

    key_path = SecretCryptoManager.default_key_path()

    assert str(key_path).startswith(str(tmp_path))
    assert key_path.name == SecretCryptoManager.DEFAULT_KEY_FILE_NAME
    assert key_path.parent.name == SecretCryptoManager.SSH_DIR_NAME


def test_write_key_file_creates_and_validates(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    _set_home(monkeypatch, tmp_path)

    key_path = SecretCryptoManager.default_key_path()
    key_b64 = SecretCryptoManager.generate_key_b64()

    written_path = SecretCryptoManager.write_key_file(key_path, key_b64)

    assert written_path.exists() is True
    assert written_path.is_file() is True

    content = written_path.read_text(encoding="utf-8").strip()
    assert content == key_b64.strip()

    SecretCryptoManager.validate_key_b64(content)

    if os.name != "nt":
        ssh_dir_mode = key_path.parent.stat().st_mode & 0o777
        key_mode = key_path.stat().st_mode & 0o777

        assert ssh_dir_mode == SecretCryptoManager.SSH_DIR_PERMISSIONS
        assert key_mode == SecretCryptoManager.KEY_FILE_PERMISSIONS


def test_load_key_bytes_prefers_file_over_env(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    _set_home(monkeypatch, tmp_path)

    key_path = SecretCryptoManager.default_key_path()
    file_key_b64 = SecretCryptoManager.generate_key_b64()
    env_key_b64 = SecretCryptoManager.generate_key_b64()

    SecretCryptoManager.write_key_file(key_path, file_key_b64)
    monkeypatch.setenv(KEY_ENV_NAME, env_key_b64)

    loaded = SecretCryptoManager.load_key_bytes(key_path, env_var_name=KEY_ENV_NAME)

    assert loaded == file_key_b64.encode("utf-8")


def test_load_key_bytes_uses_env_when_file_missing(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    _set_home(monkeypatch, tmp_path)

    key_path = SecretCryptoManager.default_key_path()
    env_key_b64 = SecretCryptoManager.generate_key_b64()

    if key_path.exists():
        key_path.unlink()

    monkeypatch.setenv(KEY_ENV_NAME, env_key_b64)

    loaded = SecretCryptoManager.load_key_bytes(key_path, env_var_name=KEY_ENV_NAME)

    assert loaded == env_key_b64.encode("utf-8")


def test_load_key_bytes_raises_when_missing(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    _set_home(monkeypatch, tmp_path)

    key_path = SecretCryptoManager.default_key_path()

    if key_path.exists():
        key_path.unlink()

    monkeypatch.delenv(KEY_ENV_NAME, raising=False)

    with pytest.raises(SecretCryptoError):
        SecretCryptoManager.load_key_bytes(key_path, env_var_name=KEY_ENV_NAME)


def test_encrypt_decrypt_round_trip_with_env(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    _set_home(monkeypatch, tmp_path)

    key_path = SecretCryptoManager.default_key_path()
    env_key_b64 = SecretCryptoManager.generate_key_b64()

    monkeypatch.setenv(KEY_ENV_NAME, env_key_b64)

    token = SecretCryptoManager.encrypt_password(
        PASSWORD_CLEAR, key_path=key_path, env_var_name=KEY_ENV_NAME
    )
    decoded = SecretCryptoManager.decrypt_password(
        token, key_path=key_path, env_var_name=KEY_ENV_NAME
    )

    assert decoded == PASSWORD_CLEAR


def test_encrypt_decrypt_round_trip_with_key_file(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    _set_home(monkeypatch, tmp_path)

    key_path = SecretCryptoManager.default_key_path()
    file_key = SecretCryptoManager.generate_key_b64()

    SecretCryptoManager.write_key_file(key_path, file_key)

    token = SecretCryptoManager.encrypt_password(PASSWORD_CLEAR_2, key_path=key_path)
    decoded = SecretCryptoManager.decrypt_password(token, key_path=key_path)

    assert decoded == PASSWORD_CLEAR_2


def test_encrypt_rejects_empty_password(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    _set_home(monkeypatch, tmp_path)

    key_path = SecretCryptoManager.default_key_path()
    env_key_b64 = SecretCryptoManager.generate_key_b64()

    monkeypatch.setenv(KEY_ENV_NAME, env_key_b64)

    with pytest.raises(SecretCryptoError):
        SecretCryptoManager.encrypt_password(
            "   ", key_path=key_path, env_var_name=KEY_ENV_NAME
        )


def test_decrypt_rejects_unsupported_version(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    _set_home(monkeypatch, tmp_path)

    key_path = SecretCryptoManager.default_key_path()
    env_key_b64 = SecretCryptoManager.generate_key_b64()

    monkeypatch.setenv(KEY_ENV_NAME, env_key_b64)

    token = SecretCryptoManager.encrypt_password(
        PASSWORD_CLEAR, key_path=key_path, env_var_name=KEY_ENV_NAME, version="v2"
    )

    with pytest.raises(SecretCryptoError):
        SecretCryptoManager.decrypt_password(
            token,
            key_path=key_path,
            env_var_name=KEY_ENV_NAME,
            accepted_versions=("v1",),
        )


def test_decrypt_fails_with_wrong_key(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    _set_home(monkeypatch, tmp_path)

    key_path = SecretCryptoManager.default_key_path()
    env_key_b64 = SecretCryptoManager.generate_key_b64()
    env_key_b64_2 = SecretCryptoManager.generate_key_b64()

    monkeypatch.setenv(KEY_ENV_NAME, env_key_b64)

    token = SecretCryptoManager.encrypt_password(
        PASSWORD_CLEAR, key_path=key_path, env_var_name=KEY_ENV_NAME
    )

    monkeypatch.setenv(KEY_ENV_NAME, env_key_b64_2)

    with pytest.raises(SecretCryptoError):
        SecretCryptoManager.decrypt_password(
            token, key_path=key_path, env_var_name=KEY_ENV_NAME
        )
