# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import base64
import contextlib
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken


class SecretCryptoError(Exception):
    """
    Secret Encryption/Decryption Failure.

    Raised when a secret cannot be encrypted or decrypted due to missing keys,
    invalid token formats, permission problems, or cryptographic validation
    failures.
    """


@dataclass(frozen=True, slots=True)
class SecretToken:
    """
    Versioned Encrypted Secret Token.

    Attributes
    ----------
    version:
        Token version string (example: "v1").
    payload:
        The encrypted payload (Fernet token string).
    """

    version: str
    payload: str


class SecretCryptoManager:
    """
    Secret Encryption Manager For Config-Stored Passwords.

    This class supports storing encrypted passwords inside JSON configuration
    (example: system.json) while keeping the decryption key outside the repo,
    typically in the user's ~/.ssh directory.

    Security Model
    --------------
    - The encrypted password may safely live in the config file.
    - The decrypt key MUST NOT live in the config file or repo.
    - The decrypt key is loaded from one of:
      1) A key file (default: ~/.ssh/pypnm_secrets.key)
      2) An environment variable (default: PYPNM_SECRET_KEY)

    Token Format
    ------------
    Tokens are stored as:

        ENC[v1]:<fernet-token>

    Where <fernet-token> is a URL-safe base64 encoded token produced by Fernet.

    Notes
    -----
    Fernet provides authenticated encryption (confidentiality + integrity). If a
    token is altered, decryption will fail with an integrity error.
    """

    DEFAULT_ENV_VAR_NAME            = "PYPNM_SECRET_KEY"
    DEFAULT_KEY_FILE_NAME           = "pypnm_secrets.key"
    DEFAULT_TOKEN_VERSION           = "v1"
    DEFAULT_TOKEN_PREFIX            = "ENC"
    SSH_DIR_NAME                    = ".ssh"

    FERNET_KEY_SIZE_BYTES           = 32

    KEY_FILE_PERMISSIONS            = 0o600
    SSH_DIR_PERMISSIONS             = 0o700

    def __init__(self) -> None:
        self.logger = logging.getLogger(f"{self.__class__.__name__}")

    @staticmethod
    def default_key_path() -> Path:
        """
        Return The Default Key File Path Under ~/.ssh.

        Returns
        -------
        Path
            The default key file path: ~/.ssh/pypnm_secrets.key
        """
        home_dir = Path.home()
        return home_dir / SecretCryptoManager.SSH_DIR_NAME / SecretCryptoManager.DEFAULT_KEY_FILE_NAME

    @staticmethod
    def build_token(payload: str, version: str = DEFAULT_TOKEN_VERSION) -> str:
        """
        Build A Versioned Token String.

        Parameters
        ----------
        payload:
            Fernet token string (URL-safe base64).
        version:
            Token version (default: "v1").

        Returns
        -------
        str
            Versioned token string in format: ENC[vX]:<payload>
        """
        return f"{SecretCryptoManager.DEFAULT_TOKEN_PREFIX}[{version}]:{payload}"

    @staticmethod
    def parse_token(token: str) -> SecretToken:
        """
        Parse A Versioned Token String.

        Parameters
        ----------
        token:
            Token string in format: ENC[vX]:<payload>

        Returns
        -------
        SecretToken
            Parsed token components.

        Raises
        ------
        SecretCryptoError
            If the token is malformed or missing required parts.
        """
        prefix = f"{SecretCryptoManager.DEFAULT_TOKEN_PREFIX}["
        if not token.startswith(prefix):
            raise SecretCryptoError("Encrypted token missing expected 'ENC[...]:...' prefix.")

        end_bracket_index = token.find("]:")
        if end_bracket_index < 0:
            raise SecretCryptoError("Encrypted token missing closing ']:' delimiter.")

        version = token[len(prefix):end_bracket_index].strip()
        if version == "":
            raise SecretCryptoError("Encrypted token version is empty.")

        payload = token[end_bracket_index + 2:].strip()
        if payload == "":
            raise SecretCryptoError("Encrypted token payload is empty.")

        return SecretToken(version=version, payload=payload)

    @staticmethod
    def generate_key_b64() -> str:
        """
        Generate A New Fernet Key As A Base64 String.

        Returns
        -------
        str
            URL-safe base64 encoded key string.
        """
        key_bytes = Fernet.generate_key()
        return key_bytes.decode("utf-8")

    @staticmethod
    def write_key_file(key_path: Path, key_b64: str) -> Path:
        """
        Write A Fernet Key To Disk With Tight Permissions.

        Parameters
        ----------
        key_path:
            Path to write the key file (example: ~/.ssh/pypnm_secrets.key).
        key_b64:
            Fernet key (URL-safe base64 string).

        Returns
        -------
        Path
            The key_path written.

        Raises
        ------
        SecretCryptoError
            If the key is invalid or cannot be written securely.
        """
        SecretCryptoManager.validate_key_b64(key_b64)
        ssh_dir = key_path.parent
        ssh_dir.mkdir(parents=True, exist_ok=True)

        with contextlib.suppress(OSError):
            os.chmod(ssh_dir, SecretCryptoManager.SSH_DIR_PERMISSIONS)

        key_path.write_text(key_b64.strip() + "\n", encoding="utf-8")

        with contextlib.suppress(OSError):
            os.chmod(key_path, SecretCryptoManager.KEY_FILE_PERMISSIONS)

        return key_path

    @staticmethod
    def validate_key_b64(key_b64: str) -> None:
        """
        Validate A Fernet Key String.

        Parameters
        ----------
        key_b64:
            Fernet key as a URL-safe base64 string.

        Raises
        ------
        SecretCryptoError
            If the key is invalid.
        """
        key_str = key_b64.strip()
        if key_str == "":
            raise SecretCryptoError("Secret key is empty.")

        try:
            raw = base64.urlsafe_b64decode(key_str.encode("utf-8"))
        except Exception as exc:
            raise SecretCryptoError(f"Secret key is not valid base64: {exc}") from exc

        if len(raw) != SecretCryptoManager.FERNET_KEY_SIZE_BYTES:
            raise SecretCryptoError(
                f"Secret key decoded size is invalid: {len(raw)} bytes (expected {SecretCryptoManager.FERNET_KEY_SIZE_BYTES})."
            )

        try:
            Fernet(key_str.encode("utf-8"))
        except Exception as exc:
            raise SecretCryptoError(f"Secret key is not a valid Fernet key: {exc}") from exc

    @staticmethod
    def load_key_bytes(key_path: Path, env_var_name: str = DEFAULT_ENV_VAR_NAME) -> bytes:
        """
        Load Secret Key Bytes From Key File Or Environment Variable.

        Resolution Order
        ----------------
        1) key_path file
        2) env var env_var_name

        Parameters
        ----------
        key_path:
            Path to the key file (example: ~/.ssh/pypnm_secrets.key).
        env_var_name:
            Environment variable name to use as fallback (default: PYPNM_SECRET_KEY).

        Returns
        -------
        bytes
            Fernet key bytes.

        Raises
        ------
        SecretCryptoError
            If no key source is available or if the key is invalid.
        """
        if key_path.exists() and key_path.is_file():
            key_b64 = key_path.read_text(encoding="utf-8").strip()
            SecretCryptoManager.validate_key_b64(key_b64)
            return key_b64.encode("utf-8")

        env_value = os.environ.get(env_var_name, "").strip()
        if env_value != "":
            SecretCryptoManager.validate_key_b64(env_value)
            return env_value.encode("utf-8")

        raise SecretCryptoError(
            f"Missing secret key. Provide key file '{key_path}' or set environment variable '{env_var_name}'."
        )

    @staticmethod
    def encrypt_password(
        password: str,
        key_path: Path | None = None,
        env_var_name: str = DEFAULT_ENV_VAR_NAME,
        version: str = DEFAULT_TOKEN_VERSION,
    ) -> str:
        """
        Encrypt A Password For Storage In system.json.

        Parameters
        ----------
        password:
            Plaintext password to encrypt.
        key_path:
            Key file path. If empty, defaults to ~/.ssh/pypnm_secrets.key
        env_var_name:
            Environment variable for key fallback (default: PYPNM_SECRET_KEY).
        version:
            Token version label (default: "v1").

        Returns
        -------
        str
            Versioned token string in format: ENC[vX]:<payload>

        Raises
        ------
        SecretCryptoError
            If encryption fails due to missing/invalid key or invalid input.
        """
        password_str = password.strip()
        if password_str == "":
            raise SecretCryptoError("Password is empty; refusing to encrypt empty value.")

        actual_key_path = key_path if key_path is not None else SecretCryptoManager.default_key_path()
        key_bytes       = SecretCryptoManager.load_key_bytes(actual_key_path, env_var_name=env_var_name)
        fernet          = Fernet(key_bytes)

        token_bytes = fernet.encrypt(password_str.encode("utf-8"))
        token_str   = token_bytes.decode("utf-8")

        return SecretCryptoManager.build_token(payload=token_str, version=version)

    @staticmethod
    def decrypt_password(
        token: str,
        key_path: Path | None = None,
        env_var_name: str = DEFAULT_ENV_VAR_NAME,
        accepted_versions: tuple[str, ...] = (DEFAULT_TOKEN_VERSION,),
    ) -> str:
        """
        Decrypt A Password Token From system.json.

        Parameters
        ----------
        token:
            Versioned token string in format: ENC[vX]:<payload>
        key_path:
            Key file path. If empty, defaults to ~/.ssh/pypnm_secrets.key
        env_var_name:
            Environment variable for key fallback (default: PYPNM_SECRET_KEY).
        accepted_versions:
            Allowed token versions (default: ("v1",)).

        Returns
        -------
        str
            Decrypted plaintext password.

        Raises
        ------
        SecretCryptoError
            If decryption fails due to invalid token, missing key, wrong key,
            unsupported token version, or integrity/authentication failure.
        """
        token_str         = token.strip()
        parsed            = SecretCryptoManager.parse_token(token_str)
        version_supported = parsed.version in accepted_versions

        if not version_supported:
            raise SecretCryptoError(
                f"Unsupported encrypted token version '{parsed.version}'. Allowed: {', '.join(accepted_versions)}"
            )

        actual_key_path = key_path if key_path is not None else SecretCryptoManager.default_key_path()
        key_bytes       = SecretCryptoManager.load_key_bytes(actual_key_path, env_var_name=env_var_name)
        fernet          = Fernet(key_bytes)

        try:
            clear_bytes = fernet.decrypt(parsed.payload.encode("utf-8"))
        except InvalidToken as exc:
            raise SecretCryptoError("Failed to decrypt password: invalid token or wrong secret key.") from exc

        clear_str = clear_bytes.decode("utf-8").strip()
        if clear_str == "":
            raise SecretCryptoError("Decrypted password is empty; token or key may be invalid.")

        return clear_str

    @staticmethod
    def encrypt_system_config_secrets(config: dict[str, Any]) -> dict[str, Any]:
        """
        Encrypt System Config Secrets In-Place Semantics (Returns Updated Copy).

        Contract
        --------
        - Never persist a 'password' key.
        - If a password exists (from 'password' or 'password_enc'), store it as
          encrypted token in 'password_enc' (ENC[...]).
        - If password is empty, keep 'password_enc' as "" and still remove 'password'.
        - SCP is not handled here (removed as an option); this function only enforces
          secret storage semantics for configured methods.
        """
        pnm = config.get("PnmFileRetrieval", {})
        retrieval = pnm.get("retrieval_method")
        if not isinstance(retrieval, dict):
            legacy = pnm.get("retrival_method")
            retrieval = legacy if isinstance(legacy, dict) else {}
        methods = retrieval.get("methods", {})

        if not isinstance(methods, dict):
            return config

        for method_cfg in methods.values():
            if not isinstance(method_cfg, dict):
                continue

            password_enc = str(method_cfg.get("password_enc", "") or "").strip()
            password     = str(method_cfg.get("password", "") or "").strip()

            token_source = password_enc if password_enc != "" else password

            if token_source == "":
                method_cfg.pop("password", None)
                method_cfg["password_enc"] = ""
                continue

            if token_source.startswith("ENC["):
                method_cfg["password_enc"] = token_source
            else:
                method_cfg["password_enc"] = SecretCryptoManager.encrypt_password(token_source)

            method_cfg.pop("password", None)

        return config
