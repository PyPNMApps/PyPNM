# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import contextlib
import logging
import os

import paramiko

from pypnm.lib.secret.crypto_manager import SecretCryptoError, SecretCryptoManager
from pypnm.lib.types import (
    HostNameStr,
    PathLike,
    RemoteDirEntries,
    SshCommandResult,
    SshOk,
    UserNameStr,
)


class SSHConnector:
    """
    SSH Connector For Secure File Transfer And Remote Commands.

    This connector provides SFTP (Paramiko) file transfers and remote command
    execution over SSH. Passwords may be provided as encrypted tokens
    (ENC[...]) and are decrypted only inside connect().

    Security Notes
    --------------
    - Encrypted password tokens may be stored in configuration.
    - Decryption happens only at connect time.
    - Plaintext password is not stored on the instance.
    """

    DEFAULT_CONNECT_TIMEOUT_SEC: int = 10
    DEFAULT_RSA_KEY_BITS: int = 2048
    DEFAULT_SSH_PORT: int = 22

    ENCRYPTED_TOKEN_PREFIX: str = "ENC["

    def __init__(
        self,
        hostname: HostNameStr,
        username: UserNameStr,
        port: int = DEFAULT_SSH_PORT,
    ) -> None:
        """
        Initialize Connection Parameters.

        Parameters
        ----------
        hostname:
            Hostname or IP address of the remote machine.
        username:
            SSH login username.
        port:
            SSH port (default: 22).
        """
        self.logger = logging.getLogger(f"{self.__class__.__name__}")

        self.hostname = hostname
        self.username = username
        self.port = int(port)

        self.ssh_client: paramiko.SSHClient | None = None
        self.sftp_client: paramiko.SFTPClient | None = None

    def connect(
        self,
        password_enc: str = "",
        private_key_path: str = "",
        auto_add_policy: bool = True,
    ) -> SshOk:
        """
        Establish An SSH Session And Initialize SFTP.

        Parameters
        ----------
        password_enc:
            Encrypted password token (ENC[...]). Plaintext is accepted only for
            backward compatibility. The plaintext password is not stored.
        private_key_path:
            Private key path for key-based authentication. Empty disables key auth.
        auto_add_policy:
            If True, unknown host keys are accepted.

        Returns
        -------
        SshOk
            True on success, False on failure.
        """
        password_token = password_enc.strip()
        key_path = private_key_path.strip()

        auth_modes: list[str] = []
        if key_path != "":
            auth_modes.append("key")
        if password_token != "":
            if password_token.startswith(self.ENCRYPTED_TOKEN_PREFIX):
                auth_modes.append("password_enc")
            else:
                auth_modes.append("password(clear-legacy)")

        self.logger.info(
            "SSH auth configured: %s",
            "+".join(auth_modes) if auth_modes else "none",
        )

        password_clear = ""
        if password_token != "":
            if password_token.startswith(self.ENCRYPTED_TOKEN_PREFIX):
                try:
                    password_clear = SecretCryptoManager.decrypt_password(
                        password_token
                    )
                except SecretCryptoError as exc:
                    self.logger.error("Failed to decrypt password token: %s", exc)
                    return False
            else:
                password_clear = password_token

        def _attempt(label: str, use_key: bool, use_password: bool) -> SshOk:
            self.logger.info("SSH auth attempt: %s", label)

            client = paramiko.SSHClient()
            client.load_system_host_keys()
            policy = (
                paramiko.AutoAddPolicy() if auto_add_policy else paramiko.RejectPolicy()
            )
            client.set_missing_host_key_policy(policy)

            connect_kwargs: dict[str, object] = {
                "hostname": self.hostname,
                "port": self.port,
                "username": self.username,
                "timeout": float(self.DEFAULT_CONNECT_TIMEOUT_SEC),
            }

            if use_key:
                connect_kwargs["key_filename"] = os.path.expanduser(key_path)

            if use_password and password_clear != "":
                connect_kwargs["password"] = password_clear

            try:
                client.connect(**connect_kwargs)  # type: ignore[arg-type]

                transport = client.get_transport()
                if transport is None or not transport.is_active():
                    self.logger.error("SSH transport is not active after connect().")
                    with contextlib.suppress(Exception):
                        client.close()
                    return False

                self.ssh_client = client
                self.sftp_client = paramiko.SFTPClient.from_transport(transport)

                self.logger.info("SSH auth succeeded: %s", label)
                self.logger.debug(
                    "Connected to %s:%d via SFTP", self.hostname, self.port
                )
                return True

            except Exception as exc:
                self.logger.info("SSH auth failed: %s (%s)", label, exc)
                with contextlib.suppress(Exception):
                    client.close()
                return False

        try:
            if key_path != "" and password_clear != "":
                if _attempt(label="key", use_key=True, use_password=False):
                    return True

                self.disconnect()
                return _attempt(
                    label="password_enc"
                    if password_token.startswith(self.ENCRYPTED_TOKEN_PREFIX)
                    else "password(clear-legacy)",
                    use_key=False,
                    use_password=True,
                )

            if key_path != "":
                return _attempt(label="key", use_key=True, use_password=False)

            if password_clear != "":
                return _attempt(
                    label="password_enc"
                    if password_token.startswith(self.ENCRYPTED_TOKEN_PREFIX)
                    else "password(clear-legacy)",
                    use_key=False,
                    use_password=True,
                )

            self.logger.error(
                "No SSH authentication configured (missing key and password_enc)."
            )
            return False

        finally:
            password_clear = ""

    def disconnect(self) -> None:
        """
        Close Any Active SFTP And SSH Sessions.
        """
        if self.sftp_client is not None:
            with contextlib.suppress(Exception):
                self.sftp_client.close()
            self.sftp_client = None

        if self.ssh_client is not None:
            with contextlib.suppress(Exception):
                self.ssh_client.close()
            self.ssh_client = None

        self.logger.debug("Disconnected from remote host")

    def send_file(self, local_path: PathLike, remote_path: PathLike) -> SshOk:
        """
        Transfer A Local File To The Remote Host Using SFTP.

        Parameters
        ----------
        local_path:
            Local path to the file to send.
        remote_path:
            Remote destination path.

        Returns
        -------
        SshOk
            True on success, False on failure.
        """
        if self.sftp_client is None:
            raise ConnectionError("Not connected - call connect() first")

        if not os.path.isfile(local_path):
            self.logger.error("Local file not found: %s", local_path)
            return False

        remote_dir = os.path.dirname(remote_path)
        if remote_dir != "":
            self._ensure_remote_dir(remote_dir)

        try:
            self.sftp_client.put(local_path, remote_path)
            self.logger.debug("SFTP: %s -> %s", local_path, remote_path)
            return True
        except Exception as exc:
            self.logger.error("SFTP send failed: %s", exc)
            return False

    def receive_file(self, remote_path: PathLike, local_path: PathLike) -> SshOk:
        """
        Fetch A Remote File To The Local Filesystem Using SFTP.

        Parameters
        ----------
        remote_path:
            Remote path of the file to retrieve.
        local_path:
            Local destination path (directory or full file path).

        Returns
        -------
        SshOk
            True on success, False on failure.
        """
        if self.sftp_client is None:
            raise ConnectionError("Not connected - call connect() first")

        local_file = local_path
        if os.path.isdir(local_path):
            local_file = os.path.join(local_path, os.path.basename(remote_path))

        local_dir = os.path.dirname(local_file)
        if local_dir != "":
            os.makedirs(local_dir, exist_ok=True)

        try:
            self.sftp_client.get(remote_path, local_file)
            self.logger.debug("SFTP: %s -> %s", remote_path, local_file)
            return True
        except Exception as exc:
            self.logger.error("SFTP receive failed: %s", exc)
            return False

    def execute_command(self, command: str) -> SshCommandResult:
        """
        Run A Remote Shell Command Via SSH.

        Parameters
        ----------
        command:
            Shell command to execute.

        Returns
        -------
        SshCommandResult
            (stdout, stderr, exit_code)
        """
        if self.ssh_client is None:
            raise ConnectionError("Not connected - call connect() first")

        try:
            _stdin, stdout, stderr = self.ssh_client.exec_command(command)
            code = stdout.channel.recv_exit_status()
            out = stdout.read().decode(errors="replace")
            err = stderr.read().decode(errors="replace")
            return out, err, int(code)
        except Exception as exc:
            self.logger.error("Command failed: %s", exc)
            return "", str(exc), -1

    def list_remote_directory(self, remote_path: PathLike = ".") -> RemoteDirEntries:
        """
        List A Remote Directory Via SFTP.

        Parameters
        ----------
        remote_path:
            Remote directory path.

        Returns
        -------
        RemoteDirEntries
            Directory entry names. Empty list on failure.
        """
        if self.sftp_client is None:
            raise ConnectionError("Not connected - call connect() first")

        try:
            return list(self.sftp_client.listdir(remote_path))
        except Exception as exc:
            self.logger.error("Listing failed: %s", exc)
            return []

    @staticmethod
    def generate_ssh_key_pair(
        key_path: PathLike = "~/.ssh/id_rsa", key_size: int = DEFAULT_RSA_KEY_BITS
    ) -> SshOk:
        """
        Generate An RSA Key Pair Locally.

        Parameters
        ----------
        key_path:
            Private key output path.
        key_size:
            RSA key size in bits.

        Returns
        -------
        SshOk
            True on success, False on failure.
        """
        logger = logging.getLogger("SSHConnector")

        try:
            path = os.path.expanduser(key_path)

            key_dir = os.path.dirname(path)
            if key_dir != "":
                os.makedirs(key_dir, exist_ok=True)

            key = paramiko.RSAKey.generate(bits=int(key_size))
            key.write_private_key_file(path)

            pub_path = f"{path}.pub"
            user = os.getenv("USER", "user")
            host = os.uname().nodename

            with open(pub_path, "w", encoding="utf-8") as handle:
                handle.write(f"ssh-rsa {key.get_base64()} {user}@{host}\n")

            return True

        except Exception as exc:
            logger.error("Key gen failed: %s", exc)
            return False

    def install_public_key(self, public_key_path: PathLike) -> SshOk:
        """
        Install A Public Key Into Remote ~/.ssh/authorized_keys.

        Parameters
        ----------
        public_key_path:
            Local public key file path.

        Returns
        -------
        SshOk
            True on success, False on failure.
        """
        if self.ssh_client is None:
            raise ConnectionError("Not connected - call connect() first")

        if not os.path.isfile(public_key_path):
            raise FileNotFoundError(f"Public key not found: {public_key_path}")

        with open(public_key_path, encoding="utf-8") as handle:
            key = handle.read().strip()

        cmd = (
            "mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
            f'grep -qxF "{key}" ~/.ssh/authorized_keys || '
            f'echo "{key}" >> ~/.ssh/authorized_keys && '
            "chmod 600 ~/.ssh/authorized_keys"
        )

        _out, err, code = self.execute_command(cmd)
        if code == 0:
            self.logger.debug("Public key installed or already present")
            return True

        self.logger.error("Key install failed: %s", err)
        return False

    def _ensure_remote_dir(self, remote_dir: PathLike) -> None:
        """
        Recursively Create Remote Directories Via SFTP.

        Parameters
        ----------
        remote_dir:
            Remote directory path.
        """
        if self.sftp_client is None:
            raise ConnectionError("Not connected - call connect() first")

        cleaned = remote_dir.strip()
        if cleaned == "" or cleaned == "/":
            return

        parts = cleaned.strip("/").split("/")
        path = ""

        for part in parts:
            if part == "":
                continue

            path += f"/{part}"
            try:
                self.sftp_client.stat(path)
            except OSError:
                self.sftp_client.mkdir(path)
