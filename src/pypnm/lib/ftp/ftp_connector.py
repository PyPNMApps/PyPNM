# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import ftplib
import logging
import os


class FTPConnector:
    """
    A simple FTP client wrapper around ftplib.FTP for basic file transfers and directory operations.

    Features:
    - Connect and authenticate to an FTP server (optionally with TLS)
    - Upload and download files
    - List remote directories
    - Create remote directories (recursively)
    - Delete remote files
    """

    def __init__(
        self,
        host: str,
        port: int = 21,
        username: str = "",
        password: str = "",
        use_tls: bool = False,
        timeout: int = 30,
    ) -> None:
        """
        Initialize FTPConnector parameters.

        Args:
            host: FTP server hostname or IP.
            port: FTP server port (default 21).
            username: FTP username.
            password: FTP password.
            use_tls: If True, use FTP_TLS instead of plain FTP.
            timeout: Socket timeout in seconds.
        """
        self.logger = logging.getLogger(__name__)
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.timeout = timeout

        self.ftp: ftplib.FTP | None = None

    def connect(self) -> bool:
        """
        Connect to the FTP server and log in.

        Returns:
            bool: True if connection and login succeed, False otherwise.
        """
        try:
            if self.use_tls:
                self.ftp = ftplib.FTP_TLS(timeout=self.timeout)
            else:
                self.ftp = ftplib.FTP(timeout=self.timeout)

            self.logger.debug(f"Connecting to FTP {self.host}:{self.port}")
            self.ftp.connect(self.host, self.port, timeout=self.timeout)
            self.logger.debug("Connected successfully; logging in")

            self.ftp.login(self.username, self.password)
            self.logger.debug("Logged in successfully")

            if self.use_tls:
                # Secure the data connection
                self.ftp.prot_p()
                self.logger.debug("Secured data connection with PROT P")

            return True

        except Exception as e:
            self.logger.error(f"FTP connection/login failed: {e}")
            return False

    def disconnect(self) -> None:
        """
        Quit the FTP session and close the connection.
        """
        if self.ftp:
            try:
                self.logger.debug("Quitting FTP session")
                self.ftp.quit()
            except Exception:
                pass
            self.logger.debug("Disconnected")
            self.ftp = None

    def list_dir(self, remote_path: str = ".") -> list[str]:
        """
        List directory contents at remote_path.

        Args:
            remote_path: The remote directory path (default: current working directory).

        Returns:
            List[str]: List of file/directory names (empty list on failure).
        """
        if not self.ftp:
            raise ConnectionError("Not connected. Call connect() first.")
        try:
            self.logger.debug(f"Listing directory: {remote_path}")
            return self.ftp.nlst(remote_path)
        except Exception as e:
            self.logger.error(f"Directory listing failed: {e}")
            return []

    def make_dirs(self, remote_directory: str) -> None:
        """
        Create nested directories on the remote FTP server (like mkdir -p).

        Args:
            remote_directory: Absolute or relative remote directory path.
        """
        if not self.ftp:
            raise ConnectionError("Not connected. Call connect() first.")
        parts = remote_directory.strip("/").split("/")
        path_so_far = ""
        for part in parts:
            path_so_far = path_so_far + "/" + part if path_so_far else part
            try:
                self.ftp.cwd(path_so_far)
            except ftplib.error_perm:
                try:
                    self.logger.debug(f"Creating directory: {path_so_far}")
                    self.ftp.mkd(path_so_far)
                    self.logger.debug(f"Created directory: {path_so_far}")
                except Exception as e:
                    self.logger.error(f"Failed to create directory {path_so_far}: {e}")
                    raise
        # Return to initial directory
        self.ftp.cwd("/")

    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """
        Upload a local file to the remote FTP server.

        Args:
            local_path: Full path to the local file.
            remote_path: Full path on the remote server including filename.

        Returns:
            bool: True if upload succeeds, False otherwise.
        """
        if not self.ftp:
            raise ConnectionError("Not connected. Call connect() first.")
        if not os.path.isfile(local_path):
            self.logger.error(f"Local file not found: {local_path}")
            return False

        try:
            remote_dir = os.path.dirname(remote_path)
            if remote_dir:
                self.make_dirs(remote_dir)

            self.logger.debug(f"Starting upload: {local_path} -> {remote_path}")
            with open(local_path, "rb") as f:
                self.ftp.storbinary(f"STOR {remote_path}", f)
            self.logger.debug(f"Upload completed: {local_path} -> {remote_path}")
            return True

        except Exception as e:
            self.logger.error(f"Upload failed: {e}")
            return False

    def download_file(self, remote_path: str, local_path: str) -> bool:
        """
        Download a file from the remote FTP server to local.

        Args:
            remote_path: Full path on the remote server including filename.
            local_path: Local destination (directory or full file path).

        Returns:
            bool: True if download succeeds, False otherwise.
        """
        if not self.ftp:
            raise ConnectionError("Not connected. Call connect() first.")

        # Determine final local file path
        if os.path.isdir(local_path):
            remote_filename = os.path.basename(remote_path)
            local_file_path = os.path.join(local_path, remote_filename)
        else:
            local_file_path = local_path

        local_dir = os.path.dirname(local_file_path)
        if local_dir:
            os.makedirs(local_dir, exist_ok=True)

        try:
            self.logger.debug(f"Starting download: {remote_path} -> {local_file_path}")
            with open(local_file_path, "wb") as f:
                self.ftp.retrbinary(f"RETR {remote_path}", f.write)
            self.logger.debug(f"Download completed: {remote_path} -> {local_file_path}")
            return True

        except Exception as e:
            self.logger.error(f"Download failed: {e}")
            return False

    def delete_file(self, remote_path: str) -> bool:
        """
        Delete a file on the remote FTP server.

        Args:
            remote_path: Full path to the remote file to delete.

        Returns:
            bool: True if deletion succeeds, False otherwise.
        """
        if not self.ftp:
            raise ConnectionError("Not connected. Call connect() first.")
        try:
            self.logger.debug(f"Deleting remote file: {remote_path}")
            self.ftp.delete(remote_path)
            self.logger.debug(f"Deleted remote file: {remote_path}")
            return True
        except Exception as e:
            self.logger.error(f"Delete failed: {e}")
            return False

    def get_size(self, remote_path: str) -> int | None:
        """
        Get size (in bytes) of a remote file.

        Args:
            remote_path: Full path to the remote file.

        Returns:
            int: Size in bytes, or None on failure.
        """
        if not self.ftp:
            raise ConnectionError("Not connected. Call connect() first.")
        try:
            size = self.ftp.size(remote_path)
            self.logger.debug(f"Size of {remote_path}: {size} bytes")
            return size
        except Exception as e:
            self.logger.error(f"Failed to get size of {remote_path}: {e}")
            return None

    def cwd(self, remote_path: str) -> bool:
        """
        Change working directory on the remote FTP server.

        Args:
            remote_path: Directory to change into.

        Returns:
            bool: True if successful, False otherwise.
        """
        if not self.ftp:
            raise ConnectionError("Not connected. Call connect() first.")
        try:
            self.logger.debug(f"Changing directory to: {remote_path}")
            self.ftp.cwd(remote_path)
            return True
        except Exception as e:
            self.logger.error(f"Failed to change directory to {remote_path}: {e}")
            return False

    def pwd(self) -> str | None:
        """
        Print the current working directory on the remote FTP server.

        Returns:
            str: The current directory, or None on failure.
        """
        if not self.ftp:
            raise ConnectionError("Not connected. Call connect() first.")
        try:
            cwd = self.ftp.pwd()
            self.logger.debug(f"Remote working directory: {cwd}")
            return cwd
        except Exception as e:
            self.logger.error(f"Failed to get remote working directory: {e}")
            return None
