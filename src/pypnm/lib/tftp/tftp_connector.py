# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
import os

from tftpy import TftpClient

from pypnm.lib.inet import Inet


class TFTPConnector:
    """
    A basic TFTP client wrapper around tftpy.TftpClient.

    Features:
    - Download (get) files from a TFTP server
    - Upload (put) files to a TFTP server
    """

    def __init__(self, host: Inet, port: int = 69, timeout: int = 5) -> None:
        """
        Args:
            host:    TFTP server hostname or IP.
            port:    TFTP server port (default 69).
            timeout: Socket timeout in seconds.
        """
        self.logger = logging.getLogger(__name__)
        self.host = host
        self.port = port
        self.timeout = timeout

    def download_file(self, remote_filename: str, local_path: str) -> bool:
        """
        Fetch a file from the TFTP server.

        Args:
            remote_filename: name of the file on the TFTP server
            local_path:      local file path (including filename) to save to

        Returns:
            True on success, False on any error.
        """
        self.logger.debug(f"Starting TFTP download: {remote_filename} → {local_path}")

        try:
            os.makedirs(os.path.dirname(local_path) or ".", exist_ok=True)
            client = TftpClient(self.host, self.port)
            client.download(remote_filename, local_path)
            self.logger.debug(f"TFTP download complete: {local_path}")
            return True

        except Exception as e:
            self.logger.error(f"TFTP download failed: {e}")
            return False

    def upload_file(self, local_path: str, remote_filename: str) -> bool:
        """
        Send a file to the TFTP server.

        Args:
            local_path:      local file to send
            remote_filename: target filename on the server

        Returns:
            True on success, False on any error.
        """
        if not os.path.isfile(local_path):
            self.logger.error(f"Local file not found: {local_path}")
            return False

        try:
            client = TftpClient(self.host, self.port)
            self.logger.debug(f"Starting TFTP upload: {local_path} → {remote_filename}")
            client.upload(remote_filename, local_path)
            self.logger.debug(f"TFTP upload complete: {remote_filename}")
            return True
        except Exception as e:
            self.logger.error(f"TFTP upload failed: {e}")
            return False
