# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import ftplib
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pypnm.lib.ftp.ftp_connector import FTPConnector


@pytest.fixture
def mock_ftp() -> MagicMock:
    m = MagicMock(spec=ftplib.FTP)
    m.nlst.return_value = ["file1.txt", "dir"]
    m.size.return_value = 1234
    m.pwd.return_value = "/"
    return m


def test_connect_plain_success(mock_ftp: MagicMock) -> None:
    # Plain FTP should connect/login; don't assert prot_p on a non-TLS client.
    with patch("ftplib.FTP", return_value=mock_ftp) as cls:
        c = FTPConnector("example.com", username="u", password="p", use_tls=False)
        assert c.connect() is True
        cls.assert_called_once()
        mock_ftp.connect.assert_called_once_with("example.com", 21, timeout=30)
        mock_ftp.login.assert_called_once_with("u", "p")


def test_connect_tls_calls_prot_p() -> None:
    m = MagicMock(spec=ftplib.FTP_TLS)
    with patch("ftplib.FTP_TLS", return_value=m):
        c = FTPConnector("host", use_tls=True)
        assert c.connect() is True
        m.prot_p.assert_called_once()


def test_connect_failure_returns_false() -> None:
    with patch("ftplib.FTP", side_effect=RuntimeError("boom")):
        c = FTPConnector("host")
        assert c.connect() is False


def test_disconnect_quit_no_raise(mock_ftp: MagicMock) -> None:
    with patch("ftplib.FTP", return_value=mock_ftp):
        c = FTPConnector("h")
        assert c.connect()
        c.disconnect()
        mock_ftp.quit.assert_called_once()
        assert c.ftp is None


def test_list_dir_returns_names(mock_ftp: MagicMock) -> None:
    with patch("ftplib.FTP", return_value=mock_ftp):
        c = FTPConnector("h")
        c.connect()
        out = c.list_dir("/some")
        mock_ftp.nlst.assert_called_once_with("/some")
        assert out == ["file1.txt", "dir"]


def test_make_dirs_creates_nested_when_missing(mock_ftp: MagicMock) -> None:
    # Let cwd fail for any subdir to force mkd; root is fine
    def cwd_side_effect(path: str) -> None:
        if path != "/":
            raise ftplib.error_perm("nope")

    mock_ftp.cwd.side_effect = cwd_side_effect
    with patch("ftplib.FTP", return_value=mock_ftp):
        c = FTPConnector("h")
        c.connect()
        c.make_dirs("/a/b/c")
        # mkd should be called for each missing component
        assert mock_ftp.mkd.call_count == 3
        mock_ftp.cwd.assert_any_call("/")  # returned to root at end


def test_upload_file_success(tmp_path: Path) -> None:
    ftp = MagicMock(spec=ftplib.FTP)

    # Track created directories so subsequent cwd to them succeeds
    created: set[str] = set()

    def cwd_side_effect(path: str) -> None:
        # Root always ok
        if path == "/":
            return
        # Accept cwd if previously "created"
        if path.lstrip("/") in created:
            return
        # Otherwise pretend it doesn't exist (trigger mkd)
        raise ftplib.error_perm("missing")

    def mkd_side_effect(path: str) -> None:
        created.add(path.lstrip("/"))

    ftp.cwd.side_effect = cwd_side_effect
    ftp.mkd.side_effect = mkd_side_effect

    local = tmp_path / "in.bin"
    local.write_bytes(b"payload")

    with patch("ftplib.FTP", return_value=ftp):
        c = FTPConnector("h")
        assert c.connect()
        ok = c.upload_file(str(local), "/x/y/out.bin")
        assert ok is True
        # ensure it tried to create both levels
        assert "x" in created and "x/y" in created
        ftp.storbinary.assert_called_once()
        args, _ = ftp.storbinary.call_args
        assert args[0].startswith("STOR ")


def test_upload_file_missing_local_returns_false() -> None:
    ftp = MagicMock(spec=ftplib.FTP)
    with patch("ftplib.FTP", return_value=ftp):
        c = FTPConnector("h")
        c.connect()
        assert c.upload_file("no_such_file.bin", "/remote.bin") is False
        ftp.storbinary.assert_not_called()


def test_download_file_to_dir_and_to_file(tmp_path: Path) -> None:
    ftp = MagicMock(spec=ftplib.FTP)

    def retr_side_effect(cmd: str, writer_cb) -> None:
        writer_cb(b"abc123")

    ftp.retrbinary.side_effect = retr_side_effect

    with patch("ftplib.FTP", return_value=ftp):
        c = FTPConnector("h")
        c.connect()

        # Download to directory path (auto-append filename)
        out_dir = tmp_path / "dl"
        out_dir.mkdir()
        ok = c.download_file("/r/file.txt", str(out_dir))
        assert ok is True
        data = (out_dir / "file.txt").read_bytes()
        assert data == b"abc123"

        # Download to explicit file path
        out_file = tmp_path / "explicit.bin"
        ok = c.download_file("/remote.bin", str(out_file))
        assert ok is True
        assert out_file.read_bytes() == b"abc123"


def test_delete_get_size_cwd_pwd(mock_ftp: MagicMock) -> None:
    with patch("ftplib.FTP", return_value=mock_ftp):
        c = FTPConnector("h")
        c.connect()

        assert c.delete_file("/a.txt") is True
        mock_ftp.delete.assert_called_once_with("/a.txt")

        assert c.get_size("/a.txt") == 1234
        mock_ftp.size.assert_called_once_with("/a.txt")

        assert c.cwd("/some") is True
        mock_ftp.cwd.assert_called_with("/some")

        assert c.pwd() == "/"
        mock_ftp.pwd.assert_called_once()


def test_get_size_failure_returns_none(mock_ftp: MagicMock) -> None:
    mock_ftp.size.side_effect = RuntimeError("oops")
    with patch("ftplib.FTP", return_value=mock_ftp):
        c = FTPConnector("h")
        c.connect()
        assert c.get_size("/bad") is None


def test_methods_raise_without_connection() -> None:
    c = FTPConnector("h")
    with pytest.raises(ConnectionError):
        c.list_dir("/")
    with pytest.raises(ConnectionError):
        c.make_dirs("/a")
    with pytest.raises(ConnectionError):
        c.upload_file(__file__, "/r")
    with pytest.raises(ConnectionError):
        c.download_file("/r", ".")
    with pytest.raises(ConnectionError):
        c.delete_file("/r")
    with pytest.raises(ConnectionError):
        c.get_size("/r")
    with pytest.raises(ConnectionError):
        c.cwd("/")
    with pytest.raises(ConnectionError):
        c.pwd()
