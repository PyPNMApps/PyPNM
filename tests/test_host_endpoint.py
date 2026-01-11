# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
import socket

import pytest

from pypnm.lib.host_endpoint import HostEndpoint
from pypnm.lib.ping import Ping
from pypnm.lib.types import HostNameStr


def test_ping_delegates_to_ping_is_reachable(monkeypatch: pytest.MonkeyPatch) -> None:
    called: dict[str, object] = {}

    def fake_is_reachable(host: str, timeout: int, count: int) -> bool:
        called["host"] = host
        called["timeout"] = timeout
        called["count"] = count
        return True

    monkeypatch.setattr(Ping, "is_reachable", fake_is_reachable)

    endpoint = HostEndpoint(HostNameStr("example.com"))
    result = endpoint.ping(timeout = 2, count = 3)

    assert result is True
    assert called["host"] == "example.com"
    assert called["timeout"] == 2
    assert called["count"] == 3


def test_resolve_returns_unique_addresses_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(host: str, _service: object) -> list[tuple[object, ...]]:
        assert host == "example.com"
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 0, 0, 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    endpoint  = HostEndpoint(HostNameStr("example.com"))
    addresses = endpoint.resolve()

    assert "192.0.2.1" in addresses
    assert "2001:db8::1" in addresses
    assert len(addresses) == 2


def test_resolve_logs_error_and_returns_empty_on_dns_failure(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    def fake_getaddrinfo(host: str, _service: int | str | None) -> list[tuple[object, ...]]:
        raise OSError("temporary failure in name resolution")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    endpoint = HostEndpoint(HostNameStr("bad-hostname.invalid"))

    logger_name = "HostEndpoint"
    with caplog.at_level(logging.ERROR, logger = logger_name):
        addresses = endpoint.resolve()

    assert addresses == []
    assert "DNS lookup failed for bad-hostname.invalid" in caplog.text


def test_resolve_google_dns_smoke() -> None:
    """
    Smoke-Test Real DNS Resolution For www.google.com.

    This test exercises the HostEndpoint.resolve() method against a well-known
    public hostname. If DNS resolution fails (for example, due to an offline
    or sandboxed environment), the test is skipped instead of treated as a
    hard failure.
    """
    endpoint  = HostEndpoint(HostNameStr("www.google.com"))
    addresses = endpoint.resolve()

    if not addresses:
        pytest.skip("DNS resolution failed for www.google.com; skipping smoke test")

    for addr in addresses:
        assert isinstance(addr, str)
        assert len(addr) > 0


def test_ping_localhost_reachable() -> None:
    """
    Verify That Localhost Is Reachable Via HostEndpoint.ping.

    This is an integration-style smoke test using the real Ping.is_reachable()
    implementation. It will fail if ICMP ping to 'localhost' is not functioning
    correctly in the current environment.
    """
    endpoint = HostEndpoint(HostNameStr("localhost"))
    assert endpoint.ping(timeout = 1, count = 1) is True
