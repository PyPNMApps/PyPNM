# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
import socket

from pypnm.lib.ping import Ping
from pypnm.lib.types import HostNameStr, InetAddressStr


class HostEndpoint:
    """
    Represents A Hostname Or IP Address And Provides DNS/Ping Helpers.

    This class wraps a single host string (hostname or IP address) and exposes
    convenience methods to perform DNS resolution and reachability checks using
    the existing Ping utility.
    """

    def __init__(self, host: HostNameStr) -> None:
        """
        Initialize A HostEndpoint For DNS Resolution And Reachability Checks.

        Parameters:
        - host: Hostname or IP address that will be used for DNS lookup and ping.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.host = host

    def ping(self, timeout: int = 1, count: int = 1) -> bool:
        """
        Check If The Host Is Reachable Using ICMP Ping.

        This method forwards to Ping.is_reachable() with the stored host value.

        Parameters:
        - timeout: Timeout in seconds for each ping attempt.
        - count: Number of ping attempts to perform.

        Returns:
        - True if the host is reachable, False otherwise.
        """
        return Ping.is_reachable(
            host=self.host,
            timeout=timeout,
            count=count,
        )

    def resolve(self) -> list[InetAddressStr]:
        """
        Resolve The Hostname To One Or More IP Addresses.

        Uses the system resolver via socket.getaddrinfo() and returns a list of
        unique IPv4/IPv6 address strings. If DNS resolution fails, an empty
        list is returned and the error is logged.

        Returns:
        - A list of IP address strings; empty if resolution fails.
        """
        try:
            infos = socket.getaddrinfo(self.host, None)
        except OSError as exc:
            self.logger.error("DNS lookup failed for %s: %s", self.host, exc)
            return []

        addresses: list[InetAddressStr] = []
        for family, _socktype, _proto, _canonname, sockaddr in infos:
            ip: str | None = None
            if family == socket.AF_INET or family == socket.AF_INET6:
                addr = sockaddr[0]
                if isinstance(addr, str):
                    ip = addr

            if ip and ip not in addresses:
                addresses.append(InetAddressStr(ip))

        return addresses
