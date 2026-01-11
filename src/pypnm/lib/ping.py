# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
import platform
import socket
import subprocess


class Ping:
    """
    A simple cross-platform Ping utility to check if a device is reachable.

    This helper resolves hostnames to concrete IPv4/IPv6 addresses where
    possible and attempts to ping each resolved address until one succeeds.
    If DNS resolution fails, it falls back to invoking ping with the original
    host string.

    This avoids hard-coding special cases such as "localhost" while still
    reflecting real network misconfigurations (for example, loopback or
    address-family issues).
    """

    @staticmethod
    def is_reachable(host: str, timeout: int = 1, count: int = 1) -> bool:
        """
        Checks if the given host is reachable via ICMP ping.

        Parameters:
        - host (str): The IP address or hostname to ping.
        - timeout (int): Timeout in seconds (default: 1)
        - count (int): Number of ping attempts (default: 1)

        Returns:
        - bool: True if the host is reachable, False otherwise.
        """
        system = platform.system().lower()

        if system == "windows":
            base_cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000)]
        else:
            base_cmd = ["ping", "-c", str(count), "-W", str(timeout)]

        targets: list[str] = []

        # If the input already looks like an IP literal, use it directly.
        if Ping._is_ip_literal(host):
            targets.append(host)
        else:
            # Resolve hostname to one or more IP addresses, preferring IPv4/IPv6
            # as returned by the system resolver.
            try:
                infos = socket.getaddrinfo(host, None)
                for _family, _socktype, _proto, _canonname, sockaddr in infos:
                    addr = sockaddr[0]
                    if isinstance(addr, str) and addr not in targets:
                        targets.append(addr)
            except OSError as exc:
                logging.error("[Ping Error] DNS lookup failed for %s: %s", host, exc)
                # Fall back to using the original host string; ping may still handle it.
                targets.append(host)

        for target in targets:
            cmd = base_cmd + [target]
            try:
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                if result.returncode == 0:
                    return True
            except FileNotFoundError as exc:
                logging.error("[Ping Error] ping command not found: %s", exc)
                break
            except Exception as exc:
                logging.error("[Ping Error] %s", exc)

        return False

    @staticmethod
    def _is_ip_literal(value: str) -> bool:
        """
        Return True if the provided string is a valid IPv4 or IPv6 literal.
        """
        try:
            socket.inet_pton(socket.AF_INET, value)
            return True
        except OSError:
            pass

        try:
            socket.inet_pton(socket.AF_INET6, value)
            return True
        except OSError:
            return False
