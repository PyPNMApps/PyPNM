# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025

from __future__ import annotations

import logging
import re
from enum import Enum
from typing import NoReturn

from pypnm.lib.inet import Inet


class SecurityLevel(str, Enum):
    """SNMPv3 security level."""

    NO_AUTH_NO_PRIV = "noAuthNoPriv"
    AUTH_NO_PRIV = "authNoPriv"
    AUTH_PRIV = "authPriv"


class AuthProtocol(str, Enum):
    """Auth protocol names; map to pysnmp later."""

    NONE = "NONE"
    MD5 = "MD5"
    SHA = "SHA"
    SHA224 = "SHA224"
    SHA256 = "SHA256"
    SHA384 = "SHA384"
    SHA512 = "SHA512"


class PrivProtocol(str, Enum):
    """Privacy (encryption) protocol names; map to pysnmp later."""

    NONE = "NONE"
    DES = "DES"
    AES = "AES"
    AES128 = "AES128"
    AES192 = "AES192"
    AES256 = "AES256"


class Snmp_v3:
    """
    SNMPv3 Client (stub).

    Provides the same public method signatures as Snmp_v2c, but all network
    operations raise NotImplementedError until the implementation is completed.

    Intended usage in config-driven code paths:
        if cfg.SNMP.version["3"]["enable"]:
            snmp = Snmp_v3(
                host=Inet(ip),
                username=...,
                security_level=SecurityLevel.AUTH_PRIV,
                auth_protocol=AuthProtocol.SHA,
                auth_password="...",
                priv_protocol=PrivProtocol.AES,
                priv_password="...",
                timeout=cfg.SNMP["timeout"],
                retries=cfg.SNMP["version"]["3"]["retries"],
                port=161,
            )
    """

    SNMP_PORT: int = 161

    def __init__(
        self,
        host: Inet,
        *,
        username: str = "",
        security_level: SecurityLevel = SecurityLevel.NO_AUTH_NO_PRIV,
        auth_protocol: AuthProtocol = AuthProtocol.NONE,
        auth_password: str = "",
        priv_protocol: PrivProtocol = PrivProtocol.NONE,
        priv_password: str = "",
        port: int = SNMP_PORT,
        timeout: int = 5,
        retries: int = 3,
    ) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self._host = host.inet
        self._port = port
        self._timeout = timeout
        self._retries = retries

        # v3 security params
        self._username = username
        self._sec_level = security_level
        self._auth_proto = auth_protocol
        self._auth_pass = auth_password
        self._priv_proto = priv_protocol
        self._priv_pass = priv_password

        # Placeholder for pysnmp engine/session later
        self._snmp_engine = None

        self._validate_params()

    def _validate_params(self) -> None:
        """
        Basic parameter checks so misconfigurations fail fast even in stub mode.
        """
        if self._sec_level in (
            SecurityLevel.AUTH_NO_PRIV,
            SecurityLevel.AUTH_PRIV,
        ) and (self._auth_proto == AuthProtocol.NONE or not self._auth_pass):
            raise ValueError("SNMPv3 auth* requires auth_protocol and auth_password.")

        if self._sec_level is SecurityLevel.AUTH_PRIV and (
            self._priv_proto == PrivProtocol.NONE or not self._priv_pass
        ):
            raise ValueError(
                "SNMPv3 authPriv requires priv_protocol and priv_password."
            )

        if not isinstance(self._host, str) or not self._host:
            raise ValueError("Invalid host provided to Snmp_v3.")

    # ─────────────────────────────────────────────────────────────────────
    # Public API (signatures align with Snmp_v2c; behavior is stubbed)
    # ─────────────────────────────────────────────────────────────────────

    async def get(
        self,
        oid: str | tuple[str, str, int],
        timeout: int | None = None,
        retries: int | None = None,
    ) -> NoReturn:
        """
        Stub for SNMP GET (v3).
        """
        self.logger.debug("Snmp_v3.get(%r) called (stub).", oid)
        raise NotImplementedError("Snmp_v3.get is not implemented yet.")

    async def walk(self, oid: str | tuple[str, str, int]) -> NoReturn:
        """
        Stub for SNMP WALK (v3).
        """
        self.logger.debug("Snmp_v3.walk(%r) called (stub).", oid)
        raise NotImplementedError("Snmp_v3.walk is not implemented yet.")

    async def set(
        self, oid: str, value: str | int | float | bytes | bool, value_type: str
    ) -> NoReturn:
        """
        Stub for SNMP SET (v3).
        """
        self.logger.debug(
            "Snmp_v3.set(%r, %r, %r) called (stub).", oid, value, value_type
        )
        raise NotImplementedError("Snmp_v3.set is not implemented yet.")

    def close(self) -> None:
        """
        Close any underlying engine/transport (no-op in stub).
        """
        self.logger.debug("Snmp_v3.close() called (stub).")
        return

    # ─────────────────────────────────────────────────────────────────────
    # Helpers (copy/keep parity with v2c where convenient)
    # ─────────────────────────────────────────────────────────────────────

    @staticmethod
    def resolve_oid(oid: str | tuple[str, str, int]) -> str:
        """
        Placeholder resolver. When you wire v3, either import COMPILED_OIDS
        or reuse shared resolver utilities.
        """
        if isinstance(oid, tuple):
            return ".".join(map(str, oid))

        if Snmp_v3.is_numeric_oid(oid):
            return oid

        # symbolic base + optional suffix, same pattern used elsewhere
        m = re.match(r"^([a-zA-Z0-9_:]+)(\..+)?$", oid)
        if not m:
            return oid
        base_sym, suffix = m.groups()
        # TODO: map base_sym using COMPILED_OIDS once imported.
        return f"{base_sym}{suffix or ''}"

    @staticmethod
    def is_numeric_oid(oid: str) -> bool:
        return bool(re.fullmatch(r"\.?(\d+\.)+\d+", oid))
