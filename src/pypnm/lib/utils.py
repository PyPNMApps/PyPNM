# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import hashlib
import time
from enum import Enum

from typing_extensions import deprecated

from pypnm.lib.types import TimeStamp, TransactionId


class TimeUnit(Enum):
    SECONDS = "s"
    MILLISECONDS = "ms"
    NANOSECONDS = "ns"


class Utils:
    """
    Legacy Time And TransactionId Utilities.

    This class is deprecated in favor of the Generate helper functions and is
    retained only for backward compatibility. New code should use Generate.
    """

    @staticmethod
    @deprecated("Use Generate.time_stamp() instead.")
    def time_stamp(unit: TimeUnit = TimeUnit.SECONDS) -> TimeStamp:
        """
        Return The Current Timestamp In The Specified Unit.

        Deprecated In Favor Of ``Generate.time_stamp``.
        """
        if unit == TimeUnit.NANOSECONDS:
            return TimeStamp(time.time_ns())
        if unit == TimeUnit.MILLISECONDS:
            return TimeStamp(time.time_ns() // 1_000_000)
        return TimeStamp(int(time.time()))

    @staticmethod
    @deprecated("Use Generate.transaction_id() instead.")
    def transaction_id(seed: int | None = None, length: int = 24) -> TransactionId:
        """
        Generate A Hashed Time-Based Transaction Identifier.

        Deprecated In Favor Of ``Generate.transaction_id``.
        """
        base_value: int = Generate.time_stamp(unit=TimeUnit.NANOSECONDS)
        if seed is not None:
            raw_value: str = f"{base_value}:{seed}"
        else:
            raw_value: str = str(base_value)

        digest_full: str = hashlib.sha256(raw_value.encode("utf-8")).hexdigest()
        max_length: int = len(digest_full)

        effective_length: int = length
        if effective_length <= 0 or effective_length > max_length:
            effective_length = max_length

        truncated: str = digest_full[:effective_length]
        return TransactionId(truncated)


class Generate:
    @staticmethod
    def time_stamp(unit: TimeUnit = TimeUnit.SECONDS) -> TimeStamp:
        """
        Return The Current Timestamp In The Specified Unit.
        """
        return TimeStamp(
            time.time_ns()
            if unit == TimeUnit.NANOSECONDS
            else time.time_ns() // 1_000_000
            if unit == TimeUnit.MILLISECONDS
            else int(time.time())
        )

    @staticmethod
    def transaction_id(seed: int | None = None, length: int = 24) -> TransactionId:
        """
        Generate A Hashed Time-Based Transaction Identifier.

        Uses a nanosecond timestamp plus an optional seed, hashed with SHA-256
        and truncated to ``length`` hex characters.
        """
        base_value: int = Generate.time_stamp(unit=TimeUnit.NANOSECONDS)
        raw_value: str = f"{base_value}:{seed}" if seed is not None else str(base_value)

        digest_full: str = hashlib.sha256(raw_value.encode("utf-8")).hexdigest()
        max_length: int = len(digest_full)

        effective_length: int = length
        if effective_length <= 0 or effective_length > max_length:
            effective_length = max_length

        truncated: str = digest_full[:effective_length]
        return TransactionId(truncated)

    @staticmethod
    def group_id(
        count: int, seed: int | None = None, length: int = 24
    ) -> list[TransactionId]:
        """
        Generate A Group Of Related Transaction Identifiers.

        Each ID is derived from the base nanosecond timestamp plus an optional
        incrementing seed offset, then hashed and truncated as in
        ``transaction_id``.
        """
        ids: list[TransactionId] = []
        for i in range(count):
            current_seed: int | None = seed + i if seed is not None else None
            ids.append(Generate.transaction_id(seed=current_seed, length=length))
        return ids

    @staticmethod
    def operation_id(seed: int | None = None, length: int = 24) -> TransactionId:
        """
        Generate A Transaction Identifier For An Operation.

        Thin wrapper around ``transaction_id`` for semantic clarity.
        """
        return Generate.transaction_id(seed=seed, length=length)
