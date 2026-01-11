from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
import logging
from typing import Any

from pydantic import BaseModel, Field

from pypnm.docsis.cm_snmp_operation import DocsIfDownstreamChannelEntry


class CodewordTotals(BaseModel):
    """
    Nested model representing codeword counters, computed error rate, and rates per second.
    """

    total_codewords: int = Field(..., description="Total codewords in the interval")
    total_errors: int = Field(
        ..., description="Total uncorrectable errors in the interval"
    )
    time_elapsed: float = Field(
        ..., description="Time elapsed between samples, in seconds"
    )
    error_rate: float = Field(
        ..., description="Uncorrectable codeword error rate (errors/codewords)"
    )
    codewords_per_second: float = Field(..., description="Codewords per second (s⁻¹)")
    errors_per_second: float = Field(..., description="Errors per second (s⁻¹)")


class DocsIfDownstreamCwErrorRateEntry(BaseModel):
    """
    Represents a single channel's codeword error statistics.
    """

    index: int = Field(..., description="SNMP index of the downstream channel")
    channel_id: int = Field(..., description="DOCSIS Channel ID")
    codeword_totals: CodewordTotals


class DocsIfDownstreamChannelCwErrorRate:
    """
    Computes codeword error rate entries for DOCSIS 3.0 SC-QAM downstream channels.
    """

    def __init__(
        self,
        entries_1: list[DocsIfDownstreamChannelEntry],
        entries_2: list[DocsIfDownstreamChannelEntry],
        channel_id_index_stack: list[tuple[int, int]],
        time_elapsed: float,
    ) -> None:
        self.logger = logging.getLogger(type(self).__name__)
        self.time_elapsed = time_elapsed

        try:
            self.entries = self._build_entries(
                entries_1, entries_2, channel_id_index_stack
            )
        except Exception:
            self.logger.error("Failed to build CW error rate entries", exc_info=True)
            self.entries = []

        try:
            self.aggregate_error_rate = self._compute_aggregate_rate()
        except Exception:
            self.logger.error("Failed to compute aggregate error rate", exc_info=True)
            self.aggregate_error_rate = 0.0

    def _build_entries(
        self,
        entries_1: list[DocsIfDownstreamChannelEntry],
        entries_2: list[DocsIfDownstreamChannelEntry],
        channel_indexes: list[tuple[int, int]],
    ) -> list[DocsIfDownstreamCwErrorRateEntry]:
        """
        Build nested error rate entries per channel using two SNMP snapshots.
        """
        cw_entries: list[DocsIfDownstreamCwErrorRateEntry] = []

        if not entries_1 or not entries_2:
            self.logger.warning(
                "One or both entry lists are empty; returning no CW error rate entries."
            )
            return cw_entries

        entry_map_1 = self._create_mapping(entries_1)
        entry_map_2 = self._create_mapping(entries_2)

        for idx, chan_id in channel_indexes:
            try:
                self.logger.debug(f"Processing channel ID {chan_id} (index {idx})")

                ent1 = entry_map_1.get(chan_id)
                ent2 = entry_map_2.get(chan_id)

                self.logger.debug(f"Ent1: {ent1}, Ent2: {ent2}")

                if ent1 is None or ent2 is None:
                    self.logger.warning(
                        f"Channel ID {chan_id} not found in both snapshots; skipping."
                    )
                    continue

                u1 = getattr(ent1.entry, "docsIfSigQExtUnerroreds", 0) or 0
                u2 = getattr(ent2.entry, "docsIfSigQExtUnerroreds", 0) or 0
                c1 = getattr(ent1.entry, "docsIfSigQExtCorrecteds", 0) or 0
                c2 = getattr(ent2.entry, "docsIfSigQExtCorrecteds", 0) or 0
                x1 = getattr(ent1.entry, "docsIfSigQExtUncorrectables", 0) or 0
                x2 = getattr(ent2.entry, "docsIfSigQExtUncorrectables", 0) or 0

                self.logger.debug(
                    f"Channel {chan_id}: unerrored {u1}->{u2}, corrected {c1}->{c2}, "
                    f"uncorrectable {x1}->{x2}"
                )

                delta_unerrored = u2 - u1
                delta_corrected = c2 - c1
                delta_uncorrected = x2 - x1

                self.logger.debug(
                    f"Channel {chan_id} deltas: unerrored={delta_unerrored}, "
                    f"corrected={delta_corrected}, uncorrected={delta_uncorrected}"
                )

                total_codewords = delta_unerrored + delta_corrected + delta_uncorrected
                total_errors = delta_uncorrected
                error_rate = (
                    total_errors / total_codewords if total_codewords > 0 else 0.0
                )

                codewords_per_sec = (
                    total_codewords / self.time_elapsed
                    if self.time_elapsed > 0
                    else 0.0
                )
                errors_per_sec = (
                    total_errors / self.time_elapsed if self.time_elapsed > 0 else 0.0
                )

                totals = CodewordTotals(
                    total_codewords=total_codewords,
                    total_errors=total_errors,
                    time_elapsed=self.time_elapsed,
                    error_rate=error_rate,
                    codewords_per_second=codewords_per_sec,
                    errors_per_second=errors_per_sec,
                )

                self.logger.debug(
                    f"Channel {chan_id}: {totals.total_codewords} codewords, {totals.total_errors} errors, rate={totals.error_rate:.6f}"
                )

                cw_entries.append(
                    DocsIfDownstreamCwErrorRateEntry(
                        index=idx,
                        channel_id=chan_id,
                        codeword_totals=totals,
                    )
                )

            except Exception:
                self.logger.error(
                    f"Exception while processing channel ID {chan_id}", exc_info=True
                )
                continue

        return cw_entries

    def _compute_aggregate_rate(self) -> float:
        """
        Compute weighted aggregate error rate across all channels.
        """
        total_errors = sum(e.codeword_totals.total_errors for e in self.entries)
        total_codewords = sum(e.codeword_totals.total_codewords for e in self.entries)
        rate = total_errors / total_codewords if total_codewords > 0 else 0.0
        self.logger.debug(f"Aggregate error rate computed: {rate:.6f}")
        return rate

    def get(self) -> list[DocsIfDownstreamCwErrorRateEntry]:
        """
        Return the list of computed codeword error rate entries.
        """
        try:
            return self.entries
        except Exception:
            self.logger.error("Failed to get CW error rate entries", exc_info=True)
            return []

    def get_dict(self) -> dict[str, Any]:
        """
        Return a dictionary representation of the entries and aggregate error rate.
        """
        try:
            return {
                "entries": [e.model_dump() for e in self.entries],
                "aggregate_error_rate": self.aggregate_error_rate,
            }
        except Exception:
            self.logger.error(
                "Failed to serialize CW error rate to dict", exc_info=True
            )
            return {"entries": [], "aggregate_error_rate": 0.0}

    def _create_mapping(
        self, entries: list[DocsIfDownstreamChannelEntry]
    ) -> dict[int, DocsIfDownstreamChannelEntry]:
        """
        Create a mapping of channel ID → entry for quick lookup.

        - Skips any entry missing a docsIfDownChannelId.
        - Logs a warning if duplicate channel IDs are encountered (last one wins).
        """
        mapping: dict[int, DocsIfDownstreamChannelEntry] = {}
        for entry in entries:
            if not isinstance(entry, DocsIfDownstreamChannelEntry):
                self.logger.warning(
                    f"Skipping non-DocsIfDownstreamChannelEntry: {entry!r}"
                )
                continue

            if not entry.entry:
                self.logger.warning(f"Skipping entry with no data: {entry!r}")
                continue

            channel_id = getattr(entry.entry, "docsIfDownChannelId", None)
            if channel_id is None:
                self.logger.warning(
                    f"Skipping entry with no docsIfDownChannelId: {entry!r}"
                )
                continue

            if channel_id in mapping:
                self.logger.warning(
                    f"Duplicate docsIfDownChannelId {channel_id}; overwriting previous entry"
                )

            mapping[int(channel_id)] = entry

        self.logger.debug(
            f"Created mapping of {len(mapping)} entries - Keys: {list(mapping.keys())}"
        )
        return mapping
