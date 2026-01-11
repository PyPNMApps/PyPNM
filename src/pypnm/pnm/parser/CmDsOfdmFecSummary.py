# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
from struct import Struct
from typing import Any, cast

from pypnm.lib.constants import FEC_SUMMARY_TYPE_LABEL, FEC_SUMMARY_TYPE_STEP_SECONDS
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.qam.types import CodeWordArray
from pypnm.lib.types import CaptureTime, ChannelId, MacAddressStr, ProfileId, TimeStamp
from pypnm.pnm.parser.model.parser_rtn_models import (
    CmDsOfdmFecSummaryModel,
    OfdmFecSumCodeWordEntryModel,
    OfdmFecSumDataModel,
)
from pypnm.pnm.parser.pnm_file_type import PnmFileType
from pypnm.pnm.parser.pnm_header import PnmHeader

SUMMARY_HDR: Struct = Struct("!B6sBB")
PROFILE_HDR: Struct = Struct("!BH")
SET_FMT: str = "!I3I"
SET_REC: Struct = Struct(SET_FMT)


class CmDsOfdmFecSummary(PnmHeader):
    """
    Parser/adapter for DOCSIS Downstream OFDM FEC Summary payloads.

    Responsibilities
    ----------------
    1) Validate file type.
    2) Parse summary header.
    3) Parse each per-profile data block.
    4) Validate timestamp cadence against the FEC summary type.
    5) Materialize CmDsOfdmFecSummaryModel.
    """

    def __init__(self, binary_data: bytes) -> None:
        """
        Initialize and parse a FEC summary blob.

        Parameters
        ----------
        binary_data : bytes
            Raw PNM buffer containing a DS OFDM FEC summary.
        """
        super().__init__(binary_data)
        self.logger = logging.getLogger(self.__class__.__name__)

        self._channel_id: ChannelId
        self._mac_address: MacAddressStr
        self._summary_type: int
        self._num_profiles: int
        self._model: CmDsOfdmFecSummaryModel

        self.__process()

    def __expected_ts_step(self) -> int | None:
        """
        Return the expected timestamp step (seconds) for the current summary type.

        Summary type comes from docsPnmCmDsOfdmFecSumType:
        - other(1):        unknown cadence → None
        - interval10min(2):1 second steps
        - interval24hr(3): 60 second steps
        """
        return FEC_SUMMARY_TYPE_STEP_SECONDS.get(int(self._summary_type))

    def __check_timestamp_sequence(
        self, profile_id: int, ts: list[int], step: int
    ) -> None:
        """
        Validate that timestamps are strictly monotonic with the expected cadence.

        Parameters
        ----------
        profile_id : int
            OFDM profile ID for logging context.
        ts : List[int]
            List of epoch timestamps.
        step : int
            Expected delta (seconds) between consecutive entries.

        Behavior
        --------
        - Logs up to 10 mismatches at ERROR level.
        - Logs a summary ERROR if any mismatch occurred.
        """
        if not ts or len(ts) < 2:
            return

        errors = 0
        for i in range(1, len(ts)):
            prev_t = int(ts[i - 1])
            curr_t = int(ts[i])
            delta = curr_t - prev_t
            if delta != step:
                errors += 1
                if errors <= 10:
                    self.logger.error(
                        "Timestamp cadence violation (profile=%d, idx=%d): "
                        "prev=%d curr=%d delta=%d expected_step=%d",
                        int(profile_id),
                        i,
                        prev_t,
                        curr_t,
                        delta,
                        step,
                    )

        if errors:
            self.logger.error(
                "Timestamp validation failed for profile=%d: %d mismatch(es) detected "
                "(expected step=%d sec, summary_type=%d '%s').",
                int(profile_id),
                errors,
                step,
                int(self._summary_type),
                FEC_SUMMARY_TYPE_LABEL.get(int(self._summary_type), "unknown"),
            )

    def __process(self) -> None:
        """
        Parse the binary FEC summary and build the model.

        Raises
        ------
        ValueError
            If file type is not OFDM_FEC_SUMMARY or buffer is too short.
        """
        if self.get_pnm_file_type() != PnmFileType.OFDM_FEC_SUMMARY:
            expected = PnmFileType.OFDM_FEC_SUMMARY.get_pnm_cann()
            file_type = self.get_pnm_file_type()
            got = file_type.get_pnm_cann() if file_type is not None else "None"
            raise ValueError(
                f"PNM file stream is not OFDM FEC Summary type: expected {expected}, got {got}"
            )

        mv = memoryview(self.pnm_data)

        if len(mv) < SUMMARY_HDR.size:
            raise ValueError(
                f"Insufficient data for FEC summary header: need {SUMMARY_HDR.size}, have {len(mv)}"
            )

        channel_id, mac_raw, summary_type, num_profiles = SUMMARY_HDR.unpack(
            mv[: SUMMARY_HDR.size]
        )

        self._channel_id = channel_id
        self._mac_address = MacAddress(mac_raw).mac_address
        self._summary_type = summary_type
        self._num_profiles = num_profiles

        pos = SUMMARY_HDR.size
        profile_entries: list[OfdmFecSumDataModel] = []

        for profile_index in range(self._num_profiles):
            if len(mv) < pos + PROFILE_HDR.size:
                self.logger.error(
                    "Truncated profile header at index %d (pos=%d, need=%d, have=%d)",
                    profile_index,
                    pos,
                    PROFILE_HDR.size,
                    len(mv) - pos,
                )
                break

            profile_id, number_of_sets = PROFILE_HDR.unpack(
                mv[pos : pos + PROFILE_HDR.size]
            )
            pos += PROFILE_HDR.size

            remaining = len(mv) - pos
            max_sets = remaining // SET_REC.size
            requested_sets = number_of_sets
            if number_of_sets > max_sets:
                self.logger.warning(
                    "Profile %d: truncating sets from %d to %d (remaining=%d bytes, record=%d bytes)",
                    int(profile_id),
                    int(requested_sets),
                    int(max_sets),
                    int(remaining),
                    int(SET_REC.size),
                )
                number_of_sets = max_sets

            set_bytes_len = number_of_sets * SET_REC.size
            sets_slice = mv[pos : pos + set_bytes_len]

            ts: list[TimeStamp] = []
            tc: CodeWordArray = []
            cc: CodeWordArray = []
            uc: CodeWordArray = []

            for rec_idx in range(number_of_sets):
                off = rec_idx * SET_REC.size
                rec = sets_slice[off : off + SET_REC.size]
                timestamp, total, corrected, uncorrectable = SET_REC.unpack(rec)

                ts.append(timestamp)
                tc.append(total)
                cc.append(corrected)
                uc.append(uncorrectable)

            pos += set_bytes_len

            step = self.__expected_ts_step()
            if step is not None:
                self.__check_timestamp_sequence(
                    int(profile_id), cast(list[int], ts), int(step)
                )
            else:
                self.logger.warning(
                    "Skipping cadence validation for summary_type=%d ('%s'), profile=%d",
                    int(self._summary_type),
                    FEC_SUMMARY_TYPE_LABEL.get(int(self._summary_type), "unknown"),
                    int(profile_id),
                )

            cwe_model = OfdmFecSumCodeWordEntryModel(
                timestamp=cast(list[TimeStamp], ts),
                total_codewords=cast(CodeWordArray, tc),
                corrected=cast(CodeWordArray, cc),
                uncorrectable=cast(CodeWordArray, uc),
            )

            profile_entry = OfdmFecSumDataModel(
                profile_id=ProfileId(profile_id),
                number_of_sets=int(number_of_sets),
                codeword_entries=cwe_model,
            )
            profile_entries.append(profile_entry)

        if len(profile_entries) != self._num_profiles:
            self.logger.debug(
                "Parsed %d profile(s), header declared %d",
                len(profile_entries),
                self._num_profiles,
            )

        first_timestamp: CaptureTime | None = None
        if profile_entries and profile_entries[0].codeword_entries.timestamp:
            first_timestamp = cast(
                CaptureTime, profile_entries[0].codeword_entries.timestamp[0]
            )

        if first_timestamp is not None and not self.override_capture_time(
            first_timestamp
        ):
            self.logger.error(
                "Unable to update CaptureTime from %s -> %s",
                self._capture_time,
                first_timestamp,
            )

        self._model = CmDsOfdmFecSummaryModel(
            pnm_header=self.getPnmHeaderParameterModel(),
            channel_id=self._channel_id,
            mac_address=self._mac_address,
            summary_type=self._summary_type,
            num_profiles=self._num_profiles,
            fec_summary_data=profile_entries,
        )

    def to_model(self) -> CmDsOfdmFecSummaryModel:
        """Return the structured pydantic model for the parsed FEC summary."""
        return self._model

    def to_dict(self) -> dict[str, Any]:
        return self._model.model_dump()
