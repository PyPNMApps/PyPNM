# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from typing import cast

from pypnm.api.routes.basic.ofdm_spec_analyzer_rpt import SingleOfdmSpecAnalyzerReport
from pypnm.api.routes.basic.spec_analyzer_analysis_rpt import (
    SpecAnaWindowAvgRptModel,
    SpectrumAnalyzerAnalysisRptModel,
    SpectrumAnalyzerSignalProcessRptModel,
)
from pypnm.lib.db.json_transaction import JsonTransactionDb
from pypnm.lib.types import ChannelId, FrequencySeriesHz, FloatSeries


class _FakeAnalysis:
    def __init__(self) -> None:
        self._results = {
            "analysis": [
                {
                    "mac_address": "aa:bb:cc:dd:ee:ff",
                    "device_details": {
                        "system_description": {
                            "HW_REV": "1.0",
                            "VENDOR": "LANCity",
                            "BOOTR": "NONE",
                            "SW_REV": "1.0.0",
                            "MODEL": "LCPET-3",
                        }
                    },
                }
            ]
        }

    def get_results(self, full_dict: bool = True) -> dict[str, object]:
        return self._results

    def get_model(self) -> list[object]:
        return []


def _build_report_model(channel_id: ChannelId) -> SpectrumAnalyzerAnalysisRptModel:
    frequencies: FrequencySeriesHz = [100]
    magnitudes: FloatSeries = [1.0]
    windows: FloatSeries = [1.0]

    window = SpecAnaWindowAvgRptModel(
        window_size=1,
        windows_average=windows,
        length=1,
    )

    signal = SpectrumAnalyzerSignalProcessRptModel(
        frequencies=frequencies,
        amplitude=magnitudes,
        anti_log=[1.0],
        window=window,
    )

    return SpectrumAnalyzerAnalysisRptModel(
        channel_id=channel_id,
        signal=signal,
    )


def test_ofdm_report_json_includes_measurement_stats(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def _fake_write_json(self, data: dict[str, object], fname: str, extension: str = "json") -> None:
        captured["data"] = data
        captured["fname"] = fname
        captured["extension"] = extension

    monkeypatch.setattr(JsonTransactionDb, "write_json", _fake_write_json)

    channel_id = ChannelId(3)
    measurement_stats_by_channel = {
        channel_id: [
            {
                "channel_id": channel_id,
                "entry": {"docsIf3CmSpectrumAnalysisCtrlCmdEnable": True},
            }
        ]
    }

    report = SingleOfdmSpecAnalyzerReport(
        _FakeAnalysis(),
        measurement_stats_by_channel=measurement_stats_by_channel,
    )
    report.register_common_analysis_model(channel_id, _build_report_model(channel_id))

    payload = cast(dict[str, object], captured.get("data", {}))
    assert payload.get("channel_id") == channel_id
    measurement_stats = cast(list[dict[str, object]], payload["measurement_stats"])
    assert "channel_id" not in measurement_stats[0]
