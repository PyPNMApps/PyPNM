from __future__ import annotations

import pytest

from pypnm.lib.interface.bridge.bridge_stats import BridgeStats


class _FakeSnmp:
    def __init__(self) -> None:
        self._walk_data: dict[str, list[tuple[str, str]]] = {
            "dot1dBasePortIfIndex": [
                ("1.3.6.1.2.1.17.1.4.1.2.1", "49")
            ],
            "dot1dTpPort": [
                ("1.3.6.1.2.1.17.4.4.1.1.1", "1")
            ],
            "dot1dTpFdbAddress": [
                ("1.3.6.1.2.1.17.4.3.1.1.170.187.204.221.238.255", "aa:bb:cc:dd:ee:ff")
            ],
            "ifStackStatus": [
                ("1.3.6.1.2.1.31.1.2.1.3.49.1", "1"),
                ("1.3.6.1.2.1.31.1.2.1.3.1.2", "1"),
            ],
        }
        self._get_data: dict[str, tuple[str, str]] = {
            "dot1dBaseBridgeAddress.0": ("1.3.6.1.2.1.17.1.1.0", "aa:bb:cc:dd:ee:ff"),
            "dot1dBaseNumPorts.0": ("1.3.6.1.2.1.17.1.2.0", "2"),
            "dot1dBaseType.0": ("1.3.6.1.2.1.17.1.3.0", "2"),
            "dot1dBasePort.1": ("1.3.6.1.2.1.17.1.4.1.1.1", "1"),
            "dot1dBasePortIfIndex.1": ("1.3.6.1.2.1.17.1.4.1.2.1", "49"),
            "dot1dBasePortCircuit.1": ("1.3.6.1.2.1.17.1.4.1.3.1", "0.0"),
            "dot1dBasePortDelayExceededDiscards.1": ("1.3.6.1.2.1.17.1.4.1.4.1", "0"),
            "dot1dBasePortMtuExceededDiscards.1": ("1.3.6.1.2.1.17.1.4.1.5.1", "0"),
            "dot1dTpPort.1": ("1.3.6.1.2.1.17.4.4.1.1.1", "1"),
            "dot1dTpPortMaxInfo.1": ("1.3.6.1.2.1.17.4.4.1.2.1", "1500"),
            "dot1dTpPortInFrames.1": ("1.3.6.1.2.1.17.4.4.1.3.1", "10"),
            "dot1dTpPortOutFrames.1": ("1.3.6.1.2.1.17.4.4.1.4.1", "20"),
            "dot1dTpPortInDiscards.1": ("1.3.6.1.2.1.17.4.4.1.5.1", "0"),
            "dot1dTpFdbPort.170.187.204.221.238.255": ("1.3.6.1.2.1.17.4.3.1.2.170.187.204.221.238.255", "1"),
            "dot1dTpFdbStatus.170.187.204.221.238.255": ("1.3.6.1.2.1.17.4.3.1.3.170.187.204.221.238.255", "3"),
            "ifType.49": ("1.3.6.1.2.1.2.2.1.3.49", "6"),
            "ifDescr.49": ("1.3.6.1.2.1.2.2.1.2.49", "eth0"),
            "ifName.49": ("1.3.6.1.2.1.31.1.1.1.1.49", "eth0_49"),
        }

    async def walk(self, oid: str) -> list[tuple[str, str]] | None:
        return self._walk_data.get(oid)

    async def get(self, oid: str) -> list[tuple[str, str]] | None:
        value = self._get_data.get(oid)
        if value is None:
            return None
        return [value]


class _FakeEmptySnmp:
    async def walk(self, oid: str) -> list[tuple[str, str]] | None:
        return None

    async def get(self, oid: str) -> list[tuple[str, str]] | None:
        return None


@pytest.fixture(autouse=True)
def _patch_snmp_get_result_value(monkeypatch: pytest.MonkeyPatch) -> None:
    def _mock_get_result_value(value: object) -> str | None:
        if value is None:
            return None
        if isinstance(value, list) and value:
            return str(value[0][1])
        if isinstance(value, tuple):
            return str(value[1])
        return str(value)

    monkeypatch.setattr("pypnm.snmp.snmp_v2c.Snmp_v2c.get_result_value", staticmethod(_mock_get_result_value))


async def test_bridge_stats_get_returns_expected_tables() -> None:
    bridge_model = await BridgeStats.get(_FakeSnmp())  # type: ignore[arg-type]
    assert bridge_model is not None
    bridge = bridge_model.model_dump()
    assert "ifIndexes" in bridge
    ifindexes = bridge["ifIndexes"]
    assert isinstance(ifindexes, dict)
    assert "49" in ifindexes
    if49 = ifindexes["49"]
    assert if49["ifType"] == 6
    assert if49["ifDescription"] == "eth0"
    assert if49["ifName"] == "eth0_49"
    assert if49["dot1dBase"][0]["dot1dBaseNumPorts"] == 2
    assert if49["dot1dBasePortEntry"][0]["dot1dBasePort"] == 1
    assert if49["dot1dTpPortEntry"][0]["dot1dTpPortOutFrames"] == 20
    assert if49["dot1dTpFdbEntry"][0]["dot1dTpFdbAddress"] == "aa:bb:cc:dd:ee:ff"
    assert if49["dot1dTpFdbEntry"][0]["dot1dTpFdbStatus"] == 3
    assert if49["ifStackEntry"][0]["ifStackHigherLayer"] == 49
    assert if49["ifStackEntry"][0]["ifStackLowerLayer"] == 1


async def test_bridge_stats_get_returns_none_when_no_walk_data() -> None:
    payload = await BridgeStats.get(_FakeEmptySnmp())  # type: ignore[arg-type]
    assert payload is None
