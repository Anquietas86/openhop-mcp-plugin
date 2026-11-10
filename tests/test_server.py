"""In-process tests for tools, resources and prompts against a fake Repeater.

The Repeater is replaced with an ``httpx2.MockTransport``, so these exercise
the real client (caching, redaction, error handling) and the real tool code
without a network or a running server.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Callable
from typing import Any

import httpx2
import pytest
from mcp.server.mcpserver.exceptions import ToolError

from openhop_mcp import server as server_mod
from openhop_mcp.client import REDACTED, OpenHopClient
from openhop_mcp.config import load_config
from openhop_mcp.security import current_auth

PUBKEY = "ab" * 32
NOW = time.time()

STATS = {
    "success": True,
    "local_hash": "0x1a",
    "uptime_seconds": 3600,
    "rx_count": 10,
    "noise_floor_dbm": -115.0,
    "neighbors": {
        PUBKEY: {"node_name": "hilltop", "rssi": -80, "snr": 9.5, "last_seen": NOW, "zero_hop": True},
        "cd" * 32: {"node_name": "valley", "rssi": -110, "snr": -4, "last_seen": NOW - 600},
    },
    "recent_packets": [],
    "config": {
        "node_name": "test-node",
        "repeater": {"mode": "forward"},
        "radio": {"spreading_factor": 8, "bandwidth": 62500, "coding_rate": 8, "preamble_length": 32},
        "duty_cycle": {"max_airtime_percent": 10.0, "enforcement_enabled": True},
        "mqtt_brokers": {"main": {"host": "broker", "password": "hunter2", "refill_tokens": 5}},
    },
}


def _routes() -> dict[str, Callable[[httpx2.Request], Any]]:
    link_rows = [
        {
            "timestamp": NOW - 3600 + i * 300,
            "rssi": -80 - (i // 6) * 8,
            "snr": 9 - (i // 6) * 6,
            "is_duplicate": i % 4 == 0,
            "path_hop_count": 1,
        }
        for i in range(12)
    ]
    noise = [{"timestamp": NOW - 3600 + i * 60, "noise_floor_dbm": -115.0 + (i % 2) * 0.5} for i in range(40)]
    noise[20]["noise_floor_dbm"] = -95.0
    noise[21]["noise_floor_dbm"] = -96.0
    return {
        "/api/stats": lambda req: STATS,
        "/api/neighbor_links": lambda req: {
            "success": True,
            "data": {
                "links": [{"peer_hash": "AB", "path_hash_size": 1, "sample_count": 12, "ewma_snr": 4.0}]
            },
        },
        "/api/neighbor_link_history": lambda req: {
            "success": True,
            "data": {"peer_hash": req.url.params["peer_hash"].upper(), "rows": link_rows},
        },
        "/api/airtime_chart_data": lambda req: {
            "success": True,
            "data": {
                "bucket_seconds": 60,
                "buckets": [
                    {"timestamp": NOW, "tx_ms": 3000, "rx_ms": 6000},
                    {"timestamp": NOW + 60, "tx_ms": 5400, "rx_ms": 1000},
                ],
            },
        },
        "/api/noise_floor_history": lambda req: {"success": True, "data": {"history": noise}},
        "/api/gps": lambda req: {"success": False, "error": "GPS not configured"},
    }


@pytest.fixture()
def fake_repeater(monkeypatch):
    calls: list[str] = []
    routes = _routes()

    def handler(request: httpx2.Request) -> httpx2.Response:
        calls.append(request.url.path)
        route = routes.get(request.url.path)
        if route is None:
            return httpx2.Response(404, json={"error": "not found"})
        return httpx2.Response(200, json=route(request))

    def get_client(self: OpenHopClient) -> httpx2.AsyncClient:
        if self._client is None:
            self._client = httpx2.AsyncClient(base_url=self.base_url, transport=httpx2.MockTransport(handler))
        return self._client

    monkeypatch.setattr(OpenHopClient, "_get_client", get_client)
    return calls


@pytest.fixture()
def srv(tmp_path, monkeypatch, fake_repeater):
    monkeypatch.setenv("OPENHOP_MCP_DATA", str(tmp_path))
    (tmp_path / "config.json").write_text(
        json.dumps(
            {
                "auth_tokens": [{"name": "t", "role": "admin", "token": "test-token-abcdefghijklmnop"}],
                "repeater_db_path": "",
            }
        )
    )
    return server_mod.build_server(load_config())


def call(srv, name: str, args: dict | None = None, role: str = "admin"):
    async def run():
        token = current_auth.set({"name": "test", "role": role, "ip": "127.0.0.1"})
        try:
            return await srv.call_tool(name, args or {})
        finally:
            current_auth.reset(token)

    return asyncio.run(run())


def structured(result) -> dict:
    assert not result.is_error, result.content
    return result.structured_content


def test_stats_summary_is_typed(srv):
    data = structured(call(srv, "openhop_stats"))
    assert data["local_hash"] == "0x1a"
    assert data["node_name"] == "test-node"
    assert data["neighbor_count"] == 2
    assert data["max_airtime_percent"] == 10.0


def test_tools_publish_output_schemas(srv):
    tools = {t.name: t for t in asyncio.run(srv.list_tools())}
    assert tools["openhop_stats"].output_schema["properties"]["local_hash"]
    assert tools["openhop_link_quality"].output_schema
    assert tools["openhop_stats"].annotations.read_only_hint is True


def test_full_stats_redacts_secrets_but_keeps_numbers(srv):
    data = structured(call(srv, "openhop_stats_full"))
    broker = data["config"]["mqtt_brokers"]["main"]
    assert broker["password"] == REDACTED
    assert broker["refill_tokens"] == 5
    assert broker["host"] == "broker"


def test_stats_cached_across_tools(srv, fake_repeater):
    call(srv, "openhop_stats")
    call(srv, "openhop_neighbors")
    assert fake_repeater.count("/api/stats") == 1


def test_neighbors_include_pubkey_and_sort(srv):
    data = structured(call(srv, "openhop_neighbors", {"sort_by": "rssi"}))
    assert data["neighbors"][0]["pubkey"] == PUBKEY
    assert data["neighbors"][0]["node_name"] == "hilltop"


def test_success_false_becomes_tool_error(srv):
    with pytest.raises(ToolError, match="GPS not configured"):
        call(srv, "openhop_gps")


def test_unknown_endpoint_is_tool_error(srv):
    with pytest.raises(ToolError, match="404"):
        call(srv, "openhop_hardware")


def test_link_quality_lists_links_without_peer(srv):
    data = structured(call(srv, "openhop_link_quality"))
    assert data["links"][0]["peer_hash"] == "AB"
    assert data["observations"] == 0


def test_link_quality_detects_degrading_link(srv):
    data = structured(call(srv, "openhop_link_quality", {"peer_hash": "ab", "hours": 1}))
    assert data["peer_hash"] == "AB"
    assert data["observations"] == 12
    assert data["trend"] == "degrading"
    assert data["duplicate_ratio"] == 0.25


def test_airtime_headroom_uses_radio_settings_and_limit(srv, fake_repeater):
    data = structured(call(srv, "openhop_airtime_headroom", {"hours": 1}))
    assert data["radio"] == {"sf": 8, "bw_hz": 62500, "cr": 8, "preamble": 32}
    assert data["max_airtime_percent"] == 10.0
    assert data["tx_percent"]["max"] == 9.0
    assert data["buckets_near_limit"] == 1
    assert data["status"] == "near limit"


def test_noise_anomalies_finds_spike(srv):
    data = structured(call(srv, "openhop_noise_anomalies", {"hours": 1}))
    assert data["event_count"] == 1
    assert data["events"][0]["direction"] == "high"
    assert data["events"][0]["samples"] == 2


def test_channel_messages_requires_admin(srv):
    with pytest.raises(ToolError, match="admin-role"):
        call(srv, "openhop_channel_messages", role="read")


def test_channels_without_history_is_tool_error(srv):
    with pytest.raises(ToolError, match="history disabled"):
        call(srv, "openhop_channels")


def test_api_read_policy_error(srv):
    with pytest.raises(ToolError, match="read-only policy"):
        call(srv, "openhop_api_read", {"path": "/api/plugins/settings"}, role="read")


def test_whoami(srv):
    assert structured(call(srv, "openhop_whoami", role="read")) == {"name": "test", "role": "read"}


def test_resources(srv):
    uris = {str(r.uri) for r in asyncio.run(srv.list_resources())}
    assert {"openhop://stats", "openhop://neighbors"} <= uris
    assert "openhop://channels" not in uris  # history disabled in this fixture
    content = asyncio.run(srv.read_resource("openhop://stats"))
    assert json.loads(content[0].content)["local_hash"] == "0x1a"


def test_prompts(srv):
    names = {p.name for p in asyncio.run(srv.list_prompts())}
    assert names == {"mesh_health_check", "diagnose_neighbor", "summarise_channel"}
    prompt = asyncio.run(srv.get_prompt("diagnose_neighbor", {"node": "hilltop"}))
    assert "hilltop" in prompt.messages[0].content.text
    assert "openhop_link_quality" in prompt.messages[0].content.text
