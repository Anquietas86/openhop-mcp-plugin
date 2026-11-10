"""MCP server entrypoint for the openHop Repeater plugin.

Exposes mesh telemetry as MCP tools, resources and prompts over Streamable
HTTP. Every request passes through :class:`openhop_mcp.security.GateMiddleware`
first, so the MCP endpoint itself is never reachable without both an allowed
source address and a bearer token. Inside MCP, :class:`openhop_mcp.audit.AuditMiddleware`
then rate-limits each token and writes an audit record for every operation.

Writes are disabled by default (``read_only: true``). Set it to false in the
plugin settings only if you deliberately want the mutating tools exposed.

Tool failures raise :class:`ToolError`, so clients see ``isError: true`` with a
readable message instead of a success result that happens to contain an
``error`` key.
"""

from __future__ import annotations

import json
import sys
import time
from typing import Any

import anyio
import uvicorn
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from . import __version__
from .analysis import airtime_headroom, link_quality, noise_anomalies
from .api_policy import PolicyError, clean_params, normalise_path
from .audit import AuditLog, AuditMiddleware, TokenRateLimiter
from .client import OpenHopClient, OpenHopError
from .config import Config, ConfigError, load_config
from .history import MAX_HISTORY_DAYS, HistoryError, RepeaterHistory
from .models import (
    AirtimeHeadroom,
    Broker,
    ChannelInfo,
    ChannelList,
    ChannelMessage,
    ChannelMessages,
    Distribution,
    Frontend,
    FrontendList,
    GpsFix,
    LinkQuality,
    LinkSnapshot,
    LogEntry,
    LogList,
    MqttStatus,
    Neighbor,
    NeighborList,
    NoiseAnomalies,
    NoiseEvent,
    Packet,
    PacketList,
    Process,
    ProcessList,
    StatsSummary,
    WhoAmI,
)
from .security import GateMiddleware, current_auth

INSTRUCTIONS = """\
This server exposes telemetry from an openHop Repeater (MeshCore mesh node).

Start with `openhop_stats` for an overview, or read the `openhop://stats`
resource. Drill into neighbours, packets, noise floor, GPS, hardware, logs,
processes, MQTT, web frontends, setup metadata, or room messages as needed.

For diagnosis, prefer the analysis tools over raw data:
`openhop_link_quality` (one neighbour's RSSI/SNR trend and gaps),
`openhop_airtime_headroom` (transmit airtime vs the duty-cycle limit) and
`openhop_noise_anomalies` (noise-floor spikes). The prompts
`mesh_health_check`, `diagnose_neighbor` and `summarise_channel` chain these
together.

Channel conversation history is NOT in the REST API. It is read directly from
the Repeater's SQLite database and decrypted with channel keys. Both history
tools need the `allow_message_history` setting. `openhop_channels` (names
only) works with any token; `openhop_channel_messages` (message content)
requires the admin role.

`openhop_api_read` only reaches an allowlist of telemetry endpoints. Plugin
settings, config backups, identity keys, transport keys and other credential
material are never reachable through it, and secret-looking fields are
redacted from every response.

Mutating tools (`openhop_send_advert`, `openhop_set_mode`,
`openhop_set_duty_cycle`, `openhop_update_duty_cycle_config`,
`openhop_update_advert_rate_limit`, `openhop_publish_neighbors`,
`openhop_query_neighbor_scopes`) only exist when the plugin operator has
explicitly disabled read-only mode, and need an admin token. If they are
absent or return an error, do not attempt workarounds.

Each token is rate limited. If a call reports a rate limit, wait and retry.
"""


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _payload(value: Any) -> dict[str, Any]:
    """Unwrap the Repeater's ``{"success": true, "data": {...}}`` envelope."""
    data = _as_dict(value)
    inner = data.get("data")
    return inner if isinstance(inner, dict) else data


def _summarise_stats(stats: dict[str, Any]) -> StatsSummary:
    """Return a compact overview rather than the full ~90 KB stats payload."""
    neighbors = stats.get("neighbors") or {}
    recent = stats.get("recent_packets") or []
    gps = _as_dict(stats.get("gps"))
    config = _as_dict(stats.get("config"))
    duty = _as_dict(config.get("duty_cycle"))
    return StatsSummary(
        local_hash=stats.get("local_hash"),
        node_name=config.get("node_name"),
        mode=_as_dict(config.get("repeater")).get("mode"),
        version=stats.get("version"),
        core_version=stats.get("core_version"),
        uptime_seconds=stats.get("uptime_seconds"),
        rx_count=stats.get("rx_count"),
        forwarded_count=stats.get("forwarded_count"),
        dropped_count=stats.get("dropped_count"),
        rx_per_hour=stats.get("rx_per_hour"),
        forwarded_per_hour=stats.get("forwarded_per_hour"),
        noise_floor_dbm=stats.get("noise_floor_dbm"),
        crc_error_count=stats.get("crc_error_count"),
        max_airtime_percent=duty.get("max_airtime_percent"),
        duty_cycle_enforced=duty.get("enforcement_enabled"),
        neighbor_count=len(neighbors) if isinstance(neighbors, (dict, list)) else 0,
        recent_packet_count=len(recent) if isinstance(recent, list) else 0,
        gps=GpsFix(
            fix=gps.get("fix") or gps.get("has_fix"),
            latitude=gps.get("latitude"),
            longitude=gps.get("longitude"),
            satellites=gps.get("satellites"),
        ),
    )


def _neighbor_nodes(stats: dict[str, Any]) -> list[dict[str, Any]]:
    neighbors = stats.get("neighbors") or {}
    if isinstance(neighbors, dict):
        return [{"pubkey": key, **node} for key, node in neighbors.items() if isinstance(node, dict)]
    if isinstance(neighbors, list):
        return [n for n in neighbors if isinstance(n, dict)]
    return []


def _distribution(value: Any) -> Distribution:
    return Distribution.model_validate(_as_dict(value))


def build_server(cfg: Config) -> MCPServer:
    audit = AuditLog(cfg.audit_log_path, max_bytes=cfg.audit_log_max_bytes) if cfg.audit_log else None
    limiter = TokenRateLimiter(cfg.rate_limit_per_minute)
    server = MCPServer(
        "openhop-mcp",
        title="openHop Repeater MCP",
        description="Authenticated telemetry access for an openHop Repeater.",
        instructions=INSTRUCTIONS,
        version=__version__,
        middleware=[AuditMiddleware(audit, limiter)],
    )
    api = OpenHopClient(
        cfg.openhop_base_url,
        cfg.openhop_api_key,
        cfg.request_timeout_seconds,
        cache_ttl=cfg.cache_ttl_seconds,
    )
    history: RepeaterHistory | None = None
    if cfg.allow_message_history and cfg.repeater_db_path:
        history = RepeaterHistory(cfg.repeater_db_path)

    read_tool = ToolAnnotations(read_only_hint=True, open_world_hint=False)
    write_tool = ToolAnnotations(
        read_only_hint=False, destructive_hint=False, idempotent_hint=True, open_world_hint=False
    )
    # Transmitting on the mesh reaches other nodes and is not idempotent.
    radio_tool = ToolAnnotations(
        read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True
    )

    def _cap(limit: int) -> int:
        return max(1, min(int(limit), cfg.max_items))

    def _require_admin(operation: str) -> None:
        auth = current_auth.get()
        if auth.get("role") != "admin":
            raise ToolError(
                f"forbidden: {operation} requires an admin-role token "
                f"(this token is {auth.get('name')!r} with role {auth.get('role')!r})"
            )

    def _require_history() -> RepeaterHistory:
        if history is None:
            raise ToolError(
                "message history disabled: set allow_message_history=true and "
                "repeater_db_path in the plugin config"
            )
        return history

    async def _get(path: str, params: dict[str, Any] | None = None) -> Any:
        try:
            return await api.get(path, params)
        except OpenHopError as exc:
            raise ToolError(str(exc)) from exc

    async def _post(path: str, body: dict[str, Any]) -> Any:
        try:
            return await api.post(path, body)
        except OpenHopError as exc:
            raise ToolError(str(exc)) from exc

    async def _stats() -> dict[str, Any]:
        stats = await _get("/api/stats")
        if not isinstance(stats, dict):
            raise ToolError(f"unexpected /api/stats response type: {type(stats).__name__}")
        return stats

    async def _neighbor_list(zero_hop_only: bool, limit: int, sort_by: str) -> NeighborList:
        nodes = _neighbor_nodes(await _stats())
        if zero_hop_only:
            nodes = [n for n in nodes if n.get("zero_hop")]
        if sort_by == "rssi":
            nodes.sort(key=lambda n: n.get("rssi") or -999, reverse=True)
        else:
            nodes.sort(key=lambda n: n.get("last_seen") or 0, reverse=True)
        capped = _cap(limit)
        return NeighborList(
            count=len(nodes),
            returned=min(len(nodes), capped),
            neighbors=[Neighbor.model_validate(n) for n in nodes[:capped]],
        )

    # -- core telemetry ------------------------------------------------------

    @server.tool(annotations=read_tool)
    async def openhop_stats() -> StatsSummary:
        """Repeater overview: identity, uptime, packet counters, noise floor, duty cycle, GPS."""
        return _summarise_stats(await _stats())

    @server.tool(annotations=read_tool)
    async def openhop_stats_full() -> dict[str, Any]:
        """The full /api/stats payload (large; secrets redacted). Prefer openhop_stats."""
        return await _stats()

    @server.tool(annotations=read_tool)
    async def openhop_neighbors(
        zero_hop_only: bool = False,
        limit: int = 50,
        sort_by: str = "last_seen",
    ) -> NeighborList:
        """List known neighbour nodes. sort_by is 'last_seen' or 'rssi'."""
        return await _neighbor_list(zero_hop_only, limit, sort_by)

    @server.tool(annotations=read_tool)
    async def openhop_recent_packets(
        limit: int = 20,
        packet_type: int | None = None,
        route: int | None = None,
    ) -> PacketList:
        """Recent packets, optionally filtered by numeric type or route."""
        capped = _cap(limit)
        data = await _get("/api/recent_packets", {"limit": capped})
        raw = _as_dict(data)
        packets = raw.get("packets", raw.get("recent_packets", raw.get("data", [])))
        packets = [p for p in packets if isinstance(p, dict)] if isinstance(packets, list) else []
        if packet_type is not None:
            packets = [p for p in packets if p.get("type") == packet_type]
        if route is not None:
            packets = [p for p in packets if p.get("route") == route]
        if packets:
            return PacketList(
                count=len(packets),
                packets=[Packet.model_validate(p) for p in packets[:capped]],
                source="api",
            )
        # The Repeater's in-memory buffer can be momentarily empty. Fall back to
        # the packets table so callers get real data instead of a bare zero.
        if history is not None:
            try:
                result = await anyio.to_thread.run_sync(
                    lambda: history.recent_packets(limit=capped, packet_type=packet_type, route=route)
                )
            except HistoryError as exc:
                return PacketList(count=0, packets=[], source="api", fallback_error=str(exc))
            return PacketList(
                count=result["count"],
                packets=[Packet.model_validate(p) for p in result["packets"]],
                source="database",
            )
        return PacketList(count=0, packets=[], source="api")

    @server.tool(annotations=read_tool)
    async def openhop_packet_stats(hours: int = 24) -> dict[str, Any]:
        """Packet counters for the last N hours."""
        return await _get("/api/packet_stats", {"hours": max(1, hours)})

    @server.tool(annotations=read_tool)
    async def openhop_packet_type_stats(hours: int = 24) -> dict[str, Any]:
        """Packet counts grouped by packet type for the last N hours."""
        return await _get("/api/packet_type_stats", {"hours": max(1, hours)})

    @server.tool(annotations=read_tool)
    async def openhop_route_stats(hours: int = 24) -> dict[str, Any]:
        """Packet counts grouped by route type for the last N hours."""
        return await _get("/api/route_stats", {"hours": max(1, hours)})

    @server.tool(annotations=read_tool)
    async def openhop_noise_floor(hours: int = 24) -> dict[str, Any]:
        """Noise floor statistics for the last N hours."""
        return await _get("/api/noise_floor_stats", {"hours": max(1, hours)})

    @server.tool(annotations=read_tool)
    async def openhop_gps() -> dict[str, Any]:
        """GPS diagnostics and parsed NMEA attributes."""
        return await _get("/api/gps")

    @server.tool(annotations=read_tool)
    async def openhop_hardware() -> dict[str, Any]:
        """Host hardware statistics (CPU, RAM, disk, temperatures)."""
        return await _get("/api/hardware_stats")

    @server.tool(annotations=read_tool)
    async def openhop_logs(
        limit: int = 50,
        level: str | None = None,
        since_id: int | None = None,
    ) -> LogList:
        """Repeater application logs, newest last. Filter by level or id."""
        data = await _get("/api/logs")
        entries = _as_dict(data).get("logs", [])
        entries = [e for e in entries if isinstance(e, dict)] if isinstance(entries, list) else []
        if since_id is not None:
            entries = [e for e in entries if (e.get("id") or 0) > since_id]
        if level:
            wanted = level.strip().upper()
            entries = [e for e in entries if str(e.get("level", "")).upper() == wanted]
        trimmed = entries[-_cap(limit) :]
        return LogList(
            count=len(entries),
            returned=len(trimmed),
            logs=[LogEntry.model_validate(e) for e in trimmed],
        )

    @server.tool(annotations=read_tool)
    async def openhop_processes(limit: int = 20, sort_by: str = "cpu") -> ProcessList:
        """Host process resource usage. sort_by is 'cpu' or 'memory'."""
        procs = _payload(await _get("/api/hardware_processes")).get("processes", [])
        procs = [p for p in procs if isinstance(p, dict)] if isinstance(procs, list) else []
        key = "memory_mb" if sort_by == "memory" else "cpu_percent"
        procs.sort(key=lambda p: p.get(key) or 0, reverse=True)
        trimmed = procs[: _cap(limit)]
        return ProcessList(
            count=len(procs),
            returned=len(trimmed),
            processes=[Process.model_validate(p) for p in trimmed],
        )

    @server.tool(annotations=read_tool)
    async def openhop_mqtt_status() -> MqttStatus:
        """MQTT bridge status and per-broker connection state."""
        payload = _payload(await _get("/api/mqtt_status"))
        brokers = payload.get("brokers", [])
        brokers = [b for b in brokers if isinstance(b, dict)] if isinstance(brokers, list) else []
        return MqttStatus(
            handler_active=payload.get("handler_active"),
            broker_count=len(brokers),
            brokers=[
                Broker.model_validate(
                    {**b, **{k: _as_dict(b.get("status")).get(k) for k in ("connected", "reconnecting")}}
                )
                for b in brokers
            ],
        )

    @server.tool(annotations=read_tool)
    async def openhop_web_frontends() -> FrontendList:
        """Configured web frontends and which one is selected."""
        payload = _payload(await _get("/api/web_frontends"))
        frontends = payload.get("frontends", [])
        frontends = [f for f in frontends if isinstance(f, dict)] if isinstance(frontends, list) else []
        return FrontendList(
            count=len(frontends),
            selected=payload.get("selected"),
            frontends=[Frontend.model_validate(f) for f in frontends],
        )

    @server.tool(annotations=read_tool)
    async def openhop_setup_info() -> dict[str, Any]:
        """Setup/hardware metadata: radio presets, serial ports, site info, hardware options."""
        out: dict[str, Any] = {}
        for key, path in (
            ("radio_presets", "/api/radio_presets"),
            ("serial_ports", "/api/serial_ports"),
            ("site_info", "/api/site_info"),
            ("hardware_options", "/api/hardware_options"),
        ):
            try:
                out[key] = await api.get(path)
            except OpenHopError as exc:
                out[key] = {"error": str(exc)}
        return out

    @server.tool(annotations=read_tool)
    async def openhop_room_messages(
        room_name: str | None = None,
        room_hash: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Room-server messages. Requires room_name or room_hash.

        Room servers only; channel chat lives in openhop_channel_messages.
        """
        if not room_name and not room_hash:
            raise ToolError("provide room_name or room_hash")
        params: dict[str, Any] = {"limit": _cap(limit)}
        if room_name:
            params["room_name"] = room_name
        if room_hash:
            params["room_hash"] = room_hash
        return await _get("/api/room_messages", params)

    # -- channel history -----------------------------------------------------

    @server.tool(annotations=read_tool)
    async def openhop_channels() -> ChannelList:
        """Configured mesh channels (names and indices only — never secrets)."""
        db = _require_history()
        try:
            result = await anyio.to_thread.run_sync(db.channels)
        except HistoryError as exc:
            raise ToolError(str(exc)) from exc
        return ChannelList(
            count=result["count"],
            channels=[ChannelInfo.model_validate(c) for c in result["channels"]],
        )

    @server.tool(annotations=read_tool)
    async def openhop_channel_messages(
        channel: str | None = None,
        days: float = 7.0,
        limit: int = 100,
        grep: str | None = None,
        include_bogus_timestamps: bool = False,
    ) -> ChannelMessages:
        """Decrypt and return channel message history from the Repeater database.

        Admin token required — message content is more sensitive than telemetry.
        Omit `channel` to search every configured channel. `days` is a rolling
        window ending now, capped at 90. `grep` is a case-insensitive substring
        filter.
        """
        _require_admin("openhop_channel_messages")
        db = _require_history()
        try:
            result = await anyio.to_thread.run_sync(
                lambda: db.messages(
                    channel,
                    days=days,
                    limit=limit,
                    grep=grep,
                    include_bogus_timestamps=include_bogus_timestamps,
                )
            )
        except HistoryError as exc:
            raise ToolError(str(exc)) from exc
        if "error" in result:
            known = ", ".join(result.get("known_channels", []))
            raise ToolError(f"unknown channel {channel!r}; known channels: {known}")
        return ChannelMessages(
            **{k: v for k, v in result.items() if k != "messages"},
            messages=[ChannelMessage.model_validate(m) for m in result["messages"]],
        )

    # -- analysis ------------------------------------------------------------

    @server.tool(annotations=read_tool)
    async def openhop_link_quality(
        peer_hash: str | None = None,
        path_hash_size: int = 1,
        hours: int = 24,
    ) -> LinkQuality:
        """Link quality for one upstream neighbour: RSSI/SNR spread, SNR trend, gaps, duplicates.

        Omit `peer_hash` to get the list of recently heard links (with their
        hashes and smoothed RSSI/SNR) to pick from. `path_hash_size` is the
        hash width in bytes shown alongside each link.
        """
        hours = max(1, min(int(hours), 24 * 30))
        if not peer_hash:
            payload = _payload(
                await _get(
                    "/api/neighbor_links",
                    {"active_within_seconds": hours * 3600, "limit": cfg.max_items},
                )
            )
            links = payload.get("links", [])
            links = [x for x in links if isinstance(x, dict)] if isinstance(links, list) else []
            return LinkQuality(hours=hours, links=[LinkSnapshot.model_validate(x) for x in links])
        payload = _payload(
            await _get(
                "/api/neighbor_link_history",
                {
                    "peer_hash": peer_hash.strip(),
                    "path_hash_size": int(path_hash_size),
                    "hours": hours,
                    "limit": 5000,
                },
            )
        )
        rows = payload.get("rows", [])
        rows = rows if isinstance(rows, list) else []
        summary = link_quality(rows, hours)
        return LinkQuality(
            peer_hash=str(payload.get("peer_hash") or peer_hash).upper(),
            path_hash_size=int(path_hash_size),
            hours=hours,
            **{k: v for k, v in summary.items() if k not in ("rssi", "snr")},
            rssi=_distribution(summary["rssi"]),
            snr=_distribution(summary["snr"]),
        )

    @server.tool(annotations=read_tool)
    async def openhop_airtime_headroom(hours: float = 1.0) -> AirtimeHeadroom:
        """Transmit airtime per minute vs the duty-cycle limit, plus receive load.

        Uses the live radio settings (SF, bandwidth, coding rate, preamble) to
        compute airtime, and the configured max_airtime_percent as the limit.
        """
        hours = max(0.1, min(float(hours), 48.0))
        stats = await _stats()
        config = _as_dict(stats.get("config"))
        radio = _as_dict(config.get("radio"))
        limit = _as_dict(config.get("duty_cycle")).get("max_airtime_percent")
        radio_params = {
            "sf": int(radio.get("spreading_factor") or 9),
            "bw_hz": int(radio.get("bandwidth") or 62500),
            "cr": int(radio.get("coding_rate") or 5),
            "preamble": int(radio.get("preamble_length") or 17),
        }
        now = time.time()
        payload = _payload(
            await _get(
                "/api/airtime_chart_data",
                {
                    "start_timestamp": now - hours * 3600,
                    "end_timestamp": now,
                    "bucket_seconds": 60,
                    **radio_params,
                },
            )
        )
        buckets = payload.get("buckets", [])
        buckets = buckets if isinstance(buckets, list) else []
        result = airtime_headroom(
            buckets,
            float(payload.get("bucket_seconds") or 60),
            float(limit) if isinstance(limit, (int, float)) else None,
        )
        return AirtimeHeadroom(
            hours=hours,
            **{k: v for k, v in result.items() if k not in ("tx_percent", "rx_percent")},
            tx_percent=_distribution(result["tx_percent"]),
            rx_percent=_distribution(result["rx_percent"]),
            radio=radio_params,
        )

    @server.tool(annotations=read_tool)
    async def openhop_noise_anomalies(
        hours: int = 24,
        threshold: float = 3.5,
        min_delta_db: float = 3.0,
    ) -> NoiseAnomalies:
        """Noise-floor spikes and dips, found with a robust (median/MAD) z-score.

        Raise `threshold` or `min_delta_db` to report only bigger excursions.
        Consecutive anomalous samples are merged into one event.
        """
        hours = max(1, min(int(hours), 24 * 30))
        payload = _payload(await _get("/api/noise_floor_history", {"hours": hours}))
        samples = payload.get("history", [])
        samples = samples if isinstance(samples, list) else []
        result = noise_anomalies(
            samples, threshold=max(1.0, float(threshold)), min_delta_db=max(0.0, float(min_delta_db))
        )
        return NoiseAnomalies(
            hours=hours,
            samples=result["samples"],
            baseline=_distribution(result["baseline"]),
            event_count=result["event_count"],
            events=[NoiseEvent.model_validate(e) for e in result["events"]],
            note=result.get("note"),
        )

    # -- identity and generic access ----------------------------------------

    @server.tool(annotations=read_tool)
    async def openhop_whoami() -> WhoAmI:
        """The identity and role granted to the calling token."""
        auth = current_auth.get()
        return WhoAmI(name=auth.get("name", "anonymous"), role=auth.get("role", "read"))

    @server.tool(annotations=read_tool)
    async def openhop_api_read(path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """GET an allowlisted read-only Repeater telemetry endpoint, e.g. '/api/gps'.

        Only telemetry paths are allowed (stats, packets, noise floor, airtime,
        CRC, neighbour links, rooms, MQTT status and similar). Credential,
        config, identity, plugin and streaming endpoints are refused. Params
        must be flat strings, numbers or booleans.
        """
        try:
            safe_path = normalise_path(path)
            safe_params = clean_params(params)
        except PolicyError as exc:
            raise ToolError(f"path rejected by read-only policy: {exc}") from exc
        result = await _get(safe_path, safe_params)
        return result if isinstance(result, dict) else {"result": result}

    @server.tool(annotations=read_tool)
    async def openhop_validate_config() -> dict[str, Any]:
        """Validate the Repeater's current configuration. Admin token required."""
        _require_admin("openhop_validate_config")
        # GET only — POST returns 405 on this route.
        return await _get("/api/validate_config")

    # -- writes --------------------------------------------------------------

    if not cfg.read_only:

        @server.tool(annotations=radio_tool)
        async def openhop_send_advert() -> dict[str, Any]:
            """Send an advert from the Repeater. Requires read_only=false and an admin token."""
            _require_admin("openhop_send_advert")
            return await _post("/api/send_advert", {})

        @server.tool(annotations=write_tool)
        async def openhop_set_mode(mode: str) -> dict[str, Any]:
            """Set Repeater mode: forward, monitor or no_tx. Admin token required."""
            _require_admin("openhop_set_mode")
            if mode not in ("forward", "monitor", "no_tx"):
                raise ToolError("mode must be one of: forward, monitor, no_tx")
            return await _post("/api/set_mode", {"mode": mode})

        @server.tool(annotations=write_tool)
        async def openhop_set_duty_cycle(enabled: bool = True) -> dict[str, Any]:
            """Enable or disable duty-cycle enforcement. Admin token required."""
            _require_admin("openhop_set_duty_cycle")
            return await _post("/api/set_duty_cycle", {"enabled": bool(enabled)})

        @server.tool(annotations=write_tool)
        async def openhop_update_duty_cycle_config(
            max_airtime_percent: float | None = None,
            enforcement_enabled: bool | None = None,
        ) -> dict[str, Any]:
            """Update duty-cycle settings. Admin token required.

            max_airtime_percent is 0.1-100.0. At least one field must be given.
            """
            _require_admin("openhop_update_duty_cycle_config")
            body: dict[str, Any] = {}
            if max_airtime_percent is not None:
                body["max_airtime_percent"] = float(max_airtime_percent)
            if enforcement_enabled is not None:
                body["enforcement_enabled"] = bool(enforcement_enabled)
            if not body:
                raise ToolError("provide max_airtime_percent and/or enforcement_enabled")
            return await _post("/api/update_duty_cycle_config", body)

        advert_rate_keys = {
            "rate_limit_enabled",
            "bucket_capacity",
            "refill_tokens",
            "refill_interval_seconds",
            "min_interval_seconds",
            "penalty_enabled",
            "violation_threshold",
            "violation_decay_seconds",
            "base_penalty_seconds",
            "penalty_multiplier",
        }

        @server.tool(annotations=write_tool)
        async def openhop_update_advert_rate_limit(settings: dict[str, Any]) -> dict[str, Any]:
            """Update advert rate-limiting settings. Admin token required.

            Accepts a settings object; unknown keys are rejected. Accepted fields:
            rate_limit_enabled, bucket_capacity, refill_tokens,
            refill_interval_seconds, min_interval_seconds, penalty_enabled,
            violation_threshold, violation_decay_seconds, base_penalty_seconds,
            penalty_multiplier.
            """
            _require_admin("openhop_update_advert_rate_limit")
            if not isinstance(settings, dict) or not settings:
                raise ToolError("settings must be a non-empty object")
            unknown = sorted(set(settings) - advert_rate_keys)
            if unknown:
                raise ToolError(f"unknown setting(s): {', '.join(unknown)}")
            return await _post("/api/update_advert_rate_limit_config", settings)

        @server.tool(annotations=radio_tool)
        async def openhop_publish_neighbors() -> dict[str, Any]:
            """Publish the current neighbour table. Admin token required."""
            _require_admin("openhop_publish_neighbors")
            return await _post("/api/publish_neighbors", {})

        @server.tool(annotations=radio_tool)
        async def openhop_query_neighbor_scopes(pubkey: str) -> dict[str, Any]:
            """Ask one zero-hop neighbour for its region scopes. Admin token required.

            `pubkey` must be a full 64-character public key (see openhop_neighbors).
            """
            _require_admin("openhop_query_neighbor_scopes")
            key = (pubkey or "").strip()
            if len(key) != 64:
                raise ToolError("pubkey must be a full 64-character public key")
            return await _post("/api/query_neighbor_scopes", {"pubkey": key})

    # -- resources -----------------------------------------------------------

    @server.resource(
        "openhop://stats",
        name="stats",
        title="Repeater overview",
        description="Compact Repeater status: identity, counters, noise floor, duty cycle, GPS.",
        mime_type="application/json",
    )
    async def stats_resource() -> str:
        try:
            stats = await api.get("/api/stats")
        except OpenHopError as exc:
            return json.dumps({"error": str(exc)})
        return _summarise_stats(_as_dict(stats)).model_dump_json(indent=2)

    @server.resource(
        "openhop://neighbors",
        name="neighbors",
        title="Neighbour table",
        description="Known neighbours, most recently heard first.",
        mime_type="application/json",
    )
    async def neighbors_resource() -> str:
        try:
            result = await _neighbor_list(False, cfg.max_items, "last_seen")
        except ToolError as exc:
            return json.dumps({"error": str(exc)})
        return result.model_dump_json(indent=2)

    if history is not None:

        @server.resource(
            "openhop://channels",
            name="channels",
            title="Mesh channels",
            description="Configured channel names and indices (never secrets).",
            mime_type="application/json",
        )
        async def channels_resource() -> str:
            try:
                result = await anyio.to_thread.run_sync(history.channels)
            except HistoryError as exc:
                return json.dumps({"error": str(exc)})
            return json.dumps({"count": result["count"], "channels": result["channels"]}, indent=2)

    # -- prompts -------------------------------------------------------------

    @server.prompt(
        name="mesh_health_check",
        title="Mesh health check",
        description="Overall health review of this Repeater and its radio neighbourhood.",
    )
    def mesh_health_check(hours: int = 24) -> str:
        return (
            f"Do a health check of this openHop Repeater over the last {hours} hours.\n\n"
            "1. Call openhop_stats for the overview (uptime, counters, noise floor, duty cycle).\n"
            "2. Call openhop_airtime_headroom (hours=1) and say whether transmit airtime is "
            "near the duty-cycle limit.\n"
            f"3. Call openhop_noise_anomalies (hours={hours}) and describe any interference events.\n"
            "4. Call openhop_neighbors (limit 20) and note neighbours not heard recently.\n"
            "5. Call openhop_logs with level=ERROR, then level=WARNING, and summarise recurring "
            "problems.\n"
            "6. Call openhop_hardware for CPU temperature, memory and disk.\n\n"
            "Finish with a short verdict (healthy / needs attention / unhealthy), the top three "
            "issues in priority order, and a concrete next step for each. Say plainly when data "
            "was missing rather than guessing."
        )

    @server.prompt(
        name="diagnose_neighbor",
        title="Diagnose a neighbour",
        description="Work out why a particular neighbour's link is weak or unreliable.",
    )
    def diagnose_neighbor(node: str, hours: int = 24) -> str:
        return (
            f"Diagnose the link between this Repeater and the neighbour {node!r} over the last "
            f"{hours} hours.\n\n"
            "1. Call openhop_neighbors and find the entry whose node_name or pubkey matches. "
            "Note its RSSI, SNR, zero_hop flag and last_seen.\n"
            "2. Call openhop_link_quality with no peer_hash to list links, pick the one whose "
            "peer_hash matches the start of that neighbour's pubkey, then call "
            f"openhop_link_quality again with that peer_hash and hours={hours}.\n"
            f"3. Call openhop_noise_anomalies (hours={hours}) to see whether local interference "
            "lines up with any drop-outs.\n\n"
            "Explain whether the problem looks like distance or terrain (consistently weak), "
            "interference (dips matching noise events), or the neighbour being intermittently "
            "offline (long gaps). Suggest what to check physically. If the neighbour cannot be "
            "found, say so and list the closest names."
        )

    @server.prompt(
        name="summarise_channel",
        title="Summarise channel chat",
        description="Summarise recent conversation on a mesh channel (needs an admin token).",
    )
    def summarise_channel(channel: str, days: float = 1.0) -> str:
        days = min(max(days, 0.01), MAX_HISTORY_DAYS)
        return (
            f"Summarise the conversation on the mesh channel {channel!r} over the last "
            f"{days:g} days.\n\n"
            f"Call openhop_channel_messages with channel={channel!r}, days={days:g} and a "
            "limit of 500. This needs an admin token; if it is refused, say so and stop.\n\n"
            "Group the summary by topic, name the most active senders, and call out anything "
            "that looks like a request for help, a network problem report, or a question that "
            "went unanswered. Quote sparingly. Do not invent messages."
        )

    return server


def main() -> None:
    try:
        cfg = load_config()
    except ConfigError as exc:
        print(f"[openhop-mcp] configuration error: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1) from None

    server = build_server(cfg)
    app = server.streamable_http_app(streamable_http_path="/mcp", host=cfg.host)
    gated = GateMiddleware(
        app,
        allowed_networks=cfg.allowed_networks,
        auth_tokens=cfg.auth_tokens,
        max_auth_failures=cfg.max_auth_failures,
        auth_failure_window_seconds=cfg.auth_failure_window_seconds,
        auth_lockout_seconds=cfg.auth_lockout_seconds,
    )

    roles = sorted({entry.role for entry in cfg.auth_tokens})
    print(
        f"[openhop-mcp] v{__version__} listening on {cfg.host}:{cfg.port} "
        f"allowed_ips={list(cfg.allowed_ips_raw)} read_only={cfg.read_only} "
        f"tokens={len(cfg.auth_tokens)} roles={roles} openhop={cfg.openhop_base_url} "
        f"rate_limit_per_minute={cfg.rate_limit_per_minute} "
        f"audit_log={cfg.audit_log_path if cfg.audit_log else 'off'}",
        file=sys.stderr,
        flush=True,
    )
    if cfg.token_file.exists():
        print(f"[openhop-mcp] generated token available at {cfg.token_file}", file=sys.stderr, flush=True)

    try:
        uvicorn.run(gated, host=cfg.host, port=cfg.port, log_level="info")
    except KeyboardInterrupt:
        pass
    except Exception as exc:  # pragma: no cover - startup failure path
        print(f"[openhop-mcp] fatal: {exc}", file=sys.stderr, flush=True)
        raise


if __name__ == "__main__":
    main()
