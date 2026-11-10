"""MCP server entrypoint for the openHop Repeater plugin.

Exposes read-only mesh telemetry as MCP tools over Streamable HTTP. Every
request passes through :class:`openhop_mcp.security.GateMiddleware` first, so
the MCP endpoint itself is never reachable without both an allowed source
address and the bearer token.

Writes are disabled by default (``read_only: true``). Set it to false in the
plugin settings only if you deliberately want the mutating tools exposed.
"""

from __future__ import annotations

import sys
from typing import Any

import anyio
import uvicorn
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from . import __version__
from .api_policy import PolicyError, clean_params, normalise_path
from .client import OpenHopClient, OpenHopError
from .config import Config, ConfigError, load_config
from .history import HistoryError, RepeaterHistory
from .security import GateMiddleware, current_auth

INSTRUCTIONS = """\
This server exposes telemetry from an openHop Repeater (MeshCore mesh node).

Tools are read-only by default. They return JSON derived from the Repeater's
REST API. Prefer `openhop_stats` first for an overview; drill into neighbours,
packets, noise floor, GPS, hardware, logs, processes, MQTT, web frontends,
setup metadata, or room messages as needed.

Channel conversation history is NOT in the REST API. It is read directly from
the Repeater's SQLite database and decrypted with channel keys. Both history
tools need the `allow_message_history` setting. `openhop_channels` (names
only) works with any token; `openhop_channel_messages` (message content)
requires the admin role.

`openhop_api_read` only reaches an allowlist of telemetry endpoints. Plugin
settings, config backups, identity keys, transport keys and other credential
material are never reachable through it.

Mutating tools (`openhop_send_advert`, `openhop_set_mode`,
`openhop_set_duty_cycle`, `openhop_update_duty_cycle_config`,
`openhop_update_advert_rate_limit`) only exist when the plugin operator has
explicitly disabled read-only mode. If they are absent or return an error,
read-only mode is active — do not attempt workarounds.
"""


def _trim_stats(stats: dict[str, Any]) -> dict[str, Any]:
    """Return a compact overview rather than the full ~90 KB stats payload."""
    neighbors = stats.get("neighbors") or {}
    recent = stats.get("recent_packets") or []
    gps = stats.get("gps") or {}
    return {
        "local_hash": stats.get("local_hash"),
        "version": stats.get("version"),
        "core_version": stats.get("core_version"),
        "uptime_seconds": stats.get("uptime_seconds"),
        "rx_count": stats.get("rx_count"),
        "forwarded_count": stats.get("forwarded_count"),
        "dropped_count": stats.get("dropped_count"),
        "rx_per_hour": stats.get("rx_per_hour"),
        "noise_floor_dbm": stats.get("noise_floor_dbm"),
        "utilization_percent": stats.get("utilization_percent"),
        "crc_error_count": stats.get("crc_error_count"),
        "radio_status": stats.get("radio_status"),
        "radio_type": stats.get("radio_type"),
        "neighbor_count": len(neighbors),
        "recent_packet_count": len(recent),
        "gps": {
            "fix": gps.get("fix") or gps.get("has_fix"),
            "latitude": gps.get("latitude"),
            "longitude": gps.get("longitude"),
            "satellites": gps.get("satellites"),
        },
    }


def _trim_neighbor(node: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "node_name",
        "contact_type",
        "is_repeater",
        "route_type",
        "zero_hop",
        "rssi",
        "snr",
        "advert_count",
        "last_seen",
        "first_seen",
        "latitude",
        "longitude",
    )
    return {key: node.get(key) for key in keys if key in node}


def _trim_packet(packet: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "timestamp",
        "type",
        "route",
        "rssi",
        "snr",
        "is_duplicate",
        "drop_reason",
        "packet_hash",
        "payload_length",
        "original_path",
        "forwarded_path",
        "transmitted",
        "airtime_ms",
    )
    return {key: packet.get(key) for key in keys if key in packet}


def _error(exc: OpenHopError) -> dict[str, Any]:
    result: dict[str, Any] = {"error": str(exc)}
    if exc.status is not None:
        result["status"] = exc.status
    return result


def build_server(cfg: Config) -> MCPServer:
    server = MCPServer(
        "openhop-mcp",
        title="openHop Repeater MCP",
        description="Authenticated telemetry access for an openHop Repeater.",
        instructions=INSTRUCTIONS,
        version=__version__,
    )
    api = OpenHopClient(cfg.openhop_base_url, cfg.openhop_api_key, cfg.request_timeout_seconds)
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

    def _require_admin(operation: str) -> dict[str, Any] | None:
        auth = current_auth.get()
        if auth.get("role") != "admin":
            return {
                "error": "forbidden",
                "reason": f"{operation} requires an admin-role token",
                "role": auth.get("role"),
                "name": auth.get("name"),
            }
        return None

    @server.tool(annotations=read_tool)
    async def openhop_stats(summary: bool = True) -> dict[str, Any]:
        """Return Repeater system statistics. summary=True trims the large payload."""
        try:
            stats = await api.get("/api/stats")
        except OpenHopError as exc:
            return _error(exc)
        if not isinstance(stats, dict):
            return {"error": "unexpected response type", "type": type(stats).__name__}
        return _trim_stats(stats) if summary else stats

    @server.tool(annotations=read_tool)
    async def openhop_neighbors(
        zero_hop_only: bool = False,
        limit: int = 50,
        sort_by: str = "last_seen",
    ) -> dict[str, Any]:
        """List known neighbour nodes. sort_by is 'last_seen' or 'rssi'."""
        try:
            stats = await api.get("/api/stats")
        except OpenHopError as exc:
            return _error(exc)
        if not isinstance(stats, dict):
            return {"error": "unexpected response type", "type": type(stats).__name__}
        neighbors = stats.get("neighbors") or {}
        if isinstance(neighbors, dict):
            nodes = [n for n in neighbors.values() if isinstance(n, dict)]
        elif isinstance(neighbors, list):
            nodes = [n for n in neighbors if isinstance(n, dict)]
        else:
            nodes = []
        if zero_hop_only:
            nodes = [n for n in nodes if n.get("zero_hop")]
        reverse = True
        if sort_by == "rssi":
            nodes.sort(key=lambda n: n.get("rssi") or -999, reverse=reverse)
        else:
            nodes.sort(key=lambda n: n.get("last_seen") or 0, reverse=reverse)
        capped = max(1, min(limit, cfg.max_items))
        return {
            "count": len(nodes),
            "returned": min(len(nodes), capped),
            "neighbors": [_trim_neighbor(n) for n in nodes[:capped]],
        }

    @server.tool(annotations=read_tool)
    async def openhop_recent_packets(
        limit: int = 20,
        packet_type: int | None = None,
        route: int | None = None,
    ) -> dict[str, Any]:
        """Return recent packets, optionally filtered by numeric type or route."""
        capped = max(1, min(limit, cfg.max_items))
        try:
            data = await api.get("/api/recent_packets", {"limit": capped})
        except OpenHopError as exc:
            return _error(exc)
        packets = data.get("packets", data.get("recent_packets", [])) if isinstance(data, dict) else []
        if not isinstance(packets, list):
            packets = []
        packets = [p for p in packets if isinstance(p, dict)]
        if packet_type is not None:
            packets = [p for p in packets if p.get("type") == packet_type]
        if route is not None:
            packets = [p for p in packets if p.get("route") == route]
        if packets:
            return {
                "count": len(packets),
                "packets": [_trim_packet(p) for p in packets[:capped]],
                "source": "api",
            }
        # The Repeater's in-memory buffer can be momentarily empty. Fall back to
        # the packets table so callers get real data instead of a bare zero.
        if history is not None:
            try:
                return await anyio.to_thread.run_sync(
                    lambda: history.recent_packets(
                        limit=capped, packet_type=packet_type, route=route
                    )
                )
            except HistoryError as exc:
                return {"count": 0, "packets": [], "source": "api", "fallback_error": str(exc)}
        return {"count": 0, "packets": [], "source": "api"}

    @server.tool(annotations=read_tool)
    async def openhop_packet_stats(hours: int = 24) -> dict[str, Any]:
        """Return packet counters for the last N hours."""
        try:
            return await api.get("/api/packet_stats", {"hours": max(1, hours)})
        except OpenHopError as exc:
            return _error(exc)

    @server.tool(annotations=read_tool)
    async def openhop_packet_type_stats(hours: int = 24) -> dict[str, Any]:
        """Return packet counts grouped by packet type for the last N hours."""
        try:
            return await api.get("/api/packet_type_stats", {"hours": max(1, hours)})
        except OpenHopError as exc:
            return _error(exc)

    @server.tool(annotations=read_tool)
    async def openhop_route_stats(hours: int = 24) -> dict[str, Any]:
        """Return packet counts grouped by route type for the last N hours."""
        try:
            return await api.get("/api/route_stats", {"hours": max(1, hours)})
        except OpenHopError as exc:
            return _error(exc)

    @server.tool(annotations=read_tool)
    async def openhop_noise_floor(hours: int = 24) -> dict[str, Any]:
        """Return noise floor statistics for the last N hours."""
        try:
            return await api.get("/api/noise_floor_stats", {"hours": max(1, hours)})
        except OpenHopError as exc:
            return _error(exc)

    @server.tool(annotations=read_tool)
    async def openhop_gps() -> dict[str, Any]:
        """Return GPS diagnostics and parsed NMEA attributes."""
        try:
            return await api.get("/api/gps")
        except OpenHopError as exc:
            return _error(exc)

    @server.tool(annotations=read_tool)
    async def openhop_hardware() -> dict[str, Any]:
        """Return host hardware statistics (CPU, RAM, disk, temperatures)."""
        try:
            return await api.get("/api/hardware_stats")
        except OpenHopError as exc:
            return _error(exc)

    @server.tool(annotations=read_tool)
    async def openhop_logs(
        limit: int = 50,
        level: str | None = None,
        since_id: int | None = None,
    ) -> dict[str, Any]:
        """Return Repeater application logs. Newest last. Filter by level or id."""
        try:
            data = await api.get("/api/logs")
        except OpenHopError as exc:
            return _error(exc)
        entries = data.get("logs", []) if isinstance(data, dict) else []
        if since_id is not None:
            entries = [e for e in entries if (e.get("id") or 0) > since_id]
        if level:
            wanted = level.strip().upper()
            entries = [e for e in entries if str(e.get("level", "")).upper() == wanted]
        capped = max(1, min(limit, cfg.max_items))
        trimmed = [
            {
                "id": e.get("id"),
                "timestamp": e.get("timestamp"),
                "level": e.get("level"),
                "logger": e.get("logger"),
                "message": e.get("message"),
            }
            for e in entries[-capped:]
        ]
        return {"count": len(entries), "returned": len(trimmed), "logs": trimmed}

    @server.tool(annotations=read_tool)
    async def openhop_processes(limit: int = 20, sort_by: str = "cpu") -> dict[str, Any]:
        """Return host process resource usage. sort_by is 'cpu' or 'memory'."""
        try:
            data = await api.get("/api/hardware_processes")
        except OpenHopError as exc:
            return _error(exc)
        payload = data.get("data", {}) if isinstance(data, dict) else {}
        procs = payload.get("processes", []) if isinstance(payload, dict) else []
        key = "memory_mb" if sort_by == "memory" else "cpu_percent"
        procs = sorted(procs, key=lambda p: p.get(key) or 0, reverse=True)
        capped = max(1, min(limit, cfg.max_items))
        trimmed = [
            {
                "pid": p.get("pid"),
                "name": p.get("name"),
                "cpu_percent": p.get("cpu_percent"),
                "memory_percent": p.get("memory_percent"),
                "memory_mb": p.get("memory_mb"),
            }
            for p in procs[:capped]
        ]
        return {"count": len(procs), "returned": len(trimmed), "processes": trimmed}

    @server.tool(annotations=read_tool)
    async def openhop_mqtt_status() -> dict[str, Any]:
        """Return MQTT bridge status and per-broker connection state."""
        try:
            data = await api.get("/api/mqtt_status")
        except OpenHopError as exc:
            return _error(exc)
        payload = data.get("data", {}) if isinstance(data, dict) else {}
        brokers = payload.get("brokers", []) if isinstance(payload, dict) else []
        trimmed = [
            {
                "name": b.get("name"),
                "host": b.get("host"),
                "enabled": b.get("enabled"),
                "connected": (b.get("status") or {}).get("connected"),
                "reconnecting": (b.get("status") or {}).get("reconnecting"),
                "format": b.get("format"),
                "neighbors": b.get("neighbors"),
            }
            for b in brokers
        ]
        return {
            "handler_active": payload.get("handler_active"),
            "broker_count": len(brokers),
            "brokers": trimmed,
        }

    @server.tool(annotations=read_tool)
    async def openhop_web_frontends() -> dict[str, Any]:
        """Return configured web frontends and which one is selected."""
        try:
            data = await api.get("/api/web_frontends")
        except OpenHopError as exc:
            return _error(exc)
        payload = data.get("data", {}) if isinstance(data, dict) else {}
        frontends = payload.get("frontends", []) if isinstance(payload, dict) else []
        trimmed = [
            {
                "id": f.get("id"),
                "kind": f.get("kind"),
                "name": f.get("name"),
                "version": f.get("version"),
                "available": f.get("available"),
                "enabled": f.get("enabled"),
                "selected": f.get("selected"),
            }
            for f in frontends
        ]
        return {
            "count": len(frontends),
            "selected": payload.get("selected"),
            "frontends": trimmed,
        }

    @server.tool(annotations=read_tool)
    async def openhop_setup_info() -> dict[str, Any]:
        """Return setup/hardware metadata: radio presets, serial ports, site info, hardware options."""
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
                out[key] = _error(exc)
        return out

    @server.tool(annotations=read_tool)
    async def openhop_room_messages(
        room_name: str | None = None,
        room_hash: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Return room-server messages. Requires room_name or room_hash.

        Room servers only; channel chat lives in openhop_channel_messages.
        """
        if not room_name and not room_hash:
            return {"error": "provide room_name or room_hash"}
        params: dict[str, Any] = {"limit": max(1, min(limit, cfg.max_items))}
        if room_name:
            params["room_name"] = room_name
        if room_hash:
            params["room_hash"] = room_hash
        try:
            return await api.get("/api/room_messages", params)
        except OpenHopError as exc:
            return _error(exc)

    @server.tool(annotations=read_tool)
    async def openhop_channels() -> dict[str, Any]:
        """List configured mesh channels (names and indices only — never secrets)."""
        if history is None:
            return {
                "error": "message history disabled",
                "hint": "set allow_message_history=true and repeater_db_path in plugin config",
            }
        try:
            return await anyio.to_thread.run_sync(history.channels)
        except HistoryError as exc:
            return {"error": str(exc)}

    @server.tool(annotations=read_tool)
    async def openhop_channel_messages(
        channel: str | None = None,
        days: float = 7.0,
        limit: int = 100,
        grep: str | None = None,
        include_bogus_timestamps: bool = False,
    ) -> dict[str, Any]:
        """Decrypt and return channel message history from the Repeater database.

        Admin token required — message content is more sensitive than telemetry.
        Omit `channel` to search every configured channel. `days` is a rolling
        window ending now, capped at 90. `grep` is a case-insensitive substring
        filter.
        """
        denied = _require_admin("openhop_channel_messages")
        if denied:
            return denied
        if history is None:
            return {
                "error": "message history disabled",
                "hint": "set allow_message_history=true and repeater_db_path in plugin config",
            }
        try:
            return await anyio.to_thread.run_sync(
                lambda: history.messages(
                    channel,
                    days=days,
                    limit=limit,
                    grep=grep,
                    include_bogus_timestamps=include_bogus_timestamps,
                )
            )
        except HistoryError as exc:
            return {"error": str(exc)}

    @server.tool(annotations=read_tool)
    async def openhop_whoami() -> dict[str, Any]:
        """Return the identity and role granted to the calling token."""
        return dict(current_auth.get())

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
            return {"error": "path rejected by read-only policy", "reason": str(exc)}
        try:
            return await api.get(safe_path, safe_params)
        except OpenHopError as exc:
            return _error(exc)

    @server.tool(annotations=read_tool)
    async def openhop_validate_config() -> dict[str, Any]:
        """Validate the Repeater's current configuration. Admin token required."""
        denied = _require_admin("openhop_validate_config")
        if denied:
            return denied
        try:
            # GET only — POST returns 405 on this route.
            return await api.get("/api/validate_config")
        except OpenHopError as exc:
            return _error(exc)

    if not cfg.read_only:
        @server.tool(annotations=radio_tool)
        async def openhop_send_advert() -> dict[str, Any]:
            """Send an advert from the Repeater. Requires read_only=false and an admin token."""
            denied = _require_admin("openhop_send_advert")
            if denied:
                return denied
            try:
                return await api.post("/api/send_advert", {})
            except OpenHopError as exc:
                return _error(exc)

        @server.tool(annotations=write_tool)
        async def openhop_set_mode(mode: str) -> dict[str, Any]:
            """Set Repeater mode. Requires read_only=false and an admin token."""
            denied = _require_admin("openhop_set_mode")
            if denied:
                return denied
            if mode not in ("forward", "monitor", "no_tx"):
                return {"error": "mode must be one of: forward, monitor, no_tx"}
            try:
                return await api.post("/api/set_mode", {"mode": mode})
            except OpenHopError as exc:
                return _error(exc)

        @server.tool(annotations=write_tool)
        async def openhop_set_duty_cycle(enabled: bool = True) -> dict[str, Any]:
            """Enable or disable duty-cycle enforcement. Admin token required."""
            denied = _require_admin("openhop_set_duty_cycle")
            if denied:
                return denied
            try:
                return await api.post("/api/set_duty_cycle", {"enabled": bool(enabled)})
            except OpenHopError as exc:
                return _error(exc)

        @server.tool(annotations=write_tool)
        async def openhop_update_duty_cycle_config(
            max_airtime_percent: float | None = None,
            enforcement_enabled: bool | None = None,
        ) -> dict[str, Any]:
            """Update duty-cycle settings. Admin token required.

            max_airtime_percent is 0.1-100.0. At least one field must be given.
            """
            denied = _require_admin("openhop_update_duty_cycle_config")
            if denied:
                return denied
            body: dict[str, Any] = {}
            if max_airtime_percent is not None:
                body["max_airtime_percent"] = float(max_airtime_percent)
            if enforcement_enabled is not None:
                body["enforcement_enabled"] = bool(enforcement_enabled)
            if not body:
                return {"error": "provide max_airtime_percent and/or enforcement_enabled"}
            try:
                return await api.post("/api/update_duty_cycle_config", body)
            except OpenHopError as exc:
                return _error(exc)

        _ADVERT_RATE_KEYS = {
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

            Accepts a settings object; unknown keys are rejected. See the Repeater
            docs for the accepted fields (rate_limit_enabled, bucket_capacity,
            refill_tokens, refill_interval_seconds, min_interval_seconds,
            penalty_enabled, violation_threshold, violation_decay_seconds,
            base_penalty_seconds, penalty_multiplier).
            """
            denied = _require_admin("openhop_update_advert_rate_limit")
            if denied:
                return denied
            if not isinstance(settings, dict) or not settings:
                return {"error": "settings must be a non-empty object"}
            unknown = sorted(set(settings) - _ADVERT_RATE_KEYS)
            if unknown:
                return {"error": f"unknown setting(s): {', '.join(unknown)}"}
            try:
                return await api.post("/api/update_advert_rate_limit_config", settings)
            except OpenHopError as exc:
                return _error(exc)

        @server.tool(annotations=radio_tool)
        async def openhop_publish_neighbors() -> dict[str, Any]:
            """Publish the current neighbour table. Admin token required."""
            denied = _require_admin("openhop_publish_neighbors")
            if denied:
                return denied
            try:
                return await api.post("/api/publish_neighbors", {})
            except OpenHopError as exc:
                return _error(exc)

        @server.tool(annotations=radio_tool)
        async def openhop_query_neighbor_scopes(pubkey: str) -> dict[str, Any]:
            """Ask one zero-hop neighbour for its region scopes. Admin token required.

            `pubkey` must be a full 64-character public key.
            """
            denied = _require_admin("openhop_query_neighbor_scopes")
            if denied:
                return denied
            key = (pubkey or "").strip()
            if len(key) != 64:
                return {"error": "pubkey must be a full 64-character public key"}
            try:
                return await api.post("/api/query_neighbor_scopes", {"pubkey": key})
            except OpenHopError as exc:
                return _error(exc)

    return server


def main() -> None:
    try:
        cfg = load_config()
    except ConfigError as exc:
        print(f"[openhop-mcp] configuration error: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1)

    server = build_server(cfg)
    app = server.streamable_http_app(streamable_http_path="/mcp", host=cfg.host)
    app = GateMiddleware(
        app,
        allowed_networks=cfg.allowed_networks,
        auth_tokens=cfg.auth_tokens,
        max_auth_failures=cfg.max_auth_failures,
        auth_failure_window_seconds=cfg.auth_failure_window_seconds,
        auth_lockout_seconds=cfg.auth_lockout_seconds,
    )

    roles = sorted({entry.role for entry in cfg.auth_tokens})
    print(
        f"[openhop-mcp] listening on {cfg.host}:{cfg.port} "
        f"allowed_ips={list(cfg.allowed_ips_raw)} read_only={cfg.read_only} "
        f"tokens={len(cfg.auth_tokens)} roles={roles} openhop={cfg.openhop_base_url}",
        file=sys.stderr,
        flush=True,
    )
    if cfg.token_file.exists():
        print(f"[openhop-mcp] generated token available at {cfg.token_file}", file=sys.stderr, flush=True)

    try:
        uvicorn.run(app, host=cfg.host, port=cfg.port, log_level="info")
    except KeyboardInterrupt:
        pass
    except Exception as exc:  # pragma: no cover - startup failure path
        print(f"[openhop-mcp] fatal: {exc}", file=sys.stderr, flush=True)
        raise


if __name__ == "__main__":
    main()
