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

import uvicorn
from mcp.server.mcpserver import MCPServer

from .client import OpenHopClient, OpenHopError
from .config import Config, ConfigError, load_config
from .security import GateMiddleware, current_auth

INSTRUCTIONS = """\
This server exposes telemetry from an openHop Repeater (MeshCore mesh node).

Tools are read-only by default. They return JSON derived from the Repeater's
REST API. Prefer `openhop_stats` first for an overview; drill into neighbours,
packets, noise floor, GPS, or hardware as needed.

Mutating tools (`openhop_send_advert`, `openhop_set_mode`) only exist when the
plugin operator has explicitly disabled read-only mode. If they are absent or
return an error, read-only mode is active — do not attempt workarounds.
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
        version="0.2.0",
    )
    api = OpenHopClient(cfg.openhop_base_url, cfg.openhop_api_key, cfg.request_timeout_seconds)

    @server.tool()
    async def openhop_stats(summary: bool = True) -> dict[str, Any]:
        """Return Repeater system statistics. summary=True trims the large payload."""
        try:
            stats = await api.get("/api/stats")
        except OpenHopError as exc:
            return _error(exc)
        if not isinstance(stats, dict):
            return {"error": "unexpected response type", "type": type(stats).__name__}
        return _trim_stats(stats) if summary else stats

    @server.tool()
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
        neighbors = stats.get("neighbors") or {}
        nodes = list(neighbors.values())
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

    @server.tool()
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
        if packet_type is not None:
            packets = [p for p in packets if p.get("type") == packet_type]
        if route is not None:
            packets = [p for p in packets if p.get("route") == route]
        return {"count": len(packets), "packets": [_trim_packet(p) for p in packets[:capped]]}

    @server.tool()
    async def openhop_packet_stats(hours: int = 24) -> dict[str, Any]:
        """Return packet counters for the last N hours."""
        try:
            return await api.get("/api/packet_stats", {"hours": max(1, hours)})
        except OpenHopError as exc:
            return _error(exc)

    @server.tool()
    async def openhop_packet_type_stats(hours: int = 24) -> dict[str, Any]:
        """Return packet counts grouped by packet type for the last N hours."""
        try:
            return await api.get("/api/packet_type_stats", {"hours": max(1, hours)})
        except OpenHopError as exc:
            return _error(exc)

    @server.tool()
    async def openhop_route_stats(hours: int = 24) -> dict[str, Any]:
        """Return packet counts grouped by route type for the last N hours."""
        try:
            return await api.get("/api/route_stats", {"hours": max(1, hours)})
        except OpenHopError as exc:
            return _error(exc)

    @server.tool()
    async def openhop_noise_floor(hours: int = 24) -> dict[str, Any]:
        """Return noise floor statistics for the last N hours."""
        try:
            return await api.get("/api/noise_floor_stats", {"hours": max(1, hours)})
        except OpenHopError as exc:
            return _error(exc)

    @server.tool()
    async def openhop_gps() -> dict[str, Any]:
        """Return GPS diagnostics and parsed NMEA attributes."""
        try:
            return await api.get("/api/gps")
        except OpenHopError as exc:
            return _error(exc)

    @server.tool()
    async def openhop_hardware() -> dict[str, Any]:
        """Return host hardware statistics (CPU, RAM, disk, temperatures)."""
        try:
            return await api.get("/api/hardware_stats")
        except OpenHopError as exc:
            return _error(exc)

    @server.tool()
    async def openhop_whoami() -> dict[str, Any]:
        """Return the identity and role granted to the calling token."""
        return dict(current_auth.get())

    @server.tool()
    async def openhop_api_read(path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """GET an allowlisted read-only Repeater endpoint, e.g. '/api/gps'.

        Rejects non-/api/ paths, streaming endpoints, and anything that looks
        mutating. Only GET is performed; there is no write equivalent here.
        """
        lowered = path.lower()
        blocked = (
            "stream",
            "restart",
            "install",
            "uninstall",
            "delete",
            "set_",
            "send_",
            "update_",
            "backup",
            "import",
        )
        if not lowered.startswith("/api/") or "://" in lowered:
            return {"error": "path must start with /api/ and be relative"}
        if any(token in lowered for token in blocked):
            return {"error": f"path rejected by read-only policy: {path}"}
        try:
            return await api.get(path, params)
        except OpenHopError as exc:
            return _error(exc)

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

    if not cfg.read_only:
        @server.tool()
        async def openhop_send_advert() -> dict[str, Any]:
            """Send an advert from the Repeater. Requires read_only=false and an admin token."""
            denied = _require_admin("openhop_send_advert")
            if denied:
                return denied
            try:
                return await api.post("/api/send_advert", {})
            except OpenHopError as exc:
                return _error(exc)

        @server.tool()
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
