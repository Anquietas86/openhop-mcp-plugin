"""Path policy for the generic ``openhop_api_read`` tool.

The Repeater's REST API mixes harmless telemetry with endpoints that return
credentials (plugin settings, config backups with secrets, the node's private
identity key, transport keys) and a few GET handlers that change state. A
substring denylist cannot keep up with that, and CherryPy decodes
percent-escapes before routing, so ``/api/transport%5Fkeys`` would slip past
one anyway.

This module uses an explicit allowlist of read-only telemetry endpoints
instead. The requested path must match an entry exactly after normalisation,
and anything with percent-escapes, dot segments, or doubled slashes is
rejected outright rather than decoded.
"""

from __future__ import annotations

from typing import Any

#: Telemetry endpoints that are safe for any authenticated token. Each was
#: checked against the upstream Repeater handlers: no credentials in the
#: response and no state change on GET. Streaming (SSE) endpoints are excluded
#: because the client does not support them.
ALLOWED_API_PATHS: frozenset[str] = frozenset(
    {
        "/api/stats",
        "/api/gps",
        "/api/logs",
        "/api/hardware_stats",
        "/api/hardware_processes",
        "/api/packet_stats",
        "/api/recent_packets",
        "/api/packet_by_hash",
        "/api/packet_by_id",
        "/api/packet_type_stats",
        "/api/route_stats",
        "/api/filtered_packets",
        "/api/bulk_packets",
        "/api/neighbor_links",
        "/api/neighbor_link_history",
        "/api/neighbor_scopes",
        "/api/rrd_data",
        "/api/packet_type_graph_data",
        "/api/metrics_graph_data",
        "/api/lbt_diagnostics",
        "/api/noise_floor_history",
        "/api/noise_floor_stats",
        "/api/noise_floor_chart_data",
        "/api/adverts_by_contact_type",
        "/api/adverts_count_by_contact_type",
        "/api/advert_rate_limit_stats",
        "/api/crc_error_count",
        "/api/crc_error_history",
        "/api/airtime_data",
        "/api/airtime_chart_data",
        "/api/room_messages",
        "/api/room_stats",
        "/api/site_info",
        "/api/hardware_options",
        "/api/radio_presets",
        "/api/serial_ports",
        "/api/web_frontends",
        "/api/mqtt_status",
        "/api/db_stats",
    }
)

#: Upper bound on query parameters so a caller cannot smuggle large payloads.
MAX_PARAMS = 16
MAX_PARAM_VALUE_LENGTH = 256


class PolicyError(ValueError):
    """Raised when a path or parameter set is not permitted."""


def normalise_path(path: str) -> str:
    """Return the canonical allowlist key for ``path`` or raise PolicyError."""
    if not isinstance(path, str) or not path:
        raise PolicyError("path must be a non-empty string")
    candidate = path.strip()
    if any(ch in candidate for ch in ("%", "?", "#", "\\", "\x00")):
        raise PolicyError("path must not contain escapes, a query string, or a fragment")
    if "://" in candidate or "//" in candidate:
        raise PolicyError("path must be a relative /api/ path")
    if not candidate.startswith("/"):
        candidate = "/" + candidate
    segments = candidate.split("/")
    if any(seg in (".", "..") for seg in segments):
        raise PolicyError("path must not contain dot segments")
    candidate = candidate.rstrip("/").lower()
    if candidate not in ALLOWED_API_PATHS:
        raise PolicyError(f"path not in the read-only allowlist: {path}")
    return candidate


def clean_params(params: Any) -> dict[str, str | int | float | bool] | None:
    """Validate query parameters: flat scalars only, bounded in count and size."""
    if params is None:
        return None
    if not isinstance(params, dict):
        raise PolicyError("params must be an object")
    if len(params) > MAX_PARAMS:
        raise PolicyError(f"too many params (max {MAX_PARAMS})")
    cleaned: dict[str, str | int | float | bool] = {}
    for key, value in params.items():
        if not isinstance(key, str) or not key or len(key) > 64:
            raise PolicyError("param names must be short strings")
        if not isinstance(value, (str, int, float, bool)):
            raise PolicyError(f"param {key!r} must be a string, number, or boolean")
        if isinstance(value, str) and len(value) > MAX_PARAM_VALUE_LENGTH:
            raise PolicyError(f"param {key!r} is too long")
        cleaned[key] = value
    return cleaned
