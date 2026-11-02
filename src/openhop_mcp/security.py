"""Network gate for the openHop MCP plugin.

Two independent controls, both fail-closed:

1. **IP allowlist** — the TCP peer address must fall inside a configured CIDR.
2. **Bearer token** — every request must carry a matching token.

This is a raw ASGI middleware (not Starlette's ``BaseHTTPMiddleware``) so that
streaming responses and Server-Sent Events pass through without buffering.

Only ``GET /healthz`` is exempt, and only from an allowed address. It reveals
nothing beyond liveness.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import sys
from typing import Awaitable, Callable

Scope = dict
Receive = Callable[[], Awaitable[dict]]
Send = Callable[[dict], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

HEALTH_PATH = "/healthz"
AUTH_HEADER = b"authorization"
ALT_AUTH_HEADER = b"x-auth-token"


def _normalise_ip(raw: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Return a parsed address, collapsing IPv4-mapped IPv6 to IPv4."""
    candidate = raw.split("%", 1)[0].strip()
    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


async def _send_json(send: Send, status: int, payload: dict, extra_headers: list[tuple[bytes, bytes]] | None = None) -> None:
    body = json.dumps(payload).encode("utf-8")
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode("ascii")),
        (b"cache-control", b"no-store"),
    ]
    if extra_headers:
        headers.extend(extra_headers)
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body, "more_body": False})


def _extract_bearer(scope: Scope) -> str:
    headers = scope.get("headers") or []
    found: dict[bytes, bytes] = {}
    for key, value in headers:
        lowered = key.lower()
        if lowered in (AUTH_HEADER, ALT_AUTH_HEADER):
            found[lowered] = value
    raw = found.get(AUTH_HEADER, b"").decode("latin-1").strip()
    if raw:
        parts = raw.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1].strip()
        return ""
    return found.get(ALT_AUTH_HEADER, b"").decode("latin-1").strip()


class GateMiddleware:
    """Enforce the IP allowlist and bearer token before the MCP app runs."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        allowed_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...],
        auth_token: str,
        health_path: str = HEALTH_PATH,
    ) -> None:
        if not allowed_networks:
            raise ValueError("allowed_networks must not be empty")
        if not auth_token:
            raise ValueError("auth_token must not be empty")
        self.app = app
        self.allowed_networks = allowed_networks
        self.auth_token = auth_token
        self.health_path = health_path

    def _ip_allowed(self, addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return any(addr in network for network in self.allowed_networks)

    def _token_ok(self, provided: str) -> bool:
        return hmac.compare_digest(provided.encode("utf-8"), self.auth_token.encode("utf-8"))

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        client = scope.get("client") or ("", 0)
        raw_ip = str(client[0]) if client and client[0] else ""
        addr = _normalise_ip(raw_ip)
        path = scope.get("path", "")

        if addr is None or not self._ip_allowed(addr):
            print(f"[gate] denied ip={raw_ip or 'unknown'} path={path}", file=sys.stderr, flush=True)
            await _send_json(send, 403, {"error": "forbidden", "reason": "source address not allowed"})
            return

        if path == self.health_path:
            await _send_json(send, 200, {"status": "ok", "service": "openhop-mcp"})
            return

        provided = _extract_bearer(scope)
        if not provided or not self._token_ok(provided):
            print(f"[gate] denied auth ip={raw_ip} path={path}", file=sys.stderr, flush=True)
            await _send_json(
                send,
                401,
                {"error": "unauthorized", "reason": "missing or invalid bearer token"},
                extra_headers=[(b"WWW-Authenticate", b'Bearer realm="openhop-mcp"')],
            )
            return

        await self.app(scope, receive, send)
