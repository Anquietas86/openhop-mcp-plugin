"""Network gate and token-role resolution for the openHop MCP plugin.

Two independent controls, both fail-closed:

1. **IP allowlist** — the TCP peer address must fall inside a configured CIDR.
2. **Bearer token** — every request must carry a configured token.

Tokens carry a role (``read`` or ``admin``). The role is resolved here and
exposed to tool handlers through a context variable, so read-only credentials
cannot reach mutating tools even when the plugin runs with ``read_only``
disabled.

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
import threading
import time
from collections import deque
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Sequence

Scope = dict
Receive = Callable[[], Awaitable[dict]]
Send = Callable[[dict], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

HEALTH_PATH = "/healthz"
AUTH_HEADER = b"authorization"
ALT_AUTH_HEADER = b"x-auth-token"

ROLES = frozenset({"read", "admin"})


@dataclass(frozen=True)
class TokenEntry:
    """A configured bearer token and the role it grants."""

    name: str
    role: str
    token: str = field(repr=False)


#: Resolved identity for the current MCP request. Tool handlers read this to
#: decide whether a mutating operation is permitted.
current_auth: ContextVar[dict[str, str]] = ContextVar(
    "openhop_auth", default={"name": "anonymous", "role": "read"}
)


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


async def _send_json(
    send: Send,
    status: int,
    payload: dict,
    extra_headers: list[tuple[bytes, bytes]] | None = None,
) -> None:
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
        auth_tokens: Sequence[TokenEntry],
        health_path: str = HEALTH_PATH,
        max_auth_failures: int = 10,
        auth_failure_window_seconds: float = 300.0,
        auth_lockout_seconds: float = 900.0,
    ) -> None:
        if not allowed_networks:
            raise ValueError("allowed_networks must not be empty")
        if not auth_tokens:
            raise ValueError("auth_tokens must not be empty")
        for entry in auth_tokens:
            if not entry.token:
                raise ValueError(f"token {entry.name!r} is empty")
            if entry.role not in ROLES:
                raise ValueError(f"token {entry.name!r} has invalid role {entry.role!r}")
        if max_auth_failures < 1:
            raise ValueError("max_auth_failures must be at least 1")
        if auth_failure_window_seconds <= 0:
            raise ValueError("auth_failure_window_seconds must be positive")
        if auth_lockout_seconds <= 0:
            raise ValueError("auth_lockout_seconds must be positive")
        self.app = app
        self.allowed_networks = allowed_networks
        self.auth_tokens = tuple(auth_tokens)
        self.health_path = health_path
        self.max_auth_failures = max_auth_failures
        self.auth_failure_window_seconds = auth_failure_window_seconds
        self.auth_lockout_seconds = auth_lockout_seconds
        self._failures: dict[str, deque[float]] = {}
        self._lockouts: dict[str, float] = {}
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> deque[float]:
        """Return the recent-failure deque for ``key``, dropping stale entries."""
        bucket = self._failures.get(key)
        if bucket is None:
            bucket = deque()
            self._failures[key] = bucket
        cutoff = now - self.auth_failure_window_seconds
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        return bucket

    def _record_failure(self, key: str) -> None:
        """Record one failed authentication and lock the key out if needed."""
        now = time.monotonic()
        with self._lock:
            bucket = self._prune(key, now)
            bucket.append(now)
            if len(bucket) >= self.max_auth_failures:
                self._lockouts[key] = now + self.auth_lockout_seconds
                bucket.clear()

    def _lockout_remaining(self, key: str) -> float:
        """Seconds left on an active lockout, or 0 when the key may proceed."""
        now = time.monotonic()
        with self._lock:
            until = self._lockouts.get(key)
            if until is None:
                return 0.0
            remaining = until - now
            if remaining <= 0:
                self._lockouts.pop(key, None)
                self._failures.pop(key, None)
                return 0.0
            return remaining

    def _clear_failures(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)
            self._lockouts.pop(key, None)

    def _ip_allowed(self, addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return any(addr in network for network in self.allowed_networks)

    def _authenticate(self, provided: str) -> TokenEntry | None:
        """Return the matching token entry.

        Every configured token is compared so the response time does not reveal
        which entry matched. ``compare_digest`` keeps each comparison constant
        time for equal-length inputs.
        """
        if not provided:
            return None
        provided_bytes = provided.encode("utf-8")
        match: TokenEntry | None = None
        for entry in self.auth_tokens:
            if hmac.compare_digest(provided_bytes, entry.token.encode("utf-8")):
                match = entry
        return match

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

        key = str(addr)
        remaining = self._lockout_remaining(key)
        if remaining > 0:
            retry_after = max(1, int(remaining + 0.999))
            print(
                f"[gate] locked out ip={raw_ip} path={path} retry_after={retry_after}s",
                file=sys.stderr,
                flush=True,
            )
            await _send_json(
                send,
                429,
                {
                    "error": "too_many_requests",
                    "reason": "too many failed authentication attempts",
                    "retry_after_seconds": retry_after,
                },
                extra_headers=[(b"Retry-After", str(retry_after).encode("ascii"))],
            )
            return

        provided = _extract_bearer(scope)
        entry = self._authenticate(provided)
        if entry is None:
            self._record_failure(key)
            print(f"[gate] denied auth ip={raw_ip} path={path}", file=sys.stderr, flush=True)
            await _send_json(
                send,
                401,
                {"error": "unauthorized", "reason": "missing or invalid bearer token"},
                extra_headers=[(b"WWW-Authenticate", b'Bearer realm="openhop-mcp"')],
            )
            return

        self._clear_failures(key)
        token_ctx = current_auth.set({"name": entry.name, "role": entry.role})
        try:
            await self.app(scope, receive, send)
        finally:
            current_auth.reset(token_ctx)
