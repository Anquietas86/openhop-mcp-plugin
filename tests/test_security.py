"""Unit tests for the ASGI gate and token-role resolution. No network required."""

from __future__ import annotations

import asyncio
import ipaddress
import time

import pytest

from openhop_mcp.security import (
    GateMiddleware,
    TokenEntry,
    _extract_bearer,
    _normalise_ip,
    current_auth,
)

ADMIN = TokenEntry(name="admin", role="admin", token="admin-token-abcdefghijklmnop")
READER = TokenEntry(name="reader", role="read", token="read-token-abcdefghijklmnop")


def _scope(path: str = "/mcp", client: str = "127.0.0.1", headers=None) -> dict:
    return {
        "type": "http",
        "path": path,
        "client": (client, 12345),
        "headers": headers or [],
    }


class _Recorder:
    """Minimal ASGI send that records the response and observed role."""

    def __init__(self) -> None:
        self.status: int | None = None
        self.headers: list[tuple[bytes, bytes]] = []
        self.body = b""
        self.role_seen: str | None = None

    async def __call__(self, message: dict) -> None:
        if message["type"] == "http.response.start":
            self.status = message["status"]
            self.headers = message.get("headers", [])
        elif message["type"] == "http.response.body":
            self.body += message.get("body", b"")

    def header(self, name: str) -> str:
        for key, value in self.headers:
            if key.decode().lower() == name.lower():
                return value.decode()
        return ""


async def _call(middleware: GateMiddleware, scope: dict) -> _Recorder:
    rec = _Recorder()

    async def app(s, r, send):
        rec.role_seen = current_auth.get().get("role")
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware.app = app  # type: ignore[assignment]
    await middleware(scope, lambda: None, rec)
    return rec


def _gate(tokens=(ADMIN,), **kwargs) -> GateMiddleware:
    async def app(scope, receive, send):  # pragma: no cover
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    params = {
        "allowed_networks": (ipaddress.ip_network("127.0.0.1/32"),),
        "auth_tokens": tokens,
    }
    params.update(kwargs)
    return GateMiddleware(app, **params)


def _auth(token: str) -> list[tuple[bytes, bytes]]:
    return [(b"authorization", b"Bearer " + token.encode())]


# --- helpers ---------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("127.0.0.1", "127.0.0.1"),
        ("::ffff:127.0.0.1", "127.0.0.1"),
        ("fe80::1%eth0", "fe80::1"),
        ("not-an-ip", None),
        ("", None),
    ],
)
def test_normalise_ip(raw, expected):
    addr = _normalise_ip(raw)
    if expected is None:
        assert addr is None
    else:
        assert str(addr) == expected


def test_extract_bearer_authorization():
    assert _extract_bearer(_scope(headers=_auth(ADMIN.token))) == ADMIN.token


def test_extract_bearer_alt_header():
    scope = _scope(headers=[(b"x-auth-token", ADMIN.token.encode())])
    assert _extract_bearer(scope) == ADMIN.token


def test_extract_bearer_malformed():
    scope = _scope(headers=[(b"authorization", b"Basic abc")])
    assert _extract_bearer(scope) == ""


def test_extract_bearer_missing():
    assert _extract_bearer(_scope()) == ""


# --- gate behaviour --------------------------------------------------------


def test_ip_allowed():
    gate = _gate()
    assert gate._ip_allowed(ipaddress.ip_address("127.0.0.1"))
    assert not gate._ip_allowed(ipaddress.ip_address("192.0.2.1"))


def test_authenticate_admin_token():
    entry = _gate()._authenticate(ADMIN.token)
    assert entry is not None and entry.role == "admin"


def test_authenticate_read_token():
    entry = _gate(tokens=(ADMIN, READER))._authenticate(READER.token)
    assert entry is not None and entry.role == "read"


def test_authenticate_unknown_token():
    assert _gate()._authenticate("wrong-token") is None


def test_denies_disallowed_ip():
    rec = asyncio.run(_call(_gate(), _scope(client="192.0.2.1")))
    assert rec.status == 403


def test_denies_unknown_client():
    scope = _scope()
    scope["client"] = None
    rec = asyncio.run(_call(_gate(), scope))
    assert rec.status == 403


def test_healthz_without_token_from_allowed_ip():
    rec = asyncio.run(_call(_gate(), _scope(path="/healthz")))
    assert rec.status == 200
    assert b"ok" in rec.body


def test_healthz_from_denied_ip():
    rec = asyncio.run(_call(_gate(), _scope(path="/healthz", client="192.0.2.1")))
    assert rec.status == 403


def test_requires_token_on_mcp():
    rec = asyncio.run(_call(_gate(), _scope()))
    assert rec.status == 401
    assert "bearer" in rec.header("www-authenticate").lower()


def test_wrong_token_rejected():
    rec = asyncio.run(_call(_gate(), _scope(headers=_auth("wrong"))))
    assert rec.status == 401


def test_valid_admin_token_passes_and_sets_role():
    rec = asyncio.run(_call(_gate(), _scope(headers=_auth(ADMIN.token))))
    assert rec.status == 200
    assert rec.body == b"ok"
    assert rec.role_seen == "admin"


def test_valid_read_token_passes_and_sets_role():
    rec = asyncio.run(
        _call(_gate(tokens=(ADMIN, READER)), _scope(headers=_auth(READER.token)))
    )
    assert rec.status == 200
    assert rec.role_seen == "read"


def test_constructor_rejects_empty_allowlist():
    with pytest.raises(ValueError):
        _gate(allowed_networks=())


def test_constructor_rejects_empty_tokens():
    with pytest.raises(ValueError):
        _gate(tokens=())


def test_constructor_rejects_invalid_role():
    bad = TokenEntry(name="bad", role="superuser", token="x" * 32)
    with pytest.raises(ValueError):
        _gate(tokens=(bad,))


def test_constructor_rejects_empty_token_value():
    bad = TokenEntry(name="empty", role="read", token="")
    with pytest.raises(ValueError):
        _gate(tokens=(bad,))


# --- rate limiting ---------------------------------------------------------


def test_rate_limit_locks_out_after_max_failures():
    gate = _gate(max_auth_failures=2, auth_failure_window_seconds=300, auth_lockout_seconds=60)
    key = "127.0.0.1"
    gate._record_failure(key)
    assert gate._lockout_remaining(key) == 0.0
    gate._record_failure(key)
    assert gate._lockout_remaining(key) > 0.0


def test_locked_out_ip_gets_429():
    gate = _gate(max_auth_failures=2, auth_lockout_seconds=60)
    gate._record_failure("127.0.0.1")
    gate._record_failure("127.0.0.1")
    rec = asyncio.run(_call(gate, _scope(headers=_auth("wrong"))))
    assert rec.status == 429
    assert rec.header("retry-after") != ""
    assert b"too_many_requests" in rec.body


def test_successful_auth_clears_failures():
    gate = _gate(max_auth_failures=2)
    gate._record_failure("127.0.0.1")
    rec = asyncio.run(_call(gate, _scope(headers=_auth(ADMIN.token))))
    assert rec.status == 200
    assert gate._lockout_remaining("127.0.0.1") == 0.0
    assert "127.0.0.1" not in gate._failures


def test_lockout_expires(monkeypatch):
    import openhop_mcp.security as security_mod

    clock = {"now": 1000.0}
    monkeypatch.setattr(security_mod.time, "monotonic", lambda: clock["now"])
    gate = _gate(max_auth_failures=1, auth_lockout_seconds=60)
    gate._record_failure("127.0.0.1")
    assert gate._lockout_remaining("127.0.0.1") == 60.0
    clock["now"] = 1061.0
    assert gate._lockout_remaining("127.0.0.1") == 0.0


def test_failures_outside_window_do_not_lock():
    gate = _gate(max_auth_failures=2, auth_failure_window_seconds=0.01)
    key = "127.0.0.1"
    gate._record_failure(key)
    time.sleep(0.02)
    gate._record_failure(key)
    assert gate._lockout_remaining(key) == 0.0


def test_constructor_rejects_bad_throttle_settings():
    with pytest.raises(ValueError):
        _gate(max_auth_failures=0)
    with pytest.raises(ValueError):
        _gate(auth_failure_window_seconds=0)
    with pytest.raises(ValueError):
        _gate(auth_lockout_seconds=0)


def test_websocket_scope_is_refused_without_reaching_app():
    reached = []

    async def app(scope, receive, send):
        reached.append(scope)

    gate = _gate()
    gate.app = app  # type: ignore[assignment]
    sent = []

    async def receive():
        return {"type": "websocket.connect"}

    async def send(message):
        sent.append(message)

    asyncio.run(gate({"type": "websocket", "path": "/mcp", "client": ("127.0.0.1", 1)}, receive, send))
    assert not reached
    assert sent == [{"type": "websocket.close", "code": 1008}]


def test_lifespan_scope_passes_through():
    reached = []

    async def app(scope, receive, send):
        reached.append(scope["type"])

    gate = _gate()
    gate.app = app  # type: ignore[assignment]
    asyncio.run(gate({"type": "lifespan"}, None, None))
    assert reached == ["lifespan"]
