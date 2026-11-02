"""Unit tests for the ASGI gate. No network or live Repeater required."""

from __future__ import annotations

import asyncio
import ipaddress

import pytest

from openhop_mcp.security import GateMiddleware, _extract_bearer, _normalise_ip

TOKEN = "unit-test-token-abcdefghijklmnop"


def _scope(path: str = "/mcp", client: str = "127.0.0.1", headers=None) -> dict:
    return {
        "type": "http",
        "path": path,
        "client": (client, 12345),
        "headers": headers or [],
    }


class _Recorder:
    """Minimal ASGI send that records the response."""

    def __init__(self) -> None:
        self.status: int | None = None
        self.headers: list[tuple[bytes, bytes]] = []
        self.body = b""

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
    await middleware(scope, lambda: None, rec)
    return rec


def _gate(**kwargs) -> GateMiddleware:
    async def app(scope, receive, send):  # pragma: no cover - never reached in denials
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    params = {
        "allowed_networks": (ipaddress.ip_network("127.0.0.1/32"),),
        "auth_token": TOKEN,
    }
    params.update(kwargs)
    return GateMiddleware(app, **params)


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
    scope = _scope(headers=[(b"authorization", b"Bearer " + TOKEN.encode())])
    assert _extract_bearer(scope) == TOKEN


def test_extract_bearer_alt_header():
    scope = _scope(headers=[(b"x-auth-token", TOKEN.encode())])
    assert _extract_bearer(scope) == TOKEN


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


def test_token_ok():
    gate = _gate()
    assert gate._token_ok(TOKEN)
    assert not gate._token_ok("wrong")


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
    scope = _scope(headers=[(b"authorization", b"Bearer wrong")])
    rec = asyncio.run(_call(_gate(), scope))
    assert rec.status == 401


def test_valid_token_passes():
    scope = _scope(headers=[(b"authorization", b"Bearer " + TOKEN.encode())])
    rec = asyncio.run(_call(_gate(), scope))
    assert rec.status == 200
    assert rec.body == b"ok"


def test_constructor_rejects_empty_allowlist():
    with pytest.raises(ValueError):
        _gate(allowed_networks=())


def test_constructor_rejects_empty_token():
    with pytest.raises(ValueError):
        _gate(auth_token="")
