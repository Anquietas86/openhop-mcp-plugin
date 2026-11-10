"""Async client for the openHop Repeater REST API.

The Repeater authenticates with an ``X-API-Key`` header (64-char hex), not a
Bearer token. ``/api/stats`` is historically reachable without a key, but every
other endpoint requires one, so a key is strongly recommended.

The plugin never logs the key. It also never forwards client-supplied headers
to the Repeater — the only outbound credentials are its own.

One ``AsyncClient`` is shared for the life of the process so connections are
reused, and GET responses are cached for a few seconds. Several tools read the
same large ``/api/stats`` payload, and on a Raspberry Pi re-fetching it for
every call is noticeable.

Every response is passed through :func:`redact` before it leaves this module,
because some Repeater endpoints (``/api/stats`` among them) embed config
sections that can hold MQTT passwords and similar secrets.
"""

from __future__ import annotations

import copy
import json
import time
from typing import Any

import anyio
import httpx2

#: Keys whose values are replaced with ``REDACTED`` anywhere in a response.
#: Matched case-insensitively against the whole key or as a substring.
SENSITIVE_KEY_PARTS: tuple[str, ...] = (
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "privkey",
    "identity_key",
    "psk",
    "jwt",
    "credential",
)
REDACTED = "[redacted]"


def _is_sensitive(key: str) -> bool:
    lowered = key.lower()
    return any(part in lowered for part in SENSITIVE_KEY_PARTS)


def redact(value: Any) -> Any:
    """Return ``value`` with secret-looking fields replaced, recursively."""
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for key, item in value.items():
            # Only string values are treated as secrets, so numeric settings
            # such as ``refill_tokens`` survive.
            if isinstance(key, str) and isinstance(item, str) and item and _is_sensitive(key):
                out[key] = REDACTED
            else:
                out[key] = redact(item)
        return out
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


class OpenHopError(RuntimeError):
    """Raised when the Repeater API cannot satisfy a request."""

    def __init__(self, message: str, *, status: int | None = None, body: Any = None) -> None:
        super().__init__(message)
        self.status = status
        self.body = body


def _cache_key(path: str, params: dict[str, Any] | None) -> str:
    return path + "?" + json.dumps(params or {}, sort_keys=True, default=str)


class OpenHopClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout: float = 15.0,
        *,
        cache_ttl: float = 3.0,
        max_cache_entries: int = 128,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.cache_ttl = max(0.0, float(cache_ttl))
        self.max_cache_entries = max_cache_entries
        self._client: httpx2.AsyncClient | None = None
        self._cache: dict[str, tuple[float, Any]] = {}
        self._inflight: dict[str, anyio.Event] = {}

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    def _get_client(self) -> httpx2.AsyncClient:
        # Created lazily so it binds to the server's running event loop.
        if self._client is None:
            self._client = httpx2.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout,
                headers=self._headers(),
                limits=httpx2.Limits(max_connections=8, max_keepalive_connections=4),
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def clear_cache(self) -> None:
        self._cache.clear()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> Any:
        if not path.startswith("/"):
            path = "/" + path
        try:
            response = await self._get_client().request(method, path, params=params, json=json_body)
        except httpx2.HTTPError as exc:
            raise OpenHopError(f"transport error calling {path}: {exc}") from exc

        text = response.text
        parsed: Any
        try:
            parsed = response.json()
        except ValueError:
            parsed = text[:2000]

        if response.status_code >= 400:
            reason = ""
            if isinstance(parsed, dict):
                reason = str(parsed.get("error") or parsed.get("message") or "")
            raise OpenHopError(
                f"Repeater returned HTTP {response.status_code}" + (f": {reason}" if reason else ""),
                status=response.status_code,
                body=redact(parsed),
            )
        # Many Repeater handlers report failure as HTTP 200 with success=false.
        if isinstance(parsed, dict) and parsed.get("success") is False:
            reason = str(parsed.get("error") or parsed.get("message") or "request failed")
            raise OpenHopError(
                f"Repeater reported an error: {reason}",
                status=response.status_code,
                body=redact(parsed),
            )
        return redact(parsed)

    async def get(self, path: str, params: dict[str, Any] | None = None, *, fresh: bool = False) -> Any:
        """GET ``path``. Results are cached for ``cache_ttl`` seconds unless ``fresh``."""
        if self.cache_ttl <= 0 or fresh:
            return await self._request("GET", path, params=params)

        key = _cache_key(path, params)
        while True:
            hit = self._cache.get(key)
            if hit is not None and hit[0] > time.monotonic():
                return copy.deepcopy(hit[1])
            waiter = self._inflight.get(key)
            if waiter is None:
                break
            # Another caller is already fetching this key; share its result.
            await waiter.wait()

        event = anyio.Event()
        self._inflight[key] = event
        try:
            value = await self._request("GET", path, params=params)
            if len(self._cache) >= self.max_cache_entries:
                now = time.monotonic()
                self._cache = {k: v for k, v in self._cache.items() if v[0] > now}
                if len(self._cache) >= self.max_cache_entries:
                    self._cache.pop(next(iter(self._cache)))
            self._cache[key] = (time.monotonic() + self.cache_ttl, value)
            return copy.deepcopy(value)
        finally:
            self._inflight.pop(key, None)
            event.set()

    async def post(self, path: str, json_body: dict[str, Any] | None = None) -> Any:
        result = await self._request("POST", path, json_body=json_body)
        # A write can change anything a cached read returned.
        self.clear_cache()
        return result
