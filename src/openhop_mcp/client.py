"""Minimal async client for the openHop Repeater REST API.

The Repeater authenticates with an ``X-API-Key`` header (64-char hex), not a
Bearer token. ``/api/stats`` is historically reachable without a key, but every
other endpoint requires one, so a key is strongly recommended.

The plugin never logs the key. It also never forwards client-supplied headers
to the Repeater — the only outbound credentials are its own.
"""

from __future__ import annotations

from typing import Any

import httpx2


class OpenHopError(RuntimeError):
    """Raised when the Repeater API cannot satisfy a request."""

    def __init__(self, message: str, *, status: int | None = None, body: Any = None) -> None:
        super().__init__(message)
        self.status = status
        self.body = body


class OpenHopClient:
    def __init__(self, base_url: str, api_key: str, timeout: float = 15.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

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
        url = f"{self.base_url}{path}"
        try:
            async with httpx2.AsyncClient(timeout=self.timeout) as client:
                response = await client.request(
                    method,
                    url,
                    params=params,
                    json=json_body,
                    headers=self._headers(),
                )
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
                f"Repeater returned HTTP {response.status_code}"
                + (f": {reason}" if reason else ""),
                status=response.status_code,
                body=parsed,
            )
        return parsed

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return await self._request("GET", path, params=params)

    async def post(self, path: str, json_body: dict[str, Any] | None = None) -> Any:
        return await self._request("POST", path, json_body=json_body)
