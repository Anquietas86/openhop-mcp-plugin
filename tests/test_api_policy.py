"""Tests for the openhop_api_read path allowlist."""

from __future__ import annotations

import pytest

from openhop_mcp.api_policy import ALLOWED_API_PATHS, PolicyError, clean_params, normalise_path


@pytest.mark.parametrize("path", ["/api/stats", "/api/gps/", "api/noise_floor_stats", "/API/Stats"])
def test_allowed_paths(path):
    assert normalise_path(path) in ALLOWED_API_PATHS


@pytest.mark.parametrize(
    "path",
    [
        # Credential and config material.
        "/api/plugins/settings",
        "/api/config_export",
        "/api/identity_export",
        "/api/transport_keys",
        "/api/transport_key",
        "/api/auth/tokens",
        "/api/identities",
        "/api/companion/channels",
        # GET with side effects upstream.
        "/api/default_region",
        "/api/update/check",
        # Encoding and traversal tricks.
        "/api/transport%5Fkeys",
        "/api/stats/../plugins/settings",
        "/api/./identity_export",
        "/api//stats",
        "/api/stats?x=1",
        "http://evil/api/stats",
        "/api/stats#frag",
        # Streaming.
        "/api/logs_stream",
        "/api/gps_stream",
        "",
    ],
)
def test_rejected_paths(path):
    with pytest.raises(PolicyError):
        normalise_path(path)


def test_allowlist_has_no_sensitive_entries():
    for path in ALLOWED_API_PATHS:
        for word in ("key", "token", "secret", "export", "import", "plugin", "config",
                     "identit", "stream", "companion", "update", "auth", "acl", "policy"):
            assert word not in path, (path, word)


def test_clean_params_accepts_scalars():
    assert clean_params({"hours": 24, "type": "advert", "flag": True}) == {
        "hours": 24, "type": "advert", "flag": True,
    }
    assert clean_params(None) is None


@pytest.mark.parametrize(
    "params",
    [
        {"nested": {"a": 1}},
        {"list": [1, 2]},
        {"long": "x" * 1000},
        {str(i): i for i in range(50)},
        "not-a-dict",
    ],
)
def test_clean_params_rejects_bad_input(params):
    with pytest.raises(PolicyError):
        clean_params(params)
