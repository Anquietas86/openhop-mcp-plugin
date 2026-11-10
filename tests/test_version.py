"""Keep the plugin manifest version in step with the package version."""

from __future__ import annotations

import json
from pathlib import Path

from openhop_mcp import __version__

ROOT = Path(__file__).resolve().parent.parent


def test_manifest_version_matches_package():
    manifest = json.loads((ROOT / "openhop-plugin.json").read_text(encoding="utf-8"))
    assert manifest["version"] == __version__


def test_manifest_defaults_match_config_defaults():
    from openhop_mcp.config import DEFAULT_CONFIG

    manifest = json.loads((ROOT / "openhop-plugin.json").read_text(encoding="utf-8"))
    assert manifest["config"]["defaults"] == DEFAULT_CONFIG
