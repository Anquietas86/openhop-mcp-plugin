"""Validate the built wheel with the real openHop Repeater parser.

Run from the plugin project root with the Repeater source checked out at a
known revision on PYTHONPATH:

    PYTHONPATH="$PWD/repeater-source" .venv/bin/python validate_wheel.py
"""

from __future__ import annotations

import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZipFile

from repeater.plugins.manifest import load_manifest_from_wheel
from repeater.plugins.storage import PluginStorage

WHEEL_GLOB = "dist/openhop_mcp_plugin-*-py3-none-any.whl"
MANIFEST_SUFFIX = "share/openhop/plugins/openhop.mcp/openhop-plugin.json"


def main() -> int:
    candidates = sorted(Path("dist").glob("openhop_mcp_plugin-*-py3-none-any.whl"))
    if not candidates:
        print("FAIL: no wheel found in dist/", file=sys.stderr)
        return 1
    wheel = candidates[-1]

    manifest = load_manifest_from_wheel(wheel)
    assert manifest.id == "openhop.mcp", manifest
    assert manifest.runtime.type == "python"
    assert manifest.runtime.entrypoint == "openhop-mcp"
    assert f"-{manifest.version}-" in wheel.name, (manifest.version, wheel.name)
    print(f"PASS manifest: {manifest.id} {manifest.version} -> {manifest.runtime.entrypoint}")

    with ZipFile(wheel) as archive:
        names = archive.namelist()
        manifests = [n for n in names if n.endswith("/openhop-plugin.json")]
        assert len(manifests) == 1, manifests
        assert manifests[0].endswith(MANIFEST_SUFFIX), manifests
        dist_info = next(n.split("/")[0] for n in names if n.endswith(".dist-info/entry_points.txt"))
        entrypoints = archive.read(f"{dist_info}/entry_points.txt").decode()
        assert "openhop-mcp = openhop_mcp.server:main" in entrypoints, entrypoints
        print("PASS wheel layout and console script")

    with TemporaryDirectory(prefix="openhop-mcp-validation-") as root:
        storage = PluginStorage(Path(root) / "plugins")
        storage.ensure_plugin_layout(manifest.id, manifest.version)
        storage.write_manifest(manifest.id, manifest.version, manifest)
        storage.set_current(manifest.id, manifest.version)
        storage.write_state(manifest.id, {"version": manifest.version, "enabled": False})
        storage.write_config(manifest.id, manifest.config_defaults)
        assert storage.load_current_manifest(manifest.id) == manifest
        config = storage.read_config(manifest.id)
        assert config["port"] == 8765
        assert config["read_only"] is True
        assert config["allowed_ips"] == ["127.0.0.1/32", "::1/128"]
        print("PASS storage round-trip and config defaults")

    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
