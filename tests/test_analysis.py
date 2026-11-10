"""Unit tests for the analysis helpers."""

from __future__ import annotations

from openhop_mcp.analysis import airtime_headroom, describe, link_quality, noise_anomalies


def test_describe_ignores_junk():
    assert describe([1, 2, 3, None, "x", True])["mean"] == 2.0
    assert describe([])["mean"] is None


def test_link_quality_stable_and_gap():
    rows = [{"timestamp": t, "rssi": -90, "snr": 5} for t in (0, 60, 120, 1000, 1060, 1120)]
    result = link_quality(rows, hours=1)
    assert result["trend"] == "stable"
    assert result["largest_gap_seconds"] == 880
    assert result["per_hour"] == 6


def test_link_quality_insufficient_data():
    assert link_quality([{"timestamp": 1, "snr": 1}], hours=1)["trend"] == "insufficient data"


def test_airtime_over_limit():
    buckets = [{"tx_ms": 7200, "rx_ms": 0}]  # 12% of a minute
    result = airtime_headroom(buckets, 60, 10.0)
    assert result["status"] == "over limit"
    assert result["peak_headroom_percent"] == -2.0


def test_airtime_unknown_limit():
    assert airtime_headroom([{"tx_ms": 10}], 60, None)["status"] == "unknown limit"


def test_noise_flat_channel_has_no_events():
    samples = [{"timestamp": i, "noise_floor_dbm": -115.0} for i in range(20)]
    assert noise_anomalies(samples)["event_count"] == 0


def test_noise_low_dip_detected_on_flat_channel():
    samples = [{"timestamp": i, "noise_floor_dbm": -115.0} for i in range(20)]
    samples[5]["noise_floor_dbm"] = -125.0
    result = noise_anomalies(samples)
    assert result["event_count"] == 1
    assert result["events"][0]["direction"] == "low"


def test_noise_too_few_samples():
    assert noise_anomalies([{"timestamp": 1, "noise_floor_dbm": -100}])["note"]
