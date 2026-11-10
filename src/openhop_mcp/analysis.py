"""Pure analysis helpers behind the higher-level MCP tools.

Everything here takes plain lists and dicts already fetched from the
Repeater and returns plain numbers, so it can be unit tested without a
Repeater or an event loop.
"""

from __future__ import annotations

import itertools
import statistics
from collections.abc import Iterable, Sequence
from typing import Any


def _numbers(values: Iterable[Any]) -> list[float]:
    out: list[float] = []
    for value in values:
        if isinstance(value, bool) or value is None:
            continue
        try:
            out.append(float(value))
        except (TypeError, ValueError):
            continue
    return out


def describe(values: Iterable[Any]) -> dict[str, float | None]:
    """Mean, median, min, max and population stdev, rounded for display."""
    nums = _numbers(values)
    if not nums:
        return {"mean": None, "median": None, "min": None, "max": None, "stdev": None}
    return {
        "mean": round(statistics.fmean(nums), 2),
        "median": round(statistics.median(nums), 2),
        "min": round(min(nums), 2),
        "max": round(max(nums), 2),
        "stdev": round(statistics.pstdev(nums), 2) if len(nums) > 1 else 0.0,
    }


# -- link quality -------------------------------------------------------------


def link_quality(rows: Sequence[dict[str, Any]], hours: float) -> dict[str, Any]:
    """Summarise one neighbour's observations (oldest first).

    Trend compares the mean SNR of the newer half of the window with the
    older half. A drop of 3 dB or more is called "degrading", a rise of 3 dB
    or more "improving".
    """
    rows = [r for r in rows if isinstance(r, dict)]
    rows.sort(key=lambda r: float(r.get("timestamp") or 0))
    count = len(rows)
    duplicates = sum(1 for r in rows if r.get("is_duplicate"))
    timestamps = _numbers(r.get("timestamp") for r in rows)

    largest_gap = None
    if len(timestamps) > 1:
        largest_gap = round(max(b - a for a, b in itertools.pairwise(timestamps)), 1)

    snr_trend_db = None
    trend = "insufficient data"
    if count >= 6:
        half = count // 2
        older = _numbers(r.get("snr") for r in rows[:half])
        newer = _numbers(r.get("snr") for r in rows[half:])
        if older and newer:
            snr_trend_db = round(statistics.fmean(newer) - statistics.fmean(older), 2)
            if snr_trend_db <= -3:
                trend = "degrading"
            elif snr_trend_db >= 3:
                trend = "improving"
            else:
                trend = "stable"

    hop_counts = _numbers(r.get("path_hop_count") for r in rows)
    return {
        "observations": count,
        "per_hour": round(count / hours, 2) if hours > 0 else None,
        "duplicate_ratio": round(duplicates / count, 3) if count else None,
        "rssi": describe(r.get("rssi") for r in rows),
        "snr": describe(r.get("snr") for r in rows),
        "snr_trend_db": snr_trend_db,
        "trend": trend,
        "largest_gap_seconds": largest_gap,
        "first_seen": timestamps[0] if timestamps else None,
        "last_seen": timestamps[-1] if timestamps else None,
        "mean_path_hops": round(statistics.fmean(hop_counts), 2) if hop_counts else None,
    }


# -- airtime ------------------------------------------------------------------


def airtime_headroom(
    buckets: Sequence[dict[str, Any]],
    bucket_seconds: float,
    max_airtime_percent: float | None,
    *,
    warn_fraction: float = 0.8,
) -> dict[str, Any]:
    """Compare per-bucket TX airtime with the duty-cycle limit.

    The Repeater enforces duty cycle per minute, so 60 s buckets line up with
    how the limit actually bites. Percentages are of wall-clock time.
    """
    span_ms = max(1.0, float(bucket_seconds) * 1000.0)
    tx_pct = [float(b.get("tx_ms") or 0) / span_ms * 100 for b in buckets if isinstance(b, dict)]
    rx_pct = [float(b.get("rx_ms") or 0) / span_ms * 100 for b in buckets if isinstance(b, dict)]

    peak_tx = max(tx_pct) if tx_pct else 0.0
    result: dict[str, Any] = {
        "buckets": len(tx_pct),
        "bucket_seconds": bucket_seconds,
        "tx_percent": describe(tx_pct),
        "rx_percent": describe(rx_pct),
        "channel_busy_percent_mean": round(
            statistics.fmean(t + r for t, r in zip(tx_pct, rx_pct, strict=False)), 2
        )
        if tx_pct
        else None,
        "max_airtime_percent": max_airtime_percent,
        "peak_headroom_percent": None,
        "buckets_near_limit": None,
        "buckets_over_limit": None,
        "status": "unknown limit",
    }
    if max_airtime_percent and max_airtime_percent > 0:
        limit = float(max_airtime_percent)
        near = sum(1 for p in tx_pct if p >= limit * warn_fraction)
        over = sum(1 for p in tx_pct if p > limit)
        result.update(
            peak_headroom_percent=round(limit - peak_tx, 2),
            buckets_near_limit=near,
            buckets_over_limit=over,
        )
        if over:
            result["status"] = "over limit"
        elif near:
            result["status"] = "near limit"
        else:
            result["status"] = "ok"
    return result


# -- noise floor --------------------------------------------------------------


def noise_anomalies(
    samples: Sequence[dict[str, Any]],
    *,
    threshold: float = 3.5,
    min_delta_db: float = 3.0,
    max_events: int = 50,
) -> dict[str, Any]:
    """Find noise-floor excursions using a robust z-score (median / MAD).

    A sample is anomalous when its modified z-score exceeds ``threshold`` and
    it is at least ``min_delta_db`` away from the median (so a very quiet,
    very steady channel does not flag sub-dB wiggles). Consecutive anomalous
    samples are merged into one event.
    """
    points = [
        (float(s["timestamp"]), float(s["noise_floor_dbm"]))
        for s in samples
        if isinstance(s, dict)
        and isinstance(s.get("timestamp"), (int, float))
        and isinstance(s.get("noise_floor_dbm"), (int, float))
    ]
    points.sort()
    values = [v for _, v in points]
    if len(values) < 5:
        return {
            "samples": len(values),
            "baseline": describe(values),
            "events": [],
            "event_count": 0,
            "note": "need at least 5 samples",
        }

    median = statistics.median(values)
    mad = statistics.median(abs(v - median) for v in values)
    scale = 1.4826 * mad if mad > 0 else None

    events: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for ts, value in points:
        delta = value - median
        z = (delta / scale) if scale else (0.0 if delta == 0 else float("inf"))
        anomalous = abs(z) > threshold and abs(delta) >= min_delta_db
        if anomalous:
            direction = "high" if delta > 0 else "low"
            if current and current["direction"] == direction:
                current["end"] = ts
                current["samples"] += 1
                if abs(delta) > abs(current["peak_delta_db"]):
                    current["peak_dbm"] = value
                    current["peak_delta_db"] = round(delta, 2)
            else:
                if current:
                    events.append(current)
                current = {
                    "start": ts,
                    "end": ts,
                    "direction": direction,
                    "samples": 1,
                    "peak_dbm": value,
                    "peak_delta_db": round(delta, 2),
                }
        elif current:
            events.append(current)
            current = None
    if current:
        events.append(current)

    events.sort(key=lambda e: abs(e["peak_delta_db"]), reverse=True)
    return {
        "samples": len(values),
        "baseline": {**describe(values), "mad": round(mad, 2)},
        "event_count": len(events),
        "events": events[:max_events],
    }
