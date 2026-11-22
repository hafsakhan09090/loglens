"""Anomaly detection over time windows.

Two signals, both easy to explain:

1. Severity spike: each window gets a severity score (errors + 0.25 * warnings).
   It is compared with a rolling robust baseline (median and MAD over the last
   `history` quiet windows). Windows already flagged as anomalous are NOT added
   to the baseline, so a long incident cannot teach the detector that it is normal.

2. Novelty: several WARN/ERROR templates appearing for the first time in the
   same window is suspicious even when the raw counts are small.

Adjacent anomalous windows are merged into one incident.
"""
from __future__ import annotations

import statistics
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List

from .parser import LogRecord

WARN_WEIGHT = 0.25


@dataclass
class Window:
    index: int
    start: datetime
    end: datetime
    records: List[LogRecord] = field(default_factory=list)
    z: float = 0.0
    anomalous: bool = False
    novel_serious: List[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.records)

    @property
    def errors(self) -> int:
        return sum(1 for r in self.records if r.level == "ERROR")

    @property
    def warns(self) -> int:
        return sum(1 for r in self.records if r.level == "WARN")

    @property
    def severity(self) -> float:
        return self.errors + WARN_WEIGHT * self.warns


@dataclass
class Incident:
    id: str
    start: datetime
    end: datetime
    windows: List[Window]
    records: List[LogRecord]
    peak_z: float
    top_templates: List[dict]
    level_counts: Dict[str, int]
    components: List[dict]
    evidence: List[LogRecord]

    @property
    def duration_seconds(self) -> int:
        return int((self.end - self.start).total_seconds())


def build_windows(records: List[LogRecord], window_seconds: int) -> List[Window]:
    if not records:
        return []
    first = min(r.ts for r in records)
    epoch = first.replace(second=0, microsecond=0)
    if window_seconds >= 3600:
        epoch = epoch.replace(minute=0)
    size = timedelta(seconds=window_seconds)
    last_index = 0
    buckets: Dict[int, List[LogRecord]] = {}
    for rec in records:
        idx = int((rec.ts - epoch).total_seconds() // window_seconds)
        buckets.setdefault(idx, []).append(rec)
        last_index = max(last_index, idx)
    windows = []
    for idx in range(last_index + 1):
        start = epoch + idx * size
        windows.append(Window(index=idx, start=start, end=start + size, records=buckets.get(idx, [])))
    return windows


def _robust_z(value: float, baseline: List[float]) -> float:
    med = statistics.median(baseline)
    mad = statistics.median(abs(x - med) for x in baseline)
    scale = max(1.4826 * mad, 1.0)  # floor: sparse error counts have MAD of zero
    return (value - med) / scale


def detect(
    records: List[LogRecord],
    window_seconds: int = 60,
    history: int = 30,
    z_threshold: float = 4.0,
    min_history: int = 8,
    novelty_min: int = 2,
    merge_gap: int = 1,
):
    """Return (windows, incidents)."""
    windows = build_windows(records, window_seconds)

    first_seen: Dict[str, int] = {}
    for w in windows:
        for rec in w.records:
            first_seen.setdefault(rec.template_id, w.index)

    baseline: List[float] = []
    for w in windows:
        w.novel_serious = sorted(
            {r.template_id for r in w.records if r.is_serious and first_seen[r.template_id] == w.index}
        )
        ready = len(baseline) >= min_history
        if ready:
            w.z = _robust_z(w.severity, baseline[-history:])
            w.anomalous = w.z >= z_threshold or len(w.novel_serious) >= novelty_min
        if not w.anomalous:
            baseline.append(w.severity)

    incidents = _merge(windows, records, first_seen, merge_gap)
    return windows, incidents


def _merge(windows: List[Window], all_records: List[LogRecord], first_seen: Dict[str, int], merge_gap: int):
    flagged = [w for w in windows if w.anomalous]
    if not flagged:
        return []
    groups: List[List[Window]] = [[flagged[0]]]
    for w in flagged[1:]:
        if w.index - groups[-1][-1].index <= merge_gap + 1:
            groups[-1].append(w)
        else:
            groups.append([w])

    incidents = []
    for n, group in enumerate(groups, start=1):
        lo, hi = group[0].index, group[-1].index
        span = [w for w in windows if lo <= w.index <= hi]
        recs = [r for w in span for r in w.records]
        incidents.append(_build_incident(f"INC-{n:03d}", span, recs, all_records, first_seen))
    return incidents


def _build_incident(inc_id, span, recs, all_records, first_seen) -> Incident:
    serious = [r for r in recs if r.is_serious]
    counts = Counter(r.template_id for r in serious)
    by_tid = {}
    for r in serious:
        by_tid.setdefault(r.template_id, []).append(r)

    top = []
    for tid, count in counts.most_common(6):
        sample = by_tid[tid][0]
        top.append(
            {
                "template_id": tid,
                "level": sample.level,
                "component": sample.component,
                "template": sample.template,
                "count": count,
                "novel": first_seen[tid] >= span[0].index,
            }
        )

    level_counts = Counter(r.level for r in recs)
    comp_counts = Counter(r.component for r in serious)
    components = [{"component": c, "count": n} for c, n in comp_counts.most_common(5)]

    evidence: Dict[int, LogRecord] = {}
    for tid, _ in counts.most_common(6):
        group = by_tid[tid]
        evidence[group[0].line_no] = group[0]
    for tid, _ in counts.most_common(3):
        group = by_tid[tid]
        if len(group) > 1:
            evidence[group[-1].line_no] = group[-1]
    start = span[0].start
    lead_up = [r for r in all_records if r.ts < start][-3:]
    for r in lead_up:
        evidence[r.line_no] = r
    ordered = sorted(evidence.values(), key=lambda r: r.line_no)[:14]

    return Incident(
        id=inc_id,
        start=span[0].start,
        end=span[-1].end,
        windows=span,
        records=recs,
        peak_z=max(w.z for w in span),
        top_templates=top,
        level_counts=dict(level_counts),
        components=components,
        evidence=ordered,
    )
