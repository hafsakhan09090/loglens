"""Evaluation against labelled incidents.

Detection:  window-level precision / recall / F1, incident-level recall,
            false incidents and detection delay.
Analysis:   per matched incident, a small rubric:
              - root_cause_hit: the root_cause text mentions an expected keyword
              - citation_precision: share of cited lines that really belong to the incident
              - clean: no validation issues and no fallback to the rules provider

Caveat: the labelled data is synthetic, so the rules baseline scores well on the
incidents it was written for. The harness is meant for comparing providers and
prompt versions on the same data (and for swapping in a public dataset).
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Dict, List, Optional

from .llm import Provider
from .pipeline import run


def _overlap(a_start: datetime, a_end: datetime, b_start: datetime, b_end: datetime) -> float:
    return max(0.0, (min(a_end, b_end) - max(a_start, b_start)).total_seconds())


def evaluate(lines: List[str], truth: dict, provider: Optional[Provider] = None, **kwargs) -> dict:
    report, incidents, windows = run(lines, provider, source="evaluation", **kwargs)
    true_incidents = [
        {**t, "start_dt": datetime.fromisoformat(t["start"]), "end_dt": datetime.fromisoformat(t["end"])}
        for t in truth["incidents"]
    ]

    # window-level detection metrics
    tp = fp = fn = 0
    for w in windows:
        positive = any(_overlap(w.start, w.end, t["start_dt"], t["end_dt"]) > 0 for t in true_incidents)
        if w.anomalous and positive:
            tp += 1
        elif w.anomalous:
            fp += 1
        elif positive:
            fn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    # incident-level matching and analysis rubric
    matched_ids = set()
    per_incident = []
    for t in true_incidents:
        best, best_overlap = None, 0.0
        for inc, rep in zip(incidents, report["incidents"]):
            ov = _overlap(inc.start, inc.end, t["start_dt"], t["end_dt"])
            if ov > best_overlap:
                best, best_overlap = (inc, rep), ov
        row: Dict[str, object] = {"id": t["id"], "name": t["name"], "detected": best is not None}
        if best:
            inc, rep = best
            matched_ids.add(inc.id)
            analysis, meta = rep["analysis"], rep["analysis_meta"]
            cited = analysis["evidence_lines"]
            truth_lines = set(t["injected_lines"])
            row.update(
                delay_seconds=max(0, int((inc.start - t["start_dt"]).total_seconds())),
                root_cause=analysis["root_cause"],
                confidence=analysis["confidence"],
                root_cause_hit=any(k in analysis["root_cause"].lower() for k in t["expected_keywords"]),
                citation_precision=(sum(1 for n in cited if n in truth_lines) / len(cited)) if cited else 0.0,
                clean=not meta["issues"] and not meta["fallback_used"],
            )
        per_incident.append(row)

    detected = [r for r in per_incident if r["detected"]]
    summary = {
        "provider": report["meta"]["provider"],
        "model": report["meta"]["model"],
        "prompt_version": report["meta"]["prompt_version"],
        "window_precision": round(precision, 3),
        "window_recall": round(recall, 3),
        "window_f1": round(f1, 3),
        "incidents_detected": f"{len(detected)}/{len(true_incidents)}",
        "false_incidents": len([i for i in incidents if i.id not in matched_ids]),
        "root_cause_accuracy": round(sum(1 for r in detected if r["root_cause_hit"]) / len(detected), 3) if detected else 0.0,
        "mean_citation_precision": round(sum(r["citation_precision"] for r in detected) / len(detected), 3) if detected else 0.0,
        "clean_outputs": f"{sum(1 for r in detected if r['clean'])}/{len(detected)}",
    }
    return {"summary": summary, "per_incident": per_incident}


def to_markdown(result: dict) -> str:
    s = result["summary"]
    out = [
        f"## Evaluation: provider `{s['provider']}` ({s['model']}), prompt {s['prompt_version']}",
        "",
        "| Metric | Value |",
        "|---|---|",
    ]
    for key in (
        "window_precision",
        "window_recall",
        "window_f1",
        "incidents_detected",
        "false_incidents",
        "root_cause_accuracy",
        "mean_citation_precision",
        "clean_outputs",
    ):
        out.append(f"| {key.replace('_', ' ')} | {s[key]} |")
    out += ["", "| Incident | Detected | Delay (s) | Root cause correct | Citation precision | Confidence |", "|---|---|---|---|---|---|"]
    for r in result["per_incident"]:
        if r["detected"]:
            out.append(
                f"| {r['id']}: {r['name']} | yes | {r['delay_seconds']} | {'yes' if r['root_cause_hit'] else 'no'} "
                f"| {r['citation_precision']:.2f} | {r['confidence']} |"
            )
        else:
            out.append(f"| {r['id']}: {r['name']} | no | - | - | - | - |")
    return "\n".join(out) + "\n"


def load_truth(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)
