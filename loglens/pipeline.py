"""End-to-end pipeline: parse -> detect -> analyse -> JSON report."""
from __future__ import annotations

from datetime import datetime
from typing import Iterable, Optional

from .detector import Incident, detect
from .llm import PROMPT_VERSION, Provider, RulesProvider, analyze_incident
from .parser import ParseResult, parse_lines


def incident_to_dict(incident: Incident, analysis: dict, meta: dict) -> dict:
    return {
        "id": incident.id,
        "start": incident.start.isoformat(),
        "end": incident.end.isoformat(),
        "duration_seconds": incident.duration_seconds,
        "peak_z": round(incident.peak_z, 1),
        "level_counts": incident.level_counts,
        "components": incident.components,
        "top_templates": incident.top_templates,
        "evidence": [
            {
                "line": r.line_no,
                "ts": r.ts.isoformat(),
                "level": r.level,
                "component": r.component,
                "text": r.message + (" | " + " ".join(r.extra[:2]) if r.extra else ""),
            }
            for r in incident.evidence
        ],
        "analysis": analysis,
        "analysis_meta": meta,
    }


def run(
    lines: Iterable[str],
    provider: Optional[Provider] = None,
    source: str = "uploaded",
    window_seconds: int = 60,
    z_threshold: float = 4.0,
):
    """Return (report_dict, incidents, windows). Pass the same lines to evaluate and to the API."""
    provider = provider or RulesProvider()
    parsed: ParseResult = parse_lines(lines)
    windows, incidents = detect(parsed.records, window_seconds=window_seconds, z_threshold=z_threshold)

    results = []
    for incident in incidents:
        analysis, meta = analyze_incident(incident, provider)
        results.append(incident_to_dict(incident, analysis, meta))

    report = {
        "meta": {
            "source": source,
            "total_lines": parsed.total_lines,
            "parsed_records": len(parsed.records),
            "unparsed_lines": parsed.unparsed_lines,
            "distinct_templates": len({r.template_id for r in parsed.records}),
            "window_seconds": window_seconds,
            "z_threshold": z_threshold,
            "provider": provider.name,
            "model": provider.model,
            "prompt_version": PROMPT_VERSION,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
        },
        "timeline": [
            {
                "start": w.start.isoformat(),
                "total": w.total,
                "errors": w.errors,
                "warns": w.warns,
                "severity": round(w.severity, 2),
                "z": round(w.z, 1),
                "anomalous": w.anomalous,
            }
            for w in windows
        ],
        "incidents": results,
    }
    return report, incidents, windows
