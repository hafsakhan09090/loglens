"""LLM layer: prompt, providers, output validation and guardrails.

The model never sees the whole log. It gets a statistical summary of one
incident plus a short, numbered list of evidence lines, and must answer with a
JSON object. Every answer is validated:

* the JSON must match the schema,
* cited line numbers must exist in the evidence we sent (anything else is
  treated as a hallucinated citation and dropped),
* an answer with no valid citation is downgraded to low confidence.

If the model returns unusable output twice, we fall back to the rule-based
provider instead of failing the whole run.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from collections import Counter
from typing import Dict, List, Optional, Tuple

from .detector import Incident

PROMPT_VERSION = "v1"

SYSTEM_PROMPT = """You are a site-reliability assistant that analyses application log incidents.
You receive a statistical summary of one anomalous time window and a numbered list of log lines (the evidence).

Rules:
- Reply with ONE JSON object and nothing else. No markdown, no commentary.
- Use only facts that appear in the input. Do not invent services, metrics or causes.
- Cite supporting evidence by line number in "evidence_lines". Only cite numbers that appear in the input.
- If the evidence is not enough to name a root cause, say so in "root_cause" and set "confidence" to "low".

JSON schema:
{
  "summary": "2-3 sentences: what happened and what was affected",
  "root_cause": "most likely cause, stated plainly",
  "confidence": "low" | "medium" | "high",
  "severity": "low" | "medium" | "high" | "critical",
  "evidence_lines": [line numbers that support the root cause],
  "recommended_actions": ["up to 5 concrete next steps"]
}"""

CONFIDENCE = ("low", "medium", "high")
SEVERITY = ("low", "medium", "high", "critical")


class AnalysisError(Exception):
    """Raised when a model answer cannot be turned into a valid analysis."""


# ---------------------------------------------------------------- prompt ----

def incident_payload(incident: Incident) -> dict:
    return {
        "window": {
            "start": incident.start.isoformat(),
            "end": incident.end.isoformat(),
            "duration_seconds": incident.duration_seconds,
        },
        "level_counts": incident.level_counts,
        "components_with_most_warnings_or_errors": incident.components,
        "top_patterns": incident.top_templates,
        "evidence": [
            {
                "line": r.line_no,
                "text": f"{r.ts:%H:%M:%S} {r.text()}" + (f" | {' '.join(r.extra[:2])}" if r.extra else ""),
            }
            for r in incident.evidence
        ],
    }


def build_user_prompt(payload: dict) -> str:
    lines = [
        f"Incident window: {payload['window']['start']} to {payload['window']['end']} "
        f"({payload['window']['duration_seconds']}s)",
        f"Log levels in window: {json.dumps(payload['level_counts'])}",
        "Most affected components: "
        + ", ".join(f"{c['component']} ({c['count']})" for c in payload["components_with_most_warnings_or_errors"]),
        "Most frequent WARN/ERROR patterns (count, novel = first seen in this window):",
    ]
    for t in payload["top_patterns"]:
        lines.append(f"  - x{t['count']} {t['level']} {t['component']}: {t['template']}" + (" [novel]" if t["novel"] else ""))
    lines.append("Evidence (line number, text):")
    for e in payload["evidence"]:
        lines.append(f"  L{e['line']}: {e['text']}")
    return "\n".join(lines)


# ------------------------------------------------------------ validation ----

def extract_json(raw: str) -> dict:
    text = raw.strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.IGNORECASE)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise AnalysisError("no JSON object found in model output")
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError as exc:
        raise AnalysisError(f"invalid JSON: {exc}") from exc


def validate_analysis(obj, allowed_lines: set) -> Tuple[dict, List[str]]:
    """Return (clean_analysis, issues). Raise AnalysisError if structurally unusable."""
    if not isinstance(obj, dict):
        raise AnalysisError("answer is not a JSON object")
    issues: List[str] = []
    clean: Dict[str, object] = {}
    for key in ("summary", "root_cause"):
        value = obj.get(key)
        if not isinstance(value, str) or not value.strip():
            raise AnalysisError(f"missing or empty '{key}'")
        clean[key] = value.strip()

    confidence = str(obj.get("confidence", "")).strip().lower()
    if confidence not in CONFIDENCE:
        raise AnalysisError("confidence must be low, medium or high")
    severity = str(obj.get("severity", "")).strip().lower()
    if severity not in SEVERITY:
        raise AnalysisError("severity must be low, medium, high or critical")

    cited = obj.get("evidence_lines")
    if not isinstance(cited, list):
        raise AnalysisError("'evidence_lines' must be a list")
    numbers: List[int] = []
    for item in cited:
        match = re.search(r"\d+", str(item))
        if match:
            numbers.append(int(match.group()))
    valid = sorted({n for n in numbers if n in allowed_lines})
    dropped = len(set(numbers)) - len(valid)
    if dropped:
        issues.append(f"dropped {dropped} citation(s) that are not in the evidence")
    if not valid:
        issues.append("no valid citation; confidence lowered")
        confidence = "low"

    actions = obj.get("recommended_actions", [])
    if not isinstance(actions, list):
        actions = []
    clean.update(
        confidence=confidence,
        severity=severity,
        evidence_lines=valid,
        recommended_actions=[str(a).strip() for a in actions if str(a).strip()][:5],
    )
    return clean, issues


# ------------------------------------------------------------- providers ----

class Provider:
    name = "base"
    model = ""

    def complete(self, system: str, user: str, context: Optional[dict] = None) -> str:
        raise NotImplementedError


_RULES = [
    (
        re.compile(r"connection pool exhausted|pool exhausted|wait time exceeded", re.I),
        "Database connection pool exhausted: requests queue for a connection and upstream calls time out.",
        "high",
        [
            "Check for long-running queries or leaked connections holding the pool.",
            "Temporarily raise the pool size or shed load while the cause is fixed.",
            "Add or lower client-side timeouts so waiting requests fail fast.",
        ],
    ),
    (
        re.compile(r"no space left|disk usage (9\d|100)|inode usage", re.I),
        "Storage volume is full, so writes and jobs that depend on disk are failing.",
        "critical",
        [
            "Free space on the affected volume (rotate logs, remove temp files).",
            "Find what grew unexpectedly and add disk usage alerts below 85%.",
        ],
    ),
    (
        re.compile(r"failed login|account locked|rate limit exceeded", re.I),
        "Repeated failed logins from a small set of addresses point to a brute-force or credential-stuffing attempt.",
        "high",
        [
            "Block or rate-limit the offending source addresses.",
            "Review locked accounts and notify affected users.",
            "Enable MFA and add login-failure alerting.",
        ],
    ),
    (
        re.compile(r"out of memory|oom|cannot allocate", re.I),
        "A service ran out of memory.",
        "high",
        ["Check memory limits and recent deploys.", "Capture a heap profile before restarting."],
    ),
]


class RulesProvider(Provider):
    """Offline baseline: keyword rules, no model. Useful as a comparison point and as a fallback."""

    name = "rules"
    model = "keyword-rules-v1"

    def complete(self, system: str, user: str, context: Optional[dict] = None) -> str:
        context = context or {}
        evidence = context.get("evidence", [])
        patterns = context.get("top_patterns", [])
        levels = context.get("level_counts", {})
        blob_for = lambda rx: [e["line"] for e in evidence if rx.search(e["text"])]

        best = None
        total = sum(p["count"] for p in patterns) or 1
        for rx, cause, severity, actions in _RULES:
            hits = sum(p["count"] for p in patterns if rx.search(p["template"]))
            # a rule must explain a meaningful share of the incident, not just background noise
            if hits / total >= 0.3 and (best is None or hits > best[0]):
                best = (hits, rx, cause, severity, actions)

        if best:
            _, rx, cause, severity, actions = best
            cited = blob_for(rx)[:5]
            confidence = "medium"
        else:
            cause = "Unclear from the available evidence; no known failure pattern matched."
            severity = "medium"
            actions = ["Inspect the cited lines manually.", "Add a rule or prompt example for this failure type."]
            cited = [e["line"] for e in evidence if " ERROR " in f" {e['text']} "][:3]
            confidence = "low"

        dominant = patterns[0]["template"] if patterns else "n/a"
        summary = (
            f"{levels.get('ERROR', 0)} errors and {levels.get('WARN', 0)} warnings between "
            f"{context['window']['start'][11:16]} and {context['window']['end'][11:16]}. Dominant pattern: {dominant}"
        )
        return json.dumps(
            {
                "summary": summary,
                "root_cause": cause,
                "confidence": confidence,
                "severity": severity,
                "evidence_lines": cited,
                "recommended_actions": actions,
            }
        )


def _post_json(url: str, headers: dict, body: dict, timeout: int) -> dict:
    request = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:300]
        raise AnalysisError(f"HTTP {exc.code} from model API: {detail}") from exc
    except urllib.error.URLError as exc:
        raise AnalysisError(f"could not reach model API: {exc.reason}") from exc


class OpenAICompatibleProvider(Provider):
    """Any server that speaks the OpenAI chat-completions format (OpenAI, Ollama, vLLM, ...)."""

    name = "openai"

    def __init__(self, api_key=None, base_url=None, model=None, timeout=60):
        self.api_key = api_key or os.environ.get("LOGLENS_API_KEY") or os.environ.get("OPENAI_API_KEY", "")
        self.base_url = (base_url or os.environ.get("LOGLENS_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
        self.model = model or os.environ.get("LOGLENS_MODEL") or "gpt-4o-mini"
        self.timeout = timeout
        if not self.api_key:
            raise AnalysisError("set LOGLENS_API_KEY (or OPENAI_API_KEY) to use the 'openai' provider")

    def complete(self, system, user, context=None):
        data = _post_json(
            f"{self.base_url}/chat/completions",
            {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            {
                "model": self.model,
                "temperature": 0.1,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            },
            self.timeout,
        )
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise AnalysisError("unexpected response shape from model API") from exc


class AnthropicProvider(Provider):
    name = "anthropic"

    def __init__(self, api_key=None, model=None, timeout=60):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("LOGLENS_API_KEY", "")
        self.model = model or os.environ.get("LOGLENS_MODEL") or "claude-sonnet-5-5"
        self.timeout = timeout
        if not self.api_key:
            raise AnalysisError("set ANTHROPIC_API_KEY to use the 'anthropic' provider")

    def complete(self, system, user, context=None):
        data = _post_json(
            "https://api.anthropic.com/v1/messages",
            {"x-api-key": self.api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
            {
                "model": self.model,
                "max_tokens": 1000,
                "temperature": 0.1,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
            self.timeout,
        )
        try:
            return "".join(block.get("text", "") for block in data["content"])
        except (KeyError, TypeError) as exc:
            raise AnalysisError("unexpected response shape from model API") from exc


def get_provider(name: str, model: Optional[str] = None) -> Provider:
    if name == "rules":
        return RulesProvider()
    if name == "openai":
        return OpenAICompatibleProvider(model=model)
    if name == "anthropic":
        return AnthropicProvider(model=model)
    raise AnalysisError(f"unknown provider '{name}' (use rules, openai or anthropic)")


# --------------------------------------------------------------- analyse ----

def analyze_incident(incident: Incident, provider: Provider, max_attempts: int = 2) -> Tuple[dict, dict]:
    """Run the model on one incident. Returns (analysis, meta)."""
    payload = incident_payload(incident)
    allowed = {e["line"] for e in payload["evidence"]}
    user_prompt = build_user_prompt(payload)

    issues: List[str] = []
    attempts = 0
    prompt = user_prompt
    for attempts in range(1, max_attempts + 1):
        try:
            raw = provider.complete(SYSTEM_PROMPT, prompt, payload)
            analysis, issues = validate_analysis(extract_json(raw), allowed)
            return analysis, _meta(provider, attempts, issues, fallback=False)
        except AnalysisError as exc:
            issues = [f"attempt {attempts} failed: {exc}"]
            prompt = user_prompt + f"\n\nYour previous answer was rejected: {exc}. Reply with valid JSON only."

    fallback = RulesProvider()
    raw = fallback.complete(SYSTEM_PROMPT, user_prompt, payload)
    analysis, extra = validate_analysis(extract_json(raw), allowed)
    return analysis, _meta(fallback, attempts, issues + extra, fallback=True)


def _meta(provider: Provider, attempts: int, issues: List[str], fallback: bool) -> dict:
    return {
        "provider": provider.name,
        "model": provider.model,
        "prompt_version": PROMPT_VERSION,
        "attempts": attempts,
        "issues": issues,
        "fallback_used": fallback,
    }
