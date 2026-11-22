"""Tests. Run with:  python -m unittest discover -s tests -v   (or: pytest)"""
import json
import threading
import unittest
import urllib.request
from datetime import datetime, timedelta
from http.server import ThreadingHTTPServer

from loglens import generate
from loglens.detector import detect
from loglens.evaluate import evaluate
from loglens.llm import (
    AnalysisError,
    Provider,
    RulesProvider,
    analyze_incident,
    extract_json,
    validate_analysis,
)
from loglens.parser import mask_message, parse_lines
from loglens.pipeline import run
from loglens.server import make_handler


def make_lines(minutes=40, spike_at=None, spike_len=3, per_min=20):
    """Quiet INFO traffic, optionally with an error burst."""
    start = datetime(2026, 1, 1, 0, 0, 0)
    lines = []
    for m in range(minutes):
        for s in range(per_min):
            ts = start + timedelta(minutes=m, seconds=s * (60 // per_min))
            in_spike = spike_at is not None and spike_at <= m < spike_at + spike_len
            if in_spike:
                lines.append(f"{ts:%Y-%m-%d %H:%M:%S} ERROR db: connection refused by host 10.0.0.{s}")
            else:
                lines.append(f"{ts:%Y-%m-%d %H:%M:%S} INFO web: request {s} ok in {s + 5}ms")
    return lines


class ParserTests(unittest.TestCase):
    def test_masking_makes_equal_templates(self):
        a = mask_message("GET /api/orders/1042 200 38ms")
        b = mask_message("GET /api/orders/7 200 91ms")
        self.assertEqual(a, b)
        self.assertEqual(a, "GET /api/orders/<NUM> <NUM> <NUM>ms")

    def test_masks_ip_uuid_hex_user(self):
        self.assertIn("<IP>", mask_message("failed from 203.0.113.9"))
        self.assertIn("<UUID>", mask_message("id 123e4567-e89b-12d3-a456-426614174000 gone"))
        self.assertIn("<HEX>", mask_message("segfault at 0x7ffe12ab"))
        self.assertEqual(mask_message("failed login for user alice"), "failed login for user <USER>")

    def test_identifiers_with_letters_are_kept(self):
        self.assertIn("sda1", mask_message("disk usage 91% on /dev/sda1"))

    def test_levels_and_continuation_lines(self):
        lines = [
            "2026-11-20 08:00:00 CRITICAL svc: boom",
            "    at module.func (file.py:12)",
            "    at other.func (file.py:99)",
            "2026-11-20 08:00:01 WARNING svc: careful",
        ]
        parsed = parse_lines(lines)
        self.assertEqual(len(parsed.records), 2)
        self.assertEqual(parsed.records[0].level, "ERROR")
        self.assertEqual(parsed.records[1].level, "WARN")
        self.assertEqual(len(parsed.records[0].extra), 2)
        self.assertEqual(parsed.records[1].line_no, 4)

    def test_leading_garbage_is_counted_not_fatal(self):
        parsed = parse_lines(["not a log line", "2026-11-20 08:00:00 INFO a: ok"])
        self.assertEqual(parsed.unparsed_lines, 1)
        self.assertEqual(len(parsed.records), 1)


class DetectorTests(unittest.TestCase):
    def test_quiet_log_has_no_incidents(self):
        _, incidents = detect(parse_lines(make_lines()).records)
        self.assertEqual(incidents, [])

    def test_burst_is_detected_with_right_span(self):
        windows, incidents = detect(parse_lines(make_lines(spike_at=20, spike_len=3)).records)
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc.start, datetime(2026, 1, 1, 0, 20))
        self.assertEqual(inc.end, datetime(2026, 1, 1, 0, 23))
        self.assertTrue(inc.top_templates[0]["novel"])

    def test_long_incident_does_not_become_the_baseline(self):
        # 15 anomalous minutes in a row: later windows must still be flagged.
        _, incidents = detect(parse_lines(make_lines(minutes=50, spike_at=15, spike_len=15)).records)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].duration_seconds, 15 * 60)

    def test_evidence_is_capped_and_sorted(self):
        _, incidents = detect(parse_lines(make_lines(spike_at=20)).records)
        lines = [r.line_no for r in incidents[0].evidence]
        self.assertLessEqual(len(lines), 14)
        self.assertEqual(lines, sorted(lines))


class LlmLayerTests(unittest.TestCase):
    def test_extract_json_handles_fences_and_chatter(self):
        self.assertEqual(extract_json('```json\n{"a": 1}\n```'), {"a": 1})
        self.assertEqual(extract_json('Sure! {"a": 2} hope that helps'), {"a": 2})
        with self.assertRaises(AnalysisError):
            extract_json("no json here")

    def good(self, **over):
        base = {
            "summary": "s", "root_cause": "r", "confidence": "high", "severity": "high",
            "evidence_lines": [10, 11], "recommended_actions": ["a"],
        }
        base.update(over)
        return base

    def test_hallucinated_citations_are_dropped(self):
        clean, issues = validate_analysis(self.good(evidence_lines=[10, 999]), {10, 11})
        self.assertEqual(clean["evidence_lines"], [10])
        self.assertTrue(any("not in the evidence" in i for i in issues))
        self.assertEqual(clean["confidence"], "high")

    def test_no_valid_citation_forces_low_confidence(self):
        clean, issues = validate_analysis(self.good(evidence_lines=[500]), {10, 11})
        self.assertEqual(clean["confidence"], "low")
        self.assertEqual(clean["evidence_lines"], [])

    def test_accepts_L_prefixed_citations(self):
        clean, _ = validate_analysis(self.good(evidence_lines=["L10", "L11"]), {10, 11})
        self.assertEqual(clean["evidence_lines"], [10, 11])

    def test_schema_violations_raise(self):
        for bad in ({"summary": "x"}, self.good(confidence="certain"), self.good(severity="meh"),
                    self.good(evidence_lines="10"), self.good(root_cause="  ")):
            with self.assertRaises(AnalysisError):
                validate_analysis(bad, {10, 11})

    def _incident(self):
        _, incidents = detect(parse_lines(make_lines(spike_at=20)).records)
        return incidents[0]

    def test_retry_then_success(self):
        incident = self._incident()
        cited = incident.evidence[0].line_no

        class Flaky(Provider):
            name, model, calls = "flaky", "test", 0

            def complete(self, system, user, context=None):
                Flaky.calls += 1
                if Flaky.calls == 1:
                    return "I think the database is down."
                return json.dumps({"summary": "s", "root_cause": "db down", "confidence": "medium",
                                   "severity": "high", "evidence_lines": [cited], "recommended_actions": []})

        analysis, meta = analyze_incident(incident, Flaky())
        self.assertEqual(meta["attempts"], 2)
        self.assertFalse(meta["fallback_used"])
        self.assertEqual(analysis["evidence_lines"], [cited])

    def test_fallback_to_rules_after_two_failures(self):
        class Broken(Provider):
            name, model = "broken", "test"

            def complete(self, system, user, context=None):
                return "not json"

        analysis, meta = analyze_incident(self._incident(), Broken())
        self.assertTrue(meta["fallback_used"])
        self.assertEqual(meta["provider"], "rules")
        self.assertIn(analysis["confidence"], ("low", "medium"))

    def test_provider_errors_also_fall_back(self):
        class Down(Provider):
            name, model = "down", "test"

            def complete(self, system, user, context=None):
                raise AnalysisError("could not reach model API")

        _, meta = analyze_incident(self._incident(), Down())
        self.assertTrue(meta["fallback_used"])


class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lines, cls.truth = generate.generate(seed=7)

    def test_generator_is_deterministic(self):
        again, _ = generate.generate(seed=7)
        self.assertEqual(again, self.lines)

    def test_all_injected_incidents_found_no_false_incidents(self):
        result = evaluate(self.lines, self.truth, RulesProvider())
        s = result["summary"]
        self.assertEqual(s["incidents_detected"], "4/4")
        self.assertEqual(s["false_incidents"], 0)
        self.assertGreaterEqual(s["window_recall"], 0.95)
        self.assertGreaterEqual(s["window_precision"], 0.9)

    def test_rules_baseline_misses_the_unseen_incident_and_says_low_confidence(self):
        result = evaluate(self.lines, self.truth, RulesProvider())
        row = {r["id"]: r for r in result["per_incident"]}
        self.assertTrue(row["A"]["root_cause_hit"])
        self.assertFalse(row["D"]["root_cause_hit"])
        self.assertEqual(row["D"]["confidence"], "low")

    def test_cited_lines_exist_in_report_evidence(self):
        report, _, _ = run(self.lines, RulesProvider())
        for inc in report["incidents"]:
            shown = {e["line"] for e in inc["evidence"]}
            self.assertTrue(set(inc["analysis"]["evidence_lines"]) <= shown)


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler("does-not-exist.json"))
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def post(self, body: str, query: str = ""):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/api/analyze{query}", data=body.encode(), method="POST")
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_analyze_endpoint_returns_report(self):
        status, body = self.post("\n".join(make_lines(spike_at=20)))
        self.assertEqual(status, 200)
        self.assertEqual(len(body["incidents"]), 1)

    def test_unparseable_input_gives_clear_error(self):
        status, body = self.post("hello\nworld")
        self.assertEqual(status, 400)
        self.assertIn("expected format", body["error"])

    def test_missing_report_is_404(self):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{self.port}/api/report")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 404)

    def test_unknown_provider_is_rejected(self):
        status, body = self.post("\n".join(make_lines()), "?provider=bogus")
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
