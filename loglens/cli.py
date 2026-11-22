"""Command line interface: generate, analyze, evaluate, serve."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import generate as gen
from .evaluate import evaluate, load_truth, to_markdown
from .llm import AnalysisError, get_provider
from .pipeline import run


def _read_lines(path: str):
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read().splitlines()


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--provider", default="rules", choices=["rules", "openai", "anthropic"])
    p.add_argument("--model", default=None, help="model name (or set LOGLENS_MODEL)")
    p.add_argument("--window", type=int, default=60, help="window size in seconds")
    p.add_argument("--z", type=float, default=4.0, help="anomaly threshold (robust z-score)")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="loglens", description="Log anomaly detection with LLM incident analysis")
    sub = parser.add_subparsers(dest="command", required=True)

    g = sub.add_parser("generate", help="write a synthetic log with labelled incidents")
    g.add_argument("--out", default="data/sample.log")
    g.add_argument("--truth", default="data/truth.json")
    g.add_argument("--seed", type=int, default=7)

    a = sub.add_parser("analyze", help="analyse a log file and write a JSON report")
    a.add_argument("logfile")
    a.add_argument("--out", default="results/report.json")
    _add_common(a)

    e = sub.add_parser("evaluate", help="score detection and analysis against labelled incidents")
    e.add_argument("--log", default="data/sample.log")
    e.add_argument("--truth", default="data/truth.json")
    e.add_argument("--out", default="results/eval.md")
    _add_common(e)

    s = sub.add_parser("serve", help="serve the dashboard and API")
    s.add_argument("--report", default="results/report.json")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--host", default="127.0.0.1", help="use 0.0.0.0 inside Docker")

    args = parser.parse_args(argv)

    try:
        if args.command == "generate":
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            gen.write(args.out, args.truth, args.seed)
            print(f"wrote {args.out} and {args.truth}")
            return 0

        if args.command == "analyze":
            provider = get_provider(args.provider, args.model)
            report, _, _ = run(_read_lines(args.logfile), provider, source=Path(args.logfile).name,
                               window_seconds=args.window, z_threshold=args.z)
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
            print(f"{report['meta']['parsed_records']} records, {len(report['incidents'])} incident(s) -> {args.out}")
            for inc in report["incidents"]:
                a_ = inc["analysis"]
                print(f"  {inc['id']} {inc['start'][11:16]}-{inc['end'][11:16]} [{a_['severity']}] {a_['root_cause']}")
            return 0

        if args.command == "evaluate":
            provider = get_provider(args.provider, args.model)
            result = evaluate(_read_lines(args.log), load_truth(args.truth), provider,
                              window_seconds=args.window, z_threshold=args.z)
            text = to_markdown(result)
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(text, encoding="utf-8")
            print(text)
            return 0

        if args.command == "serve":
            from .server import serve

            serve(args.report, args.port, args.host)
            return 0
    except (AnalysisError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
