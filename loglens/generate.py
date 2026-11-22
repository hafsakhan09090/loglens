"""Synthetic log generator with labelled incidents.

Real production logs are private, so this produces four hours of plausible
service logs plus four injected incidents with ground-truth labels. The labels
let `evaluate` measure detection precision/recall and citation accuracy.

Incident D (expired TLS certificate) is deliberately NOT covered by the
rule-based baseline, to show where an LLM is expected to add value.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta
from typing import List, Tuple

START = datetime(2026, 11, 20, 8, 0, 0)
DURATION_MINUTES = 240

# (start_minute, duration_minutes, id, name, expected root-cause keywords)
INCIDENTS = [
    (55, 9, "A", "database connection pool exhaustion", ["pool", "connection"]),
    (130, 6, "B", "disk full on storage node", ["disk", "space", "storage"]),
    (200, 5, "C", "credential stuffing against auth", ["brute", "credential", "login", "authentication"]),
    (225, 5, "D", "expired TLS certificate on payments upstream", ["certificate", "tls", "expired"]),
]

NAMES = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy"]


def _ip(rng: random.Random, prefix: str = "10.0") -> str:
    return f"{prefix}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _normal(rng: random.Random):
    roll = rng.random() * 100
    if roll < 33:
        return "INFO", "api-gateway", f"GET /api/orders/{rng.randint(1, 9999)} 200 {rng.randint(15, 120)}ms", []
    if roll < 42:
        return "INFO", "api-gateway", f"POST /api/checkout 200 {rng.randint(60, 240)}ms", []
    if roll < 50:
        return "INFO", "auth", f"user {rng.randint(1000, 9999)} logged in from {_ip(rng)}", []
    if roll < 56:
        return "INFO", "scheduler", f"job {rng.randint(100, 999)} completed in {rng.randint(200, 4000)}ms", []
    if roll < 61:
        return "INFO", "cache", f"cache hit ratio {rng.randint(82, 97)}%", []
    if roll < 76:
        return "INFO", "monitor", f"heartbeat ok node-{rng.randint(1, 6)}", []
    if roll < 84:
        return "INFO", "db-pool", f"active connections {rng.randint(5, 20)}/50", []
    if roll < 88:
        return "INFO", "storage", f"disk usage {rng.randint(55, 62)}% on /dev/sda1", []
    if roll < 94:
        return "INFO", "storage", f"write ok /var/data/{rng.randint(1, 9999)}.bin {rng.randint(5, 80)}ms", []
    if roll < 95.2:
        return "WARN", "db-pool", f"slow query took {rng.randint(800, 1500)}ms", []
    if roll < 96.4:
        return "WARN", "auth", f"failed login for user {rng.choice(NAMES)} from {_ip(rng)}", []
    if roll < 97.2:
        return "WARN", "cache", f"eviction pressure high, {rng.randint(70, 90)}% memory used", []
    noise = rng.choice(
        [
            ("ERROR", "cache", f"eviction failed for key session:{rng.randint(1, 99999)}", []),
            ("ERROR", "api-gateway", f"upstream 502 for GET /api/recommendations/{rng.randint(1, 999)}", []),
            ("ERROR", "scheduler", f"job {rng.randint(100, 999)} failed: transient network error", []),
        ]
    )
    return noise if rng.random() < 0.1 else _normal_info(rng)


def _normal_info(rng: random.Random):
    return "INFO", "monitor", f"heartbeat ok node-{rng.randint(1, 6)}", []


def _incident_lines(rng: random.Random, kind: str):
    if kind == "A":
        roll = rng.random()
        if roll < 0.35:
            return "ERROR", "db-pool", f"connection pool exhausted (active=50/50), request queued {rng.randint(500, 9000)}ms", []
        if roll < 0.6:
            extra = []
            if rng.random() < 0.3:
                extra = ["    at gateway.proxy.forward (proxy.py:88)", "    at gateway.http.handle (server.py:41)"]
            return "ERROR", "api-gateway", f"upstream timeout after 30000ms for GET /api/orders/{rng.randint(1, 9999)}", extra
        if roll < 0.8:
            return "WARN", "db-pool", f"wait time exceeded threshold: {rng.randint(1000, 8000)}ms", []
        return "ERROR", "api-gateway", f"GET /api/orders/{rng.randint(1, 9999)} 503 {rng.randint(30000, 31000)}ms", []
    if kind == "B":
        roll = rng.random()
        if roll < 0.4:
            return "ERROR", "storage", "write failed on /var/data: No space left on device", []
        if roll < 0.65:
            return "ERROR", "storage", f"disk usage {rng.randint(98, 100)}% on /dev/sda1", []
        if roll < 0.9:
            return "ERROR", "scheduler", f"job {rng.randint(100, 999)} failed: IOError writing checkpoint", []
        return "WARN", "storage", f"inode usage high: {rng.randint(93, 99)}%", []
    if kind == "C":
        roll = rng.random()
        ip = f"203.0.113.{rng.randint(1, 40)}"
        if roll < 0.7:
            return "WARN", "auth", f"failed login for user {rng.choice(NAMES)} from {ip}", []
        if roll < 0.85:
            return "ERROR", "auth", f"account locked after repeated failures for user {rng.choice(NAMES)}", []
        return "WARN", "api-gateway", f"rate limit exceeded for {ip}", []
    roll = rng.random()
    if roll < 0.55:
        return "ERROR", "api-gateway", "TLS handshake failed with upstream payments: certificate has expired", []
    if roll < 0.85:
        return "ERROR", "payments-client", f"payment request {rng.randint(1000, 9999)} aborted: SSL certificate verify failed", []
    return "WARN", "api-gateway", "retrying upstream payments connection", []


def generate(seed: int = 7) -> Tuple[List[str], dict]:
    rng = random.Random(seed)
    entries = []  # (ts, order, level, component, message, extra, tag)
    order = 0

    def add(ts, level, comp, msg, extra, tag):
        nonlocal order
        order += 1
        entries.append((ts, order, level, comp, msg, extra, tag))

    for sec in range(DURATION_MINUTES * 60):
        ts = START + timedelta(seconds=sec)
        for _ in range(rng.choice([0, 1, 1, 1, 2])):
            level, comp, msg, extra = _normal(rng)
            add(ts, level, comp, msg, extra, None)

    for start_min, duration, kind, name, _kw in INCIDENTS:
        for sec in range(duration * 60):
            ts = START + timedelta(minutes=start_min, seconds=sec)
            for _ in range(rng.choice([2, 3, 3, 4])):
                level, comp, msg, extra = _incident_lines(rng, kind)
                add(ts, level, comp, msg, extra, kind)
        if kind == "A":  # precursor: slow queries ramp up before the pool is exhausted
            for sec in range(0, 180, 4):
                ts = START + timedelta(minutes=start_min - 3, seconds=sec)
                add(ts, "WARN", "db-pool", f"slow query took {rng.randint(900, 2500)}ms", [], None)

    entries.sort(key=lambda e: (e[0], e[1]))
    lines: List[str] = []
    injected = {kind: [] for _, _, kind, _, _ in INCIDENTS}
    for ts, _o, level, comp, msg, extra, tag in entries:
        lines.append(f"{ts:%Y-%m-%d %H:%M:%S} {level} {comp}: {msg}")
        if tag:
            injected[tag].append(len(lines))
        for ex in extra:
            lines.append(ex)
            if tag:
                injected[tag].append(len(lines))

    truth = {
        "seed": seed,
        "start": START.isoformat(),
        "incidents": [
            {
                "id": kind,
                "name": name,
                "start": (START + timedelta(minutes=start_min)).isoformat(),
                "end": (START + timedelta(minutes=start_min + duration)).isoformat(),
                "expected_keywords": keywords,
                "injected_lines": injected[kind],
            }
            for start_min, duration, kind, name, keywords in INCIDENTS
        ],
    }
    return lines, truth


def write(log_path: str, truth_path: str, seed: int = 7) -> None:
    lines, truth = generate(seed)
    with open(log_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    with open(truth_path, "w", encoding="utf-8") as handle:
        json.dump(truth, handle, indent=2)
