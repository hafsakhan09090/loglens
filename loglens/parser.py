"""Log parsing and template mining.

Turns raw text lines into structured records and reduces each message to a
"template" by masking variable parts (numbers, IPs, UUIDs, user names).
Lines such as "GET /api/orders/1042 200 38ms" and "GET /api/orders/7 200 91ms"
then share one template, which is what makes counting and novelty detection possible.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, List

LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})(?:[.,]\d+)?\s+"
    r"(?P<level>DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|CRITICAL|FATAL)\s+"
    r"(?P<component>[\w.\-]+):\s*(?P<msg>.*)$"
)

_LEVEL_MAP = {
    "DEBUG": "DEBUG",
    "INFO": "INFO",
    "NOTICE": "INFO",
    "WARN": "WARN",
    "WARNING": "WARN",
    "ERROR": "ERROR",
    "CRITICAL": "ERROR",
    "FATAL": "ERROR",
}

# Order matters: more specific patterns must run before the generic number mask.
_MASKS = [
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<UUID>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), "<IP>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<HEX>"),
    (re.compile(r"(?i)\b(user\s+)[\w.@-]+"), r"\1<USER>"),
    (re.compile(r"(?<![A-Za-z_])\d+(?:\.\d+)?"), "<NUM>"),
]

MAX_EXTRA_LINES = 20


@dataclass
class LogRecord:
    line_no: int
    ts: datetime
    level: str
    component: str
    message: str
    template: str
    template_id: str
    extra: List[str] = field(default_factory=list)  # continuation lines, e.g. stack frames

    @property
    def is_serious(self) -> bool:
        return self.level in ("WARN", "ERROR")

    def text(self) -> str:
        return f"{self.level} {self.component}: {self.message}"


@dataclass
class ParseResult:
    records: List[LogRecord]
    total_lines: int
    unparsed_lines: int


def normalize_level(raw: str) -> str:
    return _LEVEL_MAP[raw.upper()]


def mask_message(message: str) -> str:
    out = message
    for pattern, repl in _MASKS:
        out = pattern.sub(repl, out)
    return out


def template_id_for(level: str, component: str, template: str) -> str:
    key = f"{level}|{component}|{template}"
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:8]


def parse_lines(lines: Iterable[str]) -> ParseResult:
    """Parse text lines. Lines that do not start a new record are treated as
    continuation lines (stack traces etc.) of the previous record."""
    records: List[LogRecord] = []
    total = 0
    unparsed = 0
    for line_no, raw in enumerate(lines, start=1):
        total += 1
        line = raw.rstrip("\r\n")
        if not line.strip():
            continue
        match = LINE_RE.match(line)
        if match:
            ts = datetime.fromisoformat(match.group("ts").replace(" ", "T"))
            level = normalize_level(match.group("level"))
            component = match.group("component")
            message = match.group("msg").strip()
            template = mask_message(message)
            records.append(
                LogRecord(
                    line_no=line_no,
                    ts=ts,
                    level=level,
                    component=component,
                    message=message,
                    template=template,
                    template_id=template_id_for(level, component, template),
                )
            )
        elif records:
            if len(records[-1].extra) < MAX_EXTRA_LINES:
                records[-1].extra.append(line.strip())
        else:
            unparsed += 1
    return ParseResult(records=records, total_lines=total, unparsed_lines=unparsed)


def parse_text(text: str) -> ParseResult:
    return parse_lines(text.splitlines())


def parse_file(path: str) -> ParseResult:
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return parse_lines(handle)
