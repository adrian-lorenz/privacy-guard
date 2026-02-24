"""Detect secrets (API keys, tokens, credentials) using regex rules.

Rules are loaded from privacy_guard/data/secret_rules.toml, converted from
the leakguard Rust scanner (/Users/adrian/Git/pyl/src/rules.rs).

Each rule specifies a secret_group: 0 means the full match is redacted;
N > 0 means only that capture group is redacted (preserving surrounding context).
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .base import BaseDetector
from ..models import Finding, PiiType

_DATA_DIR = Path(__file__).parent.parent / "data"

_SEVERITY_CONFIDENCE: dict[str, float] = {
    "CRITICAL": 1.0,
    "HIGH":     0.9,
    "MEDIUM":   0.75,
    "LOW":      0.6,
    "WARNING":  0.5,
}


@dataclass(frozen=True)
class _Rule:
    id: str
    description: str
    pattern: re.Pattern[str]
    secret_group: int
    severity: str
    tags: tuple[str, ...]


def _load_rules() -> list[_Rule]:
    with (_DATA_DIR / "secret_rules.toml").open("rb") as fh:
        data = tomllib.load(fh)

    rules: list[_Rule] = []
    for r in data["rules"]:
        flags = re.UNICODE
        if r.get("multiline"):
            flags |= re.MULTILINE
        rules.append(_Rule(
            id=r["id"],
            description=r["description"],
            pattern=re.compile(r["pattern"], flags),
            secret_group=r["secret_group"],
            severity=r["severity"],
            tags=tuple(r.get("tags", [])),
        ))
    return rules


_RULES: list[_Rule] = _load_rules()


class SecretDetector(BaseDetector):
    """Detect secrets, credentials, and API keys using pattern-based rules."""

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        counter: dict[str, int] = {}

        for rule in _RULES:
            for match in rule.pattern.finditer(text):
                g = rule.secret_group
                try:
                    secret_text = match.group(g)
                    start = match.start(g)
                    end = match.end(g)
                except IndexError:
                    continue

                if not secret_text:
                    continue

                key = PiiType.SECRET.value
                counter[key] = counter.get(key, 0) + 1
                placeholder = f"[{key}_{counter[key]}]"

                findings.append(Finding(
                    pii_type=PiiType.SECRET,
                    start=start,
                    end=end,
                    text=secret_text,
                    confidence=_SEVERITY_CONFIDENCE.get(rule.severity, 0.8),
                    placeholder=placeholder,
                    rule_id=rule.id,
                ))

        return findings
