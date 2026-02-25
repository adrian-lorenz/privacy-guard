from __future__ import annotations
import re
from .base import BaseDetector
from ..models import Finding, PiiType

# Matches DACH phone numbers in international and national format.
# International: +49/+43/+41 or 0049/0043/0041
# National (DE/AT/CH): starts with 0, not 00
# Separators allowed: space, dash, slash, parentheses
_PHONE_RE = re.compile(
    r"""
    (?<![+\d])
    (?:
        # International: +49 171 1234567 / 0049 30 12345678 / +41 44 668 18 00
        (?:\+|00)(?:49|43|41)
        [\s()\-]*
        (?:\(0\)[\s()\-]*)?         # optional (0) after country code
        \d[\d\s()\-]{5,16}\d
    |
        # National: 0171 1234567 / 030 12345678 / 0221/123456
        0(?!0)\d                    # leading 0 + first digit (not another 0)
        [\d\s\-/]{5,13}\d
    )
    (?!\d)
    """,
    re.VERBOSE,
)

_MIN_DIGITS = 9


def _digit_count(s: str) -> int:
    return sum(1 for c in s if c.isdigit())


class PhoneDetector(BaseDetector):
    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []

        for match in _PHONE_RE.finditer(text):
            raw = match.group(0).rstrip()
            if _digit_count(raw) < _MIN_DIGITS:
                continue

            findings.append(
                Finding(
                    pii_type=PiiType.PHONE,
                    start=match.start(),
                    end=match.start() + len(raw),
                    text=raw,
                    confidence=1.0,
                    placeholder="",
                )
            )

        return findings
