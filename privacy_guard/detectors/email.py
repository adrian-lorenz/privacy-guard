from __future__ import annotations
import re
from .base import BaseDetector
from ..models import Finding, PiiType

_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")


class EmailDetector(BaseDetector):
    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []

        for match in _EMAIL_RE.finditer(text):
            findings.append(
                Finding(
                    pii_type=PiiType.EMAIL,
                    start=match.start(),
                    end=match.end(),
                    text=match.group(0),
                    confidence=1.0,
                    placeholder="",
                )
            )

        return findings
