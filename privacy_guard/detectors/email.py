from __future__ import annotations
import re
from .base import BaseDetector
from ..models import Finding, PiiType

_EMAIL_RE = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
)


class EmailDetector(BaseDetector):
    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        counter: dict[str, int] = {}

        for match in _EMAIL_RE.finditer(text):
            key = PiiType.EMAIL.value
            counter[key] = counter.get(key, 0) + 1
            placeholder = f"[{key}_{counter[key]}]"

            findings.append(Finding(
                pii_type=PiiType.EMAIL,
                start=match.start(),
                end=match.end(),
                text=match.group(0),
                confidence=1.0,
                placeholder=placeholder,
            ))

        return findings
