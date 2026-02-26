from __future__ import annotations
import re
from .base import BaseDetector
from ..models import Finding, PiiType

# German document numbers: Personalausweis and Reisepass share the same format.
# Format: 1 uppercase letter (series/issuing letter) + 8 uppercase letters or digits.
# Examples: C22990047 (Personalausweis), C12345678 (Reisepass), L01X00T47
# Word boundaries prevent matching inside longer alphanumeric strings (e.g. IBANs).
_PERSONAL_ID_PATTERN = re.compile(r"\b[A-Z][A-Z0-9]{8}\b")


class PersonalIdDetector(BaseDetector):
    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in _PERSONAL_ID_PATTERN.finditer(text):
            findings.append(
                Finding(
                    pii_type=PiiType.PERSONAL_ID,
                    start=match.start(),
                    end=match.end(),
                    text=match.group(),
                    confidence=0.75,
                    placeholder="",
                )
            )
        return findings
