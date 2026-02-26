from __future__ import annotations
import re
from .base import BaseDetector
from ..models import Finding, PiiType

# German Rentenversicherungsnummer (Sozialversicherungsnummer / RVNR).
# Format: NN DDDDDD L DDD
#   NN     — 2-digit Rentenversicherungsträger code
#   DDDDDD — 6 digits encoding birth date (TTMMJJ; women add 50 to day)
#   L      — first uppercase letter of birth surname
#   DDD    — 3-digit serial + check digit
# Examples: "12 345678 X 123", "12345678X123"
_SVN_PATTERN = re.compile(r"\b\d{2}[ ]?\d{6}[ ]?[A-Z][ ]?\d{3}\b")


class SocialSecurityDetector(BaseDetector):
    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in _SVN_PATTERN.finditer(text):
            findings.append(
                Finding(
                    pii_type=PiiType.SOCIAL_SECURITY,
                    start=match.start(),
                    end=match.end(),
                    text=match.group(),
                    confidence=0.9,
                    placeholder="",
                )
            )
        return findings
