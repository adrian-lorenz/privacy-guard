from __future__ import annotations
import re
from .base import BaseDetector
from ..models import Finding, PiiType

# German Umsatzsteuer-Identifikationsnummer (USt-IdNr).
# Format: DE + 9 digits, optionally space-separated in groups of 3.
# Examples: DE123456789, DE 123 456 789, DE123 456789
_VAT_ID_PATTERN = re.compile(r"\bDE[ ]?[0-9]{3}[ ]?[0-9]{3}[ ]?[0-9]{3}\b")


def _validate_vat_id(raw: str) -> bool:
    """Validate that after stripping spaces we have exactly DE + 9 digits."""
    digits = raw.replace(" ", "")
    return len(digits) == 11 and digits[:2] == "DE" and digits[2:].isdigit()


class VatIdDetector(BaseDetector):
    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in _VAT_ID_PATTERN.finditer(text):
            if _validate_vat_id(match.group()):
                findings.append(
                    Finding(
                        pii_type=PiiType.VAT_ID,
                        start=match.start(),
                        end=match.end(),
                        text=match.group(),
                        confidence=0.85,
                        placeholder="",
                    )
                )
        return findings
