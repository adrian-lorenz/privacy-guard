from __future__ import annotations
import re
from .base import BaseDetector
from ..models import Finding, PiiType

# German Steueridentifikationsnummer (IdNr): 11 digits.
# Rules: first digit 1–9; grouped as 2-3-3-3 (with optional single space between groups).
# Examples: "12 345 678 903" (formatted), "12345678903" (raw)
# Checksum uses the ISO 7064-derived mod-11 algorithm mandated by § 139b AO.
_TAX_ID_PATTERN = re.compile(r"\b[1-9]\d(?:[ ]?\d{3}){3}\b")


def _tax_id_check_digit(digits: str) -> int | None:
    """Return the expected check digit (0–9), or None if the number is structurally invalid."""
    if digits[0] == "0":
        return None
    product = 10
    for d in digits[:10]:
        total = (product + int(d)) % 10
        if total == 0:
            total = 10
        product = (total * 2) % 11
    check = 11 - product
    if check == 10:
        return None  # structurally invalid
    if check == 11:
        check = 0
    return check


def _validate_tax_id(raw: str) -> float | None:
    """Return confidence (1.0 or 0.6), or None if the format is wrong."""
    digits = raw.replace(" ", "")
    if len(digits) != 11 or digits[0] == "0":
        return None
    expected = _tax_id_check_digit(digits)
    if expected is None:
        return None  # structurally invalid number → skip
    return 1.0 if int(digits[10]) == expected else 0.6


class TaxIdDetector(BaseDetector):
    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in _TAX_ID_PATTERN.finditer(text):
            confidence = _validate_tax_id(match.group())
            if confidence is None:
                continue
            findings.append(
                Finding(
                    pii_type=PiiType.TAX_ID,
                    start=match.start(),
                    end=match.end(),
                    text=match.group(),
                    confidence=confidence,
                    placeholder="",
                )
            )
        return findings
