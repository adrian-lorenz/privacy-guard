from __future__ import annotations
import re
from .base import BaseDetector
from ..models import Finding, PiiType

# Krankenversichertennummer (KVNR) — § 290 SGB V.
# Format: 1 uppercase letter (insurer identifier) + 9 digits = 10 chars total.
# The letter encodes a number A=01 … Z=26; digits 1-8 are the insured person's data;
# digit 9 is a check digit computed via a modified Luhn algorithm.
_KVNR_PATTERN = re.compile(r"\b[A-Z][0-9]{9}\b")


def _kvnr_checksum_valid(raw: str) -> bool:
    """Return True if the KVNR passes the § 290 SGB V modified-Luhn check."""
    letter = raw[0]
    letter_value = ord(letter) - ord("A") + 1  # A=1 … Z=26
    # Represent as two digits (A=01, J=10, Z=26)
    digits_str = f"{letter_value:02d}" + raw[1:]
    # digits_str is now 11 characters; apply weights [1,2,1,2,...] over first 10
    weights = [1, 2] * 5  # 10 positions
    total = 0
    for ch, w in zip(digits_str[:10], weights):
        product = int(ch) * w
        # Cross-sum: if product >= 10 sum its digits
        total += product // 10 + product % 10
    expected_check = total % 10
    actual_check = int(raw[9])
    return expected_check == actual_check


class KvnrDetector(BaseDetector):
    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in _KVNR_PATTERN.finditer(text):
            raw = match.group()
            valid = _kvnr_checksum_valid(raw)
            confidence = 0.95 if valid else 0.6
            findings.append(
                Finding(
                    pii_type=PiiType.KVNR,
                    start=match.start(),
                    end=match.end(),
                    text=raw,
                    confidence=confidence,
                    placeholder="",
                )
            )
        return findings
