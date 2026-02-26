from __future__ import annotations
import re
from .base import BaseDetector
from ..models import Finding, PiiType

# Formatted card patterns:
#   16-digit: XXXX[ -]XXXX[ -]XXXX[ -]XXXX  (Visa, MC, Discover, JCB)
#   15-digit: XXXX[ -]XXXXXX[ -]XXXXX        (AmEx 4-6-5)
#   14-digit: XXXX[ -]XXXXXX[ -]XXXX         (Diners Club 4-6-4)
# Raw pattern: 13–19 consecutive digits bounded by non-digit chars
_CC_PATTERN = re.compile(
    r"(?<!\d)"
    r"("
    r"\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}"  # 16-digit formatted
    r"|\d{4}[ -]\d{6}[ -]\d{5}"  # 15-digit AmEx formatted
    r"|\d{4}[ -]\d{6}[ -]\d{4}"  # 14-digit Diners formatted
    r"|\d{13,19}"  # raw digits
    r")"
    r"(?!\d)",
)


def _luhn_valid(digits: str) -> bool:
    """Return True if the digit string passes the Luhn check."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


class CreditCardDetector(BaseDetector):
    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []

        for match in _CC_PATTERN.finditer(text):
            raw = match.group(1)
            is_formatted = " " in raw or "-" in raw
            digits = raw.replace(" ", "").replace("-", "")
            luhn_ok = _luhn_valid(digits)

            if is_formatted:
                confidence = 1.0 if luhn_ok else 0.6
            else:
                if not luhn_ok:
                    continue  # too many false positives for raw unvalidated strings
                confidence = 0.9

            findings.append(
                Finding(
                    pii_type=PiiType.CREDIT_CARD,
                    start=match.start(),
                    end=match.end(),
                    text=raw,
                    confidence=confidence,
                    placeholder="",
                )
            )

        return findings
