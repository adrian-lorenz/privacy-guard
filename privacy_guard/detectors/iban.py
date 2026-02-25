from __future__ import annotations
import re
from .base import BaseDetector
from ..models import Finding, PiiType

# Country code -> expected IBAN length (without spaces)
IBAN_LENGTHS: dict[str, int] = {
    "AD": 24,
    "AE": 23,
    "AL": 28,
    "AT": 20,
    "AZ": 28,
    "BA": 20,
    "BE": 16,
    "BG": 22,
    "BH": 22,
    "BR": 29,
    "BY": 28,
    "CH": 21,
    "CR": 22,
    "CY": 28,
    "CZ": 24,
    "DE": 22,
    "DJ": 27,
    "DK": 18,
    "DO": 28,
    "EE": 20,
    "EG": 29,
    "ES": 24,
    "FI": 18,
    "FO": 18,
    "FR": 27,
    "GB": 22,
    "GE": 22,
    "GI": 23,
    "GL": 18,
    "GR": 27,
    "GT": 28,
    "HR": 21,
    "HU": 28,
    "IE": 22,
    "IL": 23,
    "IQ": 23,
    "IS": 26,
    "IT": 27,
    "JO": 30,
    "KW": 30,
    "KZ": 20,
    "LB": 28,
    "LC": 32,
    "LI": 21,
    "LT": 20,
    "LU": 20,
    "LV": 21,
    "LY": 25,
    "MC": 27,
    "MD": 24,
    "ME": 22,
    "MK": 19,
    "MN": 20,
    "MR": 27,
    "MT": 31,
    "MU": 30,
    "NI": 28,
    "NL": 18,
    "NO": 15,
    "OM": 23,
    "PK": 24,
    "PL": 28,
    "PS": 29,
    "PT": 25,
    "QA": 29,
    "RO": 24,
    "RS": 22,
    "RU": 33,
    "SA": 24,
    "SC": 31,
    "SD": 18,
    "SE": 24,
    "SI": 19,
    "SK": 24,
    "SM": 27,
    "SO": 23,
    "ST": 25,
    "SV": 28,
    "TL": 23,
    "TN": 24,
    "TR": 26,
    "UA": 29,
    "VA": 22,
    "VG": 24,
    "XK": 20,
    "YE": 30,
}

# Matches IBAN-like patterns: 2 letters, 2 digits, then alphanumeric chars
# with optional spaces (e.g. "DE89 3704 0044 0532 0130 00" or "DE89370400440532013000")
# Each group is: optional-space + one alphanumeric char (11–31 such chars after the 4-char prefix)
_IBAN_PATTERN = re.compile(
    r"\b([A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,31})(?=\s|$|[^A-Z0-9])",
    re.ASCII,
)


def _mod97(iban_digits: str) -> int:
    """ISO 7064 MOD-97-10 check."""
    remainder = 0
    for ch in iban_digits:
        if ch.isdigit():
            remainder = (remainder * 10 + int(ch)) % 97
        else:
            # A=10, B=11, ...
            val = ord(ch) - ord("A") + 10
            remainder = (remainder * 100 + val) % 97
    return remainder


def _validate_iban(raw: str) -> tuple[bool, float]:
    """Return (is_valid_format, confidence)."""
    clean = raw.replace(" ", "").upper()
    country = clean[:2]
    expected_len = IBAN_LENGTHS.get(country)
    if expected_len is None:
        return False, 0.0
    if len(clean) != expected_len:
        return False, 0.0
    # Rearrange: move first 4 chars to end, then check MOD97
    rearranged = clean[4:] + clean[:4]
    if _mod97(rearranged) == 1:
        return True, 1.0
    # Format matches but checksum fails → lower confidence
    return True, 0.6


class IbanDetector(BaseDetector):
    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []

        for match in _IBAN_PATTERN.finditer(text):
            raw = match.group(0)
            valid_format, confidence = _validate_iban(raw)
            if not valid_format:
                continue

            findings.append(
                Finding(
                    pii_type=PiiType.IBAN,
                    start=match.start(),
                    end=match.end(),
                    text=raw,
                    confidence=confidence,
                    placeholder="",
                )
            )

        return findings
