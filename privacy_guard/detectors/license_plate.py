from __future__ import annotations
import re
from .base import BaseDetector
from ..models import Finding, PiiType

# German Kfz-Kennzeichen (vehicle registration plates).
# Structure: 1-3 letter district code + 1-2 letter recognition letters + 1-4 digit number
# Optional trailing E (Elektro) or H (Historisch).
# Two separators used in practice: hyphen (official) or space.
#
# Hyphen format:  B-AB 1234  or  MÜ-XY 12E  →  conf 0.75
# Space format:   B AB 1234                  →  conf 0.65

_HYPHEN_PATTERN = re.compile(
    r"\b([A-ZÄÖÜ]{1,3})-([A-Z]{1,2})[ ]?([1-9][0-9]{0,3}[EH]?)\b"
)
_SPACE_PATTERN = re.compile(r"\b([A-ZÄÖÜ]{1,3}) ([A-Z]{1,2}) ([1-9][0-9]{0,3}[EH]?)\b")


def _valid_plate(district: str, letters: str, digits: str) -> bool:
    """Structural check: total length (without separators and optional E/H suffix) must be 4-8."""
    base_digits = digits.rstrip("EH")
    total = len(district) + len(letters) + len(base_digits)
    return 4 <= total <= 8


class LicensePlateDetector(BaseDetector):
    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []

        for match in _HYPHEN_PATTERN.finditer(text):
            district, letters, digits = match.group(1), match.group(2), match.group(3)
            if _valid_plate(district, letters, digits):
                findings.append(
                    Finding(
                        pii_type=PiiType.LICENSE_PLATE,
                        start=match.start(),
                        end=match.end(),
                        text=match.group(),
                        confidence=0.75,
                        placeholder="",
                    )
                )

        for match in _SPACE_PATTERN.finditer(text):
            district, letters, digits = match.group(1), match.group(2), match.group(3)
            if _valid_plate(district, letters, digits):
                # Avoid double-reporting if already covered by hyphen pattern
                start, end = match.start(), match.end()
                if not any(f.start == start and f.end == end for f in findings):
                    findings.append(
                        Finding(
                            pii_type=PiiType.LICENSE_PLATE,
                            start=start,
                            end=end,
                            text=match.group(),
                            confidence=0.65,
                            placeholder="",
                        )
                    )

        return findings
