from __future__ import annotations
import re
from .base import BaseDetector
from ..models import Finding, PiiType

# German Führerscheinnummer.
# Structure: authority code (1-3 letters) + 6-digit birth date (DDMMYY) + 2 serial chars.
# Total: 9-11 chars. No standardized checksum — context window required to reduce FP rate.
#
# Context keywords checked within ±200 chars of each match.
_DRIVER_LICENSE_PATTERN = re.compile(r"\b[A-Z]{1,3}[0-9]{6}[A-Z0-9]{2}\b")

_CONTEXT_KEYWORDS = re.compile(
    r"f[uü]hrerschein|fahrerlaubnis|fs[-\s]?nr|driver\s+licen[sc]e|driving\s+licen[sc]e",
    re.IGNORECASE,
)

_CONTEXT_WINDOW = 200


class DriverLicenseDetector(BaseDetector):
    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        text_lower = text.lower()

        for match in _DRIVER_LICENSE_PATTERN.finditer(text):
            # Check for context keyword within ±_CONTEXT_WINDOW characters
            window_start = max(0, match.start() - _CONTEXT_WINDOW)
            window_end = min(len(text), match.end() + _CONTEXT_WINDOW)
            window = text_lower[window_start:window_end]

            if _CONTEXT_KEYWORDS.search(window):
                findings.append(
                    Finding(
                        pii_type=PiiType.DRIVER_LICENSE,
                        start=match.start(),
                        end=match.end(),
                        text=match.group(),
                        confidence=0.75,
                        placeholder="",
                    )
                )

        return findings
