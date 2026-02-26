from __future__ import annotations
import re
from .base import BaseDetector
from ..models import Finding, PiiType

# URL query-parameter secrets: detect key=value pairs where the key is a known
# sensitive parameter name and the value is a non-trivial (≥6 chars) token.
# Only the VALUE is redacted; the key name remains visible in anonymised text
# (e.g. "?token=abc123def" → "?token=[URL_SECRET_1]").
#
# The (?<!\w) lookbehind prevents matching partial key names (e.g. "mytoken").
_URL_SECRET_KEYS = (
    r"token|api[_-]?key|apikey|api[_-]?token|access[_-]?token|"
    r"auth[_-]?token|auth|secret|password|passwd|pwd|"
    r"client[_-]?secret|private[_-]?key"
)
_URL_SECRET_PATTERN = re.compile(
    r"(?<!\w)(?:" + _URL_SECRET_KEYS + r")=([^&\s\"'<>\[\]{}]{6,})",
    re.IGNORECASE,
)


class UrlSecretDetector(BaseDetector):
    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in _URL_SECRET_PATTERN.finditer(text):
            value = match.group(1)
            start = match.start(1)
            end = match.end(1)
            findings.append(
                Finding(
                    pii_type=PiiType.URL_SECRET,
                    start=start,
                    end=end,
                    text=value,
                    confidence=0.85,
                    placeholder="",
                )
            )
        return findings
