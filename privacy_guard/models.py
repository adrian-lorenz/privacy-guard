from __future__ import annotations
from dataclasses import dataclass
from enum import Enum


class PiiType(str, Enum):
    NAME = "NAME"
    IBAN = "IBAN"
    PHONE = "PHONE"
    EMAIL = "EMAIL"
    ADDRESS = "ADDRESS"
    SECRET = "SECRET"


@dataclass(frozen=True)
class Finding:
    pii_type: PiiType
    start: int
    end: int
    text: str
    confidence: float
    placeholder: str
    rule_id: str | None = None  # set by SecretDetector to identify which rule matched

    def __len__(self) -> int:
        return self.end - self.start


@dataclass
class ScanResult:
    original_text: str
    anonymised_text: str
    findings: list[Finding]
    mapping: dict[str, str]  # placeholder -> original

    def restore(self, text: str) -> str:
        """Replace placeholders in text with their original values."""
        result = text
        for placeholder, original in self.mapping.items():
            result = result.replace(placeholder, original)
        return result
