from __future__ import annotations
import re
from pathlib import Path
from .base import BaseDetector
from ..models import Finding, PiiType

_DATA_DIR = Path(__file__).parent.parent / "data"


def _load_lines(path: Path) -> list[str]:
    """Read non-empty, non-comment lines from a data file."""
    with path.open(encoding="utf-8") as fh:
        return [
            line.strip() for line in fh if line.strip() and not line.startswith("#")
        ]


def _build_suffix_re() -> str:
    suffixes = _load_lines(_DATA_DIR / "street_suffixes.txt")
    # Longest first so the engine prefers longer matches
    suffixes.sort(key=len, reverse=True)
    return "|".join(re.escape(s) for s in suffixes)


def _build_prep_re() -> str:
    preps = _load_lines(_DATA_DIR / "street_prepositions.txt")
    # Longest first (e.g. "An der" before "Am")
    preps.sort(key=len, reverse=True)
    # Spaces in the source file → \s+ in the regex
    alts = "|".join(re.escape(p).replace(r"\ ", r"\s+") for p in preps)
    return rf"(?:{alts})\s+"


_SUFFIX_RE = _build_suffix_re()
_PREP_RE = _build_prep_re()

# PLZ: 5-digit DE (01000-99999) or 4-digit AT/CH (1000-9999)
_PLZ_RE = r"(?:\d{5}|\d{4})"

# Street name: one or more capitalized words, possibly hyphenated
_STREET_NAME_RE = r"[A-ZÄÖÜ][a-zäöüß]+(?:[-][A-ZÄÖÜ]?[a-zäöüß]+)*"

# House number: digits optionally followed by letter/suffix
_HOUSE_RE = r"\d+\s*[a-zA-Z]?(?:\s*/\s*\d+)?"

# City name: one or more capitalized words
_CITY_RE = r"[A-ZÄÖÜ][a-zäöüß]+(?:(?:\s+|-)[A-ZÄÖÜ]?[a-zäöüß]+)*"

# Fast pre-filter: a valid DACH address must contain a PLZ (4-5 digits).
# Avoids running the expensive pattern on texts that can't match.
_PLZ_PREFILTER = re.compile(r"\b\d{4,5}\b")

_ADDRESS_PATTERN = re.compile(
    rf"(?:"
    # Variant A: optional preposition + street name + suffix
    # Separator [-\s]* allows direct concat ("Hauptstraße"), space ("Mariahilfer Straße"),
    # or hyphen ("Achim-Stocker-Straße", "Bad-Straße")
    rf"(?:{_PREP_RE})?(?P<street>{_STREET_NAME_RE})[-\s]*(?P<suffix>{_SUFFIX_RE})\.?"
    rf"|"
    # Variant B: required preposition + bare noun (no suffix), e.g. "Beim Brunnen"
    rf"(?:{_PREP_RE})(?P<street2>{_STREET_NAME_RE})"
    rf")"
    rf"\s+(?P<house>{_HOUSE_RE})"
    rf",?\s+"
    rf"(?P<plz>{_PLZ_RE})\s+(?P<city>{_CITY_RE})",
    re.UNICODE | re.IGNORECASE,
)


class AddressDetector(BaseDetector):
    def detect(self, text: str) -> list[Finding]:
        if not _PLZ_PREFILTER.search(text):
            return []

        findings: list[Finding] = []

        for match in _ADDRESS_PATTERN.finditer(text):
            findings.append(
                Finding(
                    pii_type=PiiType.ADDRESS,
                    start=match.start(),
                    end=match.end(),
                    text=match.group(0),
                    confidence=0.9,
                    placeholder="",
                )
            )

        return findings
