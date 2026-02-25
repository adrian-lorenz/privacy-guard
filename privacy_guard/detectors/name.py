from __future__ import annotations
import re
import spacy
from .base import BaseDetector
from ..models import Finding, PiiType
from ..whitelist import WhitelistManager

# Titles that may appear before a name — matched greedily right before the entity span
_TITLE_BEFORE = re.compile(
    r"(?:(?:Herr|Frau|Dr\.?|Prof\.?|Mag\.?|DI|Ing\.?|Dipl\.?-?Ing\.?|"
    r"ao\.?\s*Univ\.?-?Prof\.?|Univ\.?-?Prof\.?|Priv\.?-?Doz\.?|"
    r"MSc|MBA|BSc|LL\.M)\.?\s+)+\Z",
    re.IGNORECASE,
)

_nlp: spacy.language.Language | None = None


def _get_nlp() -> spacy.language.Language:
    global _nlp
    if _nlp is None:
        try:
            # Disable pipeline components not needed for NER.
            # tok2vec must stay active because ner depends on its vectors.
            _nlp = spacy.load(
                "de_core_news_sm",
                disable=[
                    "tagger",
                    "morphologizer",
                    "parser",
                    "lemmatizer",
                    "attribute_ruler",
                ],
            )
        except OSError as exc:
            raise OSError(
                "Das spaCy-Modell 'de_core_news_sm' ist nicht installiert.\n"
                "Bitte installieren:\n"
                "  pip install "
                '"de_core_news_sm @ https://github.com/explosion/spacy-models/releases/'
                'download/de_core_news_sm-3.8.0/de_core_news_sm-3.8.0-py3-none-any.whl"\n'
                "oder:  python -m spacy download de_core_news_sm"
            ) from exc
    return _nlp


def _expand_title(text: str, start: int) -> tuple[int, bool]:
    """Look backwards from start for an inline title (Dr., Prof., Herr, …).
    Returns (new_start, has_title)."""
    prefix = text[:start]
    m = _TITLE_BEFORE.search(prefix)
    if m:
        return m.start(), True
    return start, False


class NameDetector(BaseDetector):
    def __init__(self, whitelist: WhitelistManager | None = None) -> None:
        self._whitelist = whitelist or WhitelistManager()

    def detect(self, text: str) -> list[Finding]:
        nlp = _get_nlp()
        doc = nlp(text)
        findings: list[Finding] = []

        for ent in doc.ents:
            if ent.label_ != "PER":
                continue

            start, has_title = _expand_title(text, ent.start_char)
            end = ent.end_char
            full_text = text[start:end]

            if self._whitelist.is_whitelisted(full_text):
                continue

            findings.append(
                Finding(
                    pii_type=PiiType.NAME,
                    start=start,
                    end=end,
                    text=full_text,
                    confidence=0.95 if has_title else 0.85,
                    placeholder="",
                )
            )

        return findings
