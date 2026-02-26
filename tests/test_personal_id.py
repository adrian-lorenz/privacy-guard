from __future__ import annotations
import pytest
from privacy_guard.detectors.personal_id import PersonalIdDetector
from privacy_guard import PrivacyScanner, PiiType


@pytest.fixture
def detector() -> PersonalIdDetector:
    return PersonalIdDetector()


def test_personalausweis_digits(detector: PersonalIdDetector) -> None:
    text = "Ausweis-Nr.: C22990047"
    findings = detector.detect(text)
    assert len(findings) == 1
    f = findings[0]
    assert f.text == "C22990047"
    assert f.pii_type == PiiType.PERSONAL_ID
    assert f.confidence == 0.75


def test_reisepass_digits(detector: PersonalIdDetector) -> None:
    text = "Passnummer: C12345678"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].text == "C12345678"


def test_mixed_alphanumeric(detector: PersonalIdDetector) -> None:
    # Alphanumeric doc number (letter in positions 2-9)
    text = "Ausweis: L01X00T47"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].text == "L01X00T47"


def test_too_short_not_detected(detector: PersonalIdDetector) -> None:
    # Only 8 chars — one short
    text = "Nummer: C1234567"
    findings = detector.detect(text)
    assert len(findings) == 0


def test_too_long_not_detected(detector: PersonalIdDetector) -> None:
    # 10 chars — one too long (word boundary prevents match inside longer string)
    text = "Nummer: C1234567890"
    findings = detector.detect(text)
    assert len(findings) == 0


def test_iban_not_false_positive(detector: PersonalIdDetector) -> None:
    # IBAN starts with letters+digits but is much longer; word boundary protects us
    text = "IBAN: DE89370400440532013000"
    findings = detector.detect(text)
    # DE8937040 is 9 chars but no word boundary after it inside the IBAN
    assert len(findings) == 0


def test_multiple_documents(detector: PersonalIdDetector) -> None:
    text = "PA: C22990047 und Reisepass: C12345678"
    findings = detector.detect(text)
    assert len(findings) == 2


def test_scanner_integration() -> None:
    scanner = PrivacyScanner()
    result = scanner.scan("Bitte Ausweis-Nr. C22990047 vorzeigen.")
    assert "[PERSONAL_ID_1]" in result.anonymised_text
    assert result.mapping["[PERSONAL_ID_1]"] == "C22990047"
