import pytest
from privacy_guard.detectors.phone import PhoneDetector


@pytest.fixture
def detector():
    return PhoneDetector()


def test_german_mobile(detector):
    text = "Ruf mich an: 0171 1234567"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].confidence == 1.0
    assert findings[0].placeholder == "[PHONE_1]"


def test_german_landline(detector):
    text = "Tel: 030 12345678"
    findings = detector.detect(text)
    assert len(findings) == 1


def test_german_with_country_code(detector):
    text = "Telefon: +49 171 1234567"
    findings = detector.detect(text)
    assert len(findings) == 1


def test_austrian_number(detector):
    text = "+43 1 58858-0"
    findings = detector.detect(text)
    assert len(findings) == 1


def test_swiss_number(detector):
    text = "+41 44 668 18 00"
    findings = detector.detect(text)
    assert len(findings) == 1


def test_no_false_positive_year(detector):
    # A 4-digit year should not be a phone number
    text = "Im Jahr 2024 war das so."
    findings = detector.detect(text)
    assert len(findings) == 0


def test_multiple_phones(detector):
    text = "Büro: 030 12345678, Mobil: +49 171 1234567"
    findings = detector.detect(text)
    assert len(findings) == 2


def test_placeholder_numbering(detector):
    text = "A: +49 30 12345678, B: +49 89 98765432"
    findings = detector.detect(text)
    placeholders = [f.placeholder for f in findings]
    assert "[PHONE_1]" in placeholders
    assert "[PHONE_2]" in placeholders
