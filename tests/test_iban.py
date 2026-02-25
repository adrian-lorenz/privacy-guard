import pytest
from privacy_guard.detectors.iban import IbanDetector


@pytest.fixture
def detector():
    return IbanDetector()


def test_valid_german_iban(detector):
    text = "Bitte überweise auf DE89 3704 0044 0532 0130 00"
    findings = detector.detect(text)
    assert len(findings) == 1
    f = findings[0]
    assert f.text == "DE89 3704 0044 0532 0130 00"
    assert f.confidence == 1.0


def test_valid_austrian_iban(detector):
    text = "IBAN: AT61 1904 3002 3457 3201"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].confidence == 1.0


def test_valid_swiss_iban(detector):
    text = "CH56 0483 5012 3456 7800 9"
    findings = detector.detect(text)
    assert len(findings) == 1


def test_invalid_checksum(detector):
    # Valid format but wrong checksum
    text = "DE00 3704 0044 0532 0130 00"
    findings = detector.detect(text)
    # Should still detect but with lower confidence
    assert len(findings) == 1
    assert findings[0].confidence == 0.6


def test_invalid_country(detector):
    text = "XX89 3704 0044 0532 0130 00"
    findings = detector.detect(text)
    assert len(findings) == 0


def test_wrong_length(detector):
    # DE IBAN must be 22 chars (without spaces)
    text = "DE89 3704 0044 0532 01"
    findings = detector.detect(text)
    assert len(findings) == 0


def test_multiple_ibans(detector):
    text = "Von DE89 3704 0044 0532 0130 00 nach AT61 1904 3002 3457 3201"
    findings = detector.detect(text)
    assert len(findings) == 2


def test_iban_without_spaces(detector):
    text = "IBAN: DE89370400440532013000"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].confidence == 1.0


def test_no_iban_in_plain_text(detector):
    text = "Kein IBAN hier, nur normaler Text."
    findings = detector.detect(text)
    assert len(findings) == 0
