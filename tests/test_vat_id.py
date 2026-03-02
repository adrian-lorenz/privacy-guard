from __future__ import annotations
import pytest
from privacy_guard.detectors.vat_id import VatIdDetector
from privacy_guard import PrivacyScanner, PiiType


@pytest.fixture
def detector() -> VatIdDetector:
    return VatIdDetector()


def test_plain_vat_id(detector: VatIdDetector) -> None:
    text = "USt-IdNr: DE123456789"
    findings = detector.detect(text)
    assert len(findings) == 1
    f = findings[0]
    assert f.text == "DE123456789"
    assert f.pii_type == PiiType.VAT_ID
    assert f.confidence == 0.85


def test_spaced_vat_id(detector: VatIdDetector) -> None:
    text = "Steuernummer: DE 123 456 789"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].text == "DE 123 456 789"


def test_partially_spaced_vat_id(detector: VatIdDetector) -> None:
    text = "USt-Id: DE123 456789"
    findings = detector.detect(text)
    assert len(findings) == 1


def test_lowercase_de_not_detected(detector: VatIdDetector) -> None:
    # Pattern requires uppercase DE prefix
    text = "de123456789"
    findings = detector.detect(text)
    assert len(findings) == 0


def test_too_few_digits_not_detected(detector: VatIdDetector) -> None:
    text = "DE12345678"  # only 8 digits
    findings = detector.detect(text)
    assert len(findings) == 0


def test_too_many_digits_not_detected(detector: VatIdDetector) -> None:
    # 10 digits → word boundary prevents match (regex is exactly 3+3+3 groups)
    text = "DE1234567890"
    findings = detector.detect(text)
    assert len(findings) == 0


def test_non_german_prefix_not_detected(detector: VatIdDetector) -> None:
    # French VAT starts with FR
    text = "FR12345678901"
    findings = detector.detect(text)
    assert len(findings) == 0


def test_multiple_vat_ids(detector: VatIdDetector) -> None:
    text = "Firma A: DE111222333 und Firma B: DE444555666"
    findings = detector.detect(text)
    assert len(findings) == 2


def test_scanner_integration() -> None:
    scanner = PrivacyScanner()
    result = scanner.scan("Unsere USt-IdNr ist DE123456789.")
    assert "[VAT_ID_1]" in result.anonymised_text
    assert result.mapping["[VAT_ID_1]"] == "DE123456789"
