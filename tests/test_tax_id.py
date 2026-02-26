from __future__ import annotations
import pytest
from privacy_guard.detectors.tax_id import TaxIdDetector
from privacy_guard import PrivacyScanner, PiiType


@pytest.fixture
def detector() -> TaxIdDetector:
    return TaxIdDetector()


def test_valid_checksum_formatted(detector: TaxIdDetector) -> None:
    # 12 345 678 903 has valid checksum (check digit = 3)
    text = "Steuer-ID: 12 345 678 903"
    findings = detector.detect(text)
    assert len(findings) == 1
    f = findings[0]
    assert f.text == "12 345 678 903"
    assert f.pii_type == PiiType.TAX_ID
    assert f.confidence == 1.0


def test_valid_checksum_raw(detector: TaxIdDetector) -> None:
    text = "IdNr: 12345678903"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].confidence == 1.0


def test_invalid_checksum_lower_confidence(detector: TaxIdDetector) -> None:
    # 12 345 678 901: format correct, checksum wrong (expected 3, got 1) → confidence 0.6
    text = "Steuer-ID: 12 345 678 901"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].confidence == 0.6


def test_starts_with_zero_not_detected(detector: TaxIdDetector) -> None:
    text = "01 234 567 890"
    findings = detector.detect(text)
    assert len(findings) == 0


def test_ten_digits_not_detected(detector: TaxIdDetector) -> None:
    text = "1234567890"
    findings = detector.detect(text)
    assert len(findings) == 0


def test_twelve_digits_not_detected(detector: TaxIdDetector) -> None:
    # 12 digits — doesn't match the 2-3-3-3 pattern
    text = "123456789012"
    findings = detector.detect(text)
    assert len(findings) == 0


def test_scanner_integration() -> None:
    scanner = PrivacyScanner()
    result = scanner.scan("Meine Steuer-ID lautet 12 345 678 903.")
    assert "[TAX_ID_1]" in result.anonymised_text
    assert result.mapping["[TAX_ID_1]"] == "12 345 678 903"
