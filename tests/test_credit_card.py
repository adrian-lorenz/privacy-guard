from __future__ import annotations
import pytest
from privacy_guard.detectors.credit_card import CreditCardDetector
from privacy_guard import PrivacyScanner, PiiType


@pytest.fixture
def detector() -> CreditCardDetector:
    return CreditCardDetector()


def test_valid_visa_spaces(detector: CreditCardDetector) -> None:
    text = "Karte: 4111 1111 1111 1111"
    findings = detector.detect(text)
    assert len(findings) == 1
    f = findings[0]
    assert f.text == "4111 1111 1111 1111"
    assert f.pii_type == PiiType.CREDIT_CARD
    assert f.confidence == 1.0


def test_valid_visa_dashes(detector: CreditCardDetector) -> None:
    text = "Karte: 4111-1111-1111-1111"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].text == "4111-1111-1111-1111"
    assert findings[0].confidence == 1.0


def test_valid_amex_formatted(detector: CreditCardDetector) -> None:
    # AmEx 4-6-5 format, Luhn-valid test number
    text = "AmEx: 3782 822463 10005"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].text == "3782 822463 10005"
    assert findings[0].confidence == 1.0


def test_valid_raw_luhn(detector: CreditCardDetector) -> None:
    # Raw 16-digit Luhn-valid number → confidence 0.9
    text = "Nummer: 4111111111111111 steht im Text"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].confidence == 0.9


def test_formatted_luhn_invalid(detector: CreditCardDetector) -> None:
    # Formatted but bad checksum → still detected, confidence 0.6
    text = "Karte: 4111 1111 1111 1112"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].confidence == 0.6


def test_raw_luhn_invalid_not_detected(detector: CreditCardDetector) -> None:
    # Raw digits that fail Luhn → not reported (too many false positives)
    text = "Nummer 1234567890123456 ist keine Karte"
    findings = detector.detect(text)
    assert len(findings) == 0


def test_multiple_cards(detector: CreditCardDetector) -> None:
    text = "Karte 1: 4111 1111 1111 1111 und Karte 2: 5500 0055 5555 5559"
    findings = detector.detect(text)
    assert len(findings) == 2


def test_scanner_integration() -> None:
    scanner = PrivacyScanner()
    result = scanner.scan("Bitte buche von 4111 1111 1111 1111 ab.")
    assert "[CREDIT_CARD_1]" in result.anonymised_text
    assert result.mapping["[CREDIT_CARD_1]"] == "4111 1111 1111 1111"


def test_no_false_positive_short_numbers(detector: CreditCardDetector) -> None:
    text = "Die Telefonnummer ist 089-1234"
    findings = detector.detect(text)
    assert len(findings) == 0


def test_diners_formatted(detector: CreditCardDetector) -> None:
    # Diners Club 4-6-4 format, Luhn-valid test number
    text = "Karte: 3056 930902 5904"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].confidence == 1.0
