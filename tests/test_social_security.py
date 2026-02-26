from __future__ import annotations
import pytest
from privacy_guard.detectors.social_security import SocialSecurityDetector
from privacy_guard import PrivacyScanner, PiiType


@pytest.fixture
def detector() -> SocialSecurityDetector:
    return SocialSecurityDetector()


def test_formatted_with_spaces(detector: SocialSecurityDetector) -> None:
    text = "SV-Nummer: 12 345678 X 123"
    findings = detector.detect(text)
    assert len(findings) == 1
    f = findings[0]
    assert f.text == "12 345678 X 123"
    assert f.pii_type == PiiType.SOCIAL_SECURITY
    assert f.confidence == 0.9


def test_compact_no_spaces(detector: SocialSecurityDetector) -> None:
    text = "SVNR: 12345678X123"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].text == "12345678X123"


def test_partial_spaces(detector: SocialSecurityDetector) -> None:
    text = "12 345678X123"
    findings = detector.detect(text)
    assert len(findings) == 1


def test_lowercase_letter_not_matched(detector: SocialSecurityDetector) -> None:
    # The middle letter must be uppercase
    text = "12 345678 x 123"
    findings = detector.detect(text)
    assert len(findings) == 0


def test_missing_letter_not_matched(detector: SocialSecurityDetector) -> None:
    # All digits — no letter in middle → no match
    text = "12 345678 1 123"
    findings = detector.detect(text)
    assert len(findings) == 0


def test_wrong_group_lengths(detector: SocialSecurityDetector) -> None:
    # Only 5 digits in middle group instead of 6
    text = "12 34567 X 123"
    findings = detector.detect(text)
    assert len(findings) == 0


def test_scanner_integration() -> None:
    scanner = PrivacyScanner()
    result = scanner.scan("Rentenversicherungsnummer: 12 345678 X 123")
    assert "[SOCIAL_SECURITY_1]" in result.anonymised_text
    assert result.mapping["[SOCIAL_SECURITY_1]"] == "12 345678 X 123"
