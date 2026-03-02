from __future__ import annotations
import pytest
from privacy_guard.detectors.kvnr import KvnrDetector
from privacy_guard import PrivacyScanner, PiiType


@pytest.fixture
def detector() -> KvnrDetector:
    return KvnrDetector()


def test_valid_kvnr(detector: KvnrDetector) -> None:
    # KVNR = 1 letter + 9 digits = 10 chars total.
    # T=20; digits_str = "20" + "12345678" = "2012345678" (10 chars)
    # Weights [1,2,...]: 2,0,1,4,3,8,5,3,7,7 → sum=40 → check=40%10=0
    # So T123456780 is a valid KVNR.
    text = "Versichertennummer: T123456780"
    findings = detector.detect(text)
    assert len(findings) == 1
    f = findings[0]
    assert f.text == "T123456780"
    assert f.pii_type == PiiType.KVNR
    assert f.confidence == 0.95


def test_invalid_checksum_lower_confidence(detector: KvnrDetector) -> None:
    # Change last digit from 0 to 9 → invalid checksum
    text = "Versichertennummer: T123456789"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].confidence == 0.6


def test_too_short_not_detected(detector: KvnrDetector) -> None:
    # 9 chars (letter + 8 digits) — too short for KVNR
    text = "Nr: A12345678"
    findings = detector.detect(text)
    assert len(findings) == 0


def test_too_long_not_detected(detector: KvnrDetector) -> None:
    # 11 chars — word boundary prevents match inside longer string
    text = "Nr: A12345678901"
    findings = detector.detect(text)
    assert len(findings) == 0


def test_lowercase_letter_not_detected(detector: KvnrDetector) -> None:
    # Pattern requires uppercase first letter
    text = "Nr: a123456789"
    findings = detector.detect(text)
    assert len(findings) == 0


def test_no_overlap_with_personal_id(detector: KvnrDetector) -> None:
    # PersonalId pattern is [A-Z][A-Z0-9]{8} = 9 chars; KVNR is [A-Z][0-9]{9} = 10 chars
    # A 9-char alphanumeric doc number does NOT match KVNR (must be letter + 9 digits)
    text = "Ausweis C22990047"
    findings = detector.detect(text)
    assert all(f.text != "C22990047" for f in findings)


def test_multiple_kvnr(detector: KvnrDetector) -> None:
    # T123456780 (valid check=0) and A987654321 (check=1, expected=8 → invalid but detected)
    text = "Patient 1: T123456780, Patient 2: A987654321"
    findings = detector.detect(text)
    assert len(findings) == 2


def test_scanner_integration() -> None:
    scanner = PrivacyScanner()
    result = scanner.scan("KVNR des Patienten: T123456780")
    assert "[KVNR_1]" in result.anonymised_text
    assert result.mapping["[KVNR_1]"] == "T123456780"
