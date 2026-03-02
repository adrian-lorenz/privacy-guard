from __future__ import annotations
import pytest
from privacy_guard.detectors.driver_license import DriverLicenseDetector
from privacy_guard import PrivacyScanner, PiiType


@pytest.fixture
def detector() -> DriverLicenseDetector:
    return DriverLicenseDetector()


def test_valid_with_context(detector: DriverLicenseDetector) -> None:
    # Pattern: [A-Z]{1-3} + 6 digits + 2 alphanumeric = 9-11 chars
    # B + 951204 + XY = 9 chars
    text = "Führerscheinnummer: B951204XY"
    findings = detector.detect(text)
    assert len(findings) == 1
    f = findings[0]
    assert f.text == "B951204XY"
    assert f.pii_type == PiiType.DRIVER_LICENSE
    assert f.confidence == 0.75


def test_no_context_no_finding(detector: DriverLicenseDetector) -> None:
    # Same pattern but no keyword nearby — must not be detected
    text = "Referenz: B951204XY"
    findings = detector.detect(text)
    assert len(findings) == 0


def test_fahrerlaubnis_keyword(detector: DriverLicenseDetector) -> None:
    # MU + 010185 + A1 = 10 chars
    text = "Fahrerlaubnis Nummer: MU010185A1"
    findings = detector.detect(text)
    assert len(findings) == 1


def test_driver_license_english_keyword(detector: DriverLicenseDetector) -> None:
    # AB + 230395 + XY = 10 chars
    text = "Driver license: AB230395XY"
    findings = detector.detect(text)
    assert len(findings) == 1


def test_driving_licence_british_keyword(detector: DriverLicenseDetector) -> None:
    text = "Driving licence number: AB230395XY"
    findings = detector.detect(text)
    assert len(findings) == 1


def test_fs_nr_keyword(detector: DriverLicenseDetector) -> None:
    # CD + 150582 + AB = 10 chars
    text = "FS-Nr. CD150582AB"
    findings = detector.detect(text)
    assert len(findings) == 1


def test_keyword_after_match(detector: DriverLicenseDetector) -> None:
    # Keyword appears after the match (still within context window)
    text = "Bitte CD150582AB (Führerschein) vorlegen."
    findings = detector.detect(text)
    assert len(findings) == 1


def test_too_long_not_detected(detector: DriverLicenseDetector) -> None:
    # 4 authority letters → regex requires 1-3 only → no match
    text = "Führerschein: ABCD050189XY"
    findings = detector.detect(text)
    assert len(findings) == 0


def test_context_out_of_window_not_detected(detector: DriverLicenseDetector) -> None:
    # Keyword more than 200 chars away
    keyword_before = "Führerschein " + " " * 210
    text = keyword_before + "B951204XY"
    findings = detector.detect(text)
    assert len(findings) == 0


def test_multiple_licenses(detector: DriverLicenseDetector) -> None:
    text = "Führerschein A: B951204XY und Führerschein B: MU010185A1"
    findings = detector.detect(text)
    assert len(findings) == 2


def test_scanner_integration() -> None:
    # Use 10-char value (MU + 6 digits + 2 chars) — does not match PERSONAL_ID (exactly 9 chars)
    scanner = PrivacyScanner()
    result = scanner.scan("Führerscheinnummer: MU010185A1 liegt vor.")
    assert "[DRIVER_LICENSE_1]" in result.anonymised_text
    assert result.mapping["[DRIVER_LICENSE_1]"] == "MU010185A1"
