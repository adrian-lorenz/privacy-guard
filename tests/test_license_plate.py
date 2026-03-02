from __future__ import annotations
import pytest
from privacy_guard.detectors.license_plate import LicensePlateDetector
from privacy_guard import PrivacyScanner, PiiType


@pytest.fixture
def detector() -> LicensePlateDetector:
    return LicensePlateDetector()


def test_standard_hyphen_format(detector: LicensePlateDetector) -> None:
    text = "Kennzeichen: B-AB 1234"
    findings = detector.detect(text)
    assert len(findings) == 1
    f = findings[0]
    assert f.text == "B-AB 1234"
    assert f.pii_type == PiiType.LICENSE_PLATE
    assert f.confidence == 0.75


def test_three_letter_district(detector: LicensePlateDetector) -> None:
    text = "Auto: MÜN-XY 99"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].confidence == 0.75


def test_elektro_suffix(detector: LicensePlateDetector) -> None:
    text = "E-Auto: HH-AB 1234E"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].text == "HH-AB 1234E"


def test_historisch_suffix(detector: LicensePlateDetector) -> None:
    text = "Oldtimer: K-CD 567H"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].text == "K-CD 567H"


def test_space_format(detector: LicensePlateDetector) -> None:
    text = "Fahrzeug: B AB 1234"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].confidence == 0.65


def test_single_letter_recognition(detector: LicensePlateDetector) -> None:
    text = "Kennzeichen: M-A 12"
    findings = detector.detect(text)
    assert len(findings) == 1


def test_too_long_not_detected(detector: LicensePlateDetector) -> None:
    # District part would make total > 8 chars
    text = "ABCD-EF 123"
    findings = detector.detect(text)
    # ABCD is 4 letters — regex requires 1-3, so no match
    assert len(findings) == 0


def test_number_starting_zero_not_detected(detector: LicensePlateDetector) -> None:
    # Numbers must start with 1-9
    text = "B-AB 0234"
    findings = detector.detect(text)
    assert len(findings) == 0


def test_multiple_plates(detector: LicensePlateDetector) -> None:
    text = "Autos: B-AB 1234 und HH-XY 5678"
    findings = detector.detect(text)
    assert len(findings) == 2


def test_scanner_integration() -> None:
    scanner = PrivacyScanner()
    result = scanner.scan("Das Fahrzeug B-AB 1234 war vor Ort.")
    assert "[LICENSE_PLATE_1]" in result.anonymised_text
    assert result.mapping["[LICENSE_PLATE_1]"] == "B-AB 1234"
