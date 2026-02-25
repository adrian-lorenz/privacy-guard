import pytest
from privacy_guard.detectors.address import AddressDetector


@pytest.fixture
def detector():
    return AddressDetector()


def test_german_address(detector):
    text = "Wohnhaft: Hauptstraße 12, 10115 Berlin"
    findings = detector.detect(text)
    assert len(findings) == 1
    f = findings[0]
    assert "Hauptstraße" in f.text
    assert "10115" in f.text
    assert f.confidence == 0.9


def test_austrian_address(detector):
    text = "Meine Adresse: Mariahilfer Straße 100, 1070 Wien"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert "1070" in findings[0].text


def test_swiss_address(detector):
    text = "Bahnhofstrasse 21, 8001 Zürich"
    findings = detector.detect(text)
    assert len(findings) == 1


def test_various_street_suffixes(detector):
    for suffix_text in [
        "Friedensweg 5, 80333 München",
        "Rosenallee 7, 20095 Hamburg",
        "Schillerplatz 3, 70173 Stuttgart",
    ]:
        findings = detector.detect(suffix_text)
        assert len(findings) == 1, f"Failed for: {suffix_text}"


def test_house_number_with_letter(detector):
    text = "Musterstraße 12a, 10115 Berlin"
    findings = detector.detect(text)
    assert len(findings) == 1


def test_no_false_positive(detector):
    text = "Die Straße ist lang und führt zum Wald."
    findings = detector.detect(text)
    assert len(findings) == 0


def test_multiple_addresses(detector):
    text = "Absender: Hauptstraße 1, 10115 Berlin. Empfänger: Gartenweg 5, 80333 München."
    findings = detector.detect(text)
    assert len(findings) == 2
