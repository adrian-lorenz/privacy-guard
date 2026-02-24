import pytest
from privacy_guard.detectors.name import NameDetector
from privacy_guard.whitelist import WhitelistManager


@pytest.fixture(scope="module")
def detector():
    return NameDetector()


def test_basic_name(detector):
    text = "Hallo, ich bin Mia Klaiber."
    findings = detector.detect(text)
    assert len(findings) == 1
    f = findings[0]
    assert f.text == "Mia Klaiber"
    assert f.confidence == 0.85
    assert f.placeholder == "[NAME_1]"


def test_name_with_title_dr(detector):
    text = "Dr. Thomas Schmidt hat angerufen."
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].confidence == 0.95
    assert "Thomas Schmidt" in findings[0].text


def test_name_with_title_prof(detector):
    text = "Prof. Maria Weber hält einen Vortrag."
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].confidence == 0.95


def test_name_with_herr(detector):
    text = "Sehr geehrter Herr Peter Becker,"
    findings = detector.detect(text)
    assert len(findings) == 1


def test_name_with_frau(detector):
    text = "Sehr geehrte Frau Anna Schneider,"
    findings = detector.detect(text)
    assert len(findings) == 1


def test_hyphenated_firstname(detector):
    text = "Hans-Peter Müller war dabei."
    findings = detector.detect(text)
    assert len(findings) == 1
    assert "Hans-Peter" in findings[0].text


def test_public_figure_not_masked(detector):
    text = "Friedrich Merz sprach im Bundestag."
    findings = detector.detect(text)
    assert len(findings) == 0


def test_olaf_scholz_not_masked(detector):
    text = "Olaf Scholz ist Bundeskanzler."
    findings = detector.detect(text)
    assert len(findings) == 0


def test_unknown_name_detected(detector):
    # spaCy can detect names not in any list
    text = "Kontaktiere bitte Xenia Frobeniusberg."
    findings = detector.detect(text)
    assert len(findings) == 1
    assert "Frobeniusberg" in findings[0].text


def test_multiple_names(detector):
    text = "Hans Müller und Peter Schmidt sind Kollegen."
    findings = detector.detect(text)
    assert len(findings) == 2


def test_custom_whitelist():
    wl = WhitelistManager(extra_names=["Mia Klaiber"])
    det = NameDetector(whitelist=wl)
    text = "Mia Klaiber ist whitelisted."
    findings = det.detect(text)
    assert len(findings) == 0


def test_no_false_positive_company(detector):
    text = "Die Firma Volkswagen AG hat gemeldet."
    findings = detector.detect(text)
    assert len(findings) == 0


def test_no_false_positive_location(detector):
    text = "Er fährt nach Frankfurt am Main."
    findings = detector.detect(text)
    assert len(findings) == 0
