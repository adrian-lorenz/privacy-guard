import pytest
from privacy_guard.detectors.email import EmailDetector


@pytest.fixture
def detector():
    return EmailDetector()


def test_basic_email(detector):
    text = "Schreib mir: hans.mueller@example.de"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].text == "hans.mueller@example.de"
    assert findings[0].confidence == 1.0


def test_email_with_plus(detector):
    text = "Erreichbar: user+tag@domain.com"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].text == "user+tag@domain.com"


def test_email_subdomain(detector):
    text = "Kontakt: info@mail.company.co.at"
    findings = detector.detect(text)
    assert len(findings) == 1


def test_multiple_emails(detector):
    text = "Von: a@example.de, An: b@example.at"
    findings = detector.detect(text)
    assert len(findings) == 2
    assert findings[0].text == "a@example.de"
    assert findings[1].text == "b@example.at"


def test_no_false_positive(detector):
    text = "Kein E-Mail hier, nur normaler Text."
    findings = detector.detect(text)
    assert len(findings) == 0


def test_email_in_sentence(detector):
    text = "Bitte senden Sie die Rechnung an rechnung@musterfirma.de bis Freitag."
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].text == "rechnung@musterfirma.de"
