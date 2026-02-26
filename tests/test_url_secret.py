from __future__ import annotations
import pytest
from privacy_guard.detectors.url_secret import UrlSecretDetector
from privacy_guard import PrivacyScanner, PiiType


@pytest.fixture
def detector() -> UrlSecretDetector:
    return UrlSecretDetector()


def test_token_query_param(detector: UrlSecretDetector) -> None:
    text = "https://example.com/api?token=abc123def456"
    findings = detector.detect(text)
    assert len(findings) == 1
    f = findings[0]
    assert f.text == "abc123def456"
    assert f.pii_type == PiiType.URL_SECRET
    assert f.confidence == 0.85
    # Value is replaced, key name remains
    assert text[f.start : f.end] == "abc123def456"


def test_api_key_param(detector: UrlSecretDetector) -> None:
    text = "https://api.example.com/v1?api_key=xyz789abc123"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].text == "xyz789abc123"


def test_password_param(detector: UrlSecretDetector) -> None:
    text = "?password=mySuperSecret"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].text == "mySuperSecret"


def test_access_token_param(detector: UrlSecretDetector) -> None:
    text = "&access_token=eyJhbGciOiJIUzI1NiJ9"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].text == "eyJhbGciOiJIUzI1NiJ9"


def test_value_too_short_not_detected(detector: UrlSecretDetector) -> None:
    # Value shorter than 6 chars → not detected
    text = "?token=abc12"
    findings = detector.detect(text)
    assert len(findings) == 0


def test_partial_key_name_not_matched(detector: UrlSecretDetector) -> None:
    # "mytoken" is not a bare "token" key
    text = "?mytoken=abc123def456"
    findings = detector.detect(text)
    assert len(findings) == 0


def test_multiple_secrets_in_url(detector: UrlSecretDetector) -> None:
    text = "?token=abc123def456&api_key=xyz789abc123&other=value"
    findings = detector.detect(text)
    assert len(findings) == 2


def test_scanner_integration_value_only_redacted() -> None:
    scanner = PrivacyScanner()
    text = "Aufruf: https://api.example.com?token=abc123def456"
    result = scanner.scan(text)
    assert "[URL_SECRET_1]" in result.anonymised_text
    # Key name "token=" is preserved; only the value is replaced
    assert "token=" in result.anonymised_text
    assert result.mapping["[URL_SECRET_1]"] == "abc123def456"


def test_secret_param(detector: UrlSecretDetector) -> None:
    text = "?client_secret=abcdef123456789"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].text == "abcdef123456789"
