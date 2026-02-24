import pytest
from privacy_guard import PrivacyScanner, PiiType


@pytest.fixture(scope="module")
def scanner():
    return PrivacyScanner()


def test_basic_scan_with_iban_and_name(scanner):
    text = "Bitte überweise an Hans Müller, DE89 3704 0044 0532 0130 00"
    result = scanner.scan(text)
    assert "[NAME_1]" in result.anonymised_text
    assert "[IBAN_1]" in result.anonymised_text
    assert "Hans Müller" not in result.anonymised_text
    assert "DE89 3704 0044 0532 0130 00" not in result.anonymised_text


def test_mapping_populated(scanner):
    text = "Hans Müller, DE89 3704 0044 0532 0130 00"
    result = scanner.scan(text)
    assert "[NAME_1]" in result.mapping or "[IBAN_1]" in result.mapping


def test_restore_roundtrip(scanner):
    text = "Hans Müller hat DE89 3704 0044 0532 0130 00 überwiesen."
    result = scanner.scan(text)
    restored = result.restore(result.anonymised_text)
    assert restored == text


def test_restore_partial(scanner):
    text = "Hans Müller hat DE89 3704 0044 0532 0130 00 überwiesen."
    result = scanner.scan(text)
    # Restore only the IBAN placeholder
    iban_placeholder = None
    for placeholder, original in result.mapping.items():
        if "IBAN" in placeholder:
            iban_placeholder = placeholder
            break
    assert iban_placeholder is not None
    restored = result.restore(iban_placeholder)
    assert restored == "DE89 3704 0044 0532 0130 00"


def test_deduplication(scanner):
    text = "Hans Müller schrieb an Hans Müller."
    result = scanner.scan(text)
    # Both occurrences should use the same placeholder
    assert result.anonymised_text.count("[NAME_1]") == 2
    assert len(result.mapping) == 1


def test_public_figure_not_masked(scanner):
    text = "Friedrich Merz sprach über die Wirtschaft."
    result = scanner.scan(text)
    assert "Friedrich Merz" in result.anonymised_text
    assert "[NAME" not in result.anonymised_text


def test_disable_detector(scanner):
    scanner.disable_detector(PiiType.NAME)
    text = "Hans Müller hat DE89 3704 0044 0532 0130 00 überwiesen."
    result = scanner.scan(text)
    assert "Hans Müller" in result.anonymised_text
    assert "[IBAN_1]" in result.anonymised_text


def test_enable_detector(scanner):
    scanner.disable_detector(PiiType.IBAN)
    scanner.enable_detector(PiiType.IBAN)
    text = "IBAN: DE89 3704 0044 0532 0130 00"
    result = scanner.scan(text)
    assert "[IBAN_1]" in result.anonymised_text


def test_phone_in_scan(scanner):
    text = "Ruf mich an: +49 171 1234567"
    result = scanner.scan(text)
    assert "[PHONE_1]" in result.anonymised_text


def test_address_in_scan(scanner):
    text = "Ich wohne in der Hauptstraße 5, 10115 Berlin."
    result = scanner.scan(text)
    assert "[ADDRESS_1]" in result.anonymised_text


def test_email_in_scan(scanner):
    text = "Schreib an: kontakt@example.de"
    result = scanner.scan(text)
    assert "[EMAIL_1]" in result.anonymised_text
    assert "kontakt@example.de" not in result.anonymised_text


def test_email_restore_roundtrip(scanner):
    text = "Antwort an info@musterfirma.de bitte bis Freitag."
    result = scanner.scan(text)
    assert result.restore(result.anonymised_text) == text


def test_overlap_iban_wins_over_name(scanner):
    # An IBAN shouldn't be clobbered by a name match
    text = "DE89 3704 0044 0532 0130 00"
    result = scanner.scan(text)
    assert "[IBAN_1]" in result.anonymised_text


def test_original_text_preserved(scanner):
    text = "Kein PII hier."
    result = scanner.scan(text)
    assert result.original_text == text
    assert result.anonymised_text == text
    assert result.findings == []
    assert result.mapping == {}


def test_scan_result_findings_sorted(scanner):
    text = "Hans Müller, DE89 3704 0044 0532 0130 00, +49 171 1234567"
    result = scanner.scan(text)
    starts = [f.start for f in result.findings]
    assert starts == sorted(starts)
