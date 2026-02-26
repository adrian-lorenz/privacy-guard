from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.main import app


@pytest.fixture(scope="module")
def client() -> TestClient:
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# /health
# ---------------------------------------------------------------------------


def test_health(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# /scan – basic detection
# ---------------------------------------------------------------------------


def test_scan_iban(client: TestClient) -> None:
    r = client.post("/scan", json={"text": "IBAN DE89370400440532013000"})
    assert r.status_code == 200
    data = r.json()
    assert "[IBAN_1]" in data["anonymised_text"]
    assert data["mapping"]["[IBAN_1]"] == "DE89370400440532013000"


def test_scan_email(client: TestClient) -> None:
    r = client.post("/scan", json={"text": "Schreib mir an test@example.com bitte"})
    assert r.status_code == 200
    assert "[EMAIL_1]" in r.json()["anonymised_text"]


def test_scan_returns_findings_structure(client: TestClient) -> None:
    r = client.post("/scan", json={"text": "IBAN DE89370400440532013000"})
    finding = r.json()["findings"][0]
    assert {
        "start",
        "end",
        "text",
        "pii_type",
        "confidence",
        "placeholder",
    } <= finding.keys()


# ---------------------------------------------------------------------------
# /scan – detector filter
# ---------------------------------------------------------------------------


def test_scan_detector_filter_keeps_selected(client: TestClient) -> None:
    r = client.post(
        "/scan",
        json={
            "text": "IBAN DE89370400440532013000 und test@example.com",
            "detectors": ["IBAN"],
        },
    )
    assert r.status_code == 200
    pii_types = {f["pii_type"] for f in r.json()["findings"]}
    assert "IBAN" in pii_types
    assert "EMAIL" not in pii_types


def test_scan_detector_filter_invalid_value(client: TestClient) -> None:
    r = client.post("/scan", json={"text": "test", "detectors": ["UNKNOWN"]})
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# /scan – whitelist
# ---------------------------------------------------------------------------


def test_scan_whitelist_suppresses_name(client: TestClient) -> None:
    r = client.post(
        "/scan",
        json={
            "text": "Kontaktiere Max Mustermann wegen IBAN DE89370400440532013000",
            "whitelist": ["Max Mustermann"],
        },
    )
    assert r.status_code == 200
    findings = r.json()["findings"]
    names = [
        f for f in findings if f["pii_type"] == "NAME" and f["text"] == "Max Mustermann"
    ]
    assert names == []


# ---------------------------------------------------------------------------
# /anonymize
# ---------------------------------------------------------------------------


def test_anonymize_returns_only_text(client: TestClient) -> None:
    r = client.post("/anonymize", json={"text": "IBAN DE89370400440532013000"})
    assert r.status_code == 200
    data = r.json()
    assert set(data.keys()) == {"anonymised_text"}
    assert "[IBAN_1]" in data["anonymised_text"]


def test_anonymize_detector_filter(client: TestClient) -> None:
    r = client.post(
        "/anonymize",
        json={
            "text": "IBAN DE89370400440532013000 und test@example.com",
            "detectors": ["EMAIL"],
        },
    )
    assert r.status_code == 200
    text = r.json()["anonymised_text"]
    assert "[EMAIL_1]" in text
    assert "DE89370400440532013000" in text  # IBAN not masked


# ---------------------------------------------------------------------------
# API key protection
# ---------------------------------------------------------------------------


def test_api_key_not_required_when_unset(client: TestClient) -> None:
    # Default env has no API_KEY → requests without header must pass
    r = client.post("/scan", json={"text": "test"})
    assert r.status_code == 200


def test_api_key_enforced_when_set(monkeypatch: pytest.MonkeyPatch) -> None:
    import api.main as api_main

    monkeypatch.setattr(api_main, "_API_KEY", "secret123")
    with TestClient(api_main.app) as c:
        r = c.post("/scan", json={"text": "test"})
        assert r.status_code == 401

        r = c.post("/scan", json={"text": "test"}, headers={"X-API-Key": "secret123"})
        assert r.status_code == 200
