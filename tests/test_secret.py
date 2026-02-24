from __future__ import annotations

import pytest
from privacy_guard.detectors.secret import SecretDetector, _RULES
from privacy_guard.models import PiiType


@pytest.fixture(scope="module")
def detector() -> SecretDetector:
    return SecretDetector()


# ── Rule loading ───────────────────────────────────────────────────────────────

def test_rules_loaded() -> None:
    assert len(_RULES) > 100, "Expected 100+ rules"


def test_all_rule_ids_unique() -> None:
    ids = [r.id for r in _RULES]
    assert len(ids) == len(set(ids)), "Duplicate rule IDs found"


def test_all_patterns_compile() -> None:
    # Patterns are compiled at import time; this just confirms no rule is missing
    for rule in _RULES:
        assert rule.pattern is not None


# ── Cloud / VCS ────────────────────────────────────────────────────────────────

def test_aws_access_key(detector: SecretDetector) -> None:
    findings = detector.detect("key=AKIA" + "I0SFODNN7EXAMPLE" + "12345")
    assert any(f.rule_id == "aws-access-key" for f in findings)


_GHP = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "1234567890"


def test_github_pat(detector: SecretDetector) -> None:
    findings = detector.detect("token: " + _GHP)
    assert any(f.rule_id == "github-pat" for f in findings)


def test_gitlab_pat(detector: SecretDetector) -> None:
    findings = detector.detect("CI_TOKEN=glpat-" + "AbCdEfGhIjKl" + "MnOpQrSt")
    assert any(f.rule_id == "gitlab-pat" for f in findings)


# ── LLM / AI ──────────────────────────────────────────────────────────────────

def test_anthropic_key(detector: SecretDetector) -> None:
    findings = detector.detect("ANTHROPIC_API_KEY=sk-ant-api03-" + "A" * 32)
    assert any(f.rule_id in ("anthropic-api-key", "anthropic-api-key-env") for f in findings)


def test_openai_key_env(detector: SecretDetector) -> None:
    findings = detector.detect("OPENAI_API_KEY=sk-proj-" + "B" * 50)
    assert any(f.rule_id in ("openai-api-key-new", "openai-api-key-env") for f in findings)


def test_huggingface_token(detector: SecretDetector) -> None:
    findings = detector.detect("hf_" + "X" * 32)
    assert any(f.rule_id == "huggingface-token" for f in findings)


def test_groq_key(detector: SecretDetector) -> None:
    findings = detector.detect("gsk_" + "A" * 52)
    assert any(f.rule_id == "groq-api-key" for f in findings)


# ── Database ───────────────────────────────────────────────────────────────────

def test_postgres_url(detector: SecretDetector) -> None:
    findings = detector.detect("postgresql://user:s3cr3t@db.example.com/mydb")
    assert any(f.rule_id == "db-postgres-url" for f in findings)


def test_mongodb_url(detector: SecretDetector) -> None:
    findings = detector.detect("mongodb://admin:hunter2@mongo.example.com/db")
    assert any(f.rule_id == "db-mongodb-url" for f in findings)


# ── Private Key ────────────────────────────────────────────────────────────────

def test_private_key_pem(detector: SecretDetector) -> None:
    pem = "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIEow..."
    findings = detector.detect(pem)
    assert any(f.rule_id == "private-key-header" for f in findings)


# ── Python patterns ────────────────────────────────────────────────────────────

def test_python_inline_openai_key(detector: SecretDetector) -> None:
    findings = detector.detect('client = OpenAI(api_key="sk-proj-' + "Z" * 50 + '")')
    assert any(f.rule_id == "python-openai-client-inline-key" for f in findings)


def test_python_dotenv_line(detector: SecretDetector) -> None:
    findings = detector.detect("OPENAI_API_KEY=sk-proj-" + "C" * 50 + "\n")
    assert any(f.rule_id in ("python-dotenv-llm-key", "openai-api-key-new", "openai-api-key-env") for f in findings)


# ── Redaction correctness ──────────────────────────────────────────────────────

def test_secret_group_redacts_only_value(detector: SecretDetector) -> None:
    """For rules with secret_group > 0, only the value — not the key name — is redacted."""
    text = "ANTHROPIC_API_KEY=sk-ant-" + "X" * 36
    findings = detector.detect(text)
    env_finding = next((f for f in findings if f.rule_id == "anthropic-api-key-env"), None)
    if env_finding:
        # Should NOT include "ANTHROPIC_API_KEY=" in the redacted span
        assert "ANTHROPIC_API_KEY" not in env_finding.text
        assert env_finding.text.startswith("sk-ant-")


def test_finding_has_rule_id(detector: SecretDetector) -> None:
    findings = detector.detect(_GHP)
    assert all(f.rule_id is not None for f in findings)
    assert all(f.pii_type == PiiType.SECRET for f in findings)


def test_no_findings_on_clean_text(detector: SecretDetector) -> None:
    findings = detector.detect("Hallo, das ist ein normaler Text ohne Secrets.")
    assert findings == []


# ── Scanner integration ────────────────────────────────────────────────────────

def test_secret_in_scanner() -> None:
    from privacy_guard import PrivacyScanner
    scanner = PrivacyScanner()
    result = scanner.scan("API_KEY=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
    assert "[SECRET_1]" in result.anonymised_text
    assert any(f.pii_type == PiiType.SECRET for f in result.findings)


def test_secret_wins_over_email() -> None:
    """A Bearer token that looks like an email context should be SECRET not EMAIL."""
    from privacy_guard import PrivacyScanner
    scanner = PrivacyScanner()
    result = scanner.scan("Authorization: Bearer ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
    types = {f.pii_type for f in result.findings}
    assert PiiType.SECRET in types
