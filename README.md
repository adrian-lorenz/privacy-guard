# privacy-guard

DSGVO/GDPR-konformes Erkennen und Ersetzen von personenbezogenen Daten (PII) in Text —
regel- und musterbasiert, kein ML-Inference zur Laufzeit.

Designed für den Einsatz vor LLM-Prompts: sensitive Daten werden durch stabile,
umkehrbare Platzhalter ersetzt und können nach der LLM-Antwort wiederhergestellt werden.

## Features

| Typ | Beispiele |
|---|---|
| **Namen** | „Hans Müller", „Dr. Anna Schmidt" (via spaCy NER) |
| **IBAN** | DE89 3704 0044 0532 0130 00 (+ ISO 7064 Prüfsumme) |
| **Telefon** | +49 89 12345678, 0800 123456 |
| **E-Mail** | kontakt@example.de |
| **Adresse** | Hauptstraße 12, 79100 Freiburg |
| **Secrets** | API-Keys, Tokens, Passwörter (122 Muster) |

- Personen des öffentlichen Lebens (Politiker, CEOs, Prominente) werden **nicht** maskiert
- Gleicher Originaltext → gleicher Platzhalter (Deduplication)
- `ScanResult.restore()` ersetzt Platzhalter zurück in den LLM-Output

## Installation

```bash
pip install privacy-guard
```

Der **Namens-Detektor** benötigt zusätzlich ein spaCy-Modell:

```bash
pip install "de_core_news_sm @ https://github.com/explosion/spacy-models/releases/download/de_core_news_sm-3.8.0/de_core_news_sm-3.8.0-py3-none-any.whl"
# oder:
python -m spacy download de_core_news_sm
```

Alle anderen Detektoren (IBAN, Telefon, E-Mail, Adresse, Secrets) funktionieren ohne das Modell.

## Schnellstart

```python
from privacy_guard import PrivacyScanner

scanner = PrivacyScanner()

result = scanner.scan(
    "Bitte überweise 500 € an Hans Müller, IBAN DE89 3704 0044 0532 0130 00. "
    "Rückfragen an h.mueller@example.de oder +49 89 123456."
)

print(result.anonymised_text)
# → "Bitte überweise 500 € an [NAME_1], IBAN [IBAN_1]. Rückfragen an [EMAIL_1] oder [PHONE_1]."

print(result.mapping)
# → {"[NAME_1]": "Hans Müller", "[IBAN_1]": "DE89 3704 0044 0532 0130 00", ...}

# LLM-Antwort wiederherstellen
llm_response = "Vielen Dank, [NAME_1]! Ihre Überweisung von [IBAN_1] wurde verarbeitet."
print(result.restore(llm_response))
# → "Vielen Dank, Hans Müller! Ihre Überweisung von DE89 3704 0044 0532 0130 00 wurde verarbeitet."
```

### Detektoren einzeln steuern

```python
from privacy_guard import PrivacyScanner, PiiType

scanner = PrivacyScanner()
scanner.disable_detector(PiiType.NAME)   # Namens-Detektor deaktivieren
scanner.enable_detector(PiiType.NAME)    # wieder aktivieren

# Eigene Whitelist-Einträge (werden nicht maskiert)
scanner = PrivacyScanner(extra_whitelist_names=["Erika Musterfrau"])
```

### Nur bestimmte Findings auswerten

```python
secrets = [f for f in result.findings if f.pii_type == PiiType.SECRET]
for s in secrets:
    print(f"  {s.rule_id}: {s.text!r}  (confidence={s.confidence})")
```

## Lizenz

MIT — siehe [LICENSE](LICENSE).
