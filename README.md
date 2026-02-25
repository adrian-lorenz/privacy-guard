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

---

## Python-Package

### Installation

```bash
pip install privacy-guard-scanner
```

Der **Namens-Detektor** benötigt zusätzlich ein spaCy-Modell:

```bash
pip install "de_core_news_sm @ https://github.com/explosion/spacy-models/releases/download/de_core_news_sm-3.8.0/de_core_news_sm-3.8.0-py3-none-any.whl"
# oder:
python -m spacy download de_core_news_sm
```

Alle anderen Detektoren (IBAN, Telefon, E-Mail, Adresse, Secrets) funktionieren ohne das Modell.

### Schnellstart

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

---

## REST-API (Docker)

Das Repo enthält eine FastAPI-Oberfläche, die als Docker-Image auf Docker Hub bereitgestellt wird.

[![Docker Hub](https://img.shields.io/docker/v/noxway/privacy-guard?label=Docker%20Hub&logo=docker)](https://hub.docker.com/r/noxway/privacy-guard)

### Schnellstart

```bash
# Image direkt von Docker Hub ziehen und starten:
docker run -p 8000:8000 noxway/privacy-guard:latest
```

Oder mit `docker compose` (zieht das Image automatisch von Docker Hub):

```bash
docker compose up
```

Wer das Image lieber lokal bauen möchte, ersetzt in `docker-compose.yml` die Zeile `image:` durch `build: .`.

### Endpunkte

| Methode | Pfad | Beschreibung |
|---|---|---|
| `GET` | `/health` | Liveness-Check |
| `POST` | `/scan` | Text scannen, Findings + anonymisierten Text zurückgeben |
| `POST` | `/anonymize` | Nur anonymisierten Text zurückgeben |

### Request-Schema

Beide POST-Endpunkte akzeptieren dasselbe JSON-Schema:

```json
{
  "text": "Hans Müller, IBAN DE89370400440532013000",
  "detectors": ["IBAN", "EMAIL"],
  "whitelist": ["Hans Müller"]
}
```

| Feld | Typ | Default | Beschreibung |
|---|---|---|---|
| `text` | `string` | — | Zu scannender Text |
| `detectors` | `string[]` | alle | Aktive Detektoren: `NAME`, `IBAN`, `PHONE`, `EMAIL`, `ADDRESS`, `SECRET` |
| `whitelist` | `string[]` | `[]` | Namen, die der Namens-Detektor ignorieren soll |

### Beispiel

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"text": "Kontakt: hans@example.de, IBAN DE89370400440532013000", "detectors": ["EMAIL", "IBAN"]}'
```

```json
{
  "anonymised_text": "Kontakt: [EMAIL_1], IBAN [IBAN_1]",
  "findings": [
    {"start": 9, "end": 25, "text": "hans@example.de", "pii_type": "EMAIL", "confidence": 1.0, "placeholder": "[EMAIL_1]"},
    {"start": 32, "end": 54, "text": "DE89370400440532013000", "pii_type": "IBAN", "confidence": 1.0, "placeholder": "[IBAN_1]"}
  ],
  "mapping": {
    "[EMAIL_1]": "hans@example.de",
    "[IBAN_1]": "DE89370400440532013000"
  }
}
```

### Konfiguration

Die API wird über Umgebungsvariablen konfiguriert:

| Variable | Default | Beschreibung |
|---|---|---|
| `API_KEY` | — | Wenn gesetzt, muss jeder Request den Header `X-API-Key: <key>` mitschicken |
| `CORS_ORIGINS` | `*` | Erlaubte Origins, kommagetrennt (z.B. `https://myapp.example.com`) |

```yaml
# docker-compose.yml
services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      API_KEY: mein-geheimer-key
      CORS_ORIGINS: https://myapp.example.com
```

---

## Lizenz

MIT — siehe [LICENSE](LICENSE).
