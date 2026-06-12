# SCAMShield

> Scam and phishing detection in text (SMS, e-mails, messages): an explainable scoring
> engine, a Streamlit demo, a train/evaluate pipeline and a Chrome extension.

![CI](https://github.com/ablanchard-dev/scamshield/actions/workflows/ci.yml/badge.svg?branch=main)
![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

SCAMShield analyzes a piece of text and returns a scam probability together with the
signals that triggered it (not a black box). Built to be explainable, tested and deployable.

## Features

- Explainable scoring: every verdict lists its red flags (urgency, bait, payment/credential requests…) and its hints (domain, URL, sender).
- Data-driven signals: domain/URL reputation, suspicious TLDs, known phishing senders, denylist/allowlist phrase lists.
- `train -> predict -> metrics` pipeline: CSV scripts to train, predict and measure performance.
- Streamlit demo: paste a message, see the score and the reasons live.
- Chrome extension: scoring directly in the browser.
- Tests + CI: a `tests/` suite (behavior + contract) run by GitHub Actions.

## Quick start

```bash
git clone https://github.com/ablanchard-dev/scamshield.git
cd scamshield

python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows:     .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Run the Streamlit demo
streamlit run app/main.py
```

Score a CSV file from the command line:

```bash
python predict_csv.py            # predictions
python metrics_csv.py            # metrics (precision / recall / etc.)
```

## How it works

The engine (`scamshield/scorer.py`) combines several weighted signals:

| Signal | Source |
|---|---|
| Risky phrasings | `data/denylist_phrases.txt` / `allowlist_phrases.txt` |
| Domains & URLs | `data/url_reputation.json`, `bad_domains.txt`, `suspicious_tlds.txt` |
| Senders | `data/known_phishing_senders.txt`, `malicious_senders.txt`, `trusted_senders.txt` |
| Attachments | `data/dangerous_attachment_hashes.txt`, `suspicious_attachments.txt` |

The result is a probability from 0 to 1 + the list of reasons, which makes every decision auditable.

## Structure

```
scamshield/        # scoring engine (scorer, url_utils) + reference data
app/main.py        # Streamlit interface
extension/         # Chrome extension (manifest + popup)
data/              # signal lists + CSV datasets
tests/             # behavior + contract tests
predict_csv.py / metrics_csv.py / seed_data.py
.github/workflows/ # CI (lint + tests) and release
```

## Tests

```bash
pytest
```

GitHub Actions runs the tests on every push (badge above).

## License

MIT.
