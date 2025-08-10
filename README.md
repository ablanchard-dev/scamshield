# SCAMShield — Starter MVP (Local-First)

A tiny, working prototype that scores **texts and URLs** for phishing/scam risk and
explains *why* it flagged them. Built to be extremely lightweight and deployable in minutes.

## What’s inside
- **Streamlit app** (`app/main.py`) — paste text or a URL to get a **risk score (0–100)** and human explanations.
- **Heuristics engine** (`scamshield/scorer.py`) — urgency wording, OTP/$$ markers, brand impersonation, look‑alike domains, suspicious TLDs.
- **URL helpers** (`scamshield/url_utils.py`) — normalization, domain distance, basic homograph defense.
- **Chrome extension skeleton** (`extension/`) — a ready popup/manifest to later hit a tiny API.
- **Data** (`data/sample_texts.txt`) — quick messages to test.

## Run locally
```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app/main.py
```

## Deploy to Hugging Face Spaces
- Create a new Space (type **Streamlit**), upload this repo, let it build.
- Optionally pin Space hardware to CPU Basic (free tier).

## Roadmap (very short-term)
- OCR pipeline (images → text): Tesseract/EasyOCR → `score_text`.
- API (FastAPI): `/score-text`, `/score-url` for the browser extension.
- Report generator (PDF) from the Streamlit result page.
- Feedback button to tune weights continuously.

> ⚠️ Prototype only — heuristics are explainable and fast, not a substitute for full enterprise detection.
