# Cyber Fraud Guardian

> Citizen Fraud-Message Guardian — Cyber Kavach Challenge 2026, BSides Ahmedabad

A layered fraud detection system that **detects**, **verifies**, **explains**, and helps citizens **respond** to suspected scam messages. No single AI model is the sole authority — deterministic checks, threat intelligence, and evidence fusion provide the foundation; an LLM explains what was already verified.

## Quick Start

```bash
# 1. Clone and install
cd CyberKawach
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt

# 2. Configure environment
copy .env.example .env
# Edit .env with your API keys

# 3. Run backend
python -m uvicorn backend.main:app --reload --port 8000

# 4. Open frontend
# Open frontend/index.html in a browser, or serve it:
python -m http.server 3000 --directory frontend
```

## Architecture

```
INPUT (text/URL — screenshot via OCR in P1)
  → Normalization + IOC Extraction
  → Rule Engine (fast triage) | ML baseline (optional) | URL/Domain Analysis | Threat Intel
  → Evidence Fusion → Risk Score + Confidence
  → Explanation (Gemini preferred, deterministic fallback if unavailable)
  → Adaptive Response (state-dependent guidance)
```

## Project Structure

```
CyberKawach/
├── backend/                 # Python FastAPI backend
│   ├── main.py              # App entry point + API routes
│   ├── config.py            # Settings and environment
│   ├── models/              # Pydantic schemas (Evidence Contract)
│   │   ├── evidence.py      # Core evidence contract
│   │   └── api.py           # Request/response schemas
│   ├── modules/             # Analysis pipeline
│   │   ├── ingestion.py     # Text/URL extraction + normalization
│   │   ├── rules.py         # Rule-based fraud detection
│   │   ├── url_analyzer.py  # URL/domain analysis
│   │   ├── brand_check.py   # Brand impersonation detection
│   │   ├── threat_intel.py  # Threat intel adapters
│   │   ├── fusion.py        # Evidence fusion + risk scoring
│   │   ├── gemini.py        # Gemini grounded explanation
│   │   ├── fallback_explanation.py  # Deterministic template fallback
│   │   └── response.py      # Adaptive response state machine
│   ├── services/            # External service integrations
│   │   ├── safe_browsing.py
│   │   ├── phishtank.py
│   │   ├── urlhaus.py
│   │   └── abuseipdb.py
│   └── utils/               # Shared utilities
│       ├── sanitize.py      # Input sanitization
│       └── logging.py       # Structured logging
├── frontend/                # Vanilla HTML/CSS/JS
│   ├── index.html
│   ├── css/
│   │   └── main.css
│   ├── js/
│   │   ├── app.js           # Main application logic
│   │   ├── api.js           # Backend API client
│   │   └── components.js    # UI component renderers
│   └── assets/
│       └── icons/           # Lucide SVG icons
├── fixtures/                # Sample/demo data
│   ├── sample_messages.json
│   └── sample_evidence.json
├── tests/                   # Test suite
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

## Tech Stack

| Component | Choice | Why |
|-----------|--------|-----|
| Backend | Python + FastAPI | Rapid development, async, Pydantic validation |
| Frontend | Vanilla HTML/CSS/JS | Zero build step, hackathon speed |
| LLM | Gemini Flash-Lite/Flash | Free tier, non-critical — deterministic fallback if unavailable |
| URL Safety | Local heuristics + Safe Browsing | No-cost, deterministic, P0 |
| Phishing Intel | PhishTank | Free, well-maintained, P0 |
| IP Intel | AbuseIPDB | 1,000/day free, P2 optional |
| URL Malware | URLhaus | Free, P2 optional |
| Domain Intel | RDAP | Free, standard protocol |
| Campaign Graph | NetworkX | Zero dependencies beyond Python |

## License

Built for Cyber Kavach Challenge 2026. See event rules for usage terms.
