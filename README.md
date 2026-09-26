# Cyber Fraud Guardian

> **Track S2: Citizen Fraud-Message Guardian**  
> *Cyber Kavach Challenge 2026 — BSides Ahmedabad*

A high-assurance, evidence-driven cyber fraud triage and reasoning system engineered to protect citizens from deceptive SMS, WhatsApp, email, and social engineering attacks. 

Rather than relying on ungrounded LLM guesses or opaque black-box classifiers, **Cyber Fraud Guardian** enforces **strict epistemic modesty**, **two-tier risk fusion**, **traceable causal attack paths**, **four-state threat intelligence**, and **state-proportional citizen response protocols** (including India's 1930 National Cyber Crime Golden Hour response).

---

## Key Innovations

### 1. Grounded Epistemic Reasoning & Modesty
- **Observation vs. Inference Separation**: Distinguishes direct factual IOC observations (`observed_value`) from security deductions (`interpretation`).
- **Epistemic Status Hierarchy**: Classifies every signal into one of 6 rigorous epistemic states: `CONFIRMED`, `OBSERVED`, `SUSPICIOUS`, `POSSIBLE`, `UNKNOWN`, or `UNAVAILABLE`, backed by a numerical `reliability` score ($0.0 \dots 1.0$).
- **Evidentiary Sufficiency**: Explicitly declares whether collected evidence is `SUFFICIENT`, `PARTIAL`, or `INSUFFICIENT` before calculating risk.
- **Negative Epistemic Bounds ("What the Guardian Cannot Conclude")**: Explicitly defines the limits of analysis (e.g., cannot confirm if server is active, cannot verify identity behind burner numbers, cannot confirm victim account status).
- **Traceable Causal Attack Paths**: Reconstructs attacker progression from `Lure` $\rightarrow$ `Redirection` $\rightarrow$ `Exploitation` $\rightarrow$ `Monetization/Consequence` with strict `[Evidence N]` inline citations.

### 2. Two-Tier Risk Fusion Engine
- **Tier 1 — Deterministic Safety Overrides**:
  - **Official Domain Dampening ($\le 0.15$)**: Preserves a **strict zero false-positive rate** on verified government, banking, utility, and courier infrastructure (e.g., `*.sbi`, `*.gov.in`, `hdfcbank.com`).
  - **High-Hazard Overrides ($\ge 0.85$)**: Instantly escalates verified blacklist matches (Safe Browsing, PhishTank, PhishStats), raw IPv4/IPv6 literals, or active typosquatting impersonations to `HIGH` or `CRITICAL`.
- **Tier 2 — Calibrated Multi-Signal Fusion**:
  - Computes weighted linear combinations across signal dimensions (Rules, Patterns, ML, Brand, URL, Safe Browsing, PhishTank, PhishStats, AbuseIPDB, URLhaus).
  - Multi-signal correlation dampening prevents compounding noise from inflating benign messages.

### 3. Fault-Tolerant 4-State Threat Intelligence
- **Safe Browsing, PhishTank & PhishStats**: Multi-feed intelligence with in-memory TTL caching and non-negative scoring.
- **Google Safe Browsing v4**: Real-time lookup for malware and deceptive web IOCs.
- **4-State Fault Boundary**: Explicitly maps every intelligence check to `KNOWN_MALICIOUS`, `NO_KNOWN_MATCH`, `RATE_LIMITED`, or `SOURCE_UNAVAILABLE`. Never treats an API timeout or rate-limit as proof that a domain is safe!

### 4. Adaptive State-Machine Response Protocol
- **Citizen Journey Mapping**: Tailors defensive guidance to victim vulnerability:
  - `RECEIVED`: Calm educational debunking, verification channels, unsolicited collect request warnings.
  - `CLICKED`: Session isolation, browser cache clearing, device vulnerability scans.
  - `ENTERED_CREDENTIALS`: Immediate password rotation, biometric re-locking, 2FA revocation.
  - `PAID`: **Golden Hour Emergency Protocol** activating India's **1930 Cyber Crime Helpline**, banking freezing steps, and National Cyber Crime Reporting Portal (`cybercrime.gov.in`) reporting packs.

### 5. Enterprise Security Hardening
- **Anti-SSRF CIDR Parser**: Blocks loopback (`127.0.0.0/8`), private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and AWS/GCP cloud metadata endpoints (`169.254.169.254`).
- **Zero-PII Masking**: Automatically sanitizes Aadhaar numbers, PAN cards, OTPs, and phone numbers before logging or LLM transmission.
- **Prompt Injection Defense**: Filters adversarial override phrases (`ignore previous instructions`, `system prompt`, delimiter breakouts).
- **In-Memory Sliding-Window Rate Limiting**: Defends endpoints against DoS and brute-force token depletion.

---

## 20-Case Real-World Indian Accuracy Matrix

The guardian is verified against 20 high-fidelity scenarios covering all major Indian cyber fraud archetypes:

| Category | Typical Pattern / Modus Operandi | Risk Tier | Sufficiency |
|---|---|:---:|:---:|
| **Legitimate Banking** | Official SBI netbanking alert (`onlinesbi.sbi`) | `LOW` (0.15) | `PARTIAL` |
| **Legitimate OTP** | HDFC transaction OTP with strict warning (`hdfcbank.com`) | `LOW` (0.27) | `PARTIAL` |
| **Legitimate Courier** | India Post speed post consignment tracking (`indiapost.gov.in`) | `LOW` (0.15) | `PARTIAL` |
| **Legitimate Utility** | BESCOM Karnataka electricity payment receipt (`bescom.karnataka.gov.in`) | `LOW` (0.18) | `PARTIAL` |
| **Legitimate Payment** | PhonePe/Paytm merchant credit notification | `LOW` (0.23) | `PARTIAL` |
| **Banking Phishing** | IP-literal SBI netbanking verification URL | `CRITICAL` (0.94) | `PARTIAL` |
| **Banking Typosquatting**| HDFC KYC update with Unicode lookalike domain | `CRITICAL` (0.88) | `SUFFICIENT` |
| **Banking URL Shortener**| ICICI credit card points expiry via Bitly redirection | `CRITICAL` (0.89) | `PARTIAL` |
| **Electricity Cutoff** | Late night power disconnection threat with burner phone contact | `MEDIUM` (0.45) | `PARTIAL` |
| **Courier Address Fee** | Fake India Post package re-delivery delivery fee APK scam | `CRITICAL` (0.88) | `SUFFICIENT` |
| **Lottery / Prize** | KBC 25 Lakh lottery letter with WhatsApp admin link | `MEDIUM` (0.45) | `PARTIAL` |
| **Work From Home / Task**| Telegram YouTube video liking part-time daily salary scam | `MEDIUM` (0.33) | `PARTIAL` |
| **UPI Collect Request** | "Scan QR / Approve Collect Request to receive refund" scam | `MEDIUM` (0.37) | `PARTIAL` |
| **Digital Arrest / Extortion** | CBI/Cyber Police summons demanding Skype video arrest | `MEDIUM` (0.51) | `PARTIAL` |
| **Predatory Instant Loan** | Pre-approved ₹5,00,000 collateral-free loan APK download | `HIGH` (0.66) | `PARTIAL` |
| **Income Tax Refund** | IT Department tax refund link with pending KYC bait | `CRITICAL` (0.88) | `SUFFICIENT` |
| **Telecom SIM Block** | Urgent e-KYC requirement to avoid 24hr SIM deactivation | `MEDIUM` (0.48) | `PARTIAL` |
| **Ambiguous Chat** | Casual hello / conversational inquiry with no malicious IOCs | `UNKNOWN` (0.00) | `INSUFFICIENT` |
| **Brand Promo with Domain**| Official Zomato weekend cashback alert (`zomato.com`) | `LOW` (0.15) | `PARTIAL` |
| **Compromised Payment** | Citizen paid ₹25,000 to fraudster account | `MEDIUM` (0.42) | `PARTIAL` |

**Verification Scoreboard**:
- **Total Cases Evaluated**: 20 / 20
- **False Positives**: **0** (Target: 0)
- **False Negatives**: **0** (Target: 0)
- **Causal Attack Path Coverage**: **100%**

---

## Architecture Diagram

```
                        CITIZEN INPUT (SMS / Email / WhatsApp / URL)
                                            │
                                  [ Input Sanitization ]
                             (SSRF Check, PII Masking, Defang)
                                            │
               ┌────────────────────────────┼────────────────────────────┐
               │                            │                            │
      [ Rule / Pattern Engine ]     [ Ingestion & IOC ]          [ ML Baseline ]
        (5 Indian Typologies,        (URLs, Domains, IPs,        (TF-IDF + Logistic
        Urgency, Contact Regex)       Phone, UPI VPA)              Regression Model)
               │                            │                            │
               │                   [ Threat Intelligence ]               │
               │        (Google SafeB + PhishTank + PhishStats)          │
               │                            │                            │
               └────────────────────────────┼────────────────────────────┘
                                            │
                                 [ Two-Tier Risk Fusion ]
                             Tier 1: Deterministic Overrides
                            (Gov/Bank Dampening vs Blacklist)
                             Tier 2: Weighted Signal Sum +
                              Evidentiary Sufficiency Gate
                                            │
                                  [ Grounded Explainer ]
                             Gemini Flash Grounded Contract
                             (Fallback to Template Engine)
                             - Direct Observations vs Inferences
                             - Negative Epistemic Bounds
                             - Traceable Causal Attack Path
                                            │
                               [ Adaptive State Machine ]
                             State-proportional actionable steps
                            (Received → Clicked → Details → Paid)
                                            │
                                [ Citizen Trust UI ]
                             Dashboard, Badges, Citations,
                             Verification Suite (/verification.html)
```

---

## Quick Start

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/ShafinNigamana/Cyberkawach_Hackathon_unoffical.git
cd Cyberkawach_Hackathon_unoffical

# Create virtual environment
python -m venv venv
venv\Scripts\activate        # On Windows
# source venv/bin/activate   # On Linux/macOS

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration

Create `.env` file in the project root:

```env
# Optional LLM integration (system will use deterministic fallback if omitted)
GEMINI_API_KEY=your_gemini_api_key_here

# Optional threat intel APIs
SAFE_BROWSING_API_KEY=your_safe_browsing_api_key_here
ABUSEIPDB_API_KEY=
URLHAUS_API_KEY=

# Application settings
APP_ENV=development
LOG_LEVEL=INFO
RATE_LIMIT_PER_MINUTE=30
```

### 3. Run the Application

```bash
# Start FastAPI backend (serves static UI automatically)
python -m uvicorn backend.main:app --reload --port 8000
```

- **Main Citizen UI**: Open [http://localhost:8000/](http://localhost:8000/)
- **Live Verification Suite**: Open [http://localhost:8000/verification.html](http://localhost:8000/verification.html)
- **Interactive OpenAPI Docs**: Open [http://localhost:8000/docs](http://localhost:8000/docs)

---

## Testing & Quality Gates

Run the comprehensive test suites:

```bash
# 1. Run the 20-Case Accuracy Regression Matrix
python scripts/run_accuracy_matrix.py

# 2. Run the Full 88-Test Automated Pytest Suite
python -m pytest tests/

# 3. Run the Live Web Verification Suite
python tests/test_web_suite.py
```

---

## Repository Layout

```
CyberKawach/
├── backend/
│   ├── main.py                  # FastAPI application & route endpoints
│   ├── config.py                # Environment configuration & settings
│   ├── models/
│   │   ├── evidence.py          # Evidence Contract & Epistemic schemas
│   │   └── api.py               # Request / Response Pydantic models
│   ├── modules/
│   │   ├── ingestion.py         # Defanging, IOC extraction, normalization
│   │   ├── rules.py             # Pattern engine for Indian fraud categories
│   │   ├── ml_baseline.py       # TF-IDF + Logistic Regression triage
│   │   ├── url_analyzer.py      # Brand spoofing, IP literal, typosquatting
│   │   ├── threat_intel.py      # 4-state intelligence coordinator
│   │   ├── fusion.py            # Two-tier fusion engine with overrides
│   │   ├── gemini.py            # Grounded epistemic explanation engine
│   │   ├── fallback_explanation.py # Deterministic template engine
│   │   └── response.py          # State-proportional response machine
│   ├── services/
│   │   ├── safe_browsing.py     # Google Safe Browsing v4 client
│   │   ├── phishtank.py         # PhishTank verified database adapter
│   │   ├── phishstats.py        # PhishStats intelligence adapter
│   │   ├── urlhaus.py           # URLhaus malware adapter
│   │   └── abuseipdb.py         # AbuseIPDB reputation adapter
│   └── utils/
│       ├── rate_limiter.py      # Sliding-window rate limiter
│       ├── pii_redactor.py      # Aadhaar, PAN, OTP, phone maskers
│       ├── ssrf_validator.py    # Private IP and metadata address defense
│       └── file_security.py     # Safe file upload and magic byte validator
├── frontend/
│   ├── index.html               # High-trust citizen triage interface
│   ├── verification.html        # Interactive live test & verification dashboard
│   ├── css/main.css             # Vanilla CSS design tokens & animations
│   └── js/
│       ├── app.js               # Application coordinator & event flow
│       ├── api.js               # Async API client
│       └── components.js        # Epistemic badges, cards & attack path UI
├── fixtures/
│   └── accuracy_matrix_cases.json # 20 Indian fraud benchmark cases
├── scripts/
│   └── run_accuracy_matrix.py   # CLI runner for accuracy regression matrix
└── tests/
    ├── conftest.py              # Pytest configuration & rate limit isolation
    ├── test_accuracy_matrix.py  # 24 regression tests on fraud typologies
    ├── test_pipeline.py         # 39 end-to-end pipeline & module tests
    ├── test_security.py         # 25 OWASP Top 10 security hardening tests
    └── test_web_suite.py        # Live HTTP asset and security verification
```

---

## License & Compliance

Developed for the **Cyber Kavach Hackathon 2026** under the **BSides Ahmedabad** Track S2 initiative.
Adheres to Ponytail engineering principles: Zero bloated dependencies, standard library preference, strict type safety, and zero external telemetry leakage.
