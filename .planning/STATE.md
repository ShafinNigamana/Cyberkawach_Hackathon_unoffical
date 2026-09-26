# State: Cyber Fraud Guardian

## Project Reference

See: `.planning/PROJECT.md` & `README.md` (updated 2026-09-26)

**Core Value:** A high-assurance, evidence-driven fraud triage & reasoning engine with grounded epistemic modesty, two-tier risk fusion, zero false positives on legitimate traffic, and 100% causal attack path coverage.
**Current Status:** All Phases Complete (0 through 11). Ready for Hackathon Evaluation & Live Demonstration.

## Phase History & Execution Summary

- **Phase 0: Architecture Freeze** — Locked Evidence Contract schemas, API surface, repository layout, environment configuration.
- **Phase 1: Core Pipeline** — Ingestion, rule engine, TF-IDF + Logistic Regression ML baseline, URL analyzer, brand check, fusion scoring, Gemini + deterministic fallback, adaptive response, citizen-trust UI.
- **Phase 2: Security & Stability Hardening** — OWASP Top 10 defense, anti-SSRF IP/CIDR validator, zero-PII masking (PAN, Aadhaar, OTP), prompt injection defense, and sliding-window rate limiting.
- **Phase 3: Threat Intel 4-State Architecture** — Transitioned from binary threat checks to 4-state error boundaries (`FOUND`, `NOT_FOUND`, `RATE_LIMITED`, `UNAVAILABLE`), integrated Google Safe Browsing, PhishTank, and PhishStats.
- **Phase 4: Two-Tier Risk Fusion Engine** — Tier 1 deterministic safety overrides (official domain dampening $\le 0.15$ guaranteeing zero false positives; blacklist overrides $\ge 0.85$), Tier 2 weighted fusion across 9 signal dimensions with evidentiary sufficiency evaluation (`SUFFICIENT`, `PARTIAL`, `INSUFFICIENT`).
- **Phase 5: Laya Model Evidence** — Fast typed model decisions integrated with bounded model authority.
- **Phase 6: Grounded Epistemic Explanation Engine** — Gemini contract enforcing observation vs inference separation (`observed_value` vs `interpretation`), epistemic statuses (`CONFIRMED`, `OBSERVED`, `SUSPICIOUS`, `POSSIBLE`, `UNKNOWN`, `UNAVAILABLE`), reliability weighting, and Negative Epistemic Bounds ("What the Guardian Cannot Conclude").
- **Phase 7: Traceable Attack Paths & Threat Intel Modernization** — Causal attack path reconstruction (`Lure` $\rightarrow$ `Redirection` $\rightarrow$ `Exploitation` $\rightarrow$ `Monetization/Consequence`) with `[Evidence N]` citations.
- **Phase 8: State-Specific Proportional Response** — Proportional guidance mapped across citizen journey (`received`, `clicked`, `entered_credentials`, `paid`), including National Cyber Crime 1930 Golden Hour emergency protocol.
- **Phase 9: Frontend Epistemic Badges & Negative Bounds UI** — Rendered sufficiency badges, epistemic badges, reliability scores, negative bounds section, and interactive causal attack path cards.
- **Phase 10: 20-Case Accuracy Regression Matrix** — Validated 20 real-world Indian cyber fraud typologies (zero false positives, zero false negatives, 100% attack path coverage).
- **Phase 11: Demo Polish & Final Quality Gate** — Live web suite verification (`test_web_suite.py`), complete pytest test suite with test isolation fixture (`tests/conftest.py`), header navigation to verification dashboard, comprehensive `README.md`.

## Active Decisions
- Threat intelligence architecture finalized as Google Safe Browsing + PhishTank + PhishStats. OpenPhish completely purged from runtime and configuration.
- Free APIs only with guaranteed deterministic fallbacks.
- Strictly decoupled direct factual observations from analytical interpretations.
- Negative epistemic bounds rendered on all citizen explanation cards.

---
*Last updated: 2026-09-26 after Phase 11 Final Quality Gate*
