# Cyber Fraud Guardian — S2: Citizen Fraud-Message Guardian

## What This Is

A citizen-facing fraud message analysis tool that detects, verifies, explains, and helps respond to suspected scam messages (SMS, email, chat, screenshots). Built for the Cyber Kavach Challenge 2026 national hackathon at BSides Ahmedabad. The system uses a layered decision architecture — fast local triage, deterministic threat-intel verification, and grounded LLM explanation — so no single model is the sole authority.

## Core Value

A complete, evidence-driven fraud analysis pipeline that works end-to-end even with every optional component disabled — detection, verification, explanation, and adaptive response must survive as a functioning demo at all times.

## Context

- **Event:** Cyber Kavach Challenge 2026, BSides Ahmedabad
- **Build window:** 26–27 September 2026, demos/judging 27 September
- **Team size:** 2–4 members, free entry
- **Track:** S2 — Citizen Fraud-Message Guardian (fixed)
- **Product principle:** DETECT → VERIFY → EXPLAIN → PROTECT → RESPOND → REPORT
- **Core thesis:** Fast, evidence-driven fraud guardian — not another generic "AI scam detector." Local decision layer triages, threat intelligence and deterministic checks verify evidence, LLM explains verified findings and adapts the response.

### Architecture

```
INPUT: text / SMS / email / chat, URL (screenshot via OCR in P1)
  → Normalization + IOC extraction
  → in parallel: Rule Engine (fast triage) | ML baseline (optional) | Laya (typed decisions, P1) | URL/Domain/Threat-Intel
  → Evidence Fusion → risk score + confidence
  → HIGH CONFIDENCE → direct decision | UNCERTAIN/CONFLICT → Gemini (with deterministic fallback)
  → Explanation + guidance
  → Attack path | Incident response | Campaign/Fraud DNA (P2)
```

### Research Grounding

| Priority | Paper | Feeds |
|----------|-------|-------|
| 1 | APOLLO — GPT-based phishing detection + explanations | Gemini explanation layer |
| 2 | XF-PhishBERT — explainability, URL decomposition | Evidence fusion / explainability |
| 3 | PhishLumos — campaign-level phishing mitigation | Fraud DNA / campaign graph |
| 4 | Conversational Scams research | Conversation-level analysis (P3) |
| 5 | SmishTank smishing dataset | Training/eval data design |
| 6 | Explanations in phishing warning dialogs (150-participant study) | Citizen-facing explanation UX |

## Requirements

### Validated

(None yet — ship to validate)

### Active

#### P0 — Must Survive (demo-critical)
- [ ] **DET-01**: Text/URL ingestion, normalization, IOC extraction (REQ-01)
- [ ] **DET-02**: Rule-based fraud/category detection + optional TF-IDF/Logistic Regression baseline (REQ-02)
- [ ] **URL-01**: URL & domain analyzer — punycode, TLD, lexical, redirects (REQ-03)
- [ ] **BRD-01**: Brand impersonation check — registry + similarity (REQ-04)
- [x] **TI-01**: 3 threat-intel adapters — Google Safe Browsing + PhishTank + PhishStats (REQ-05)
- [ ] **FUS-01**: Evidence fusion + risk score with provenance (REQ-06)
- [ ] **EXP-01**: Explanation layer — Gemini grounded explanation with deterministic/template fallback (REQ-07)
- [ ] **RSP-01**: Adaptive response state machine — received/clicked/entered creds/paid (REQ-08)
- [ ] **UI-01**: Working end-to-end UI with visible evidence items (REQ-09)

#### P1 — Should Have
- [ ] **OCR-01**: Screenshot OCR — PaddleOCR primary, Tesseract fallback (REQ-10)
- [ ] **LAY-01**: Laya typed-decision integration + calibration, graceful fallback (REQ-11)

#### P2 — Nice to Have
- [ ] **TI-02**: Additional threat-intel adapters — URLhaus + AbuseIPDB (REQ-05b)
- [ ] **DNA-01**: Fraud DNA / campaign correlation with NetworkX (REQ-12)
- [ ] **GRP-01**: Seeded campaign graph / related-incident view (REQ-13)

#### P3 — Stretch
- [ ] **CNV-01**: Conversation-level (multi-message) analysis (REQ-14)
- [ ] **LNG-01**: Hindi/Gujarati/Hinglish handling via IndicTrans2 (REQ-15)
- [ ] **RPT-01**: Evidence pack export PDF/JSON + reporting handoff (REQ-16)
- [ ] **CAL-01**: Confidence calibration — ECE/Brier, threshold tuning (REQ-17)

#### Cross-Cutting (Phase 2+)
- [ ] **SEC-01**: Input validation at all trust boundaries
- [ ] **SEC-02**: API error handling with graceful degradation
- [ ] **SEC-03**: Rate limiting
- [ ] **SEC-04**: SSRF protection (app fetches user-submitted URLs)
- [ ] **SEC-05**: File-upload type/size limits
- [ ] **SEC-06**: Prompt-injection defense
- [ ] **SEC-07**: PII redaction before any cloud call
- [ ] **SEC-08**: Evidence provenance logging
- [ ] **SEC-09**: Structured logging

### Out of Scope

- Full autonomous agent swarm — too complex, too risky for demo
- Custom LLM training — no time, no compute budget
- Carrier/WhatsApp integration — requires production APIs, no sandbox available
- Complex production graph infrastructure (Neo4j) — NetworkX only unless time allows
- Large paid-API footprint — free tiers only, paid as fallback
- Mobile native app — web-first only
- User authentication/accounts — not needed for demo
- Real-time message monitoring — batch analysis only

## Constraints

- **Timeline**: 26–27 September 2026, ~24-hour build window. Hard stop at 60–70% to freeze features.
- **Budget**: Zero. Free API tiers only (Safe Browsing non-commercial, PhishTank, PhishStats). URLhaus and AbuseIPDB are P2 stretch integrations.
- **Security**: All work sandboxed/synthetic. No live system probing. DPDP-compliant. PII redacted before cloud calls.
- **Hackathon rules**: Responsible disclosure. Scam content treated as untrusted data at every layer.
- **Tech stack**: Python backend, vanilla HTML/CSS/JS frontend, Gemini Flash-Lite/Flash for LLM.
- **Accessibility**: WCAG AA minimum contrast. No emoji as icons. Lucide/Heroicons SVG only.

## Judging Weights

| Criterion | Weight |
|-----------|--------|
| Fit & relevance | 25% |
| Technical soundness & security rigour | 25% |
| Feasibility & deployability | 20% |
| Innovation & originality | 15% |
| Demonstration & clarity | 15% |

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Laya deferred to Phase 3 (after working baseline) | Experimental; demo must not depend on it. Rules + threat-intel + explanation are permanent fallback. | — Pending |
| OCR deferred to P1 | Not demo-critical; text/URL input covers the complete demo path | — Pending |
| NetworkX over Neo4j for campaign graph | Zero-dependency, works locally, no infra risk | — Pending |
| Evidence Contract as internal API | Every module reads/writes the same object — decouples components | — Pending |
| Gemini non-critical with deterministic fallback | If Gemini fails/times out/hits quota, deterministic template explanation from verified evidence. Demo never fails because Gemini is unavailable. | — Pending |
| P0 threat-intel finalized to Safe Browsing + PhishTank + PhishStats | URLhaus and AbuseIPDB deferred to P2 to reduce P0 integration risk | — Done |
| ML baseline separate from rule engine | TF-IDF/LogReg is optional ML, not part of deterministic rule matching | — Pending |
| Free APIs only, paid as fallback | No budget; hackathon constraint | — Pending |
| Conservative UI aesthetic (fintech/gov) | Judge-legible, citizen-trust, WCAG AA | — Pending |

## Build Discipline

1. **Phase 0**: Freeze architecture — repo, env, API contracts, DB schema, Evidence Contract. No feature code.
2. **Phase 1**: Complete end-to-end P0 pipeline. Must demo even with all optionals disabled.
3. **Phase 2**: Stability/security hardening. Break each external API and confirm graceful degradation.
4. **Phase 3**: Laya integration — only if Phase 1 checkpoint passes. Keep only if measurably helps.
5. **Phase 4**: Innovation modules — each independent, individually disable-able. Fraud DNA → campaign graph → OCR → multilingual → conversation analysis.
6. **Phase 5**: Polish — UI, demo dataset, dashboard, evidence export, animation, documentation.
7. **Hard stop**: At ~60–70% of build time, stop adding anything risky. Testing → integration → bug fixing → demo rehearsal only.

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-09-25 after initialization*
