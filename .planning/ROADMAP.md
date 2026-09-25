# Roadmap: Cyber Fraud Guardian

**Created:** 2026-09-25
**Granularity:** Coarse (hackathon — 6 phases)
**Build window:** 26–27 September 2026

## Phase 0: Architecture Freeze

**Goal:** Lock all contracts, schemas, repo structure, and environment before any feature code.

**Delivers:**
- Repository layout with backend/frontend separation
- Evidence Contract schema (internal API)
- REST API contract (frontend ↔ backend)
- Environment variable list and .env.example
- Sample input fixtures
- Gemini grounding contract (system rules)

**Requirements:** None directly — enables all subsequent phases.

**Exit criteria:** Evidence Contract and API surface reviewed and confirmed. No feature code written.

**Status:** Active

---

## Phase 1: Core Pipeline (P0 — Must Demo)

**Goal:** Complete end-to-end pipeline from input to adaptive response. Must work as a full demo even with every optional component disabled.

**Delivers:**
- Text/URL ingestion + normalization + IOC extraction (DET-01)
- Rule-based fraud detection + optional TF-IDF/Logistic Regression ML baseline (DET-02)
- URL & domain analyzer (URL-01)
- Brand impersonation check (BRD-01)
- 2 threat-intel adapters: Google Safe Browsing + PhishTank (TI-01)
- Evidence fusion + risk score (FUS-01)
- Explanation layer — Gemini with deterministic/template fallback (EXP-01)
- Adaptive response state machine (RSP-01)
- Working end-to-end UI (UI-01)

**Requirements:** DET-01, DET-02, URL-01, BRD-01, TI-01, FUS-01, EXP-01, RSP-01, UI-01

**Exit criteria:** Upload a scam message → see extracted indicators → see rule engine + URL analysis results → see threat-intel (Safe Browsing + PhishTank) as individual sourced items → see fused risk score → see explanation (Gemini or deterministic fallback) citing evidence → see adaptive response for different user states. Disable Gemini API key and confirm deterministic fallback explanation still works.

**Checkpoint:** Deliberately break each external API and confirm the app still degrades gracefully.

**Status:** Pending

---

## Phase 2: Security & Stability Hardening

**Goal:** Harden every trust boundary and external dependency. No demo-breaking failures.

**Delivers:**
- Input validation (SEC-01)
- API error handling with graceful degradation (SEC-02)
- Rate limiting (SEC-03)
- SSRF protection (SEC-04)
- File-upload restrictions (SEC-05)
- Prompt-injection defense (SEC-06)
- PII redaction (SEC-07)
- Evidence provenance (SEC-08)
- Structured logging (SEC-09)

**Requirements:** SEC-01 through SEC-09

**Exit criteria:** Break each external API deliberately → app degrades gracefully, never crashes. Submit prompt-injection payloads → model role unchanged. Submit malicious URLs → SSRF blocked.

**Status:** Pending

---

## Phase 3: Laya Integration (Conditional)

**Goal:** Integrate Laya typed-decision model — only if Phase 1 checkpoint passes. Keep only if it measurably improves detection over rules + threat-intel alone.

**Delivers:**
- Laya model integration with typed outputs (LAY-01)
- Calibration against working baseline
- Graceful fallback — Laya disabled = pipeline works identically

**Requirements:** LAY-01

**Entry gate:** Phase 1 checkpoint passed (end-to-end demo working without Laya).

**Exit criteria:** Side-by-side comparison with and without Laya on test cases. Decision: keep or disable.

**Kill switch:** If Laya integration takes >2 hours or measurably degrades the pipeline, disable and move to Phase 5.

**Status:** Pending

---

## Phase 4: Innovation Modules (Each Independent)

**Goal:** Add differentiating features. Each module is independent and individually disable-able. Stop and move to Phase 5 at the hard-stop time marker.

**Delivers (in priority order):**
1. Fraud DNA fingerprinting / campaign correlation (DNA-01)
2. Seeded campaign graph / related-incident view (GRP-01)
3. Additional threat-intel adapters — URLhaus + AbuseIPDB (TI-02)
4. Screenshot OCR — PaddleOCR → Tesseract fallback (OCR-01)
5. Multilingual/code-mixed handling (LNG-01)
6. Conversation-level analysis (CNV-01)
7. Confidence calibration (CAL-01)

**Requirements:** DNA-01, GRP-01, TI-02, OCR-01, LNG-01, CNV-01, CAL-01

**Exit criteria:** Each enabled module produces correct evidence items that render in the UI with provenance. Each disabled module does not break the pipeline.

**Hard stop:** At ~60–70% of remaining build time, stop and move to Phase 5 regardless.

**Status:** Pending

---

## Phase 5: Polish & Demo Prep

**Goal:** Final polish, demo dataset, rehearsal. No new features.

**Delivers:**
- UI polish and animations (hover/transition only)
- Demo dataset with realistic scam messages
- Evidence pack export (RPT-01)
- Dashboard view
- Demo rehearsal walkthrough
- Documentation
- Pre-delivery checklist verification

**Requirements:** RPT-01, UI-01 (polish)

**Exit criteria:** Full demo rehearsal passes the 10-step judge walkthrough script. Pre-delivery checklist green.

**Status:** Pending

---

## Do-Not-Risk-the-Demo List

If time pressure mounts, these are explicitly forbidden additions:
- Full autonomous agent swarm
- Custom LLM training
- Carrier/WhatsApp integration
- Complex production graph infrastructure
- Large paid-API footprint

Route all remaining time to Phase 5 instead.

---
*Roadmap created: 2026-09-25*
*Last updated: 2026-09-25 after initialization*
