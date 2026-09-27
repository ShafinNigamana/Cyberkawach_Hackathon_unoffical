# Requirements: Cyber Fraud Guardian

**Defined:** 2026-09-25
**Core Value:** A complete, evidence-driven fraud analysis pipeline that works end-to-end even with every optional component disabled.

## v1 Requirements

### Ingestion & Extraction

- [ ] **DET-01**: Text/URL ingestion with normalization and IOC extraction from SMS, email, chat text
- [ ] **OCR-01**: Screenshot OCR — PaddleOCR primary, Tesseract fallback (P1)

### Detection & Analysis

- [ ] **DET-02**: Rule-based fraud/category detection with deterministic pattern matching + optional TF-IDF/Logistic Regression ML baseline
- [ ] **URL-01**: URL & domain analyzer — punycode detection, suspicious TLD, lexical analysis, redirect following
- [ ] **BRD-01**: Brand impersonation check — known brand registry + string similarity matching
- [ ] **LAY-01**: Laya typed-decision integration with calibration and graceful fallback (P1)

### Threat Intelligence

- [x] **TI-01**: 3 P0 threat-intel adapters (Google Safe Browsing + PhishTank + PhishStats) with individual sourcing
- [ ] **TI-02**: Additional threat-intel adapters (URLhaus + AbuseIPDB) — P2, only if time remains

### Fusion & Scoring

- [ ] **FUS-01**: Evidence fusion combining all upstream signals into risk score with provenance tracking
- [ ] **CAL-01**: Confidence calibration — ECE/Brier scoring, threshold tuning (P3)

### Explanation & Response

- [ ] **EXP-01**: Explanation layer — Gemini grounded explanation with deterministic/template-based fallback. If Gemini fails, times out, or hits quota, the system generates a structured explanation from verified evidence objects. Demo must never fail because Gemini is unavailable.
- [ ] **RSP-01**: Adaptive response state machine — branches on received/clicked/entered creds/paid

### Campaign Intelligence

- [ ] **DNA-01**: Fraud DNA fingerprinting / campaign correlation using NetworkX (P2)
- [ ] **GRP-01**: Seeded campaign graph / related-incident view (P2)
- [ ] **CNV-01**: Conversation-level multi-message analysis (P3)

### Localization

- [ ] **LNG-01**: Hindi/Gujarati/Hinglish handling via IndicTrans2 (P3)

### Reporting & UI

- [ ] **UI-01**: Working end-to-end UI — evidence-dense, every threat-intel result visible with source
- [ ] **RPT-01**: Evidence pack export PDF/JSON + reporting handoff (P3)

### Security & Hardening (Cross-cutting, Phase 2+)

- [ ] **SEC-01**: Input validation at all trust boundaries
- [ ] **SEC-02**: API error handling with graceful degradation — each external API has tested failure path
- [ ] **SEC-03**: Rate limiting on API endpoints
- [ ] **SEC-04**: SSRF protection — app fetches user-submitted URLs safely
- [ ] **SEC-05**: File-upload type/size limits
- [ ] **SEC-06**: Prompt-injection defense — scam content never changes model role
- [ ] **SEC-07**: PII redaction before any cloud API call
- [ ] **SEC-08**: Evidence provenance — every evidence item traceable to its source
- [ ] **SEC-09**: Structured logging for debugging and audit trail

## v2 Requirements

Deferred beyond hackathon scope.

- **ADV-01**: Advanced dashboard with analytics
- **ADV-02**: Multi-tenant support
- **ADV-03**: Real-time message monitoring
- **ADV-04**: Mobile native application

## Out of Scope

| Feature | Reason |
|---------|--------|
| Autonomous agent swarm | Too complex, too risky for 24h demo |
| Custom LLM training | No time, no compute budget |
| Carrier/WhatsApp integration | Requires production APIs |
| Neo4j graph database | NetworkX sufficient; no infra risk |
| Paid API dependencies | Free tiers only; paid as fallback |
| User authentication | Not needed for demo |
| Real-time monitoring | Batch analysis only |

## Traceability

| Requirement | Tier | Phase | Status |
|-------------|------|-------|--------|
| DET-01 | P0 | Phase 1 | Pending |
| DET-02 | P0 | Phase 1 | Pending |
| URL-01 | P0 | Phase 1 | Pending |
| BRD-01 | P0 | Phase 1 | Pending |
| TI-01  | P0 | Phase 1 | Pending |
| FUS-01 | P0 | Phase 1 | Pending |
| EXP-01 | P0 | Phase 1 | Pending |
| RSP-01 | P0 | Phase 1 | Pending |
| UI-01  | P0 | Phase 1 | Pending |
| SEC-01 through SEC-09 | P0 | Phase 2 | Pending |
| OCR-01 | P1 | Phase 4 | Pending |
| LAY-01 | P1 | Phase 3 | Pending |
| TI-02  | P2 | Phase 4 | Pending |
| DNA-01 | P2 | Phase 4 | Pending |
| GRP-01 | P2 | Phase 4 | Pending |
| CNV-01 | P3 | Phase 4 | Pending |
| LNG-01 | P3 | Phase 4 | Pending |
| RPT-01 | P3 | Phase 5 | Pending |
| CAL-01 | P3 | Phase 4 | Pending |

**Coverage:**
- v1 requirements: 28 total (19 functional + 9 security)
- Mapped to phases: 28
- Unmapped: 0 ✓

---
*Requirements defined: 2026-09-25*
*Last updated: 2026-09-25 after initialization*
