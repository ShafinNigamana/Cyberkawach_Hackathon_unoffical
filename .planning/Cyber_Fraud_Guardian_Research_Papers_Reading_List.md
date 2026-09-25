CYBER FRAUD GUARDIAN

Research Paper Reading List

For the S2 — Citizen Fraud-Message Guardian hackathon concept

Purpose: give the team a focused research map covering smishing detection, explainability, LLMs, calibration, phishing URLs, infrastructure graphs, campaign intelligence, conversational scams, and Indian-language NLP.

# How to Use This Document

This is a teammate-oriented reading list. The papers are organized by the part of the proposed system they can inform. The goal is not to copy an existing method, but to understand the state of the art, identify what has already been done, and determine where the hackathon implementation can make a distinct engineering contribution.

| Priority | Paper / Topic | Why it matters for this project |
| --- | --- | --- |
| 1 | APOLLO | Direct precedent for LLM-based phishing detection + user-facing explanations. |
| 2 | XF-PhishBERT | Explainability, few-shot learning, URL decomposition and counterfactual explanations. |
| 3 | PhishLumos | Campaign-level intelligence using related infrastructure rather than only one URL. |
| 4 | Conversational Scams | Moves beyond one message to multi-message scam trajectories. |
| 5 | Smishing Dataset I | Concrete smishing data and useful dataset/metadata structure. |
| 6 | Explanations in Warning Dialogs | Research basis for how warnings should communicate risk to citizens. |

# 1. Smishing / SMS Fraud Detection

## 1. Smishing Dataset I: Phishing SMS Dataset from Smishtank.com

Year: 2024 | Authors: Daniel Timko; Muhammad Lutfor Rahman

Why read: Useful for training-data design, real smishing examples, and understanding how sender, brand and URL metadata can be represented. The paper reports 1,090 community-sourced smishing samples.

arXiv: https://arxiv.org/abs/2402.18430

DOI: https://doi.org/10.1145/3626232.3653282

## 2. Advancements of SMS Spam Detection: A Comprehensive Survey of NLP and ML Techniques

Year: 2024 | Authors: Mohammed Rasol Al Saidat; Suleiman Y. Yerima; Khaled Shaalan

Why read: A broad survey of rule-based, NLP, machine-learning and deep-learning approaches to SMS/spam/smishing detection. Particularly useful for understanding what is already established so the team does not present existing techniques as novel.

ScienceDirect: https://www.sciencedirect.com/science/article/pii/S1877050924029995

DOI: https://doi.org/10.1016/j.procs.2024.10.198

# 2. Explainable Phishing Detection

## 3. Explanations in warning dialogs to help users defend against phishing attacks

Year: 2023 | Authors: Giuseppe Desolda; Joseph Aneke; Carmelo Ardito; Rosa Lanzilotti; Maria Francesca Costabile

Why read: Directly relevant to the plain-language explanation feature. It studies phishing warning dialogs that explain why something is suspicious rather than merely displaying a warning. The study included 150 participants.

ScienceDirect: https://www.sciencedirect.com/science/article/pii/S1071581923000654

DOI: https://doi.org/10.1016/j.ijhcs.2023.103056

## 4. XF-PhishBERT: Explainable few-shot learning with ModernBERT for detecting emerging phishing attacks

Year: 2025 | Authors: Mohammed Tawfik et al.

Why read: Relevant to explainability, few-shot learning and emerging phishing. The work combines ModernBERT with explanation mechanisms including SHAP, attention visualization, URL decomposition and counterfactual explanations.

Nature / Scientific Reports: https://www.nature.com/articles/s41598-025-27500-0

DOI: https://doi.org/10.1038/s41598-025-27500-0

# 3. LLM-Based Phishing Detection

## 5. APOLLO: A GPT-based tool to detect phishing emails and generate explanations that warn users

Year: 2025 | Authors: Giuseppe Desolda; Francesco Greco; Luca Viganò

Why read: Probably the most directly relevant LLM paper for the project. APOLLO combines preprocessing, URL enrichment, GPT-4o and user-facing explanations. It is important both as a foundation and as something the team should distinguish its own architecture from.

ACM / DOI: https://doi.org/10.1145/3733049

arXiv preprint: https://arxiv.org/abs/2410.07997

# 4. Confidence and Calibration

## 6. Trust calibration of automated security IT artifacts: A multi-domain study of phishing-website detection tools

Year: 2021 | Authors: Study on user trust calibration for automated security artifacts

Why read: Useful for deciding how to display confidence and how to avoid encouraging users to blindly trust an automated security verdict. It supports the idea that the UI should communicate system capability and uncertainty appropriately.

ScienceDirect: https://www.sciencedirect.com/science/article/abs/pii/S0378720620303323

DOI: https://doi.org/10.1016/j.im.2020.103394

## 7. A Transformer network calibrated with fuzzy logic for phishing URL detection

Year: 2025 | Authors: Seok-Jun Buu; Sung-Bae Cho

Why read: Relevant to combining deep learning with explicit/structured decision logic and calibration for URL detection. The paper evaluates on datasets containing more than one million URLs.

ScienceDirect: https://www.sciencedirect.com/science/article/pii/S0165011425002131

DOI: https://doi.org/10.1016/j.fss.2025.109474

# 5. Graph / Infrastructure Intelligence

## 8. A graph-theoretic approach for the detection of phishing webpages

Year: 2020 | Authors: Graph-based phishing detection study

Why read: Foundational graph-oriented work showing that relationships in the web/infrastructure graph can provide phishing signals rather than relying only on individual URL text.

ScienceDirect: https://www.sciencedirect.com/science/article/pii/S016740482030078X

DOI: https://doi.org/10.1016/j.cose.2020.101793

## 9. Efficient Phishing URL Detection Using Graph-Based Machine Learning and Loopy Belief Propagation

Year: 2025 | Authors: Wenye Guo; Qun Wang; Hao Yue; Haijian Sun; Rose Qingyang Hu

Why read: A more recent graph approach incorporating URL structure and network-level information such as IP addresses and authoritative nameservers. Useful when designing an infrastructure graph instead of treating every URL as an isolated record.

arXiv: https://arxiv.org/abs/2501.06912

DOI: https://doi.org/10.1109/ICC52391.2025.11161346

## 10. Graph-Based Phishing Domain Detection via Certificate-DNS Heterogeneous Networks

Year: 2025 | Authors: Luca Bianchi; Elena Rossi; Luca Ferraro

Why read: Directly relevant to Fraud DNA / campaign graphs because it models relationships among domains, IPs, TLS certificates and registrars. This is useful as architectural inspiration for infrastructure correlation.

Preprint: https://www.preprints.org/manuscript/202512.2708

Note: Treat this as a preprint and do not present its findings as established peer-reviewed results without checking the current publication status.

# 6. Campaign-Level Phishing Intelligence

## 11. PhishLumos: From a Single URL to Campaign-Level Phishing Mitigation

Year: 2026 | Authors: Campaign-level phishing intelligence study

Why read: Very important for the proposed campaign-correlation feature. The work moves from examining one URL to identifying related infrastructure and entire phishing campaigns using domains, IPs, certificates and historical scan data in a graph.

IEEE / DOI: https://doi.org/10.1109/ACCESS.2026.3696597

arXiv: https://arxiv.org/abs/2509.21772

# 7. Conversational Scam Detection

## 12. An Explainable Agentic System for Detection of Conversational Scams with Summary-Based Memory

Year: 2026 | Authors: Ahmed Omar Salim Adnan; Yogananda Manjunath; Shivanjali Khare

Why read: Relevant if the system grows from one-message detection into conversation-level analysis. It introduces ConScamBench-278 and studies scams that develop across multiple interactions.

arXiv: https://arxiv.org/abs/2607.11707

# 8. Indian-Language AI

## 13. IndicTrans2: Towards High-Quality and Accessible Machine Translation Models for all 22 Scheduled Indian Languages

Year: 2023 | Authors: AI4Bharat research team

Why read: Useful for the multilingual layer, especially if the project supports Hindi, Gujarati and other Indian languages. It introduced a system covering all 22 scheduled Indian languages and the Bharat Parallel Corpus Collection.

arXiv: https://arxiv.org/abs/2305.16307

Project: https://github.com/AI4Bharat/IndicTrans2

# 9. DNS / Domain Lifecycle Intelligence

## 14. Registration, Detection, and Deregistration: Analyzing DNS Abuse for Phishing Attacks

Year: 2025 | Authors: DNS abuse / phishing lifecycle research

Why read: Useful for domain-lifecycle intelligence and understanding how phishing domains move through registration, detection and deregistration. The study analyzes 690,502 phishing domains across 39 months.

arXiv: https://arxiv.org/abs/2502.09549

# 10. Laya / JEV: Important Non-Paper References

Laya itself is not a research paper. It is an open-source implementation/model for typed, non-autoregressive decision making. It is relevant to the proposed System-1 layer because it can return structured decisions such as yes/no probability, choice, and score in one forward pass.

- Use Laya as a fast, specialized fraud-triage model rather than assuming the base checkpoint is already a high-quality scam detector.

- Fine-tune it on fraud-specific data for decisions such as fraud/non-fraud, fraud category, impersonation, credential request, payment request, and escalation-to-deeper-analysis.

- Calibrate its probabilities before using confidence thresholds; raw probabilities can be overconfident.

- Architecturally, the intended pattern is Laya/System-1 for fast triage and Gemini/System-2 for deeper, grounded explanation when the evidence is uncertain or conflicting.

Laya repository: https://github.com/he-jev/laya

Laya benchmark / documentation: https://github.com/NandhaKishorM/laya

# 11. JEV/Laya System-1 Preprint (2026)

A September 2026 preprint discusses JEV/Laya-style System-1 decision layers in security/LLM systems. Its domain is penetration-testing harnesses rather than citizen fraud detection, so it should be treated as architectural inspiration rather than direct evidence for this problem.

arXiv: https://arxiv.org/abs/2609.28940

# 12. Research-to-Implementation Map

| Project component | Key research to read | What the team can take from it |
| --- | --- | --- |
| Smishing classifier | Smishing Dataset I; SMS Spam Survey | Dataset structure, classical ML/NLP baselines, smishing-specific features. |
| Plain-language explanations | Explanations in warning dialogs; APOLLO | Evidence-backed warnings and LLM-generated explanations. |
| Explainable model layer | XF-PhishBERT | Feature attribution, URL decomposition, counterfactual explanation ideas. |
| URL analysis | Transformer + fuzzy calibration; graph URL detection | Hybrid ML + structured security features + calibration. |
| Fraud DNA / infrastructure graph | Graph-theoretic phishing; graph ML; certificate-DNS graph | Relate domains, IPs, certificates, registrars and other infrastructure. |
| Campaign correlation | PhishLumos | Pivot from one URL/message to related campaign infrastructure. |
| Conversation-level fraud | Conversational Scam Detection | Analyze scam progression across multiple messages. |
| Indian-language support | IndicTrans2 | Hindi/Gujarati and broader Indian-language support. |
| Domain lifecycle | DNS abuse / phishing lifecycle paper | Use registration and detection timing as additional evidence. |
| Fast decision engine | Laya documentation + System-1 preprint | Typed decisions, fast triage, escalation logic and confidence calibration. |

# 13. Recommended Reading Order for the Team

| Order | Read | Purpose |
| --- | --- | --- |
| 1 | APOLLO | Understand what an LLM-based phishing assistant already looks like. |
| 2 | XF-PhishBERT | Understand explainability, few-shot learning and counterfactual ideas. |
| 3 | PhishLumos | Understand campaign-level correlation and why single-URL detection is not enough. |
| 4 | Conversational Scams | Understand multi-message scam trajectories. |
| 5 | Smishing Dataset I | Understand realistic smishing data and metadata. |
| 6 | Explanations in warning dialogs | Understand how to present risk to normal users. |
| 7 | Graph-based phishing papers | Deepen infrastructure graph design. |
| 8 | Calibration paper(s) | Design confidence and UI safely. |
| 9 | IndicTrans2 | Design the Indian-language layer. |
| 10 | DNS abuse lifecycle | Add domain timing/lifecycle intelligence. |

# 14. What Can Be Novel for the Hackathon

Using a research paper by itself is not novelty. The project can become distinctive by combining research-backed ideas into a coherent, feasible citizen-fraud workflow.

- Fast local typed-decision triage using Laya, with calibrated escalation instead of sending every message to an LLM.

- Evidence fusion across message features, URL/domain intelligence, brand impersonation checks and threat-intelligence sources.

- Grounded Gemini explanations based on verified evidence instead of making the LLM the sole security authority.

- Campaign-level correlation that can connect a new message to previously observed domains, infrastructure and scam patterns.

- Conversation-level analysis for scams that build trust over multiple messages rather than relying only on one-message classification.

- Indian-language and code-mixed support (for example Hindi-English or Gujarati-English fraud messages).

# 15. Source and Verification Notes

The list above reflects the research sources previously identified for the Cyber Fraud Guardian concept and is intended as a team reading map. Publication status can change, especially for preprints. Before citing any paper in a final presentation or report, check the current publisher page or DOI record.

Important distinction: Research-backed does not mean the project should reproduce the paper. The hackathon contribution should be an explicit engineering extension, integration, evaluation, or deployment-oriented adaptation.
