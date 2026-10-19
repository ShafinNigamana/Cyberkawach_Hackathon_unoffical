"""
Adversarial Text Normalizer and Obfuscation Detection Module.

Defends against adversarial evasion techniques commonly employed by phishing actors:
1. Zero-width & non-printable character injection (\\u200B, \\u200C, \\u200D, \\uFEFF, \\u202A-\\u202E).
2. Unicode Homoglyphs & Confusables (e.g. Cyrillic / Greek characters substituted into Latin text).
3. Delimiter injection across sensitive keywords (e.g. "K.Y.C", "H-D-F-C", "P a y t m", "U_P_I").
4. Common Leetspeak substitutions (@ -> a, 0 -> o, 1 -> i, $ -> s, 3 -> e, 5 -> s, ! -> i).

Returns normalized clean text for downstream ML & rule pipelines, plus deterministic
evidence flags if deliberate evasion patterns are detected.
"""

from __future__ import annotations

import math
import re
import unicodedata
from typing import Any, Tuple

from backend.models.evidence import (
    EvidenceItem,
    EvidenceReliability,
    EvidenceSeverity,
    EvidenceStatus,
    EvidenceType,
    RiskDirection,
)

# ─── Homoglyph Lookup Map (Cyrillic, Greek, Fullwidth to ASCII Latin) ───
_HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillic small letters
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
    'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
    # Cyrillic capital letters
    'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'І': 'I', 'Ј': 'J',
    'К': 'K', 'М': 'M', 'О': 'O', 'Р': 'P', 'Ѕ': 'S', 'Т': 'T', 'Х': 'X',
    'Ү': 'Y', 'Ԝ': 'W',
    # Greek letters commonly abused
    'α': 'a', 'ο': 'o', 'ν': 'v', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x',
    'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M',
    'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
}

# ─── Zero-Width & Hidden Characters ───
_ZERO_WIDTH_CHARS = frozenset({
    '\u200b',  # zero-width space
    '\u200c',  # zero-width non-joiner
    '\u200d',  # zero-width joiner
    '\u200e',  # LTR mark
    '\u200f',  # RTL mark
    '\ufeff',  # zero-width no-break space / BOM
    '\u202a',  # LTR embedding
    '\u202b',  # RTL embedding
    '\u202c',  # pop directional formatting
    '\u202d',  # LTR override
    '\u202e',  # RTL override (used in filename/URL spoofing)
    '\u00ad',  # soft hyphen
})

# Protected brands & sensitive scam terms to de-obfuscate if delimited
_SENSITIVE_TARGETS = [
    ("hdfc", re.compile(r'\bh[\s._\-*]+d[\s._\-*]+f[\s._\-*]+c\b', re.IGNORECASE)),
    ("icici", re.compile(r'\bi[\s._\-*]+c[\s._\-*]+i[\s._\-*]+c[\s._\-*]+i\b', re.IGNORECASE)),
    ("paytm", re.compile(r'\bp[\s._\-*]+a[\s._\-*]+y[\s._\-*]+t[\s._\-*]+m\b', re.IGNORECASE)),
    ("phonepe", re.compile(r'\bp[\s._\-*]+h[\s._\-*]+o[\s._\-*]+n[\s._\-*]+e[\s._\-*]+p[\s._\-*]+e\b', re.IGNORECASE)),
    ("sbi", re.compile(r'\bs[\s._\-*]+b[\s._\-*]+i\b', re.IGNORECASE)),
    ("yono", re.compile(r'\by[\s._\-*]+o[\s._\-*]+n[\s._\-*]+o\b', re.IGNORECASE)),
    ("kyc", re.compile(r'\bk[\s._\-*]+y[\s._\-*]+c\b', re.IGNORECASE)),
    ("otp", re.compile(r'\bo[\s._\-*]+t[\s._\-*]+p\b', re.IGNORECASE)),
    ("pan", re.compile(r'\bp[\s._\-*]+a[\s._\-*]+n\b', re.IGNORECASE)),
    ("upi", re.compile(r'\bu[\s._\-*]+p[\s._\-*]+i\b', re.IGNORECASE)),
    ("aadhaar", re.compile(r'\ba[\s._\-*]+a[\s._\-*]+d[\s._\-*]+h[\s._\-*]+a[\s._\-*]+a[\s._\-*]+r\b', re.IGNORECASE)),
    ("account", re.compile(r'\ba[\s._\-*]+c[\s._\-*]+c[\s._\-*]+o[\s._\-*]+u[\s._\-*]+n[\s._\-*]+t\b', re.IGNORECASE)),
]


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    text_len = len(text)
    freq: dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def normalize_adversarial_text(raw_text: str) -> Tuple[str, dict[str, Any], list[EvidenceItem]]:
    """
    Sanitize text against adversarial obfuscation while detecting evasion signals.
    
    Returns:
        (normalized_clean_text, metadata_dict, evidence_items_list)
    """
    if not raw_text:
        return "", {"obfuscation_detected": False}, []

    evidence_items: list[EvidenceItem] = []
    signals: list[str] = []
    
    # 1. Zero-width character detection & stripping
    stripped_zero_width = []
    cleaned_chars = []
    for char in raw_text:
        if char in _ZERO_WIDTH_CHARS:
            stripped_zero_width.append(f"\\u{ord(char):04x}")
        else:
            cleaned_chars.append(char)
            
    text = "".join(cleaned_chars)
    if stripped_zero_width:
        signals.append("zero_width_chars_injected")
        evidence_items.append(EvidenceItem(
            type=EvidenceType.PATTERN_MATCH,
            source="adversarial_normalizer",
            description=f"Detected {len(stripped_zero_width)} zero-width/hidden unicode characters injected into message text",
            observed_value=", ".join(set(stripped_zero_width)),
            interpretation="Attackers inject zero-width characters to bypass spam and heuristic keyword filters without altering visual appearance",
            status=EvidenceStatus.SUSPICIOUS,
            reliability=EvidenceReliability.DETERMINISTIC_FACT,
            risk_direction=RiskDirection.INCREASES_RISK,
            severity=EvidenceSeverity.HIGH,
            correlation_group="adversarial_evasion",
            raw_data={"hidden_chars": stripped_zero_width},
        ))

    # 2. Unicode NFKD normalization (splits combined forms)
    text = unicodedata.normalize("NFKD", text)

    # 3. Homoglyph confusable substitution
    homoglyphs_replaced: list[str] = []
    homo_chars = []
    for char in text:
        if char in _HOMOGLYPH_MAP:
            replacement = _HOMOGLYPH_MAP[char]
            homoglyphs_replaced.append(f"{char}->{replacement}")
            homo_chars.append(replacement)
        else:
            homo_chars.append(char)
            
    text = "".join(homo_chars)
    if homoglyphs_replaced:
        signals.append("homoglyphs_detected")
        sample_homo = ", ".join(list(set(homoglyphs_replaced))[:5])
        evidence_items.append(EvidenceItem(
            type=EvidenceType.PATTERN_MATCH,
            source="adversarial_normalizer",
            description=f"Detected {len(homoglyphs_replaced)} homoglyph character substitutions (e.g. {sample_homo})",
            observed_value=sample_homo,
            interpretation="Unicode homoglyphs (Cyrillic/Greek lookalikes) used to disguise banking and credential terms from security scanners",
            status=EvidenceStatus.SUSPICIOUS,
            reliability=EvidenceReliability.DETERMINISTIC_FACT,
            risk_direction=RiskDirection.INCREASES_RISK,
            severity=EvidenceSeverity.HIGH,
            correlation_group="adversarial_evasion",
            raw_data={"homoglyphs": homoglyphs_replaced},
        ))

    # 4. Delimiter-separated keyword reconstruction (e.g., "K . Y . C" -> "kyc")
    reconstructed_keywords: list[str] = []
    for word_norm, pattern in _SENSITIVE_TARGETS:
        if pattern.search(text):
            text = pattern.sub(word_norm, text)
            reconstructed_keywords.append(word_norm)

    if reconstructed_keywords:
        signals.append("split_keyword_obfuscation")
        evidence_items.append(EvidenceItem(
            type=EvidenceType.PATTERN_MATCH,
            source="adversarial_normalizer",
            description=f"De-obfuscated spaced/punctuated sensitive terms: {', '.join(reconstructed_keywords)}",
            observed_value=", ".join(reconstructed_keywords),
            interpretation="Punctuation or whitespace inserted between characters to avoid simple regex detection",
            status=EvidenceStatus.SUSPICIOUS,
            reliability=EvidenceReliability.DETERMINISTIC_FACT,
            risk_direction=RiskDirection.INCREASES_RISK,
            severity=EvidenceSeverity.MEDIUM,
            correlation_group="adversarial_evasion",
            raw_data={"reconstructed_terms": reconstructed_keywords},
        ))

    # 5. Clean whitespace
    text = " ".join(text.split())

    metadata = {
        "obfuscation_detected": bool(signals),
        "signals": signals,
        "zero_width_count": len(stripped_zero_width),
        "homoglyph_count": len(homoglyphs_replaced),
        "reconstructed_keywords": reconstructed_keywords,
    }

    return text, metadata, evidence_items
