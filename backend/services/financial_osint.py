"""
Financial & Banking Open-Source Intelligence (OSINT) Service.

Provides:
1. Indian Bank IFSC Code resolution (via Razorpay IFSC open registry + offline fallback)
2. UPI VPA format validation and deceptive institutional handle detection
"""

from __future__ import annotations

import logging
import re
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

# Known Indian Bank IFSC Prefix Mapping for offline fast-path / fallback
KNOWN_IFSC_BANKS: dict[str, str] = {
    "SBIN": "State Bank of India",
    "HDFC": "HDFC Bank",
    "ICIC": "ICICI Bank",
    "UTIB": "Axis Bank",
    "PUNB": "Punjab National Bank",
    "BARB": "Bank of Baroda",
    "CNRB": "Canara Bank",
    "UBIN": "Union Bank of India",
    "BKID": "Bank of India",
    "IOBA": "Indian Overseas Bank",
    "IDIB": "Indian Bank",
    "CBIN": "Central Bank of India",
    "YESB": "Yes Bank",
    "KKBK": "Kotak Mahindra Bank",
    "INDB": "IndusInd Bank",
    "FDRL": "Federal Bank",
    "IDFB": "IDFC FIRST Bank",
    "MAHB": "Bank of Maharashtra",
    "PSIB": "Punjab & Sind Bank",
    "UCOB": "UCO Bank",
    "PYTM": "Paytm Payments Bank",
    "AIRP": "Airtel Payments Bank",
    "IPOS": "India Post Payments Bank",
    "JIOP": "Jio Payments Bank",
}

# Common consumer UPI PSP handles frequently abused in payment diversion scams
CONSUMER_UPI_HANDLES: set[str] = {
    "okhdfcbank",
    "okaxis",
    "oksbi",
    "okicici",
    "ybl",
    "ibl",
    "axl",
    "paytm",
    "apl",
    "fbl",
    "jupiteraxis",
    "icici",
    "postbank",
}

# Institutional keywords that fraudsters put in consumer handles to look official
INSTITUTIONAL_KEYWORDS: list[str] = [
    "bescom", "uppcl", "mseb", "electricity", "bill", "refund", "support",
    "care", "helpline", "officer", "police", "cybercell", "cbi", "customs",
    "challan", "rto", "tax", "income.tax", "sbi.kyc", "hdfc.kyc", "lottery",
    "reward", "cashback", "pmkisan", "aadhaar"
]


def extract_ifsc_codes(text: str) -> list[str]:
    """Extract standard Indian Financial System Code (IFSC) tokens from text."""
    if not text:
        return []
    # 4 alphabetic characters, followed by '0', followed by 6 alphanumeric characters
    matches = re.findall(r"\b([A-Z]{4}0[A-Z0-9]{6})\b", text.upper())
    return list(dict.fromkeys(matches))


def extract_upi_vpas(text: str) -> list[str]:
    """Extract UPI Virtual Payment Addresses (VPAs)."""
    if not text:
        return []
    matches = re.findall(
        r"\b([a-zA-Z0-9.\-_]{2,50}@[a-zA-Z0-9.\-_]{2,30})\b",
        text
    )
    # Filter out obvious false positives like email addresses with .com / .org
    valid_vpas = []
    for m in matches:
        handle = m.split("@", 1)[1].lower()
        if not any(handle.endswith(tld) for tld in [".com", ".net", ".org", ".edu", ".gov", ".co.in", ".in"]):
            valid_vpas.append(m)
        elif handle in ["paytm", "upi", "postbank"]:
            valid_vpas.append(m)
    return list(dict.fromkeys(valid_vpas))


async def lookup_ifsc_razorpay(ifsc: str, timeout: float = 3.0) -> dict[str, Any]:
    """
    Look up IFSC details via Razorpay open API (https://ifsc.razorpay.com/<IFSC>).
    Falls back to offline bank prefix dictionary if offline or unavailable.
    """
    code = (ifsc or "").strip().upper()
    if not re.match(r"^[A-Z]{4}0[A-Z0-9]{6}$", code):
        return {"valid": False, "ifsc": code, "error": "Invalid IFSC structure"}

    bank_prefix = code[:4]
    fallback_bank = KNOWN_IFSC_BANKS.get(bank_prefix, "Unknown / Regional Bank")

    url = f"https://ifsc.razorpay.com/{code}"
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "valid": True,
                    "ifsc": code,
                    "bank": data.get("BANK", fallback_bank),
                    "branch": data.get("BRANCH", "Main Branch"),
                    "city": data.get("CITY", ""),
                    "district": data.get("DISTRICT", ""),
                    "state": data.get("STATE", ""),
                    "source": "razorpay_api",
                }
            elif resp.status_code == 404:
                return {
                    "valid": False,
                    "ifsc": code,
                    "bank": fallback_bank,
                    "error": "IFSC not found in RBI master list",
                    "source": "razorpay_api",
                }
    except Exception as e:
        logger.debug("Razorpay IFSC lookup failed (%s); using offline prefix map", type(e).__name__)

    return {
        "valid": True if bank_prefix in KNOWN_IFSC_BANKS else False,
        "ifsc": code,
        "bank": fallback_bank,
        "branch": "Branch lookup unavailable (offline)",
        "city": "Unknown",
        "district": "Unknown",
        "state": "Unknown",
        "source": "offline_prefix_map",
    }


def analyze_upi_vpa(vpa: str) -> dict[str, Any]:
    """
    Analyze UPI VPA for deceptive masquerading (e.g. consumer handle impersonating electricity board).
    """
    clean_vpa = (vpa or "").strip().lower()
    if "@" not in clean_vpa:
        return {"valid": False, "vpa": vpa, "deceptive": False}

    username, handle = clean_vpa.split("@", 1)
    is_consumer_psp = handle in CONSUMER_UPI_HANDLES

    flagged_keywords = [kw for kw in INSTITUTIONAL_KEYWORDS if kw in username]
    is_deceptive = is_consumer_psp and len(flagged_keywords) > 0

    return {
        "valid": True,
        "vpa": clean_vpa,
        "username": username,
        "handle": handle,
        "is_consumer_psp": is_consumer_psp,
        "matched_institutional_keywords": flagged_keywords,
        "deceptive": is_deceptive,
        "reason": (
            f"Consumer UPI handle (@{handle}) claiming institutional authority ('{','.join(flagged_keywords)}')"
            if is_deceptive else None
        ),
    }
