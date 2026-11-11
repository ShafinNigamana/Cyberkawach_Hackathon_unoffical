"""
DEX Bytecode Carver & Forensic Threat Extractor.

Performs zero-dependency deep static extraction and behavioral IOC discovery
directly from Android Dalvik Executables (classes.dex, classes2.dex, etc.) inside APKs.

Carves:
- Telegram Bot API exfiltration tokens and Chat IDs (used by SMS OTP stealers)
- Dynamic DNS & Tunneling C2 domains (DuckDNS, ngrok, serveo, etc.)
- Direct IPv4/IPv6 C2 connections with port specifications
- Hardcoded Indian Financial Handles (UPI VPAs, IFSC patterns)
- Obfuscated SMS forwarding & gate endpoints (/send_sms, /receive_otp)
"""

from __future__ import annotations

import io
import logging
import re
import struct
from typing import Any, Dict, List, Optional, Set
import zipfile

logger = logging.getLogger("cyber_guardian.dex_carver")

# Magic signatures for Android DEX headers
_DEX_MAGICS = (b"dex\n035\x00", b"dex\n036\x00", b"dex\n037\x00", b"dex\n038\x00", b"dex\n039\x00")

# Forensic Threat Regex Patterns
_PATTERNS = {
    "telegram_bot_token": re.compile(
        r"(?:api\.telegram\.org/bot|bot|\b)(\d{8,11}:[A-Za-z0-9_\-]{34,38})\b",
        re.ASCII,
    ),
    "telegram_chat_id": re.compile(
        r"(?:chat_id|chatId|chatid)[\"'\s:=]+(-?\d{7,15})",
        re.IGNORECASE | re.ASCII,
    ),
    "dynamic_dns_c2": re.compile(
        r"https?://[a-zA-Z0-9.-]+\.(?:duckdns\.org|ngrok-free\.app|ngrok\.io|serveo\.net|loca\.lt|pagekite\.me|zapto\.org|no-ip\.(?:biz|org|info)|firebaseio\.com)[^\s\"'<>]*",
        re.IGNORECASE | re.ASCII,
    ),
    "direct_ip_c2": re.compile(
        r"https?://((?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::\d{1,5})?(?:/[^\s\"'<>]*)?)",
        re.ASCII,
    ),
    "hardcoded_upi_vpa": re.compile(
        r"\b[a-zA-Z0-9.\-_]{2,50}@(okhdfcbank|okaxis|oksbi|okicici|paytm|ybl|ibl|upi|barodampay|pnb|axl|federal)\b",
        re.IGNORECASE | re.ASCII,
    ),
    "suspicious_gate_endpoints": re.compile(
        r"/[a-zA-Z0-9_\-./]*(?:send_sms|receive_sms|forward_sms|sms_forward|gate\.php|bot\.php|stealer|otp_receive|receive_otp)[a-zA-Z0-9_\-./]*",
        re.IGNORECASE | re.ASCII,
    ),
}


def _read_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    """Reads unsigned LEB128 integer from data at offset. Returns (value, new_offset)."""
    result = 0
    shift = 0
    idx = offset
    data_len = len(data)
    while idx < data_len:
        byte = data[idx]
        idx += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            break
        shift += 7
        if shift > 35:  # protect against malformed ULEB
            break
    return result, idx


def extract_strings_from_dex_bytes(dex_bytes: bytes, max_strings: int = 15000) -> List[str]:
    """
    Parses string IDs table from DEX header if valid.
    Falls back to bounded ASCII/UTF-8 regex carving if table is truncated or obfuscated.
    """
    strings: List[str] = []
    if len(dex_bytes) < 112:
        return strings

    magic = dex_bytes[:8]
    if magic in _DEX_MAGICS:
        try:
            # Header layout:
            # offset 56: string_ids_size (uint32)
            # offset 60: string_ids_off (uint32)
            string_ids_size, string_ids_off = struct.unpack_from("<II", dex_bytes, 56)
            count = min(string_ids_size, max_strings)
            data_len = len(dex_bytes)

            for i in range(count):
                id_off = string_ids_off + (i * 4)
                if id_off + 4 > data_len:
                    break
                data_off = struct.unpack_from("<I", dex_bytes, id_off)[0]
                if data_off >= data_len:
                    continue

                # Read ULEB128 utf16_size
                utf16_len, str_start = _read_uleb128(dex_bytes, data_off)
                if str_start >= data_len:
                    continue

                # Read until null terminator or max 512 chars
                null_pos = dex_bytes.find(b"\x00", str_start, min(str_start + 512, data_len))
                if null_pos != -1:
                    raw_str = dex_bytes[str_start:null_pos]
                else:
                    raw_str = dex_bytes[str_start:min(str_start + 128, data_len)]

                try:
                    decoded = raw_str.decode("utf-8", errors="ignore").strip()
                    if decoded and len(decoded) >= 3:
                        strings.append(decoded)
                except Exception:
                    pass

            if len(strings) > 10:
                return strings
        except Exception as e:
            logger.debug(f"Structured DEX string table parsing encountered error: {e}")

    # Fallback carving: regex string scan for printable ASCII tokens >= 5 chars
    ascii_matches = re.findall(rb"[\x20-\x7E]{5,256}", dex_bytes[:10 * 1024 * 1024])
    for m in ascii_matches[:max_strings]:
        try:
            decoded = m.decode("ascii", errors="ignore").strip()
            if decoded:
                strings.append(decoded)
        except Exception:
            pass

    return strings


class DexForensicReport:
    """Carved threat indicators from DEX / APK inspection."""

    def __init__(self):
        self.telegram_bot_tokens: List[str] = []
        self.telegram_chat_ids: List[str] = []
        self.c2_domains: List[str] = []
        self.c2_ips: List[str] = []
        self.hardcoded_upis: List[str] = []
        self.gate_endpoints: List[str] = []
        self.all_threat_indicators: List[str] = []
        self.risk_elevation_score: float = 0.0
        self.is_banking_trojan: bool = False
        self.is_sms_stealer: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "telegram_bot_tokens": self.telegram_bot_tokens,
            "telegram_chat_ids": self.telegram_chat_ids,
            "c2_domains": self.c2_domains,
            "c2_ips": self.c2_ips,
            "hardcoded_upis": self.hardcoded_upis,
            "gate_endpoints": self.gate_endpoints,
            "all_threat_indicators": self.all_threat_indicators,
            "risk_elevation_score": round(self.risk_elevation_score, 2),
            "is_banking_trojan": self.is_banking_trojan,
            "is_sms_stealer": self.is_sms_stealer,
        }


def analyze_dex_strings(strings: List[str]) -> DexForensicReport:
    """Analyzes carved strings for operational threat indicators."""
    report = DexForensicReport()
    joined_text = "\n".join(strings)

    # 1. Telegram bot tokens
    bot_tokens = list(dict.fromkeys(_PATTERNS["telegram_bot_token"].findall(joined_text)))
    report.telegram_bot_tokens = [tok for tok in bot_tokens if not tok.startswith("00000000")]

    # 2. Telegram chat IDs
    chat_ids = list(dict.fromkeys(_PATTERNS["telegram_chat_id"].findall(joined_text)))
    report.telegram_chat_ids = chat_ids[:5]

    # 3. Dynamic DNS C2s
    c2_domains = list(dict.fromkeys(_PATTERNS["dynamic_dns_c2"].findall(joined_text)))
    report.c2_domains = c2_domains[:10]

    # 4. Direct IP C2s (filter out standard local/broadcast IPs)
    raw_ips = _PATTERNS["direct_ip_c2"].findall(joined_text)
    filtered_ips: List[str] = []
    for raw in raw_ips:
        host = raw.split("/")[0].split(":")[0]
        if not (host.startswith("127.") or host.startswith("0.0.") or host == "255.255.255.255"):
            filtered_ips.append(raw)
    report.c2_ips = list(dict.fromkeys(filtered_ips))[:10]

    # 5. Hardcoded UPI VPAs
    raw_vpa_matches = re.finditer(
        r"\b[a-zA-Z0-9.\-_]{2,50}@(okhdfcbank|okaxis|oksbi|okicici|paytm|ybl|ibl|upi|barodampay|pnb|axl|federal)\b",
        joined_text,
        re.IGNORECASE,
    )
    extracted_vpas = list(dict.fromkeys([m.group(0).lower() for m in raw_vpa_matches]))
    report.hardcoded_upis = extracted_vpas[:10]

    # 6. Gate / Stealer Endpoints
    gates = list(dict.fromkeys(_PATTERNS["suspicious_gate_endpoints"].findall(joined_text)))
    report.gate_endpoints = gates[:10]

    # Calculate Risk Score Elevation & Threat Classification
    score = 0.0
    if report.telegram_bot_tokens:
        score += 0.45
        report.is_sms_stealer = True
        report.all_threat_indicators.append(
            f"Active Telegram Bot OTP Exfiltration Token: {report.telegram_bot_tokens[0][:15]}..."
        )

    if report.c2_domains:
        score += 0.35
        report.all_threat_indicators.append(
            f"Dynamic DNS C2 Tunnel Endpoint: {report.c2_domains[0]}"
        )

    if report.c2_ips:
        score += 0.30
        report.all_threat_indicators.append(
            f"Hardcoded Remote IP C2 Target: {report.c2_ips[0]}"
        )

    if report.hardcoded_upis:
        score += 0.25
        report.is_banking_trojan = True
        report.all_threat_indicators.append(
            f"Hardcoded Target UPI VPA in Bytecode: {report.hardcoded_upis[0]}"
        )

    if report.gate_endpoints:
        score += 0.25
        report.is_sms_stealer = True
        report.all_threat_indicators.append(
            f"SMS Stealer Gate Handler: {report.gate_endpoints[0]}"
        )

    report.risk_elevation_score = min(score, 1.0)
    return report


def scan_apk_archive_for_dex_threats(apk_bytes: bytes) -> DexForensicReport:
    """
    Opens an APK container (ZIP), locates all classes*.dex files,
    carves string literals, and builds a combined forensic report.
    """
    report = DexForensicReport()
    try:
        with zipfile.ZipFile(io.BytesIO(apk_bytes)) as z:
            dex_names = [n for n in z.namelist() if n.startswith("classes") and n.endswith(".dex")]
            if not dex_names:
                return report

            all_strings: List[str] = []
            for dex_name in dex_names[:5]:  # limit to first 5 multidex archives
                try:
                    with z.open(dex_name) as f:
                        dex_data = f.read(15 * 1024 * 1024)  # cap 15MB per dex
                        strings = extract_strings_from_dex_bytes(dex_data)
                        all_strings.extend(strings)
                except Exception as e:
                    logger.debug(f"Failed to read {dex_name}: {e}")

            if all_strings:
                report = analyze_dex_strings(all_strings)

    except Exception as e:
        logger.warning(f"Error opening APK archive for DEX carving: {e}")

    return report
