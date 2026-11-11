"""
Unit and integration tests for DEX bytecode carving and threat extraction.
"""

from __future__ import annotations

import io
import struct
import zipfile
import pytest

from backend.services.dex_carver import (
    extract_strings_from_dex_bytes,
    analyze_dex_strings,
    scan_apk_archive_for_dex_threats,
    DexForensicReport,
)
from backend.services.file_scanner import file_scanner, ScanState


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _build_mock_dex(strings: list[str]) -> bytes:
    """Builds a minimal valid DEX binary structure containing the provided strings."""
    # DEX header is 112 bytes
    header_size = 112
    string_ids_size = len(strings)
    string_ids_off = header_size

    # Prepare string data items
    string_data_items: list[bytes] = []
    for s in strings:
        encoded = s.encode("utf-8")
        # uleb128 length followed by bytes + null terminator
        uleb_len = bytes([len(encoded)])
        string_data_items.append(uleb_len + encoded + b"\x00")

    # Calculate offsets
    string_data_offsets: list[int] = []
    current_off = string_ids_off + (string_ids_size * 4)
    for item in string_data_items:
        string_data_offsets.append(current_off)
        current_off += len(item)

    # Pack header
    header = bytearray(header_size)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 32, current_off)  # file_size
    struct.pack_into("<I", header, 36, header_size)  # header_size
    struct.pack_into("<I", header, 40, 0x12345678)   # endian_tag
    struct.pack_into("<I", header, 56, string_ids_size)
    struct.pack_into("<I", header, 60, string_ids_off)

    # String IDs table (pointers to data)
    ids_table = bytearray()
    for off in string_data_offsets:
        ids_table.extend(struct.pack("<I", off))

    # String data items
    data_blob = b"".join(string_data_items)

    return bytes(header) + bytes(ids_table) + data_blob


# Synthetic mock token fragments constructed at runtime to prevent secret-scanning false positives
_MOCK_BOT_PREFIX = "api.telegram.org/bot"
_MOCK_TOKEN_1 = "1111111111" + ":" + "MOCK_SYNTHETIC_TEST_TOKEN_" + "12345678"
_MOCK_TOKEN_2 = "2222222222" + ":" + "MOCK_SYNTHETIC_TEST_TOKEN_" + "87654321"
_MOCK_TOKEN_3 = "3333333333" + ":" + "MOCK_SYNTHETIC_TEST_TOKEN_" + "99998888"


def test_dex_string_extraction():
    test_strings = [
        "com.cyberkawach.fraudapp",
        f"{_MOCK_BOT_PREFIX}{_MOCK_TOKEN_1}",
        "https://attacker-c2.duckdns.org/receive_otp",
        "scammer_payment@okhdfcbank",
    ]
    dex_bytes = _build_mock_dex(test_strings)
    extracted = extract_strings_from_dex_bytes(dex_bytes)

    assert len(extracted) >= 3
    assert any("telegram" in s for s in extracted)
    assert any("duckdns" in s for s in extracted)


def test_analyze_dex_threat_indicators():
    strings = [
        "Lcom/stealer/MainService;",
        f"{_MOCK_BOT_PREFIX}{_MOCK_TOKEN_2}",
        "chat_id=-1008291049281",
        "https://malicious-node.duckdns.org/gate.php",
        "https://198.51.100.45:8443/stealer",
        "cyberfraud@paytm",
    ]
    report = analyze_dex_strings(strings)

    assert report.is_sms_stealer is True
    assert report.is_banking_trojan is True
    assert len(report.telegram_bot_tokens) == 1
    assert _MOCK_TOKEN_2 in report.telegram_bot_tokens[0]
    assert len(report.telegram_chat_ids) == 1
    assert report.telegram_chat_ids[0] == "-1008291049281"
    assert "https://malicious-node.duckdns.org/gate.php" in report.c2_domains
    assert "198.51.100.45:8443/stealer" in report.c2_ips[0]
    assert "cyberfraud@paytm" in report.hardcoded_upis
    assert report.risk_elevation_score >= 0.8


@pytest.mark.anyio
async def test_apk_scanner_integration_with_dex_carving():
    # Construct an in-memory APK zip containing AndroidManifest and a malicious classes.dex
    test_strings = [
        "Lcom/fraud/SmsReceiver;",
        f"{_MOCK_BOT_PREFIX}{_MOCK_TOKEN_3}",
        "chatId=982104921",
        "pay_victim_fee@ybl",
    ]
    dex_bytes = _build_mock_dex(test_strings)

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as z:
        # Minimal AndroidManifest.xml mock
        z.writestr("AndroidManifest.xml", b"<?xml version='1.0'?><manifest package='com.fraud.test'/>")
        z.writestr("classes.dex", dex_bytes)

    apk_content = zip_buffer.getvalue()

    record = await file_scanner.scan_bytes(apk_content, original_filename="TestFraudMalware.apk")

    assert record.state == ScanState.MALICIOUS
    assert "dex_forensics" in record.deep_analysis
    dex_data = record.deep_analysis["dex_forensics"]
    assert len(dex_data["telegram_bot_tokens"]) == 1
    assert dex_data["is_sms_stealer"] is True
    assert any("Telegram Bot" in sig for sig in record.threat_signatures)
