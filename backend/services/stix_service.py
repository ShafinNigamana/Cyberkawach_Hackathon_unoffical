"""
STIX 2.1 Threat Intelligence Export Service.

Converts CyberKawach incident evidence and forensic graphs into
standard OASIS STIX 2.1 JSON bundles for integration with enterprise
SIEM, SOAR, TIP, and MISP threat sharing platforms.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List
import uuid

from backend.models.evidence import IncidentEvidence


def _format_rfc3339(dt: datetime) -> str:
    """Formats datetime as RFC 3339 / ISO 8601 UTC with trailing 'Z'."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _deterministic_stix_id(type_name: str, seed: str) -> str:
    """Generates a reproducible UUIDv5 STIX ID based on type and seed content."""
    namespace = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
    u = uuid.uuid5(namespace, f"{type_name}:{seed}")
    return f"{type_name}--{u}"


def generate_stix_bundle(evidence: IncidentEvidence) -> Dict[str, Any]:
    """Generates an OASIS STIX 2.1 compliant JSON bundle from IncidentEvidence."""
    now_str = _format_rfc3339(datetime.now(timezone.utc))
    created_str = (
        _format_rfc3339(evidence.created_at)
        if isinstance(evidence.created_at, datetime)
        else now_str
    )

    objects: List[Dict[str, Any]] = []

    # 1. Identity Object (CyberKawach Platform)
    identity_id = _deterministic_stix_id("identity", "cyberkawach-platform")
    identity_sdo = {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": created_str,
        "modified": now_str,
        "name": "CyberKawach Forensic Triage Engine",
        "identity_class": "system",
        "sectors": ["government-public-services", "financial-services"],
        "description": "Autonomous threat triage and evidentiary platform for Indian cyber forensics and citizen fraud mitigation.",
    }
    objects.append(identity_sdo)

    # 2. Malware / Attack-Pattern Object
    category = (evidence.fraud_category or "financial_phishing").lower()
    factors = getattr(evidence.risk, "contributing_factors", []) or getattr(evidence.risk, "factors", []) or []
    is_malware = any(
        kw in category for kw in ("malware", "apk", "trojan", "stealer", "ransomware")
    ) or any(
        "apk" in (f or "").lower() or "dex" in (f or "").lower()
        for f in factors
    )

    main_threat_id: str
    if is_malware:
        main_threat_id = _deterministic_stix_id("malware", evidence.incident_id)
        threat_obj = {
            "type": "malware",
            "spec_version": "2.1",
            "id": main_threat_id,
            "created": created_str,
            "modified": now_str,
            "name": f"Mobile Fraud Carrier ({evidence.incident_id})",
            "description": evidence.message or "Sideloaded Android financial trojan / SMS stealer",
            "malware_types": ["trojan", "screen-capture", "credential-harvester"],
            "is_family": False,
            "created_by_ref": identity_id,
        }
    else:
        main_threat_id = _deterministic_stix_id("attack-pattern", evidence.incident_id)
        threat_obj = {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": main_threat_id,
            "created": created_str,
            "modified": now_str,
            "name": f"Social Engineering & Financial Phishing ({evidence.incident_id})",
            "description": evidence.message or "Indian financial lure with spoofed banking credentials",
            "created_by_ref": identity_id,
        }
    objects.append(threat_obj)

    # 3. Indicators for URLs
    for url_obj in evidence.urls:
        u_val = url_obj.url
        ind_id = _deterministic_stix_id("indicator", f"url:{u_val}")
        ind_sdo = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": created_str,
            "modified": now_str,
            "name": f"Malicious URL Indicator: {url_obj.domain or u_val[:30]}",
            "indicator_types": ["malicious-activity"],
            "pattern": f"[url:value = '{u_val}']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": created_str,
            "created_by_ref": identity_id,
        }
        objects.append(ind_sdo)

        # Relationship
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": _deterministic_stix_id("relationship", f"{ind_id}-indicates-{main_threat_id}"),
            "created": created_str,
            "modified": now_str,
            "relationship_type": "indicates",
            "source_ref": ind_id,
            "target_ref": main_threat_id,
            "created_by_ref": identity_id,
        })

    # 4. Indicators for IOCs (IPs, hashes, carved C2s)
    for ioc in evidence.iocs:
        ioc_clean = ioc.strip()
        pattern: str
        if "." in ioc_clean and ioc_clean.replace(".", "").isdigit():
            # IPv4 address
            pattern = f"[ipv4-addr:value = '{ioc_clean}']"
            ind_name = f"C2 IP Indicator: {ioc_clean}"
        elif len(ioc_clean) == 64 and all(c in "0123456789abcdefABCDEF" for c in ioc_clean):
            # SHA-256 file hash
            pattern = f"[file:hashes.'SHA-256' = '{ioc_clean.lower()}']"
            ind_name = f"Payload Hash Indicator: {ioc_clean[:12]}..."
        else:
            pattern = f"[domain-name:value = '{ioc_clean}']"
            ind_name = f"Suspicious Host: {ioc_clean}"

        ioc_id = _deterministic_stix_id("indicator", f"ioc:{ioc_clean}")
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": ioc_id,
            "created": created_str,
            "modified": now_str,
            "name": ind_name,
            "indicator_types": ["malicious-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": created_str,
            "created_by_ref": identity_id,
        })

        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": _deterministic_stix_id("relationship", f"{ioc_id}-indicates-{main_threat_id}"),
            "created": created_str,
            "modified": now_str,
            "relationship_type": "indicates",
            "source_ref": ioc_id,
            "target_ref": main_threat_id,
            "created_by_ref": identity_id,
        })

    bundle_id = _deterministic_stix_id("bundle", evidence.incident_id)
    return {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": objects,
    }
