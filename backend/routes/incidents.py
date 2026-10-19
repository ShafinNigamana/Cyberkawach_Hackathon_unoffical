"""
Incident Management, Dossier Retrieval, Relationship Graph, and Export Router.
Enforces strict IDOR protection, input validation, and evidentiary consistency.
"""

from __future__ import annotations

import logging
import secrets
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from backend.config import get_settings
from backend.models.api import (
    AnalyzeResponse,
    IncidentGraphResponse,
    IncidentHistoryItem,
    IncidentHistoryResponse,
    OSINTResponse,
    UpdateUserStateRequest,
)
from backend.routes.auth import get_current_user, get_current_user_optional
from backend.services.incident_store import incident_store
from backend.services.neo4j_repository import neo4j_repo
from backend.utils.rate_limiter import check_rate_limit
from backend.utils.sanitize import (
    escape_for_display,
    validate_incident_id,
    validate_language,
)
from backend.utils.security_logging import safe_error_message

logger = logging.getLogger("cyber_guardian.incidents")
settings = get_settings()

incidents_router = APIRouter(prefix="/api/incidents", tags=["incidents"])


@incidents_router.get("", response_model=IncidentHistoryResponse)
async def list_citizen_incidents(raw_request: Request, limit: int = 50):
    """
    List past incidents owned by the authenticated citizen ('My Checks').
    Strictly isolated per user to guarantee zero IDOR leakage.
    """
    user = get_current_user(raw_request)
    clamped_limit = max(1, min(limit, 100))
    items = neo4j_repo.list_user_incidents(user["user_id"], limit=clamped_limit)

    history_items = [
        IncidentHistoryItem(
            incident_id=str(item.get("incident_id")),
            created_at=str(item.get("created_at", "")),
            input_type=str(item.get("input_type", "text")),
            title=str(item.get("title", f"Incident {item.get('incident_id')}")),
            message_preview=str(item.get("message_preview", "")),
            risk_level=str(item.get("risk_level", "low")),
            risk_score=float(item.get("risk_score", 0.0)),
            fraud_category=str(item.get("fraud_category", "generic")),
            current_user_state=str(item.get("current_user_state", "received")),
            campaign_id=item.get("campaign_id"),
        )
        for item in items
    ]
    return IncidentHistoryResponse(incidents=history_items, total=len(history_items))


@incidents_router.get("/{incident_id}")
async def get_incident_by_id(incident_id: str, raw_request: Request):
    """
    Retrieve incident dossier by ID.
    Enforces strict IDOR protection — returns 404/unauthorized if owned by another citizen.
    """
    if not validate_incident_id(incident_id):
        raise HTTPException(status_code=400, detail="Invalid incident ID format")

    user = get_current_user_optional(raw_request)
    user_id = user["user_id"] if user else None

    # When Neo4j datastore is active, it is the authoritative store
    if settings.neo4j_enabled and neo4j_repo.is_available():
        record = neo4j_repo.get_incident(incident_id, user_id=user_id)
        if record:
            if user_id:
                neo4j_repo.log_audit_event("INCIDENT_VIEWED", user_id, "Incident", incident_id)
            return record
        raise HTTPException(status_code=404, detail="Incident not found or unauthorized.")

    # Check bounded in-memory store as offline fallback
    if incident_id in incident_store:
        ev = incident_store[incident_id]
        return AnalyzeResponse(
            incident_id=ev.incident_id,
            input_type=ev.input_type,
            message_preview=ev.message[:200],
            risk=ev.risk,
            evidence=ev.evidence,
            urls=ev.urls,
            brands=ev.brands,
            threat_intel=ev.threat_intel,
            explanation=ev.explanation,
            response=ev.response,
            laya=ev.laya if ev.laya.available else None,
            ml_classifier=ev.ml_classifier if ev.ml_classifier.available else None,
            classification=ev.ml_classifier.classification if ev.ml_classifier.available else None,
            model_confidence=ev.ml_classifier.confidence if ev.ml_classifier.available else None,
            fraud_dna=ev.fraud_dna if ev.fraud_dna.available else None,
            fraud_category=ev.fraud_category,
            language=ev.language,
            response_language=ev.response_language,
            input_language=ev.input_language,
            processing_time_ms=ev.processing_time_ms,
            modules_executed=ev.modules_executed,
            modules_failed=ev.modules_failed,
        )

    raise HTTPException(status_code=404, detail="Incident not found or unauthorized.")


@incidents_router.get("/{incident_id}/graph", response_model=IncidentGraphResponse)
async def get_incident_relationship_graph(incident_id: str, raw_request: Request):
    """
    Retrieve the contextual relationship graph for visualization:
    Incident, Sender, Brand, URL, Domain, Campaign, and Related Incidents.
    Enforces IDOR checks.
    """
    if not validate_incident_id(incident_id):
        raise HTTPException(status_code=400, detail="Invalid incident ID format")

    user = get_current_user_optional(raw_request)
    user_id = user["user_id"] if user else None

    # When Neo4j datastore is active, it is the authoritative graph store
    if settings.neo4j_enabled and neo4j_repo.is_available():
        graph_data = neo4j_repo.get_incident_graph(incident_id, user_id=user_id)
        if graph_data:
            return IncidentGraphResponse(
                incident_id=graph_data.get("incident_id", incident_id),
                nodes=graph_data.get("nodes", []),
                edges=graph_data.get("edges", []),
                node_count=graph_data.get("node_count", len(graph_data.get("nodes", []))),
                edge_count=graph_data.get("edge_count", len(graph_data.get("edges", []))),
                summary=f"Campaign {graph_data.get('campaign', {}).get('campaign_id', 'CAMP-STANDALONE')} with {len(graph_data.get('related_incidents', []))} related incidents",
            )
        raise HTTPException(status_code=404, detail="Incident graph not found or unauthorized.")

    # In-memory fallback graph representation
    if incident_id in incident_store:
        ev = incident_store[incident_id]
        nodes = [
            {"id": incident_id, "label": "Incident", "type": "Incident", "properties": {"risk": ev.risk.level.value}}
        ]
        edges = []
        for b in ev.brands:
            bid = f"brand_{b.brand_name}"
            nodes.append({"id": bid, "label": b.brand_name, "type": "Brand", "properties": {"name": b.brand_name}})
            edges.append({"source": incident_id, "target": bid, "relationship": "CLAIMS_BRAND", "properties": {"label": "claims brand"}})
        for u in ev.urls:
            uid = f"url_{abs(hash(u.url)) % 1000000}"
            nodes.append({"id": uid, "label": u.domain or u.url, "type": "URL", "properties": {"url": u.url}})
            edges.append({"source": incident_id, "target": uid, "relationship": "CONTAINS_URL", "properties": {"label": "contains url"}})
        camp_id = getattr(ev.fraud_dna, "campaign_id", None)
        if camp_id:
            nodes.append({"id": camp_id, "label": f"Campaign {camp_id}", "type": "Campaign", "properties": {}})
            edges.append({"source": incident_id, "target": camp_id, "relationship": "BELONGS_TO", "properties": {}})

        return IncidentGraphResponse(
            incident_id=incident_id,
            nodes=nodes,
            edges=edges,
            node_count=len(nodes),
            edge_count=len(edges),
            summary="Incident relationship graph (in-memory mode)",
        )

    raise HTTPException(status_code=404, detail="Incident graph not found or unauthorized.")


@incidents_router.get("/{incident_id}/history")
async def get_incident_action_history(incident_id: str, raw_request: Request):
    """
    Retrieve adaptive response history and user state transitions.
    Enforces IDOR checks.
    """
    if not validate_incident_id(incident_id):
        raise HTTPException(status_code=400, detail="Invalid incident ID format")

    user = get_current_user_optional(raw_request)
    user_id = user["user_id"] if user else None

    # Authoritative ownership check in Neo4j
    if settings.neo4j_enabled and neo4j_repo.is_available():
        inc = neo4j_repo.get_incident(incident_id, user_id=user_id)
        if not inc:
            raise HTTPException(status_code=404, detail="Incident history not found or unauthorized.")
    else:
        inc = incident_store.get(incident_id)
        if not inc:
            raise HTTPException(status_code=404, detail="Incident history not found or unauthorized.")
        if hasattr(inc, "__dict__"):
            inc = {
                "created_at": inc.created_at.isoformat(),
                "current_user_state": "received",
            }

    current_state = inc.get("current_user_state", "received") if inc else "received"
    created_ts = inc.get("created_at") if inc else incident_store[incident_id].created_at.isoformat()
    history = [
        {
            "state": "received",
            "action": "Message ingested and forensic analysis executed",
            "timestamp": created_ts,
        }
    ]
    if current_state != "received":
        history.append({
            "state": current_state,
            "action": f"User interaction progressed to {current_state}",
            "timestamp": inc.get("updated_at") if inc else "",
        })

    return {
        "incident_id": incident_id,
        "current_state": current_state,
        "history": history,
    }


@incidents_router.post("/{incident_id}/state", response_model=AnalyzeResponse)
async def update_user_state(
    incident_id: str,
    request: UpdateUserStateRequest,
    raw_request: Request,
):
    """
    Update user interaction state and regenerate adaptive response.
    Supports on-the-fly language switching without re-querying threat intel.
    """
    check_rate_limit(raw_request)

    if not validate_incident_id(incident_id):
        raise HTTPException(status_code=400, detail="Invalid incident ID format")

    if incident_id not in incident_store:
        raise HTTPException(status_code=404, detail="Incident not found")

    evidence = incident_store[incident_id]

    req_lang = getattr(request, "response_language", None) or getattr(request, "language", None)
    if req_lang:
        valid_lang = validate_language(req_lang)
        evidence.response_language = valid_lang
        evidence.language = valid_lang
        if getattr(evidence.explanation, "provider", "") in ("rule_engine", "ml_fallback", "deterministic_fallback", None):
            try:
                from backend.modules.fallback_explanation import generate_fallback_explanation
                evidence = generate_fallback_explanation(evidence)
            except Exception as e:
                logger.warning("Failed to regenerate fallback explanation for new language: %s", safe_error_message(e))

    try:
        from backend.modules.response import generate_response
        evidence = generate_response(evidence, request.user_state)
    except Exception as e:
        evidence.errors.append(f"response_update: {safe_error_message(e)}")

    incident_store[incident_id] = evidence

    if settings.neo4j_enabled:
        user = get_current_user_optional(raw_request)
        user_id = user["user_id"] if user else None
        try:
            state_val = request.user_state.value if hasattr(request.user_state, "value") else str(request.user_state)
            neo4j_repo.save_incident_action(
                incident_id=incident_id,
                state=state_val,
                action_taken=f"State transitioned to {state_val}",
                user_id=user_id,
            )
            neo4j_repo.log_audit_event("INCIDENT_ACTION", user_id, "Incident", incident_id, {"new_state": state_val})
        except Exception as e:
            logger.warning("Failed to record incident action in Neo4j: %s", safe_error_message(e))

    return AnalyzeResponse(
        incident_id=evidence.incident_id,
        input_type=evidence.input_type,
        message_preview=evidence.message[:200],
        risk=evidence.risk,
        evidence=evidence.evidence,
        urls=evidence.urls,
        brands=evidence.brands,
        threat_intel=evidence.threat_intel,
        explanation=evidence.explanation,
        response=evidence.response,
        laya=evidence.laya if evidence.laya.available else None,
        ml_classifier=evidence.ml_classifier if evidence.ml_classifier.available else None,
        classification=evidence.ml_classifier.classification if evidence.ml_classifier.available else None,
        model_confidence=evidence.ml_classifier.confidence if evidence.ml_classifier.available else None,
        fraud_dna=evidence.fraud_dna if evidence.fraud_dna.available else None,
        fraud_category=evidence.fraud_category,
        language=evidence.language,
        response_language=evidence.response_language,
        input_language=evidence.input_language,
        processing_time_ms=evidence.processing_time_ms,
        modules_executed=evidence.modules_executed,
        modules_failed=evidence.modules_failed,
    )


@incidents_router.post("/{incident_id}/osint", response_model=OSINTResponse)
async def get_incident_osint(
    incident_id: str,
    raw_request: Request = None,
):
    """
    Asynchronous OSINT enrichment endpoint for an incident.
    Fetches WHOIS domain age and crt.sh Certificate Transparency logs
    via a background thread pool, translates facts to Evidence Contract items.
    """
    if raw_request:
        check_rate_limit(raw_request)

    current_settings = get_settings()
    if not current_settings.osint_enabled:
        return OSINTResponse(status="disabled", evidence=[], raw={})

    if not validate_incident_id(incident_id):
        raise HTTPException(status_code=400, detail="Invalid incident ID format")

    if incident_id not in incident_store:
        raise HTTPException(status_code=404, detail="Incident or domain not found")

    incident = incident_store[incident_id]

    domain = None
    if incident.urls:
        for u in incident.urls:
            if u.domain:
                domain = u.domain
                break

    if not domain and incident.iocs:
        for ioc in incident.iocs:
            clean_ioc = ioc.strip().lower()
            if "." in clean_ioc and "/" not in clean_ioc and " " not in clean_ioc and not clean_ioc.endswith("."):
                domain = clean_ioc
                break

    if not domain:
        raise HTTPException(status_code=404, detail="Incident or domain not found")

    import anyio
    from backend.services.osint_enrichment import get_osint_enrichment
    from backend.services.osint_evidence_translator import translate_osint_evidence

    raw = await anyio.to_thread.run_sync(get_osint_enrichment, domain)
    evidence_items = translate_osint_evidence(raw)

    return OSINTResponse(
        status=raw.get("status", "unavailable"),
        evidence=evidence_items,
        raw=raw,
    )


@incidents_router.get("/{incident_id}/report")
@incidents_router.get("/{incident_id}/export")
async def export_incident(
    incident_id: str,
    format: str = "json",
    raw_request: Request = None,
):
    """
    Export full forensic incident dossier for Law Enforcement / National Cyber Crime Helpline (1930).
    Format options: 'json' or 'html' (printable official cyber police complaint format).
    """
    if raw_request:
        check_rate_limit(raw_request)

    if not validate_incident_id(incident_id):
        raise HTTPException(status_code=400, detail="Invalid incident ID format")

    if incident_id not in incident_store:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident = incident_store[incident_id]

    if settings.neo4j_enabled and raw_request:
        user = get_current_user_optional(raw_request)
        user_id = user["user_id"] if user else None
        report_id = f"rep_{secrets.token_hex(6)}"
        try:
            neo4j_repo.save_report_metadata(report_id, incident_id, format=format, user_id=user_id)
            neo4j_repo.log_audit_event("REPORT_GENERATED", user_id, "Report", report_id, {"format": format})
        except Exception as e:
            logger.warning("Failed to record report metadata in Neo4j: %s", safe_error_message(e))

    import hashlib
    raw_hash = hashlib.sha256((incident.message or "").encode("utf-8")).hexdigest()

    evidence_summary = [
        {
            "source": item.source,
            "description": item.description,
            "confidence": f"{item.confidence:.0%}" if item.confidence is not None else "100%",
            "type": item.type.value if hasattr(item.type, "value") else str(item.type),
        }
        for item in incident.evidence
    ]

    export_data = {
        "incident_id": incident.incident_id,
        "timestamp_utc": incident.created_at.isoformat(),
        "sha256_message_hash": raw_hash,
        "risk_level": incident.risk.level.value,
        "risk_score": incident.risk.score,
        "fraud_category": incident.fraud_category or "generic",
        "evidence_dossier": evidence_summary,
        "extracted_urls": [u.url for u in incident.urls],
        "extracted_domains": [u.domain for u in incident.urls if u.domain],
        "campaign_id": incident.fraud_dna.campaign_id if incident.fraud_dna.available else None,
        "related_incidents": incident.fraud_dna.related_incidents if incident.fraud_dna.available else [],
        "helpline_1930_advisory": (
            "If financial loss occurred within the last 24 hours (Golden Hour), "
            "immediately call 1930 or submit details on https://cybercrime.gov.in."
        ),
    }

    if format.lower() == "html":
        ioc_rows = "".join(f"<tr><td>Domain/URL</td><td>{escape_for_display(u.url)}</td></tr>" for u in incident.urls) if incident.urls else "<tr><td colspan='2'>No web URLs extracted</td></tr>"
        evidence_rows = "".join(f"<tr><td>{escape_for_display(item['source'])}</td><td>{escape_for_display(item['description'])}</td><td>{item['confidence']}</td></tr>" for item in evidence_summary)

        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Cyber Crime Forensic Incident Dossier - {escape_for_display(incident.incident_id)}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.6; color: #222; max-width: 800px; margin: 30px auto; padding: 25px; border: 1px solid #ddd; border-radius: 8px; }}
        h1 {{ color: #b91c1c; border-bottom: 2px solid #b91c1c; padding-bottom: 8px; font-size: 20px; }}
        h2 {{ font-size: 15px; color: #374151; margin-top: 18px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 12px; }}
        th {{ background-color: #f3f4f6; }}
        .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-weight: bold; background: #fee2e2; color: #991b1b; }}
        .evidence-box {{ background: #f9fafb; padding: 12px; border-left: 4px solid #3b82f6; margin-top: 8px; font-size: 13px; font-family: monospace; white-space: pre-wrap; }}
        .print-btn {{ margin-bottom: 15px; padding: 8px 16px; background: #2563eb; color: white; border: none; border-radius: 4px; cursor: pointer; }}
        @media print {{ .print-btn {{ display: none; }} }}
    </style>
</head>
<body>
    <button class="print-btn" onclick="window.print()">Print / Save as PDF</button>
    <h1>CYBER FRAUD FORENSIC INCIDENT DOSSIER</h1>
    <p><strong>Complaint Reference / Incident ID:</strong> {escape_for_display(incident.incident_id)}</p>
    <p><strong>Timestamp (UTC):</strong> {escape_for_display(incident.created_at.isoformat())}</p>
    <p><strong>Threat Classification:</strong> <span class="badge">{escape_for_display(incident.risk.level.value.upper())} ({incident.risk.score:.0%})</span> | Category: {escape_for_display(incident.fraud_category or 'Unspecified')}</p>
    <p><strong>SHA-256 Content Hash:</strong> <code>{raw_hash}</code></p>
    
    <h2>1. Untrusted Evidentiary Message</h2>
    <div class="evidence-box">{escape_for_display(incident.message)}</div>

    <h2>2. Extracted Indicators of Compromise (IOCs)</h2>
    <table>
        <tr><th>Type</th><th>Observed Value</th></tr>
        {ioc_rows}
    </table>

    <h2>3. Forensic Evidence Dossier</h2>
    <table>
        <tr><th>Source Module</th><th>Finding & Forensic Description</th><th>Confidence</th></tr>
        {evidence_rows}
    </table>

    <h2>4. National Cyber Crime Reporting Advisory</h2>
    <p>For financial fraud: Call <strong>1930</strong> (National Cyber Crime Reporting Helpline) within the golden hour, or file a complaint at <strong>https://cybercrime.gov.in</strong> quoting this technical dossier.</p>
</body>
</html>"""
        return HTMLResponse(content=html_content, status_code=200)

    return JSONResponse(content=export_data, status_code=200)
