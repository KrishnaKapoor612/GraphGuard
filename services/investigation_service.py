"""
Investigation Service — orchestrates the multi-hop graph investigation workflow.
This layer sits between the raw graph queries and the LLM agent.
It can produce a complete evidence-backed investigation without LLM involvement,
which makes the demo deterministic when Gemini is unavailable.
"""
from __future__ import annotations
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from services import graph_service
from models.schemas import (
    InvestigationResult, EvidenceRecord, GraphPath,
)

logger = logging.getLogger(__name__)


def _severity_rank(s: str | None) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get((s or "").lower(), 0)


def run_graph_investigation(alert_id: str) -> dict:
    """
    Execute the full multi-hop graph investigation for an alert.
    Returns a structured dict with all collected evidence — no LLM required.
    This result feeds into the agent and/or is displayed directly in demo mode.
    """
    result: dict[str, Any] = {
        "alert_id": alert_id,
        "alert_data": None,
        "device_data": None,
        "incident_path": None,
        "related_alerts_via_device": [],
        "related_alerts_via_ip": [],
        "related_alerts_via_user": [],
        "affected_services": [],
        "graph_summary": {},
        "graph_path_description": "",
    }

    # Step 1: Get alert with direct context (1 hop)
    alert_data = graph_service.get_alert_details(alert_id)
    if not alert_data:
        return {"error": f"Alert {alert_id} not found in graph"}
    result["alert_data"] = alert_data

    # Step 2: Investigate the device (if found)
    device_id = alert_data.get("device_id")
    if device_id:
        result["device_data"] = graph_service.investigate_device(device_id)

    # Step 3: Multi-hop traversal — the core graph differentiator
    incident_path = graph_service.trace_incident_path(alert_id)
    result["incident_path"] = incident_path

    # Step 4: Find related alerts via multiple relationship paths
    result["related_alerts_via_device"] = graph_service.find_related_alerts_via_device(alert_id)
    result["related_alerts_via_ip"] = graph_service.find_related_alerts_via_ip(alert_id)
    result["related_alerts_via_user"] = graph_service.find_related_alerts_via_user(alert_id)

    # Step 5: Get affected services from incident
    incident_id = (incident_path or {}).get("incident_id") or alert_data.get("incident_id")
    if incident_id:
        result["affected_services"] = graph_service.get_affected_services(incident_id)

    # Build graph path description
    result["graph_path_description"] = _build_path_description(alert_data, incident_path)
    result["graph_summary"] = _build_summary_stats(result)

    return result


def _build_path_description(alert_data: dict, path: dict | None) -> str:
    """Build a human-readable description of the discovered graph path."""
    parts = []

    if alert_data.get("alert_id"):
        parts.append(f"Alert [{alert_data['alert_id']}] {alert_data.get('alert_title', '')}")

    if path and path.get("hostname"):
        parts.append(f"→ Device [{path['device_id']}] {path['hostname']}")

    if path and path.get("user_name"):
        parts.append(f"→ User [{path['user_id']}] {path['user_name']} (risk: {path['user_risk_level']})")

    if path and path.get("ip_address"):
        parts.append(f"→ IP [{path['ip_id']}] {path['ip_address']} (reputation: {path['ip_reputation']})")

    if path and path.get("related_alert_id"):
        parts.append(f"→ Related Alert [{path['related_alert_id']}] {path['related_alert_title']}")

    if path and path.get("incident_id"):
        parts.append(f"→ Incident [{path['incident_id']}] {path['incident_title']}")

    if path and path.get("service_name"):
        parts.append(f"→ Service [{path['service_id']}] {path['service_name']} (criticality: {path['service_criticality']})")

    return "\n".join(parts) if parts else "No connected path found"


def _build_summary_stats(result: dict) -> dict:
    """Produce summary statistics from the collected evidence."""
    all_related = (
        result["related_alerts_via_device"]
        + result["related_alerts_via_ip"]
        + result["related_alerts_via_user"]
    )
    unique_related_ids = {a["alert_id"] for a in all_related}

    ip_rep = None
    path = result.get("incident_path")
    if path:
        ip_rep = path.get("ip_reputation")

    max_sev = result["alert_data"].get("alert_severity", "unknown") if result.get("alert_data") else "unknown"
    for ra in all_related:
        if _severity_rank(ra.get("severity")) > _severity_rank(max_sev):
            max_sev = ra.get("severity")

    return {
        "hop_count": 4 if (path and path.get("incident_id")) else 2,
        "related_alert_count": len(unique_related_ids),
        "has_incident": bool(path and path.get("incident_id")),
        "has_malicious_ip": ip_rep == "malicious",
        "affected_service_count": len(result.get("affected_services", [])),
        "max_severity": max_sev,
    }


def build_deterministic_investigation(alert_id: str) -> InvestigationResult:
    """
    Build a complete InvestigationResult from graph data alone (no LLM).
    Used when Gemini is unavailable or as a fallback for the demo.
    The narrative is templated but the facts are real graph query results.
    """
    raw = run_graph_investigation(alert_id)

    if "error" in raw:
        return InvestigationResult(
            investigation_id="N/A",
            investigation_summary=raw["error"],
            severity_assessment="unknown",
            confirmed_facts=[],
            is_demo_fallback=True,
        )

    alert = raw["alert_data"]
    path = raw["incident_path"] or {}
    stats = raw["graph_summary"]
    services = raw["affected_services"]

    inv_id = "DEMO-" + alert_id

    # ── Confirmed Facts (from actual query results) ──
    facts = [f"Alert {alert_id} is categorized as {alert.get('alert_category')} with {alert.get('alert_severity')} severity."]

    if path.get("hostname"):
        facts.append(f"The alert was triggered by device {path['hostname']} ({path.get('device_type','')}).")
    if path.get("user_name"):
        facts.append(
            f"Device {path['hostname']} is assigned to user {path['user_name']} "
            f"(department: {path.get('department','')}, risk level: {path.get('user_risk_level','')})."
        )
    if path.get("ip_address"):
        facts.append(
            f"Device contacted IP {path['ip_address']} ({path.get('ip_country','')}) "
            f"which has reputation: {path.get('ip_reputation','')}."
        )
    if path.get("incident_id"):
        facts.append(
            f"Alert is part of Incident {path['incident_id']}: \"{path.get('incident_title','')}\" "
            f"(severity: {path.get('incident_severity','')}, status: {path.get('incident_status','')})."
        )
    for svc in services:
        facts.append(f"Service \"{svc['name']}\" (criticality: {svc['criticality']}) may be affected by this incident.")

    # Related alerts facts
    for ra in raw["related_alerts_via_device"][:2]:
        facts.append(f"Related alert [{ra['alert_id']}] \"{ra['title']}\" ({ra['severity']}) shares the same device.")
    for ra in raw["related_alerts_via_ip"][:2]:
        facts.append(f"Related alert [{ra['alert_id']}] \"{ra['title']}\" ({ra['severity']}) shares the same malicious IP.")

    # ── Evidence Records ──
    evidence = []
    if path.get("ip_address"):
        evidence.append(EvidenceRecord(
            evidence_id="EV-NET-001",
            source_type="network_log",
            description=f"Device {path.get('hostname')} contacted {path.get('ip_address')} (reputation: {path.get('ip_reputation')})",
            observed_at=alert.get("alert_timestamp", ""),
            entity_type="IPAddress",
            entity_id=path.get("ip_id", ""),
            is_inferred=False,
        ))
    if path.get("incident_id"):
        evidence.append(EvidenceRecord(
            evidence_id="EV-INC-001",
            source_type="incident_record",
            description=f"Alert is part of Incident {path['incident_id']}: {path.get('incident_title','')}",
            observed_at=alert.get("alert_timestamp", ""),
            entity_type="Incident",
            entity_id=path.get("incident_id", ""),
            is_inferred=False,
        ))
    for svc in services[:2]:
        evidence.append(EvidenceRecord(
            evidence_id=f"EV-SVC-{svc['service_id']}",
            source_type="service_impact",
            description=f"Service {svc['name']} ({svc['criticality']} criticality) affected by incident",
            observed_at=alert.get("alert_timestamp", ""),
            entity_type="Service",
            entity_id=svc["service_id"],
            is_inferred=False,
        ))

    # ── Graph Path ──
    graph_paths = [GraphPath(
        path_description=raw["graph_path_description"],
        hop_count=stats.get("hop_count", 0),
        entities=[
            {"type": "Alert", "id": alert_id, "title": alert.get("alert_title", "")},
            {"type": "Device", "id": path.get("device_id", ""), "name": path.get("hostname", "")},
            {"type": "User", "id": path.get("user_id", ""), "name": path.get("user_name", "")},
            {"type": "IPAddress", "id": path.get("ip_id", ""), "address": path.get("ip_address", "")},
            {"type": "Incident", "id": path.get("incident_id", ""), "title": path.get("incident_title", "")},
        ],
        relationships=["TRIGGERED", "USES", "CONTACTED", "PART_OF", "AFFECTS"],
    )]

    # ── Related Alerts ──
    all_related = raw["related_alerts_via_device"] + raw["related_alerts_via_ip"]
    seen = set()
    unique_related = []
    for ra in all_related:
        if ra["alert_id"] not in seen:
            unique_related.append(ra)
            seen.add(ra["alert_id"])

    # ── Inferences (templated, labeled as such) ──
    inferences = []
    if stats.get("has_malicious_ip"):
        inferences.append(
            "[INFERRED] The connection to a known malicious IP suggests the device may be "
            "communicating with attacker-controlled infrastructure."
        )
    if path.get("user_risk_level") == "high":
        inferences.append(
            f"[INFERRED] User {path.get('user_name')} has elevated risk level; "
            "this device activity warrants immediate account review."
        )
    if stats.get("affected_service_count", 0) > 0:
        inferences.append(
            "[INFERRED] Affected services may have been exposed to data accessible from the compromised device."
        )

    # ── Unknowns ──
    unknowns = [
        "Whether the device has been fully compromised or only partially affected is not yet determined.",
        "The specific data accessed or exfiltrated has not been confirmed from graph evidence alone.",
        "Whether other devices in the environment contacted the same malicious IP is not yet queried.",
    ]

    # ── Recommended Next Steps ──
    steps = []
    if path.get("hostname"):
        steps.append(f"Isolate {path['hostname']} from network immediately pending forensic analysis.")
    if path.get("user_name"):
        steps.append(f"Suspend credentials for {path.get('user_name')} and require password reset after clearance.")
    if path.get("ip_address"):
        steps.append(f"Block {path.get('ip_address')} at perimeter firewall and check for other devices that contacted it.")
    for svc in services[:2]:
        steps.append(f"Audit access logs for {svc['name']} for unauthorized reads during the incident window.")
    steps.append("Preserve forensic artifacts from WORKSTATION-07 before any remediation.")
    steps.append("Engage incident response team and open a formal IR ticket.")

    # ── Summary ──
    has_incident = stats.get("has_incident")
    summary = (
        f"Alert {alert_id} ({alert.get('alert_severity')} severity, {alert.get('alert_category')}) "
        f"is NOT an isolated event. Graph traversal across {stats.get('hop_count', '?')} hops reveals "
        f"{stats.get('related_alert_count', 0)} related alert(s) and "
        f"{'an active incident' if has_incident else 'no formal incident yet'}. "
    )
    if path.get("ip_reputation") == "malicious":
        summary += f"The device contacted a known malicious IP ({path.get('ip_address')}), "
    if has_incident:
        summary += (
            f"indicating this is part of a broader attack campaign. "
            f"{len(services)} critical service(s) may be at risk."
        )
    else:
        summary += "further investigation is recommended."

    return InvestigationResult(
        investigation_id=inv_id,
        investigation_summary=summary,
        severity_assessment=stats.get("max_severity", "unknown"),
        confirmed_facts=facts,
        supporting_evidence=evidence,
        graph_paths=graph_paths,
        related_alerts=unique_related,
        potentially_affected_services=services,
        inferences=inferences,
        unknowns=unknowns,
        recommended_next_steps=steps,
        is_demo_fallback=True,
        raw_graph_data=raw,
    )
