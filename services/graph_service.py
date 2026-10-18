"""
Graph Service — Low-level interface to FalkorDB queries.
Returns raw dicts/lists; transformation to Pydantic models happens in investigation_service.
All functions use parameterized queries from database/queries.py.
"""
from __future__ import annotations
import logging
from typing import Any

import config
from database.connection import get_graph
from database import queries

logger = logging.getLogger(__name__)


def _run(cypher: str, params: dict | None = None) -> list[list[Any]]:
    """Execute a Cypher query and return result_set rows."""
    try:
        g = get_graph()
        result = g.query(cypher, params or {})
        return result.result_set or []
    except Exception as exc:
        logger.error("Graph query failed: %s | params=%s | error=%s", cypher[:80], params, exc)
        raise


def get_database_stats() -> dict:
    """Return real stats by querying each entity count."""
    def count(q: str) -> int:
        try:
            rows = _run(q)
            return int(rows[0][0]) if rows else 0
        except Exception:
            return 0

    return {
        "total_nodes": count(queries.COUNT_ALL_NODES),
        "total_relationships": count(queries.COUNT_ALL_RELS),
        "alert_count": count(queries.COUNT_ALERTS),
        "open_incident_count": count(queries.COUNT_OPEN_INCIDENTS),
        "investigation_count": count(queries.COUNT_INVESTIGATIONS),
        "user_count": count(queries.COUNT_USERS),
        "device_count": count(queries.COUNT_DEVICES),
        "ip_count": count(queries.COUNT_IPS),
        "service_count": count(queries.COUNT_SERVICES),
    }


def list_alerts(limit: int = 50) -> list[dict]:
    """Return all alerts ordered by timestamp descending."""
    rows = _run(queries.GET_ALL_ALERTS, {"limit": limit})
    keys = ["id", "title", "severity", "category", "timestamp", "status"]
    return [dict(zip(keys, row)) for row in rows]


def get_alert_details(alert_id: str) -> dict | None:
    """Fetch a single alert by ID with all directly connected entities."""
    rows = _run(queries.GET_ALERT_WITH_CONTEXT, {"alert_id": alert_id})
    if not rows:
        return None

    row = rows[0]
    keys = [
        "alert_id", "alert_title", "alert_severity", "alert_category",
        "alert_timestamp", "alert_status", "alert_description",
        "device_id", "device_hostname", "device_type", "device_status",
        "user_id", "user_name", "user_department", "user_risk_level",
        "ip_id", "ip_address", "ip_reputation", "ip_country",
        "incident_id", "incident_title", "incident_severity", "incident_status",
    ]
    return dict(zip(keys, row))


def investigate_device(device_id: str) -> dict | None:
    """Full device investigation: owner, alerts triggered, IPs contacted, incidents."""
    rows = _run(queries.GET_DEVICE_INVESTIGATION, {"device_id": device_id})
    if not rows:
        return None

    row = rows[0]
    keys = [
        "device_id", "hostname", "device_type", "device_status", "last_seen",
        "user_id", "user_name", "user_risk_level",
        "triggered_alert_ids", "contacted_ips", "ip_reputations",
        "related_alert_ids", "incident_ids",
    ]
    return dict(zip(keys, row))


def trace_incident_path(alert_id: str) -> dict | None:
    """
    KEY MULTI-HOP QUERY: Follow the full evidence chain from an alert.
    Alert → Device → User → IP → Related Alerts → Incident → Affected Services.
    This is the core differentiating graph traversal.
    """
    rows = _run(queries.TRACE_INCIDENT_PATH, {"alert_id": alert_id})
    if not rows:
        return None

    row = rows[0]
    keys = [
        "start_alert_id", "start_alert_title", "start_alert_severity",
        "device_id", "hostname", "device_type",
        "user_id", "user_name", "department", "user_risk_level",
        "ip_id", "ip_address", "ip_reputation", "ip_country",
        "related_alert_id", "related_alert_title", "related_alert_severity",
        "incident_id", "incident_title", "incident_severity", "incident_status",
        "service_id", "service_name", "service_criticality", "service_owner_team",
    ]
    return dict(zip(keys, row))


def find_related_alerts_via_device(alert_id: str, limit: int = 10) -> list[dict]:
    """Find alerts that share the same triggering device."""
    rows = _run(queries.FIND_RELATED_ALERTS_VIA_DEVICE, {"alert_id": alert_id, "limit": limit})
    keys = ["alert_id", "title", "severity", "category", "timestamp", "status", "via_device"]
    return [dict(zip(keys, row)) for row in rows]


def find_related_alerts_via_ip(alert_id: str, limit: int = 10) -> list[dict]:
    """Find alerts connected through the same suspicious IP address."""
    rows = _run(queries.FIND_RELATED_ALERTS_VIA_IP, {"alert_id": alert_id, "limit": limit})
    keys = ["alert_id", "title", "severity", "category", "timestamp", "status", "via_ip", "ip_reputation"]
    return [dict(zip(keys, row)) for row in rows]


def find_related_alerts_via_user(alert_id: str, limit: int = 10) -> list[dict]:
    """Find alerts connected through the same user."""
    rows = _run(queries.FIND_RELATED_ALERTS_VIA_USER, {"alert_id": alert_id, "limit": limit})
    keys = ["alert_id", "title", "severity", "category", "timestamp", "status", "via_user"]
    return [dict(zip(keys, row)) for row in rows]


def get_affected_services(incident_id: str) -> list[dict]:
    """Return services affected by an incident."""
    rows = _run(queries.GET_AFFECTED_SERVICES, {"incident_id": incident_id})
    keys = ["service_id", "name", "criticality", "owner_team"]
    return [dict(zip(keys, row)) for row in rows]


def get_incident_details(incident_id: str) -> dict | None:
    """Return full incident details with related alerts and users."""
    rows = _run(queries.GET_INCIDENT_DETAILS, {"incident_id": incident_id})
    if not rows:
        return None
    row = rows[0]
    keys = ["incident_id", "title", "severity", "status", "created_at",
            "alert_ids", "involved_users", "affected_services"]
    return dict(zip(keys, row))


def get_all_graph_data_for_visualization(alert_id: str | None = None) -> dict:
    """
    Return nodes and edges for graph visualization.
    If alert_id is given, returns only the subgraph connected to that alert (up to 3 hops).
    Otherwise returns a sample of the full graph.
    """
    nodes = []
    edges = []
    seen_nodes: set[str] = set()
    seen_edges: set[tuple] = set()

    def add_node(nid: str, label: str, props: dict):
        if nid and nid not in seen_nodes:
            nodes.append({"id": nid, "label": label, "properties": props})
            seen_nodes.add(nid)

    def add_edge(src: str, rel: str, dst: str):
        key = (src, rel, dst)
        if src and dst and key not in seen_edges:
            edges.append({"source": src, "relation": rel, "target": dst})
            seen_edges.add(key)

    if alert_id:
        # Pull alert with direct context
        alert_data = get_alert_details(alert_id)
        if alert_data:
            add_node(alert_data["alert_id"], "Alert", {
                "title": alert_data["alert_title"],
                "severity": alert_data["alert_severity"],
                "status": alert_data["alert_status"],
            })
            if alert_data.get("device_id"):
                add_node(alert_data["device_id"], "Device", {
                    "hostname": alert_data["device_hostname"],
                    "type": alert_data["device_type"],
                })
                add_edge(alert_data["device_id"], "TRIGGERED", alert_data["alert_id"])
            if alert_data.get("user_id"):
                add_node(alert_data["user_id"], "User", {
                    "name": alert_data["user_name"],
                    "department": alert_data["user_department"],
                    "risk_level": alert_data["user_risk_level"],
                })
                add_edge(alert_data["user_id"], "USES", alert_data["device_id"])
            if alert_data.get("ip_id"):
                add_node(alert_data["ip_id"], "IPAddress", {
                    "address": alert_data["ip_address"],
                    "reputation": alert_data["ip_reputation"],
                })
                add_edge(alert_data["device_id"], "CONTACTED", alert_data["ip_id"])
            if alert_data.get("incident_id"):
                add_node(alert_data["incident_id"], "Incident", {
                    "title": alert_data["incident_title"],
                    "severity": alert_data["incident_severity"],
                })
                add_edge(alert_data["alert_id"], "PART_OF", alert_data["incident_id"])

        # Add related alerts via IP
        related = find_related_alerts_via_ip(alert_id)
        for r in related:
            add_node(r["alert_id"], "Alert", {
                "title": r["title"],
                "severity": r["severity"],
                "status": r["status"],
            })

        # Add related alerts via device
        related_d = find_related_alerts_via_device(alert_id)
        for r in related_d:
            add_node(r["alert_id"], "Alert", {
                "title": r["title"],
                "severity": r["severity"],
                "status": r["status"],
            })

        # Add incident path
        path = trace_incident_path(alert_id)
        if path:
            if path.get("incident_id"):
                inc_id = path["incident_id"]
                add_node(inc_id, "Incident", {"title": path["incident_title"], "severity": path["incident_severity"]})
                add_edge(alert_id, "PART_OF", inc_id)

                services = get_affected_services(inc_id)
                for svc in services:
                    add_node(svc["service_id"], "Service", {"name": svc["name"], "criticality": svc["criticality"]})
                    add_edge(inc_id, "AFFECTS", svc["service_id"])

            if path.get("related_alert_id"):
                add_node(path["related_alert_id"], "Alert", {
                    "title": path["related_alert_title"],
                    "severity": path["related_alert_severity"],
                })
                if path.get("ip_id"):
                    add_edge(path["ip_id"], "ASSOCIATED_WITH", path["related_alert_id"])

    return {"nodes": nodes, "edges": edges}
