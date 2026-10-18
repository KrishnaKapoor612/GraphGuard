"""
GraphGuard Synthetic Demo Data — Idempotent Seed Script.

Scenario A (Suspicious): Multi-hop attack chain
  Marcus Chen (high-risk user) → WORKSTATION-07 → contacted 185.220.101.45 (Tor exit node)
  → triggered Alert A-104 (Suspicious Outbound) → part of INC-001 (Data Exfiltration)
  → affects PAYMENT-SVC (critical) and HR-PORTAL (high)

Scenario B (Related activity):
  WORKSTATION-07 also triggered A-105 (Port Scan Detected) → same Incident INC-001
  185.220.101.45 also ASSOCIATED_WITH Alert A-106 (C2 Beacon Attempt)

Scenario C (Benign baseline):
  Alice Thompson (low-risk) → LAPTOP-22 → contacted 8.8.8.8 (Google DNS)
  → triggered Alert A-201 (Unusual DNS Query volume) — false_positive, no incident

Run this script at any time; MERGE ensures no duplicates.
"""
from __future__ import annotations
import sys
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


NODES = {
    "users": [
        {
            "id": "U-001",
            "name": "Marcus Chen",
            "department": "Engineering",
            "role": "Senior Developer",
            "risk_level": "high",
        },
        {
            "id": "U-002",
            "name": "Alice Thompson",
            "department": "HR",
            "role": "HR Coordinator",
            "risk_level": "low",
        },
        {
            "id": "U-003",
            "name": "Ryan Patel",
            "department": "Finance",
            "role": "Finance Analyst",
            "risk_level": "medium",
        },
        {
            "id": "U-004",
            "name": "Sarah Kim",
            "department": "IT Security",
            "role": "Security Engineer",
            "risk_level": "low",
        },
    ],
    "devices": [
        {
            "id": "D-001",
            "hostname": "WORKSTATION-07",
            "device_type": "workstation",
            "status": "compromised_suspected",
            "last_seen": "2024-03-15T02:47:00Z",
        },
        {
            "id": "D-002",
            "hostname": "LAPTOP-22",
            "device_type": "laptop",
            "status": "healthy",
            "last_seen": "2024-03-15T09:12:00Z",
        },
        {
            "id": "D-003",
            "hostname": "SERVER-DB-01",
            "device_type": "server",
            "status": "healthy",
            "last_seen": "2024-03-15T10:00:00Z",
        },
        {
            "id": "D-004",
            "hostname": "LAPTOP-45",
            "device_type": "laptop",
            "status": "healthy",
            "last_seen": "2024-03-14T17:30:00Z",
        },
    ],
    "ip_addresses": [
        {
            "id": "IP-001",
            "address": "185.220.101.45",
            "reputation": "malicious",
            "country": "Netherlands",
        },
        {
            "id": "IP-002",
            "address": "8.8.8.8",
            "reputation": "clean",
            "country": "United States",
        },
        {
            "id": "IP-003",
            "address": "192.0.2.99",
            "reputation": "suspicious",
            "country": "Romania",
        },
        {
            "id": "IP-004",
            "address": "10.0.0.1",
            "reputation": "clean",
            "country": "Internal",
        },
    ],
    "alerts": [
        {
            "id": "A-104",
            "title": "Suspicious Outbound Connection to Known Tor Exit Node",
            "severity": "critical",
            "category": "Network Anomaly",
            "timestamp": "2024-03-15T02:47:00Z",
            "status": "open",
            "description": (
                "WORKSTATION-07 established an encrypted outbound connection to 185.220.101.45, "
                "a known Tor exit node associated with data exfiltration campaigns. "
                "Connection persisted for 47 minutes with 2.3GB of outbound data transfer."
            ),
        },
        {
            "id": "A-105",
            "title": "Internal Port Scan Detected from Engineering Workstation",
            "severity": "high",
            "category": "Reconnaissance",
            "timestamp": "2024-03-15T01:23:00Z",
            "status": "open",
            "description": (
                "WORKSTATION-07 performed a systematic TCP port scan across 254 internal hosts "
                "on ports 22, 80, 443, 1433, 3306. This behavior is consistent with pre-exfiltration "
                "reconnaissance to identify database and web servers."
            ),
        },
        {
            "id": "A-106",
            "title": "C2 Beacon Attempt Blocked by Firewall",
            "severity": "high",
            "category": "Malware",
            "timestamp": "2024-03-14T23:15:00Z",
            "status": "open",
            "description": (
                "Firewall blocked outbound C2 communication attempt to 185.220.101.45. "
                "Beacon pattern matches known Cobalt Strike malleable C2 profile. "
                "Blocking may have delayed but not prevented the subsequent successful connection."
            ),
        },
        {
            "id": "A-201",
            "title": "Unusual DNS Query Volume",
            "severity": "low",
            "category": "Network Anomaly",
            "timestamp": "2024-03-15T09:05:00Z",
            "status": "false_positive",
            "description": (
                "LAPTOP-22 generated elevated DNS query volume (>500 queries/hour) "
                "to 8.8.8.8. Investigation confirmed this was caused by a misconfigured "
                "browser extension performing background tab prefetching. No malicious activity detected."
            ),
        },
        {
            "id": "A-301",
            "title": "Failed Login Attempts — Finance System",
            "severity": "medium",
            "category": "Authentication",
            "timestamp": "2024-03-14T14:00:00Z",
            "status": "investigating",
            "description": (
                "12 failed login attempts to the Finance portal from LAPTOP-45 "
                "over a 3-minute window. Account belonged to Ryan Patel. "
                "Likely brute-force or credential stuffing attempt."
            ),
        },
    ],
    "incidents": [
        {
            "id": "INC-001",
            "title": "Suspected Data Exfiltration via Compromised Engineering Workstation",
            "severity": "critical",
            "status": "active",
            "created_at": "2024-03-15T03:00:00Z",
        },
        {
            "id": "INC-002",
            "title": "Finance Portal Credential Attack",
            "severity": "medium",
            "status": "investigating",
            "created_at": "2024-03-14T14:30:00Z",
        },
    ],
    "services": [
        {
            "id": "SVC-001",
            "name": "Payment Processing Service",
            "criticality": "critical",
            "owner_team": "Platform Engineering",
        },
        {
            "id": "SVC-002",
            "name": "HR Employee Portal",
            "criticality": "high",
            "owner_team": "HR Technology",
        },
        {
            "id": "SVC-003",
            "name": "Internal Finance System",
            "criticality": "high",
            "owner_team": "Finance IT",
        },
        {
            "id": "SVC-004",
            "name": "Corporate DNS Resolver",
            "criticality": "medium",
            "owner_team": "Network Operations",
        },
    ],
    "evidence": [
        {
            "id": "EV-001",
            "source_type": "network_log",
            "description": "47-minute encrypted outbound session from WORKSTATION-07 to 185.220.101.45, 2.3GB transferred",
            "observed_at": "2024-03-15T02:47:00Z",
        },
        {
            "id": "EV-002",
            "source_type": "network_log",
            "description": "Port scan activity originating from WORKSTATION-07 across internal subnet 10.0.0.0/24",
            "observed_at": "2024-03-15T01:23:00Z",
        },
        {
            "id": "EV-003",
            "source_type": "firewall_log",
            "description": "Firewall block event: outbound C2 beacon to 185.220.101.45 from WORKSTATION-07",
            "observed_at": "2024-03-14T23:15:00Z",
        },
        {
            "id": "EV-004",
            "source_type": "threat_intel",
            "description": "185.220.101.45 listed in multiple threat intelligence feeds as active Tor exit node and C2 host",
            "observed_at": "2024-03-15T00:00:00Z",
        },
    ],
}

RELATIONSHIPS = [
    # User → Device
    ("U-001", "USES", "D-001"),      # Marcus Chen uses WORKSTATION-07
    ("U-002", "USES", "D-002"),      # Alice Thompson uses LAPTOP-22
    ("U-003", "USES", "D-004"),      # Ryan Patel uses LAPTOP-45
    ("U-004", "USES", "D-003"),      # Sarah Kim uses SERVER-DB-01

    # Device → IP (CONTACTED)
    ("D-001", "CONTACTED", "IP-001"),  # WORKSTATION-07 → Tor exit node
    ("D-001", "CONTACTED", "IP-004"),  # WORKSTATION-07 → Internal (normal)
    ("D-002", "CONTACTED", "IP-002"),  # LAPTOP-22 → Google DNS (benign)
    ("D-004", "CONTACTED", "IP-003"),  # LAPTOP-45 → suspicious IP

    # Device → Alert (TRIGGERED)
    ("D-001", "TRIGGERED", "A-104"),  # WORKSTATION-07 → critical outbound alert
    ("D-001", "TRIGGERED", "A-105"),  # WORKSTATION-07 → port scan alert
    ("D-002", "TRIGGERED", "A-201"),  # LAPTOP-22 → DNS alert (benign)
    ("D-004", "TRIGGERED", "A-301"),  # LAPTOP-45 → auth alert

    # IP → Alert (ASSOCIATED_WITH)
    ("IP-001", "ASSOCIATED_WITH", "A-104"),  # Tor IP → outbound connection alert
    ("IP-001", "ASSOCIATED_WITH", "A-106"),  # Tor IP → C2 beacon alert (pre-existing)
    ("IP-003", "ASSOCIATED_WITH", "A-301"),  # Suspicious IP → finance brute force

    # Alert → Incident (PART_OF)
    ("A-104", "PART_OF", "INC-001"),  # Critical outbound → exfiltration incident
    ("A-105", "PART_OF", "INC-001"),  # Port scan → same incident (recon phase)
    ("A-106", "PART_OF", "INC-001"),  # C2 beacon → same incident (initial access attempt)
    ("A-301", "PART_OF", "INC-002"),  # Auth attack → finance credential incident

    # Incident → Service (AFFECTS)
    ("INC-001", "AFFECTS", "SVC-001"),  # Exfiltration → payment service at risk
    ("INC-001", "AFFECTS", "SVC-002"),  # Exfiltration → HR portal at risk
    ("INC-002", "AFFECTS", "SVC-003"),  # Finance attack → finance system

    # User → Incident (INVOLVED_IN)
    ("U-001", "INVOLVED_IN", "INC-001"),  # Marcus Chen implicated in exfiltration
    ("U-003", "INVOLVED_IN", "INC-002"),  # Ryan Patel implicated in finance attack

    # Evidence → Incident (SUPPORTS)
    ("EV-001", "SUPPORTS", "INC-001"),
    ("EV-002", "SUPPORTS", "INC-001"),
    ("EV-003", "SUPPORTS", "INC-001"),
    ("EV-004", "SUPPORTS", "INC-001"),
]


def seed_graph(graph, verbose: bool = True) -> dict:
    """
    Idempotently seed all nodes and relationships.
    Uses MERGE to prevent duplicates on re-runs.
    Returns a summary dict with counts.
    """
    counts = {
        "users": 0, "devices": 0, "ip_addresses": 0,
        "alerts": 0, "incidents": 0, "services": 0,
        "evidence": 0, "relationships": 0,
    }

    def vprint(msg: str):
        if verbose:
            print(msg)
            logger.info(msg)

    # ── Users ──
    for u in NODES["users"]:
        graph.query(
            "MERGE (n:User {id: $id}) SET n.name=$name, n.department=$dept, n.role=$role, n.risk_level=$risk",
            {"id": u["id"], "name": u["name"], "dept": u["department"], "role": u["role"], "risk": u["risk_level"]},
        )
        counts["users"] += 1
    vprint(f"  [+] {counts['users']} users")

    # ── Devices ──
    for d in NODES["devices"]:
        graph.query(
            "MERGE (n:Device {id: $id}) SET n.hostname=$hostname, n.device_type=$dtype, n.status=$status, n.last_seen=$last_seen",
            {"id": d["id"], "hostname": d["hostname"], "dtype": d["device_type"], "status": d["status"], "last_seen": d["last_seen"]},
        )
        counts["devices"] += 1
    vprint(f"  [+] {counts['devices']} devices")

    # ── IP Addresses ──
    for ip in NODES["ip_addresses"]:
        graph.query(
            "MERGE (n:IPAddress {id: $id}) SET n.address=$addr, n.reputation=$rep, n.country=$country",
            {"id": ip["id"], "addr": ip["address"], "rep": ip["reputation"], "country": ip["country"]},
        )
        counts["ip_addresses"] += 1
    vprint(f"  [+] {counts['ip_addresses']} IP addresses")

    # ── Alerts ──
    for a in NODES["alerts"]:
        graph.query(
            "MERGE (n:Alert {id: $id}) SET n.title=$title, n.severity=$sev, n.category=$cat, n.timestamp=$ts, n.status=$status, n.description=$desc",
            {"id": a["id"], "title": a["title"], "sev": a["severity"], "cat": a["category"],
             "ts": a["timestamp"], "status": a["status"], "desc": a["description"]},
        )
        counts["alerts"] += 1
    vprint(f"  [+] {counts['alerts']} alerts")

    # ── Incidents ──
    for inc in NODES["incidents"]:
        graph.query(
            "MERGE (n:Incident {id: $id}) SET n.title=$title, n.severity=$sev, n.status=$status, n.created_at=$created_at",
            {"id": inc["id"], "title": inc["title"], "sev": inc["severity"],
             "status": inc["status"], "created_at": inc["created_at"]},
        )
        counts["incidents"] += 1
    vprint(f"  [+] {counts['incidents']} incidents")

    # ── Services ──
    for svc in NODES["services"]:
        graph.query(
            "MERGE (n:Service {id: $id}) SET n.name=$name, n.criticality=$crit, n.owner_team=$team",
            {"id": svc["id"], "name": svc["name"], "crit": svc["criticality"], "team": svc["owner_team"]},
        )
        counts["services"] += 1
    vprint(f"  [+] {counts['services']} services")

    # ── Evidence ──
    for ev in NODES["evidence"]:
        graph.query(
            "MERGE (n:Evidence {id: $id}) SET n.source_type=$src, n.description=$desc, n.observed_at=$obs",
            {"id": ev["id"], "src": ev["source_type"], "desc": ev["description"], "obs": ev["observed_at"]},
        )
        counts["evidence"] += 1
    vprint(f"  [+] {counts['evidence']} evidence records")

    # ── Relationships ──
    node_label_map = {
        "U-": "User", "D-": "Device", "IP-": "IPAddress",
        "A-": "Alert", "INC-": "Incident", "SVC-": "Service", "EV-": "Evidence",
    }

    def get_label(node_id: str) -> str:
        for prefix, label in node_label_map.items():
            if node_id.startswith(prefix):
                return label
        raise ValueError(f"Cannot determine label for node ID: {node_id}")

    for (src_id, rel_type, dst_id) in RELATIONSHIPS:
        src_label = get_label(src_id)
        dst_label = get_label(dst_id)
        cypher = (
            f"MATCH (src:{src_label} {{id: $src_id}}), (dst:{dst_label} {{id: $dst_id}}) "
            f"MERGE (src)-[:{rel_type}]->(dst)"
        )
        graph.query(cypher, {"src_id": src_id, "dst_id": dst_id})
        counts["relationships"] += 1

    vprint(f"  [+] {counts['relationships']} relationships")
    return counts


def reset_graph(graph, confirm: bool = False) -> None:
    """
    DELETE ALL NODES AND RELATIONSHIPS in the graph.
    Requires explicit confirm=True to prevent accidents.
    """
    if not confirm:
        print("Reset aborted: pass confirm=True to delete all data.")
        return
    print("Deleting all graph data...")
    graph.query("MATCH (n) DETACH DELETE n")
    print("Graph cleared.")


def run_seed(verbose: bool = True) -> bool:
    """Entry point called by scripts/seed_demo.py and the Streamlit UI."""
    import sys
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))

    try:
        from database.connection import get_graph
        graph = get_graph()
    except ConnectionError as exc:
        print(f"[-] Cannot connect to FalkorDB: {exc}")
        return False

    print("Seeding GraphGuard demo graph...")
    counts = seed_graph(graph, verbose=verbose)
    total_nodes = sum(v for k, v in counts.items() if k != "relationships")
    print(f"\n[OK] Seed complete: {total_nodes} nodes, {counts['relationships']} relationships")
    print("  Demonstration scenarios:")
    print("  * Scenario A: Marcus Chen / WORKSTATION-07 -> TorIP -> INC-001 (Data Exfiltration)")
    print("  * Scenario B: INC-001 affects Payment Service and HR Portal")
    print("  * Scenario C: Alice Thompson / LAPTOP-22 -> benign DNS alert (false positive)")
    return True


if __name__ == "__main__":
    import sys
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    success = run_seed()
    sys.exit(0 if success else 1)
