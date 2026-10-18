"""
GraphGuard Cypher Query Library.

All queries are parameterized — no user input is ever interpolated directly.
Queries are read-only (MATCH/RETURN) except for explicit persistence operations.

FalkorDB Cypher subset used here:
- MATCH / WHERE / RETURN / WITH / LIMIT / ORDER BY
- CREATE / MERGE (for seed and persistence)
- Relationship traversal: (a)-[:REL]->(b)
- Variable-length paths: (a)-[*1..3]->(b)
- count(), collect(), properties() functions
"""

# ─── Schema / Index Creation ────────────────────────────────────────────────

CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS FOR (n:User) ON (n.id)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Device) ON (n.id)",
    "CREATE INDEX IF NOT EXISTS FOR (n:IPAddress) ON (n.id)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Alert) ON (n.id)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Incident) ON (n.id)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Service) ON (n.id)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Investigation) ON (n.id)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Evidence) ON (n.id)",
]


# ─── Stats Queries ──────────────────────────────────────────────────────────

COUNT_ALL_NODES = "MATCH (n) RETURN count(n) AS cnt"
COUNT_ALL_RELS = "MATCH ()-[r]->() RETURN count(r) AS cnt"
COUNT_ALERTS = "MATCH (a:Alert) RETURN count(a) AS cnt"
COUNT_OPEN_INCIDENTS = "MATCH (i:Incident) WHERE i.status <> 'resolved' RETURN count(i) AS cnt"
COUNT_INVESTIGATIONS = "MATCH (i:Investigation) RETURN count(i) AS cnt"
COUNT_USERS = "MATCH (u:User) RETURN count(u) AS cnt"
COUNT_DEVICES = "MATCH (d:Device) RETURN count(d) AS cnt"
COUNT_IPS = "MATCH (ip:IPAddress) RETURN count(ip) AS cnt"
COUNT_SERVICES = "MATCH (s:Service) RETURN count(s) AS cnt"


# ─── Alert Queries ───────────────────────────────────────────────────────────

GET_ALL_ALERTS = """
MATCH (a:Alert)
RETURN a.id, a.title, a.severity, a.category, a.timestamp, a.status
ORDER BY a.timestamp DESC
LIMIT $limit
"""

GET_ALERT_BY_ID = """
MATCH (a:Alert {id: $alert_id})
RETURN a.id, a.title, a.severity, a.category, a.timestamp, a.status, a.description
"""

GET_ALERT_WITH_CONTEXT = """
MATCH (a:Alert {id: $alert_id})
OPTIONAL MATCH (d:Device)-[:TRIGGERED]->(a)
OPTIONAL MATCH (d)-[:CONTACTED]->(ip:IPAddress)
OPTIONAL MATCH (u:User)-[:USES]->(d)
OPTIONAL MATCH (a)-[:PART_OF]->(inc:Incident)
OPTIONAL MATCH (ip)-[:ASSOCIATED_WITH]->(a)
RETURN
    a.id AS alert_id,
    a.title AS alert_title,
    a.severity AS alert_severity,
    a.category AS alert_category,
    a.timestamp AS alert_timestamp,
    a.status AS alert_status,
    a.description AS alert_description,
    d.id AS device_id,
    d.hostname AS device_hostname,
    d.device_type AS device_type,
    d.status AS device_status,
    u.id AS user_id,
    u.name AS user_name,
    u.department AS user_department,
    u.risk_level AS user_risk_level,
    ip.id AS ip_id,
    ip.address AS ip_address,
    ip.reputation AS ip_reputation,
    ip.country AS ip_country,
    inc.id AS incident_id,
    inc.title AS incident_title,
    inc.severity AS incident_severity,
    inc.status AS incident_status
"""


# ─── Device Investigation ────────────────────────────────────────────────────

GET_DEVICE_INVESTIGATION = """
MATCH (d:Device {id: $device_id})
OPTIONAL MATCH (u:User)-[:USES]->(d)
OPTIONAL MATCH (d)-[:TRIGGERED]->(a:Alert)
OPTIONAL MATCH (d)-[:CONTACTED]->(ip:IPAddress)
OPTIONAL MATCH (ip)-[:ASSOCIATED_WITH]->(related_alert:Alert)
OPTIONAL MATCH (a)-[:PART_OF]->(inc:Incident)
RETURN
    d.id AS device_id,
    d.hostname AS hostname,
    d.device_type AS device_type,
    d.status AS device_status,
    d.last_seen AS last_seen,
    u.id AS user_id,
    u.name AS user_name,
    u.risk_level AS user_risk_level,
    collect(DISTINCT a.id) AS triggered_alert_ids,
    collect(DISTINCT ip.address) AS contacted_ips,
    collect(DISTINCT ip.reputation) AS ip_reputations,
    collect(DISTINCT related_alert.id) AS related_alert_ids,
    collect(DISTINCT inc.id) AS incident_ids
"""


# ─── Multi-hop Investigation (the key differentiator) ───────────────────────

TRACE_INCIDENT_PATH = """
MATCH (a:Alert {id: $alert_id})
OPTIONAL MATCH path1 = (d:Device)-[:TRIGGERED]->(a)
OPTIONAL MATCH path2 = (u:User)-[:USES]->(d)
OPTIONAL MATCH path3 = (d)-[:CONTACTED]->(ip:IPAddress)
OPTIONAL MATCH path4 = (ip)-[:ASSOCIATED_WITH]->(related_a:Alert)
OPTIONAL MATCH path5 = (a)-[:PART_OF]->(inc:Incident)
OPTIONAL MATCH path6 = (inc)-[:AFFECTS]->(svc:Service)
OPTIONAL MATCH path7 = (u)-[:INVOLVED_IN]->(inc)
RETURN
    a.id AS start_alert_id,
    a.title AS start_alert_title,
    a.severity AS start_alert_severity,
    d.id AS device_id,
    d.hostname AS hostname,
    d.device_type AS device_type,
    u.id AS user_id,
    u.name AS user_name,
    u.department AS department,
    u.risk_level AS user_risk_level,
    ip.id AS ip_id,
    ip.address AS ip_address,
    ip.reputation AS ip_reputation,
    ip.country AS ip_country,
    related_a.id AS related_alert_id,
    related_a.title AS related_alert_title,
    related_a.severity AS related_alert_severity,
    inc.id AS incident_id,
    inc.title AS incident_title,
    inc.severity AS incident_severity,
    inc.status AS incident_status,
    svc.id AS service_id,
    svc.name AS service_name,
    svc.criticality AS service_criticality,
    svc.owner_team AS service_owner_team
"""

FIND_RELATED_ALERTS_VIA_DEVICE = """
MATCH (a:Alert {id: $alert_id})<-[:TRIGGERED]-(d:Device)-[:TRIGGERED]->(other:Alert)
WHERE other.id <> $alert_id
RETURN
    other.id AS alert_id,
    other.title AS title,
    other.severity AS severity,
    other.category AS category,
    other.timestamp AS timestamp,
    other.status AS status,
    d.hostname AS via_device
LIMIT $limit
"""

FIND_RELATED_ALERTS_VIA_USER = """
MATCH (a:Alert {id: $alert_id})<-[:TRIGGERED]-(d:Device)<-[:USES]-(u:User)-[:USES]->(d2:Device)-[:TRIGGERED]->(other:Alert)
WHERE other.id <> $alert_id
RETURN
    other.id AS alert_id,
    other.title AS title,
    other.severity AS severity,
    other.category AS category,
    other.timestamp AS timestamp,
    other.status AS status,
    u.name AS via_user
LIMIT $limit
"""

FIND_RELATED_ALERTS_VIA_IP = """
MATCH (a:Alert {id: $alert_id})<-[:TRIGGERED]-(d:Device)-[:CONTACTED]->(ip:IPAddress)-[:ASSOCIATED_WITH]->(other:Alert)
WHERE other.id <> $alert_id
RETURN
    other.id AS alert_id,
    other.title AS title,
    other.severity AS severity,
    other.category AS category,
    other.timestamp AS timestamp,
    other.status AS status,
    ip.address AS via_ip,
    ip.reputation AS ip_reputation
LIMIT $limit
"""


# ─── Incident / Service Queries ──────────────────────────────────────────────

GET_AFFECTED_SERVICES = """
MATCH (inc:Incident {id: $incident_id})-[:AFFECTS]->(svc:Service)
RETURN
    svc.id AS service_id,
    svc.name AS name,
    svc.criticality AS criticality,
    svc.owner_team AS owner_team
"""

GET_INCIDENT_DETAILS = """
MATCH (inc:Incident {id: $incident_id})
OPTIONAL MATCH (a:Alert)-[:PART_OF]->(inc)
OPTIONAL MATCH (u:User)-[:INVOLVED_IN]->(inc)
OPTIONAL MATCH (inc)-[:AFFECTS]->(svc:Service)
RETURN
    inc.id AS incident_id,
    inc.title AS title,
    inc.severity AS severity,
    inc.status AS status,
    inc.created_at AS created_at,
    collect(DISTINCT a.id) AS alert_ids,
    collect(DISTINCT u.name) AS involved_users,
    collect(DISTINCT svc.name) AS affected_services
"""


# ─── Investigation Persistence ───────────────────────────────────────────────

SAVE_INVESTIGATION = """
MERGE (inv:Investigation {id: $inv_id})
SET inv.question = $question,
    inv.summary = $summary,
    inv.created_at = $created_at,
    inv.outcome = $outcome,
    inv.recommended_steps = $recommended_steps,
    inv.severity_assessment = $severity_assessment
RETURN inv.id
"""

LINK_INVESTIGATION_TO_ALERT = """
MATCH (inv:Investigation {id: $inv_id})
MATCH (a:Alert {id: $alert_id})
MERGE (inv)-[:EXAMINED]->(a)
"""

SAVE_EVIDENCE_NODE = """
MERGE (ev:Evidence {id: $ev_id})
SET ev.source_type = $source_type,
    ev.description = $description,
    ev.observed_at = $observed_at
RETURN ev.id
"""

LINK_INVESTIGATION_TO_EVIDENCE = """
MATCH (inv:Investigation {id: $inv_id})
MATCH (ev:Evidence {id: $ev_id})
MERGE (inv)-[:USED_EVIDENCE]->(ev)
"""

LINK_EVIDENCE_TO_INCIDENT = """
MATCH (ev:Evidence {id: $ev_id})
MATCH (inc:Incident {id: $inc_id})
MERGE (ev)-[:SUPPORTS]->(inc)
"""

GET_ALL_INVESTIGATIONS = """
MATCH (inv:Investigation)
RETURN
    inv.id AS id,
    inv.question AS question,
    inv.summary AS summary,
    inv.created_at AS created_at,
    inv.outcome AS outcome,
    inv.severity_assessment AS severity_assessment
ORDER BY inv.created_at DESC
LIMIT $limit
"""

GET_INVESTIGATION_BY_ID = """
MATCH (inv:Investigation {id: $inv_id})
OPTIONAL MATCH (inv)-[:EXAMINED]->(a:Alert)
OPTIONAL MATCH (inv)-[:USED_EVIDENCE]->(ev:Evidence)
RETURN
    inv.id AS id,
    inv.question AS question,
    inv.summary AS summary,
    inv.created_at AS created_at,
    inv.outcome AS outcome,
    inv.severity_assessment AS severity_assessment,
    inv.recommended_steps AS recommended_steps,
    collect(DISTINCT a.id) AS examined_alert_ids,
    collect(DISTINCT ev.id) AS evidence_ids
"""

GET_INVESTIGATIONS_FOR_ALERT = """
MATCH (inv:Investigation)-[:EXAMINED]->(a:Alert {id: $alert_id})
RETURN
    inv.id AS id,
    inv.question AS question,
    inv.summary AS summary,
    inv.created_at AS created_at,
    inv.outcome AS outcome
ORDER BY inv.created_at DESC
LIMIT 5
"""
