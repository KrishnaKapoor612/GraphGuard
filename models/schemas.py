"""
Pydantic schemas for GraphGuard data models.
These represent the structured data returned from graph queries and agent output.
"""
from __future__ import annotations
from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field


# ─── Graph Entity Models ────────────────────────────────────────────────────

class UserNode(BaseModel):
    id: str
    name: str
    department: str
    role: str
    risk_level: str  # low | medium | high | critical


class DeviceNode(BaseModel):
    id: str
    hostname: str
    device_type: str
    status: str
    last_seen: str


class IPAddressNode(BaseModel):
    id: str
    address: str
    reputation: str  # clean | suspicious | malicious | unknown
    country: str


class AlertNode(BaseModel):
    id: str
    title: str
    severity: str  # low | medium | high | critical
    category: str
    timestamp: str
    status: str  # open | investigating | resolved | false_positive
    description: str


class IncidentNode(BaseModel):
    id: str
    title: str
    severity: str
    status: str
    created_at: str


class ServiceNode(BaseModel):
    id: str
    name: str
    criticality: str  # low | medium | high | critical
    owner_team: str


class InvestigationNode(BaseModel):
    id: str
    question: str
    summary: str
    created_at: str
    outcome: str  # confirmed_threat | likely_benign | inconclusive | under_investigation


class EvidenceNode(BaseModel):
    id: str
    source_type: str  # alert | device | user | ip_address | network_log
    description: str
    observed_at: str


# ─── Investigation Result Model ─────────────────────────────────────────────

class GraphPath(BaseModel):
    """A traced path through the graph showing how entities connect."""
    path_description: str
    entities: list[dict[str, Any]] = Field(default_factory=list)
    relationships: list[str] = Field(default_factory=list)
    hop_count: int = 0


class EvidenceRecord(BaseModel):
    """A piece of evidence retrieved from the graph."""
    evidence_id: str
    source_type: str
    description: str
    observed_at: str
    entity_type: str  # the node type this came from
    entity_id: str
    is_inferred: bool = False  # True if AI-interpreted, False if directly queried


class InvestigationResult(BaseModel):
    """Full structured output from an investigation."""
    investigation_id: str
    investigation_summary: str
    severity_assessment: str  # low | medium | high | critical | unknown
    confirmed_facts: list[str] = Field(default_factory=list)
    supporting_evidence: list[EvidenceRecord] = Field(default_factory=list)
    graph_paths: list[GraphPath] = Field(default_factory=list)
    related_alerts: list[dict[str, Any]] = Field(default_factory=list)
    potentially_affected_services: list[dict[str, Any]] = Field(default_factory=list)
    inferences: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    is_demo_fallback: bool = False  # True if Gemini was unavailable
    raw_graph_data: dict[str, Any] = Field(default_factory=dict)


class AlertSummary(BaseModel):
    """Lightweight summary for listing alerts."""
    id: str
    title: str
    severity: str
    category: str
    timestamp: str
    status: str


class DatabaseStats(BaseModel):
    """Metrics derived from real database queries."""
    total_nodes: int = 0
    total_relationships: int = 0
    alert_count: int = 0
    open_incident_count: int = 0
    investigation_count: int = 0
    user_count: int = 0
    device_count: int = 0
    ip_count: int = 0
    service_count: int = 0
