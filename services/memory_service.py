"""
Memory Service — persistent investigation storage in FalkorDB.
Saves and retrieves investigation records so the agent remembers across sessions.
"""
from __future__ import annotations
import uuid
import logging
from datetime import datetime, timezone
from typing import Any

from database.connection import get_graph
from database import queries

logger = logging.getLogger(__name__)


def save_investigation(
    question: str,
    summary: str,
    outcome: str,
    severity_assessment: str,
    recommended_steps: list[str],
    examined_alert_id: str | None = None,
    evidence_descriptions: list[dict] | None = None,
    incident_id: str | None = None,
) -> str:
    """
    Persist an investigation to FalkorDB.
    Returns the investigation ID.
    Uses MERGE on a stable ID derived from question+alert to prevent duplicates.
    """
    g = get_graph()

    # Stable ID: hash of question + alert_id to prevent duplicate investigations
    import hashlib
    hash_input = f"{question}:{examined_alert_id or ''}"
    inv_id = "INV-" + hashlib.md5(hash_input.encode()).hexdigest()[:8].upper()

    created_at = datetime.now(timezone.utc).isoformat()
    steps_str = " | ".join(recommended_steps) if recommended_steps else ""

    # Save the Investigation node (MERGE is idempotent)
    g.query(queries.SAVE_INVESTIGATION, {
        "inv_id": inv_id,
        "question": question,
        "summary": summary,
        "created_at": created_at,
        "outcome": outcome,
        "recommended_steps": steps_str,
        "severity_assessment": severity_assessment,
    })
    logger.info("Saved investigation %s", inv_id)

    # Link to the alert that was examined
    if examined_alert_id:
        try:
            g.query(queries.LINK_INVESTIGATION_TO_ALERT, {
                "inv_id": inv_id,
                "alert_id": examined_alert_id,
            })
        except Exception as exc:
            logger.warning("Could not link investigation to alert %s: %s", examined_alert_id, exc)

    # Save evidence nodes and link them
    if evidence_descriptions:
        for i, ev_data in enumerate(evidence_descriptions[:10]):  # cap at 10
            ev_id = f"{inv_id}-EV-{i+1:02d}"
            try:
                g.query(queries.SAVE_EVIDENCE_NODE, {
                    "ev_id": ev_id,
                    "source_type": ev_data.get("source_type", "investigation"),
                    "description": ev_data.get("description", "")[:500],
                    "observed_at": ev_data.get("observed_at", created_at),
                })
                g.query(queries.LINK_INVESTIGATION_TO_EVIDENCE, {
                    "inv_id": inv_id,
                    "ev_id": ev_id,
                })
                if incident_id:
                    g.query(queries.LINK_EVIDENCE_TO_INCIDENT, {
                        "ev_id": ev_id,
                        "inc_id": incident_id,
                    })
            except Exception as exc:
                logger.warning("Could not save evidence %s: %s", ev_id, exc)

    return inv_id


def get_all_investigations(limit: int = 20) -> list[dict]:
    """Retrieve all investigations from FalkorDB, ordered newest first."""
    try:
        g = get_graph()
        rows = g.query(queries.GET_ALL_INVESTIGATIONS, {"limit": limit}).result_set or []
        keys = ["id", "question", "summary", "created_at", "outcome", "severity_assessment"]
        return [dict(zip(keys, row)) for row in rows]
    except Exception as exc:
        logger.error("Failed to retrieve investigations: %s", exc)
        return []


def get_investigation_by_id(inv_id: str) -> dict | None:
    """Retrieve a single investigation with its linked alerts and evidence."""
    try:
        g = get_graph()
        rows = g.query(queries.GET_INVESTIGATION_BY_ID, {"inv_id": inv_id}).result_set or []
        if not rows:
            return None
        row = rows[0]
        keys = [
            "id", "question", "summary", "created_at", "outcome",
            "severity_assessment", "recommended_steps",
            "examined_alert_ids", "evidence_ids",
        ]
        result = dict(zip(keys, row))
        # Deserialize recommended_steps
        if result.get("recommended_steps"):
            result["recommended_steps_list"] = [
                s.strip() for s in result["recommended_steps"].split("|") if s.strip()
            ]
        return result
    except Exception as exc:
        logger.error("Failed to get investigation %s: %s", inv_id, exc)
        return None


def get_investigations_for_alert(alert_id: str) -> list[dict]:
    """Return prior investigations that examined a specific alert."""
    try:
        g = get_graph()
        rows = g.query(queries.GET_INVESTIGATIONS_FOR_ALERT, {"alert_id": alert_id}).result_set or []
        keys = ["id", "question", "summary", "created_at", "outcome"]
        return [dict(zip(keys, row)) for row in rows]
    except Exception as exc:
        logger.error("Failed to get investigations for alert %s: %s", alert_id, exc)
        return []
