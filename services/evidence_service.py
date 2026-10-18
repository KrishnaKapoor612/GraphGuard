"""
Evidence Service — thin wrapper for retrieving and formatting evidence records.
"""
from __future__ import annotations
import logging

from database.connection import get_graph
from database import queries

logger = logging.getLogger(__name__)


def get_evidence_for_investigation(inv_id: str) -> list[dict]:
    """Return all evidence nodes linked to an investigation."""
    try:
        g = get_graph()
        rows = g.query(
            """
            MATCH (inv:Investigation {id: $inv_id})-[:USED_EVIDENCE]->(ev:Evidence)
            RETURN ev.id, ev.source_type, ev.description, ev.observed_at
            """,
            {"inv_id": inv_id},
        ).result_set or []
        keys = ["id", "source_type", "description", "observed_at"]
        return [dict(zip(keys, row)) for row in rows]
    except Exception as exc:
        logger.error("Failed to get evidence for %s: %s", inv_id, exc)
        return []
