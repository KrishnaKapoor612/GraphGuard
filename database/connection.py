"""
FalkorDB connection management.
Provides a cached singleton connection and graceful error handling.
"""
from __future__ import annotations
import logging
from typing import Optional

logger = logging.getLogger(__name__)

_db_instance = None
_graph_instance = None


def get_db():
    """
    Return a FalkorDB connection instance (cached).
    Raises ConnectionError with a clear message if the database is unavailable.
    """
    global _db_instance
    if _db_instance is not None:
        return _db_instance

    try:
        from falkordb import FalkorDB
        import config

        kwargs: dict = {
            "host": config.FALKORDB_HOST,
            "port": config.FALKORDB_PORT,
        }
        if config.FALKORDB_USERNAME:
            kwargs["username"] = config.FALKORDB_USERNAME
        if config.FALKORDB_PASSWORD:
            kwargs["password"] = config.FALKORDB_PASSWORD
        # Note: FalkorDB Python client uses ssl parameter if supported
        # We omit ssl by default for local dev

        _db_instance = FalkorDB(**kwargs)
        logger.info(
            "Connected to FalkorDB at %s:%s",
            config.FALKORDB_HOST,
            config.FALKORDB_PORT,
        )
        return _db_instance

    except ImportError:
        raise ConnectionError(
            "FalkorDB Python client not installed. Run: pip install falkordb"
        )
    except Exception as exc:
        raise ConnectionError(
            f"Cannot connect to FalkorDB at {config.FALKORDB_HOST}:{config.FALKORDB_PORT}. "
            f"Ensure FalkorDB is running (e.g. `docker run -p 6379:6379 falkordb/falkordb`). "
            f"Original error: {exc}"
        ) from exc


def get_graph():
    """Return the graph object for the configured graph name."""
    global _graph_instance
    if _graph_instance is not None:
        return _graph_instance

    import config
    db = get_db()
    _graph_instance = db.select_graph(config.GRAPH_NAME)
    return _graph_instance


def reset_connection():
    """Clear cached connection (useful for testing)."""
    global _db_instance, _graph_instance
    _db_instance = None
    _graph_instance = None


def check_connection() -> tuple[bool, str]:
    """
    Test the database connection.
    Returns (success: bool, message: str).
    """
    try:
        graph = get_graph()
        # Lightweight ping: count nodes
        result = graph.query("MATCH (n) RETURN count(n) AS cnt")
        cnt = result.result_set[0][0] if result.result_set else 0
        return True, f"Connected - {cnt} nodes in graph"
    except ConnectionError as exc:
        return False, str(exc)
    except Exception as exc:
        return False, f"Unexpected error: {exc}"
