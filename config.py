"""
GraphGuard Configuration
Loads settings from environment variables (.env file via python-dotenv).
Never exposes secrets; provides safe defaults and clear error messages.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from the project root (graphguard/) or two levels up
_env_path = Path(__file__).parent / ".env"
if _env_path.exists():
    load_dotenv(_env_path)
else:
    load_dotenv()  # Try from cwd


#FalkorDB
FALKORDB_HOST: str = os.getenv("FALKORDB_HOST", "localhost")
FALKORDB_PORT: int = int(os.getenv("FALKORDB_PORT", "6379"))
FALKORDB_USERNAME: str | None = os.getenv("FALKORDB_USERNAME") or None
FALKORDB_PASSWORD: str | None = os.getenv("FALKORDB_PASSWORD") or None
FALKORDB_SSL: bool = os.getenv("FALKORDB_SSL", "false").lower() == "true"
GRAPH_NAME: str = os.getenv("GRAPHGUARD_GRAPH_NAME", "graphguard")

#  Gemini / Google AI
GOOGLE_API_KEY: str | None = os.getenv("GOOGLE_API_KEY")
GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")

# ─── Application ───────────────────────────────────────────────────────────

APP_TITLE: str = "GraphGuard"
APP_TAGLINE: str = "Every alert has a story. Follow the graph to find it."
DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"

# Maximum results for graph queries to keep UI responsive
MAX_QUERY_RESULTS: int = 50
MAX_HOPS: int = 3


def get_config_status() -> dict:
    """Return configuration status without exposing secret values."""
    return {
        "falkordb_host": FALKORDB_HOST,
        "falkordb_port": FALKORDB_PORT,
        "falkordb_ssl": FALKORDB_SSL,
        "falkordb_auth_configured": bool(FALKORDB_USERNAME or FALKORDB_PASSWORD),
        "graph_name": GRAPH_NAME,
        "google_api_key_configured": bool(GOOGLE_API_KEY and GOOGLE_API_KEY != "your_google_api_key_here"),
        "gemini_model": GEMINI_MODEL,
    }


def is_gemini_available() -> bool:
    """Return True if Gemini is configured with a real API key."""
    return bool(
        GOOGLE_API_KEY
        and GOOGLE_API_KEY != "your_google_api_key_here"
        and len(GOOGLE_API_KEY) > 10
    )
