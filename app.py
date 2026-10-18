"""
GraphGuard — Main Streamlit Application Entry Point
Every alert has a story. Follow the graph to find it.

Run: streamlit run app.py
"""
import sys
import os

# Ensure graphguard/ is in the Python path
sys.path.insert(0, os.path.dirname(__file__))

import streamlit as st

# ── Page Configuration ──
st.set_page_config(
    page_title="GraphGuard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS — Dark cybersecurity theme ──
st.markdown("""
<style>
    /* Main background */
    .stApp {
        background-color: #0d0d1a;
        color: #c8d8e8;
    }

    /* Sidebar */
    section[data-testid="stSidebar"] {
        background-color: #0a0a14;
        border-right: 1px solid #1e2a4a;
    }

    /* Metric cards */
    div[data-testid="metric-container"] {
        background: #0d1b2a;
        border: 1px solid #1e3a5f;
        border-radius: 8px;
        padding: 12px;
    }

    /* Buttons — primary */
    .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #4a1a8f, #7b2fd4);
        color: white;
        border: 1px solid #9b4bf4;
        border-radius: 6px;
        font-weight: bold;
        letter-spacing: 0.5px;
    }
    .stButton > button[kind="primary"]:hover {
        background: linear-gradient(135deg, #5a2aaf, #9b4bf4);
    }

    /* Headers */
    h1, h2, h3 {
        color: #8ab4f8 !important;
    }

    /* Code blocks */
    code {
        background: #1a2a3a !important;
        color: #88ccff !important;
        padding: 2px 6px;
        border-radius: 4px;
    }

    /* Info/success/warning boxes */
    .stAlert {
        border-radius: 8px;
    }

    /* Selectbox */
    .stSelectbox > div > div {
        background-color: #0d1b2a;
        border-color: #1e3a5f;
        color: #c8d8e8;
    }

    /* Text input */
    .stTextInput > div > div > input,
    .stTextArea > div > div > textarea {
        background-color: #0d1b2a;
        border-color: #1e3a5f;
        color: #c8d8e8;
    }

    /* Tab bar */
    .stTabs [data-baseweb="tab-list"] {
        background-color: #0a0a14;
        border-bottom: 1px solid #1e2a4a;
    }
    .stTabs [data-baseweb="tab"] {
        color: #8a9ab8;
    }
    .stTabs [aria-selected="true"] {
        color: #8ab4f8 !important;
        border-bottom-color: #8ab4f8 !important;
    }

    /* Dividers */
    hr {
        border-color: #1e2a4a !important;
    }

    /* Expanders */
    details > summary {
        color: #8ab4f8;
    }

    /* Hide Streamlit branding */
    #MainMenu, footer { visibility: hidden; }
</style>
""", unsafe_allow_html=True)

import config
from database.connection import check_connection


# ── Session State Defaults ──
if "page" not in st.session_state:
    st.session_state["page"] = "Overview"
if "selected_alert" not in st.session_state:
    st.session_state["selected_alert"] = None
if "last_result" not in st.session_state:
    st.session_state["last_result"] = None


# ── Sidebar ──
with st.sidebar:
    # Logo + Tagline
    st.markdown(
        """
        <div style='text-align:center;padding:16px 0 8px 0'>
            <div style='font-size:2.5rem'>🛡️</div>
            <div style='font-size:1.4rem;font-weight:bold;color:#8ab4f8;letter-spacing:1px'>
                GraphGuard
            </div>
            <div style='font-size:0.75rem;color:#667799;font-style:italic;margin-top:4px'>
                Every alert has a story.<br>Follow the graph to find it.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("<hr style='border-color:#1e2a4a'>", unsafe_allow_html=True)

    # Navigation
    st.markdown("**Navigation**")
    pages = ["Overview", "Investigate", "Graph Explorer", "Investigation History"]
    for page in pages:
        icons = {
            "Overview": "📊",
            "Investigate": "🔍",
            "Graph Explorer": "🕸️",
            "Investigation History": "📁",
        }
        is_active = st.session_state["page"] == page
        btn_style = "primary" if is_active else "secondary"
        if st.button(f"{icons[page]} {page}", use_container_width=True, key=f"nav_{page}"):
            st.session_state["page"] = page
            st.rerun()

    st.markdown("<hr style='border-color:#1e2a4a'>", unsafe_allow_html=True)

    # Status Panel
    st.markdown("**System Status**")

    # FalkorDB status
    db_ok, db_msg = check_connection()
    if db_ok:
        st.markdown("🟢 **FalkorDB** Connected")
    else:
        st.markdown("🔴 **FalkorDB** Unavailable")
        with st.expander("How to start FalkorDB"):
            st.code("docker run -p 6379:6379 falkordb/falkordb", language="bash")

    # Gemini status
    if config.is_gemini_available():
        st.markdown(f"🟢 **Gemini** Ready ({config.GEMINI_MODEL})")
    else:
        st.markdown("🟡 **Gemini** Not configured")
        with st.expander("Configure Gemini"):
            st.write("Add to `.env`:")
            st.code("GOOGLE_API_KEY=your_key_here")
            st.write("Get key: [aistudio.google.com](https://aistudio.google.com/)")

    st.markdown("<hr style='border-color:#1e2a4a'>", unsafe_allow_html=True)

    # Demo Mode Controls
    st.markdown("**Demo Controls**")

    if st.button("🌱 Seed Demo Data", use_container_width=True, help="Load synthetic security scenarios into FalkorDB"):
        if db_ok:
            with st.spinner("Seeding demo graph..."):
                try:
                    from database.seed import run_seed
                    success = run_seed(verbose=False)
                    if success:
                        st.success("Demo data seeded!")
                        st.rerun()
                    else:
                        st.error("Seed failed — check DB connection")
                except Exception as exc:
                    st.error(f"Seed error: {exc}")
        else:
            st.error("FalkorDB not available")

    if st.button("🚀 Run Demo Investigation", use_container_width=True, help="Investigate alert A-104 automatically"):
        st.session_state["selected_alert"] = "A-104"
        st.session_state["investigation_question"] = (
            "Investigate alert A-104. Is this an isolated event, "
            "or is it connected to other suspicious activity?"
        )
        st.session_state["page"] = "Investigate"
        st.rerun()

    st.markdown("<hr style='border-color:#1e2a4a'>", unsafe_allow_html=True)
    st.caption("Graph Hacks 2026 | Track 1")
    st.caption("Synthetic data only — demo purposes")


# ── Main Content ──
current_page = st.session_state.get("page", "Overview")

if current_page == "Overview":
    from ui import overview
    overview.render()

elif current_page == "Investigate":
    from ui import investigate
    investigate.render()

elif current_page == "Graph Explorer":
    from ui import graph_explorer
    graph_explorer.render()

elif current_page == "Investigation History":
    from ui import history
    history.render()
