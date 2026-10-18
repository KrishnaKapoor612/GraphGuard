"""
Overview page — real metrics from FalkorDB + recent alerts + demo shortcuts.
"""
import streamlit as st
from database.connection import check_connection
from services.graph_service import get_database_stats, list_alerts


SEVERITY_COLORS = {
    "critical": "#FF4444",
    "high": "#FF8C00",
    "medium": "#FFD700",
    "low": "#4CAF50",
    "unknown": "#888888",
}

STATUS_COLORS = {
    "open": "#FF4444",
    "investigating": "#FF8C00",
    "resolved": "#4CAF50",
    "false_positive": "#888888",
}


def render():
    st.markdown("## 🛡️ Security Operations Overview")
    st.markdown("*Real-time metrics from the GraphGuard graph database*")

    # ── Connection Status ──
    conn_ok, conn_msg = check_connection()
    if conn_ok:
        st.success(f"✅ FalkorDB Connected — {conn_msg}")
    else:
        st.error(f"❌ FalkorDB Unavailable — {conn_msg}")
        st.info("Start FalkorDB: `docker run -p 6379:6379 falkordb/falkordb`")
        return

    # ── Live Stats ──
    try:
        stats = get_database_stats()

        col1, col2, col3, col4, col5 = st.columns(5)
        with col1:
            st.metric("📊 Graph Nodes", stats["total_nodes"])
        with col2:
            st.metric("🔗 Relationships", stats["total_relationships"])
        with col3:
            st.metric(
                "🚨 Alerts",
                stats["alert_count"],
            )
        with col4:
            st.metric(
                "🔥 Open Incidents",
                stats["open_incident_count"],
                delta=None,
            )
        with col5:
            st.metric("🔍 Investigations", stats["investigation_count"])

        st.markdown("---")

        # ── Entity Breakdown ──
        col_a, col_b = st.columns(2)
        with col_a:
            st.markdown("#### Entity Counts")
            entity_data = {
                "👤 Users": stats["user_count"],
                "💻 Devices": stats["device_count"],
                "🌐 IP Addresses": stats["ip_count"],
                "⚙️ Services": stats["service_count"],
            }
            for label, count in entity_data.items():
                col_label, col_count = st.columns([3, 1])
                with col_label:
                    st.write(label)
                with col_count:
                    st.write(f"**{count}**")

        with col_b:
            st.markdown("#### Demo Scenarios")
            st.info(
                "**Scenario A — Suspicious (Alert A-104)**\n"
                "Marcus Chen → WORKSTATION-07 → Tor Exit Node → INC-001\n"
                "→ Payment Service at risk (4-hop discovery)"
            )
            st.success(
                "**Scenario B — Benign (Alert A-201)**\n"
                "Alice Thompson → LAPTOP-22 → Google DNS\n"
                "→ False positive — no incident"
            )

    except Exception as exc:
        st.error(f"Could not retrieve graph statistics: {exc}")
        return

    st.markdown("---")

    # ── Recent Alerts ──
    st.markdown("#### Recent Alerts")
    try:
        alerts = list_alerts(limit=10)
        if not alerts:
            st.info("No alerts found. Run the seed script to populate demo data.")
        else:
            for alert in alerts:
                sev = alert.get("severity", "unknown").lower()
                sev_color = SEVERITY_COLORS.get(sev, "#888888")
                status = alert.get("status", "")
                status_color = STATUS_COLORS.get(status, "#888888")

                with st.container():
                    col_sev, col_id, col_title, col_status, col_action = st.columns([1, 1, 5, 1.5, 1.5])
                    with col_sev:
                        st.markdown(
                            f"<span style='background-color:{sev_color};color:white;padding:2px 6px;"
                            f"border-radius:4px;font-size:0.75rem;font-weight:bold'>{sev.upper()}</span>",
                            unsafe_allow_html=True,
                        )
                    with col_id:
                        st.write(f"`{alert.get('id','')}`")
                    with col_title:
                        st.write(alert.get("title", "")[:60])
                    with col_status:
                        st.markdown(
                            f"<span style='color:{status_color};font-size:0.8rem'>{status}</span>",
                            unsafe_allow_html=True,
                        )
                    with col_action:
                        if st.button("Investigate →", key=f"inv_{alert['id']}"):
                            st.session_state["selected_alert"] = alert["id"]
                            st.session_state["page"] = "Investigate"
                            st.rerun()

    except Exception as exc:
        st.error(f"Could not load alerts: {exc}")

    st.markdown("---")
    st.caption("GraphGuard Demo — Synthetic data only. No real security data.")
