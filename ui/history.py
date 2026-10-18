"""
Investigation History — retrieve and display past investigations from FalkorDB.
Demonstrates cross-session persistent memory.
"""
from __future__ import annotations
import streamlit as st
from services.memory_service import get_all_investigations, get_investigation_by_id


SEVERITY_COLORS = {
    "critical": "#FF4444",
    "high": "#FF8C00",
    "medium": "#FFD700",
    "low": "#4CAF50",
    "unknown": "#888888",
}

OUTCOME_COLORS = {
    "confirmed_threat": "#FF4444",
    "likely_benign": "#4CAF50",
    "inconclusive": "#FFD700",
    "under_investigation": "#FF8C00",
}


def render():
    st.markdown("## 📁 Investigation History")
    st.markdown(
        "*Previous investigations are retrieved from FalkorDB — not from in-memory chat history. "
        "This demonstrates persistent graph-based memory across sessions.*"
    )

    # ── Follow-up Question Demo ──
    with st.expander("💡 Follow-up Question Demo", expanded=False):
        st.markdown(
            "**Ask:** *\"What did we find when we investigated alert A-104 earlier?\"*\n\n"
            "The application retrieves the saved investigation from FalkorDB using graph queries, "
            "demonstrating that context persists across browser sessions and application restarts."
        )
        followup = st.text_input(
            "Follow-up question",
            value="What did we find when we investigated alert A-104 earlier?",
        )
        if st.button("Retrieve from Graph Memory"):
            import re
            alert_match = re.search(r'\bA-\d+\b', followup)
            if alert_match:
                alert_id = alert_match.group()
                try:
                    from services.memory_service import get_investigations_for_alert
                    prior = get_investigations_for_alert(alert_id)
                    if prior:
                        st.success(f"Found {len(prior)} investigation(s) for alert {alert_id} in FalkorDB")
                        for p in prior:
                            st.markdown(f"**{p['id']}** ({p.get('outcome','')}) — {p.get('created_at','')[:16]}")
                            st.write(p.get("summary", "")[:300])
                    else:
                        st.info(f"No prior investigations found for alert {alert_id}. Run an investigation first.")
                except Exception as exc:
                    st.error(f"Could not retrieve from graph: {exc}")

    st.markdown("---")

    # ── Load All Investigations ──
    try:
        investigations = get_all_investigations(limit=20)
    except Exception as exc:
        st.error(f"Could not load investigation history: {exc}")
        st.info("Make sure FalkorDB is running and demo data is seeded.")
        return

    if not investigations:
        st.info(
            "No investigations saved yet. Go to the **Investigate** tab, "
            "select an alert, and run an investigation."
        )
        return

    st.markdown(f"**{len(investigations)} investigation(s) found in FalkorDB**")

    # ── Investigation List ──
    for inv in investigations:
        sev = inv.get("severity_assessment", "unknown").lower()
        sev_color = SEVERITY_COLORS.get(sev, "#888")
        outcome = inv.get("outcome", "unknown")
        outcome_color = OUTCOME_COLORS.get(outcome, "#888")

        with st.container():
            col_meta, col_summary, col_action = st.columns([1.5, 4, 1])

            with col_meta:
                st.markdown(
                    f"<div style='background:#0d1b2a;border:1px solid #1e3a5f;"
                    f"border-radius:6px;padding:8px'>"
                    f"<code style='font-size:0.8rem'>{inv.get('id','')}</code><br>"
                    f"<small style='color:#aaa'>{(inv.get('created_at','') or '')[:16]}</small><br>"
                    f"<span style='background:{sev_color};color:white;padding:1px 5px;"
                    f"border-radius:3px;font-size:0.7rem'>{sev.upper()}</span> "
                    f"<span style='color:{outcome_color};font-size:0.75rem'>{outcome}</span>"
                    f"</div>",
                    unsafe_allow_html=True,
                )

            with col_summary:
                q = inv.get("question", "")
                s = inv.get("summary", "")
                st.markdown(f"**Q:** {q[:80]}")
                st.caption(s[:150] + ("..." if len(s) > 150 else ""))

            with col_action:
                if st.button("Open →", key=f"open_{inv['id']}"):
                    st.session_state["open_investigation_id"] = inv["id"]

        st.markdown("<hr style='border-color:#1e3a5f;margin:4px 0'>", unsafe_allow_html=True)

    # ── Investigation Detail View ──
    open_id = st.session_state.get("open_investigation_id")
    if open_id:
        st.markdown("---")
        st.markdown(f"### Investigation Detail: `{open_id}`")

        try:
            detail = get_investigation_by_id(open_id)
            if not detail:
                st.warning(f"Investigation {open_id} not found in graph.")
            else:
                col_a, col_b = st.columns(2)
                with col_a:
                    st.markdown("**Question asked:**")
                    st.write(detail.get("question", "N/A"))
                    st.markdown("**Created at:**")
                    st.write((detail.get("created_at") or "")[:19])
                    st.markdown("**Outcome:**")
                    outcome = detail.get("outcome", "unknown")
                    oc = OUTCOME_COLORS.get(outcome, "#888")
                    st.markdown(
                        f"<span style='color:{oc};font-weight:bold'>{outcome}</span>",
                        unsafe_allow_html=True,
                    )

                with col_b:
                    st.markdown("**Severity Assessment:**")
                    sev = detail.get("severity_assessment", "unknown")
                    sc = SEVERITY_COLORS.get(sev, "#888")
                    st.markdown(
                        f"<span style='color:{sc};font-weight:bold'>{sev.upper()}</span>",
                        unsafe_allow_html=True,
                    )
                    alerts_examined = detail.get("examined_alert_ids") or []
                    if alerts_examined:
                        st.markdown(f"**Alerts examined:** {', '.join(str(a) for a in alerts_examined if a)}")
                    evs = detail.get("evidence_ids") or []
                    if evs:
                        st.markdown(f"**Evidence records:** {len([e for e in evs if e])}")

                st.markdown("**Summary:**")
                st.info(detail.get("summary", "No summary available"))

                steps_raw = detail.get("recommended_steps") or ""
                if steps_raw:
                    st.markdown("**Recommended Next Steps:**")
                    steps = [s.strip() for s in steps_raw.split("|") if s.strip()]
                    for i, step in enumerate(steps, 1):
                        st.write(f"{i}. {step}")

        except Exception as exc:
            st.error(f"Could not load investigation detail: {exc}")

        if st.button("Close detail view"):
            del st.session_state["open_investigation_id"]
            st.rerun()
