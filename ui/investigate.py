"""
Investigation workspace — main investigation UI.
"""
from __future__ import annotations
import streamlit as st
from services.graph_service import list_alerts
from services.agent_service import run_agent_investigation
from services.memory_service import get_investigations_for_alert
from models.schemas import InvestigationResult
import config


SEVERITY_COLORS = {
    "critical": "#FF4444",
    "high": "#FF8C00",
    "medium": "#FFD700",
    "low": "#4CAF50",
    "unknown": "#888888",
}

EXAMPLE_QUESTIONS = [
    "Investigate alert A-104. Is this an isolated event or connected to other suspicious activity?",
    "What devices are involved in incident INC-001 and what services are at risk?",
    "Is there a pattern connecting the alerts triggered by WORKSTATION-07?",
    "What did we find when we investigated alert A-104 previously?",
    "Is alert A-201 a false positive or part of a larger attack?",
]


def render():
    st.markdown("## 🔍 Investigation Workspace")

    # ── Gemini Status Banner ──
    if not config.is_gemini_available():
        st.warning(
            "⚠️ **Demo Mode** — Gemini API key not configured. "
            "Graph queries are fully functional. AI narrative will be templated. "
            "Add `GOOGLE_API_KEY` to `.env` to enable live AI synthesis.",
            icon="🤖",
        )
    else:
        st.success(f"✅ Gemini ready ({config.GEMINI_MODEL})", icon="🤖")

    st.markdown("---")

    # ── Alert Selector + Question Input ──
    col_left, col_right = st.columns([1, 2])

    with col_left:
        st.markdown("#### Select Alert")
        try:
            alerts = list_alerts(limit=20)
            alert_options = {
                f"{a['id']} — {a['title'][:45]}": a["id"]
                for a in alerts
            }
        except Exception:
            alert_options = {}
            st.warning("Could not load alerts from graph.")

        # Pre-select if navigated from overview
        default_alert_idx = 0
        preselected = st.session_state.get("selected_alert")
        if preselected and alert_options:
            keys = list(alert_options.keys())
            for i, k in enumerate(keys):
                if alert_options[k] == preselected:
                    default_alert_idx = i
                    break

        selected_key = st.selectbox(
            "Alert",
            options=list(alert_options.keys()),
            index=default_alert_idx,
            label_visibility="collapsed",
        )
        selected_alert_id = alert_options.get(selected_key, "") if alert_options else ""

        if selected_alert_id:
            # Show quick alert info
            try:
                from services.graph_service import get_alert_details
                alert_info = get_alert_details(selected_alert_id)
                if alert_info:
                    sev = alert_info.get("alert_severity", "unknown").lower()
                    color = SEVERITY_COLORS.get(sev, "#888888")
                    st.markdown(
                        f"<div style='background:#1a1a2e;border:1px solid {color};"
                        f"border-radius:8px;padding:10px;margin-top:8px'>"
                        f"<b style='color:{color}'>{sev.upper()}</b> | {alert_info.get('alert_category','')}<br>"
                        f"<small style='color:#aaa'>{alert_info.get('alert_timestamp','')[:16]}</small><br>"
                        f"<small>{alert_info.get('alert_description','')[:120]}...</small>"
                        f"</div>",
                        unsafe_allow_html=True,
                    )
            except Exception:
                pass

            # Prior investigations for this alert
            try:
                prior = get_investigations_for_alert(selected_alert_id)
                if prior:
                    st.markdown(f"**{len(prior)} prior investigation(s)** for this alert")
                    with st.expander("View prior investigations"):
                        for p in prior:
                            st.write(f"**{p['id']}** — {p['outcome']}")
                            st.caption(p.get("summary", "")[:100])
            except Exception:
                pass

    with col_right:
        st.markdown("#### Investigation Question")
        question = st.text_area(
            "Question",
            value=st.session_state.get("investigation_question",
                  "Investigate alert A-104. Is this an isolated event, or is it connected to other suspicious activity?"),
            height=100,
            label_visibility="collapsed",
        )
        st.session_state["investigation_question"] = question

        st.markdown("**Example questions:**")
        for eq in EXAMPLE_QUESTIONS:
            if st.button(f"→ {eq[:70]}", key=f"eq_{hash(eq)}"):
                st.session_state["investigation_question"] = eq
                # Parse alert_id from question
                import re
                match = re.search(r'\bA-\d+\b', eq)
                if match and alert_options:
                    for k, v in alert_options.items():
                        if v == match.group():
                            st.session_state["selected_alert"] = v
                st.rerun()

    # ── Investigate Button ──
    st.markdown("---")
    col_btn, col_info = st.columns([1, 3])
    with col_btn:
        run_btn = st.button(
            "🔍 Investigate",
            type="primary",
            disabled=not selected_alert_id,
        )
    with col_info:
        st.caption(
            "The agent will follow graph relationships across up to 4 hops to find connected evidence."
        )

    # ── Run Investigation ──
    if run_btn and selected_alert_id:
        with st.spinner("🔄 Agent running graph traversal..."):
            try:
                result = run_agent_investigation(
                    question=question or f"Investigate alert {selected_alert_id}",
                    alert_id=selected_alert_id,
                )
                st.session_state["last_result"] = result
                st.session_state["last_alert_id"] = selected_alert_id
            except Exception as exc:
                st.error(f"Investigation failed: {exc}")
                return

    # ── Display Results ──
    result: InvestigationResult | None = st.session_state.get("last_result")
    if result:
        _render_result(result)


def _render_result(result: InvestigationResult):
    if result.is_demo_fallback:
        st.info("📊 **Graph-mode results** — AI narrative is templated from actual graph data. Add GOOGLE_API_KEY for live AI synthesis.", icon="ℹ️")

    st.markdown("---")
    st.markdown(f"### Investigation `{result.investigation_id}`")

    # ── Severity + Summary ──
    sev = result.severity_assessment.lower()
    sev_color = SEVERITY_COLORS.get(sev, "#888888")
    col_sum, col_sev = st.columns([4, 1])
    with col_sev:
        st.markdown(
            f"<div style='background:{sev_color};color:white;text-align:center;"
            f"padding:12px;border-radius:8px;font-weight:bold;font-size:1.1rem'>"
            f"SEVERITY<br>{sev.upper()}</div>",
            unsafe_allow_html=True,
        )
    with col_sum:
        st.markdown(f"**Investigation Summary**")
        st.markdown(
            f"<div style='background:#1a1a2e;border-left:4px solid {sev_color};"
            f"padding:12px;border-radius:0 8px 8px 0;line-height:1.6'>"
            f"{result.investigation_summary}</div>",
            unsafe_allow_html=True,
        )

    st.markdown("---")

    # ── Two column layout for facts + evidence ──
    col_facts, col_evidence = st.columns([1, 1])

    with col_facts:
        if result.confirmed_facts:
            st.markdown("#### ✅ Confirmed Facts")
            st.caption("Directly retrieved from graph database queries")
            for fact in result.confirmed_facts:
                st.markdown(
                    f"<div style='background:#0d1b2a;border:1px solid #1e3a5f;"
                    f"border-radius:6px;padding:8px;margin-bottom:4px;font-size:0.85rem'>"
                    f"• {fact}</div>",
                    unsafe_allow_html=True,
                )

        if result.inferences:
            st.markdown("#### 🔶 Inferences")
            st.caption("AI interpretation — not directly observed in graph")
            for inf in result.inferences:
                st.markdown(
                    f"<div style='background:#1a1000;border:1px solid #5a3000;"
                    f"border-radius:6px;padding:8px;margin-bottom:4px;font-size:0.85rem'>"
                    f"{inf}</div>",
                    unsafe_allow_html=True,
                )

        if result.unknowns:
            st.markdown("#### ❓ Unknowns")
            st.caption("What the graph does not yet reveal")
            for unk in result.unknowns:
                st.markdown(
                    f"<div style='background:#0a0a0a;border:1px solid #333;"
                    f"border-radius:6px;padding:8px;margin-bottom:4px;font-size:0.85rem;color:#aaa'>"
                    f"• {unk}</div>",
                    unsafe_allow_html=True,
                )

    with col_evidence:
        if result.supporting_evidence:
            st.markdown("#### 📋 Supporting Evidence")
            st.caption("Evidence records with source entity references")
            for ev in result.supporting_evidence:
                badge = "🔵 DB Fact" if not ev.is_inferred else "🟡 Inferred"
                st.markdown(
                    f"<div style='background:#0d1b2a;border:1px solid #1e4a6f;"
                    f"border-radius:6px;padding:10px;margin-bottom:6px'>"
                    f"<b>{badge}</b> <code>{ev.evidence_id}</code><br>"
                    f"<small style='color:#8ab4f8'>{ev.entity_type} [{ev.entity_id}]</small><br>"
                    f"<small>{ev.description}</small>"
                    f"</div>",
                    unsafe_allow_html=True,
                )

        if result.potentially_affected_services:
            st.markdown("#### ⚠️ Potentially Affected Services")
            for svc in result.potentially_affected_services:
                crit = svc.get("criticality", "unknown")
                crit_color = SEVERITY_COLORS.get(crit, "#888")
                st.markdown(
                    f"<div style='background:#1a0505;border:1px solid {crit_color};"
                    f"border-radius:6px;padding:8px;margin-bottom:4px'>"
                    f"<b>{svc.get('name','')}</b> "
                    f"<span style='color:{crit_color}'>[{crit.upper()}]</span><br>"
                    f"<small>Owner: {svc.get('owner_team','')}</small>"
                    f"</div>",
                    unsafe_allow_html=True,
                )

    st.markdown("---")

    # ── Graph Path ──
    if result.graph_paths:
        st.markdown("#### 🕸️ Graph Evidence Path")
        st.caption("Multi-hop traversal path discovered by querying FalkorDB")
        for path in result.graph_paths:
            st.markdown(
                f"<div style='background:#0a0a1a;border:1px solid #4a4a8f;"
                f"border-radius:8px;padding:14px;font-family:monospace;font-size:0.85rem;"
                f"line-height:2.0;white-space:pre-wrap'>"
                f"Hops: {path.hop_count}\n\n{path.path_description}"
                f"</div>",
                unsafe_allow_html=True,
            )

    # ── Related Alerts ──
    if result.related_alerts:
        st.markdown("#### 🔗 Related Alerts (discovered via graph)")
        st.caption("These alerts were NOT returned by a direct alert lookup — they were discovered through graph relationships")
        cols = st.columns(min(len(result.related_alerts), 3))
        for i, alert in enumerate(result.related_alerts[:6]):
            with cols[i % 3]:
                sev = alert.get("severity", "unknown").lower()
                color = SEVERITY_COLORS.get(sev, "#888")
                connection = alert.get("via_device") or alert.get("via_ip") or alert.get("via_user") or "graph"
                st.markdown(
                    f"<div style='background:#0d1b2a;border:1px solid {color};"
                    f"border-radius:6px;padding:10px;margin-bottom:6px'>"
                    f"<b style='color:{color}'>{sev.upper()}</b> "
                    f"<code>{alert.get('alert_id','')}</code><br>"
                    f"<small>{alert.get('title','')[:50]}</small><br>"
                    f"<small style='color:#8ab4f8'>via: {connection}</small>"
                    f"</div>",
                    unsafe_allow_html=True,
                )

    # ── Recommended Next Steps ──
    if result.recommended_next_steps:
        st.markdown("#### 🛡️ Recommended Next Steps")
        st.caption("⚠️ All actions require human review and approval before execution")
        for i, step in enumerate(result.recommended_next_steps, 1):
            col_num, col_step = st.columns([0.2, 5])
            with col_num:
                st.markdown(f"**{i}.**")
            with col_step:
                st.markdown(step)

    # ── Graph Explorer Link ──
    st.markdown("---")
    if st.button("📊 View in Graph Explorer →", type="secondary"):
        st.session_state["graph_alert_id"] = st.session_state.get("last_alert_id")
        st.session_state["page"] = "Graph Explorer"
        st.rerun()
