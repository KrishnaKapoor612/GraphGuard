"""
Graph Explorer — interactive visualization of the investigation subgraph.
Uses Plotly for the network graph (avoids PyVis iframe issues with Streamlit).
"""
from __future__ import annotations
import streamlit as st
import plotly.graph_objects as go
import math
from services.graph_service import get_all_graph_data_for_visualization, list_alerts


NODE_COLORS = {
    "Alert": "#FF4444",
    "Device": "#4A9EFF",
    "User": "#A855F7",
    "IPAddress": "#FF8C00",
    "Incident": "#FF1493",
    "Service": "#00BCD4",
    "Investigation": "#4CAF50",
    "Evidence": "#FFD700",
}

NODE_SYMBOLS = {
    "Alert": "triangle-up",
    "Device": "square",
    "User": "circle",
    "IPAddress": "diamond",
    "Incident": "star",
    "Service": "hexagon",
    "Investigation": "cross",
    "Evidence": "pentagon",
}


def _layout_nodes(nodes: list, edges: list) -> dict[str, tuple[float, float]]:
    """Simple circular force-directed layout."""
    if not nodes:
        return {}

    positions: dict[str, tuple[float, float]] = {}
    n = len(nodes)

    # Group by label for concentric layout
    by_label: dict[str, list] = {}
    for node in nodes:
        label = node.get("label", "Unknown")
        by_label.setdefault(label, []).append(node["id"])

    label_order = ["User", "Device", "IPAddress", "Alert", "Incident", "Service"]
    radius = 1.0
    for label in label_order + [l for l in by_label if l not in label_order]:
        node_ids = by_label.get(label, [])
        if not node_ids:
            continue
        for i, nid in enumerate(node_ids):
            angle = (2 * math.pi * i / max(len(node_ids), 1)) + (label_order.index(label) * 0.5 if label in label_order else 0)
            r = radius + label_order.index(label) * 0.4 if label in label_order else radius + 2.5
            positions[nid] = (r * math.cos(angle), r * math.sin(angle))
        radius += 0.2

    return positions


def _build_plotly_graph(graph_data: dict) -> go.Figure:
    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])

    if not nodes:
        fig = go.Figure()
        fig.add_annotation(text="No graph data available", x=0.5, y=0.5, showarrow=False)
        return fig

    positions = _layout_nodes(nodes, edges)

    # Build edge traces
    edge_traces = []
    for edge in edges:
        src = edge.get("source")
        dst = edge.get("target")
        if src in positions and dst in positions:
            x0, y0 = positions[src]
            x1, y1 = positions[dst]
            edge_traces.append(go.Scatter(
                x=[x0, x1, None],
                y=[y0, y1, None],
                mode="lines",
                line=dict(width=1.5, color="#334466"),
                hoverinfo="none",
                showlegend=False,
            ))
            # Edge label midpoint
            edge_traces.append(go.Scatter(
                x=[(x0 + x1) / 2],
                y=[(y0 + y1) / 2],
                mode="text",
                text=[edge.get("relation", "")],
                textfont=dict(size=9, color="#667799"),
                hoverinfo="none",
                showlegend=False,
            ))

    # Build node traces per label type
    node_traces = []
    by_label: dict[str, list] = {}
    for node in nodes:
        label = node.get("label", "Unknown")
        by_label.setdefault(label, []).append(node)

    for label, label_nodes in by_label.items():
        xs, ys, texts, hovers = [], [], [], []
        for node in label_nodes:
            nid = node["id"]
            if nid not in positions:
                continue
            x, y = positions[nid]
            xs.append(x)
            ys.append(y)
            props = node.get("properties", {})
            display_name = (
                props.get("name") or props.get("hostname") or
                props.get("address") or props.get("title") or nid
            )
            texts.append(f"<b>{nid}</b>")
            hover_lines = [f"<b>{label}: {nid}</b>"]
            for k, v in props.items():
                if v:
                    hover_lines.append(f"{k}: {v}")
            hovers.append("<br>".join(hover_lines))

        color = NODE_COLORS.get(label, "#888888")
        symbol = NODE_SYMBOLS.get(label, "circle")
        node_traces.append(go.Scatter(
            x=xs, y=ys,
            mode="markers+text",
            name=label,
            marker=dict(
                symbol=symbol,
                size=18,
                color=color,
                line=dict(width=2, color="#ffffff"),
            ),
            text=texts,
            textposition="top center",
            textfont=dict(size=9, color="#ccddff"),
            hovertext=hovers,
            hoverinfo="text",
        ))

    all_traces = edge_traces + node_traces

    fig = go.Figure(
        data=all_traces,
        layout=go.Layout(
            paper_bgcolor="#0a0a1a",
            plot_bgcolor="#0a0a1a",
            showlegend=True,
            legend=dict(
                font=dict(color="#ccddff"),
                bgcolor="#111133",
                bordercolor="#334466",
            ),
            hovermode="closest",
            margin=dict(l=10, r=10, t=40, b=10),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            height=550,
            title=dict(
                text="Investigation Subgraph",
                font=dict(color="#8ab4f8", size=14),
                x=0.5,
            ),
        ),
    )
    return fig


def render():
    st.markdown("## 🕸️ Graph Explorer")
    st.caption("Explore the investigation subgraph — nodes, relationships, and evidence paths from FalkorDB")

    col_sel, col_info = st.columns([2, 3])
    with col_sel:
        try:
            alerts = list_alerts(limit=20)
            alert_options = {"— Full Overview —": None}
            alert_options.update({
                f"{a['id']} — {a['title'][:40]}": a["id"]
                for a in alerts
            })
        except Exception:
            alert_options = {"— Full Overview —": None}
            st.warning("Could not load alerts.")

        # Pre-select from session state
        preselected = st.session_state.get("graph_alert_id")
        default_idx = 0
        if preselected:
            for i, v in enumerate(alert_options.values()):
                if v == preselected:
                    default_idx = i
                    break

        chosen_key = st.selectbox(
            "Focus alert",
            options=list(alert_options.keys()),
            index=default_idx,
        )
        chosen_alert_id = alert_options[chosen_key]

    with col_info:
        st.markdown("#### Node Legend")
        cols = st.columns(4)
        for i, (label, color) in enumerate(NODE_COLORS.items()):
            with cols[i % 4]:
                st.markdown(
                    f"<span style='background:{color};color:white;"
                    f"padding:2px 6px;border-radius:4px;font-size:0.7rem'>{label}</span>",
                    unsafe_allow_html=True,
                )

    st.markdown("---")

    # ── Load Graph Data ──
    try:
        with st.spinner("Loading graph data from FalkorDB..."):
            graph_data = get_all_graph_data_for_visualization(chosen_alert_id)

        node_count = len(graph_data.get("nodes", []))
        edge_count = len(graph_data.get("edges", []))

        if node_count == 0:
            st.info("No graph data found. Make sure the demo data is seeded.")
            return

        st.markdown(f"**Showing {node_count} nodes, {edge_count} edges** from FalkorDB graph queries")

        fig = _build_plotly_graph(graph_data)
        st.plotly_chart(fig, use_container_width=True)

        # ── Node Inspector ──
        st.markdown("#### Node Inspector")
        nodes = graph_data.get("nodes", [])
        if nodes:
            node_options = {f"{n['label']} [{n['id']}]": n for n in nodes}
            selected_node_key = st.selectbox("Select node to inspect", list(node_options.keys()))
            selected_node = node_options[selected_node_key]

            col_nid, col_props = st.columns([1, 2])
            with col_nid:
                label = selected_node["label"]
                color = NODE_COLORS.get(label, "#888")
                st.markdown(
                    f"<div style='background:{color}22;border:1px solid {color};"
                    f"border-radius:8px;padding:12px;text-align:center'>"
                    f"<b style='color:{color};font-size:1.1rem'>{label}</b><br>"
                    f"<code>{selected_node['id']}</code></div>",
                    unsafe_allow_html=True,
                )
            with col_props:
                props = selected_node.get("properties", {})
                for k, v in props.items():
                    if v:
                        st.write(f"**{k}:** {v}")

            # Show connected edges
            edges = graph_data.get("edges", [])
            connected = [
                e for e in edges
                if e["source"] == selected_node["id"] or e["target"] == selected_node["id"]
            ]
            if connected:
                st.markdown(f"**Connections ({len(connected)}):**")
                for e in connected:
                    direction = "→" if e["source"] == selected_node["id"] else "←"
                    other = e["target"] if e["source"] == selected_node["id"] else e["source"]
                    st.write(f"  {direction} `[{e['relation']}]` → `{other}`")

    except ConnectionError as exc:
        st.error(f"Database connection error: {exc}")
    except Exception as exc:
        st.error(f"Graph visualization error: {exc}")
