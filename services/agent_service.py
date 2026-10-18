"""
Agent Service — Gemini + LangChain investigation agent.

Uses predefined safe graph tools. The LLM cannot execute arbitrary Cypher.
All graph evidence comes from the parameterized query library.

Tool calling flow:
  User question → Agent decides which tools to call → Tools query FalkorDB →
  Results returned to agent → Agent synthesizes evidence-grounded response →
  Structured InvestigationResult returned to UI
"""
from __future__ import annotations
import json
import logging
import os
from typing import Any

import config
from models.schemas import InvestigationResult, EvidenceRecord, GraphPath
from services import graph_service
from services import memory_service
from services.investigation_service import run_graph_investigation, build_deterministic_investigation

logger = logging.getLogger(__name__)


# ─── LangChain Tool Definitions ─────────────────────────────────────────────

def _make_tools():
    """Create LangChain tools wrapping the safe graph service functions."""
    try:
        from langchain.tools import tool as lc_tool
    except ImportError:
        return []

    @lc_tool
    def get_alert_details(alert_id: str) -> str:
        """
        Retrieve an alert and its directly connected entities (device, user, IP, incident).
        Input: alert_id (string, e.g. 'A-104')
        Returns: JSON with alert properties and connected entity details.
        """
        data = graph_service.get_alert_details(alert_id)
        if not data:
            return json.dumps({"error": f"Alert {alert_id} not found"})
        return json.dumps(data, default=str)

    @lc_tool
    def investigate_device(device_id: str) -> str:
        """
        Investigate a device: its user, all alerts triggered, IPs contacted, and linked incidents.
        Input: device_id (string, e.g. 'D-001')
        Returns: JSON with device investigation details.
        """
        data = graph_service.investigate_device(device_id)
        if not data:
            return json.dumps({"error": f"Device {device_id} not found"})
        return json.dumps(data, default=str)

    @lc_tool
    def find_related_alerts(alert_id: str) -> str:
        """
        Find alerts related to the given alert via shared device, user, or IP address.
        This is a multi-hop graph query that reveals connections a single lookup would miss.
        Input: alert_id (string)
        Returns: JSON with lists of related alerts grouped by connection type.
        """
        via_device = graph_service.find_related_alerts_via_device(alert_id)
        via_ip = graph_service.find_related_alerts_via_ip(alert_id)
        via_user = graph_service.find_related_alerts_via_user(alert_id)
        return json.dumps({
            "via_device": via_device,
            "via_ip": via_ip,
            "via_user": via_user,
        }, default=str)

    @lc_tool
    def trace_incident_path(alert_id: str) -> str:
        """
        Trace the full multi-hop evidence path from an alert to incident and affected services.
        Path: Alert → Device → User → IP → Related Alerts → Incident → Affected Services.
        This query traverses multiple relationship types in a single execution.
        Input: alert_id (string)
        Returns: JSON with the full connected path.
        """
        data = graph_service.trace_incident_path(alert_id)
        if not data:
            return json.dumps({"result": "No incident path found for this alert"})
        return json.dumps(data, default=str)

    @lc_tool
    def get_affected_services(incident_id: str) -> str:
        """
        Retrieve services potentially affected by an incident.
        Input: incident_id (string, e.g. 'INC-001')
        Returns: JSON list of affected services with criticality ratings.
        """
        services = graph_service.get_affected_services(incident_id)
        return json.dumps(services, default=str)

    @lc_tool
    def save_investigation(
        question: str,
        summary: str,
        outcome: str,
        severity_assessment: str,
        recommended_steps: str,
        alert_id: str = "",
    ) -> str:
        """
        Save this investigation to FalkorDB for future reference.
        This enables persistent memory across sessions.
        Input: question, summary, outcome (confirmed_threat|likely_benign|inconclusive),
               severity_assessment, recommended_steps (pipe-separated), alert_id (optional).
        Returns: JSON with the investigation_id.
        """
        steps = [s.strip() for s in recommended_steps.split("|") if s.strip()]
        inv_id = memory_service.save_investigation(
            question=question,
            summary=summary,
            outcome=outcome,
            severity_assessment=severity_assessment,
            recommended_steps=steps,
            examined_alert_id=alert_id or None,
        )
        return json.dumps({"investigation_id": inv_id, "saved": True})

    @lc_tool
    def get_previous_investigation(investigation_id: str) -> str:
        """
        Retrieve a previously saved investigation from FalkorDB by its ID.
        This demonstrates cross-session persistent memory.
        Input: investigation_id (string, e.g. 'INV-ABCD1234')
        Returns: JSON with the full saved investigation context.
        """
        data = memory_service.get_investigation_by_id(investigation_id)
        if not data:
            return json.dumps({"error": f"Investigation {investigation_id} not found"})
        return json.dumps(data, default=str)

    return [
        get_alert_details,
        investigate_device,
        find_related_alerts,
        trace_incident_path,
        get_affected_services,
        save_investigation,
        get_previous_investigation,
    ]


# ─── Agent System Prompt ─────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are GraphGuard, an AI-powered cybersecurity incident investigator.
You have access to tools that query a FalkorDB graph database containing security entities:
Users, Devices, IP Addresses, Alerts, Incidents, Services, Investigations, and Evidence.

Your investigation process:
1. Use get_alert_details to understand the alert and its immediate context
2. Use trace_incident_path to follow the multi-hop graph path (Alert→Device→User→IP→Incident→Services)
3. Use find_related_alerts to discover connected alerts the analyst might have missed
4. Use get_affected_services if an incident is found
5. Save your investigation with save_investigation

CRITICAL RULES:
- Only cite facts that came from tool results. Never invent node IDs, IP addresses, or graph paths.
- Clearly distinguish CONFIRMED FACTS (from graph queries) from INFERENCES (your interpretation).
- If a tool returns no results, say so honestly — do not fabricate a result.
- Never recommend automatically disabling accounts or blocking IPs without human approval.
- All recommended actions require human review before execution.

Output format: Respond with a valid JSON object containing these exact fields:
{
  "investigation_summary": "...",
  "severity_assessment": "critical|high|medium|low|unknown",
  "confirmed_facts": ["fact1", "fact2"],
  "inferences": ["[INFERRED] ..."],
  "unknowns": ["what we don't know..."],
  "recommended_next_steps": ["step1", "step2"],
  "graph_paths": [{"path_description": "...", "hop_count": N}],
  "related_alerts": [{"alert_id": "...", "title": "..."}],
  "potentially_affected_services": [{"name": "...", "criticality": "..."}],
  "investigation_id": "...",
  "outcome": "confirmed_threat|likely_benign|inconclusive"
}
"""


# ─── Main Agent Entry Point ───────────────────────────────────────────────────

def run_agent_investigation(question: str, alert_id: str | None = None) -> InvestigationResult:
    """
    Run the Gemini agent to investigate a security question.
    Falls back to deterministic graph investigation if Gemini is unavailable.
    """
    if not config.is_gemini_available():
        logger.info("Gemini not configured — using deterministic investigation")
        if alert_id:
            result = build_deterministic_investigation(alert_id)
            # Save the investigation even in demo mode
            _save_deterministic(result, question, alert_id)
            return result
        return InvestigationResult(
            investigation_id="N/A",
            investigation_summary=(
                " Gemini API key not configured. "
                "Set GOOGLE_API_KEY in your .env file to enable AI-powered investigation. "
                "Graph queries and demo mode are still fully functional."
            ),
            severity_assessment="unknown",
            confirmed_facts=[],
            is_demo_fallback=True,
        )

    try:
        return _run_gemini_agent(question, alert_id)
    except Exception as exc:
        logger.error("Gemini agent failed: %s", exc)
        # Graceful fallback
        if alert_id:
            result = build_deterministic_investigation(alert_id)
            result.is_demo_fallback = True
            result.investigation_summary = (
                f"[WARN] AI synthesis unavailable (error: {str(exc)[:100]}). "
                f"Displaying graph-only results.\n\n{result.investigation_summary}"
            )
            return result
        return InvestigationResult(
            investigation_id="N/A",
            investigation_summary=f"Investigation failed: {exc}",
            severity_assessment="unknown",
            is_demo_fallback=True,
        )


def _save_deterministic(result: InvestigationResult, question: str, alert_id: str):
    """Persist a deterministic investigation result to FalkorDB."""
    try:
        ev_data = [
            {"source_type": ev.source_type, "description": ev.description, "observed_at": ev.observed_at}
            for ev in result.supporting_evidence
        ]
        inv_id = memory_service.save_investigation(
            question=question,
            summary=result.investigation_summary,
            outcome="confirmed_threat" if result.severity_assessment in ("critical", "high") else "inconclusive",
            severity_assessment=result.severity_assessment,
            recommended_steps=result.recommended_next_steps,
            examined_alert_id=alert_id,
            evidence_descriptions=ev_data,
        )
        result.investigation_id = inv_id
    except Exception as exc:
        logger.warning("Could not save investigation: %s", exc)


def _run_gemini_agent(question: str, alert_id: str | None) -> InvestigationResult:
    """Run the actual Gemini + LangChain agent."""
    from langchain_google_genai import ChatGoogleGenerativeAI
    try:
        from langchain.agents import AgentExecutor, create_tool_calling_agent
    except ImportError:
        from langchain_classic.agents import AgentExecutor, create_tool_calling_agent
    from langchain_core.messages import SystemMessage
    from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder

    # Pre-collect graph evidence to inject into the prompt for better grounding
    graph_context = ""
    if alert_id:
        raw = run_graph_investigation(alert_id)
        graph_context = f"\n\nPre-collected graph context for alert {alert_id}:\n{json.dumps(raw, default=str)[:3000]}"

    llm = ChatGoogleGenerativeAI(
        model=config.GEMINI_MODEL,
        google_api_key=config.GOOGLE_API_KEY,
        temperature=0.1,  # Low temperature for deterministic factual output
    )

    tools = _make_tools()

    prompt = ChatPromptTemplate.from_messages([
        SystemMessage(content=SYSTEM_PROMPT + graph_context),
        ("human", "{input}"),
        MessagesPlaceholder("agent_scratchpad"),
    ])

    agent = create_tool_calling_agent(llm, tools, prompt)
    executor = AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=config.DEBUG,
        max_iterations=8,
        handle_parsing_errors=True,
        return_intermediate_steps=True,
    )

    full_question = question
    if alert_id:
        full_question = f"Investigate alert {alert_id}. Question: {question}"

    response = executor.invoke({"input": full_question})
    output = response.get("output", "")

    return _parse_agent_output(output, alert_id)


def _parse_agent_output(output: Any, alert_id: str | None) -> InvestigationResult:
    """
    Parse the agent's JSON output into an InvestigationResult.
    Falls back to deterministic result if parsing fails.
    """
    # Normalize output to string (handles lists, content blocks, AIMessage, etc.)
    if isinstance(output, list):
        text_parts = []
        for item in output:
            if isinstance(item, dict) and "text" in item:
                text_parts.append(item["text"])
            elif isinstance(item, str):
                text_parts.append(item)
            elif hasattr(item, "content"):
                text_parts.append(str(item.content))
            else:
                text_parts.append(str(item))
        output_str = "\n".join(text_parts)
    elif hasattr(output, "content"):
        output_str = str(output.content)
    else:
        output_str = str(output)

    # Try to extract JSON from the output
    import re
    json_match = re.search(r'\{[\s\S]*\}', output_str)
    if json_match:
        try:
            data = json.loads(json_match.group())
            paths = []
            for p in data.get("graph_paths", []):
                paths.append(GraphPath(
                    path_description=p.get("path_description", ""),
                    hop_count=p.get("hop_count", 0),
                ))

            # Save to FalkorDB
            inv_id = data.get("investigation_id", "GEMINI-" + (alert_id or "UNK"))
            try:
                steps = data.get("recommended_next_steps", [])
                inv_id = memory_service.save_investigation(
                    question=data.get("investigation_summary", "")[:200],
                    summary=data.get("investigation_summary", ""),
                    outcome=data.get("outcome", "inconclusive"),
                    severity_assessment=data.get("severity_assessment", "unknown"),
                    recommended_steps=steps,
                    examined_alert_id=alert_id,
                )
            except Exception as exc:
                logger.warning("Could not persist Gemini investigation: %s", exc)

            return InvestigationResult(
                investigation_id=inv_id,
                investigation_summary=data.get("investigation_summary", output_str),
                severity_assessment=data.get("severity_assessment", "unknown"),
                confirmed_facts=data.get("confirmed_facts", []),
                graph_paths=paths,
                related_alerts=data.get("related_alerts", []),
                potentially_affected_services=data.get("potentially_affected_services", []),
                inferences=data.get("inferences", []),
                unknowns=data.get("unknowns", []),
                recommended_next_steps=data.get("recommended_next_steps", []),
                is_demo_fallback=False,
            )
        except json.JSONDecodeError:
            pass

    # Fallback: couldn't parse JSON, use deterministic result with agent text
    if alert_id:
        result = build_deterministic_investigation(alert_id)
        result.investigation_summary = output_str + "\n\n" + result.investigation_summary
        return result

    return InvestigationResult(
        investigation_id="PARSE-ERR",
        investigation_summary=output_str,
        severity_assessment="unknown",
        is_demo_fallback=True,
    )
