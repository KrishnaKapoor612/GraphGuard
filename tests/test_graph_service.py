"""
Tests for graph queries and graph service layer.
Uses mocks to isolate from the database — no live FalkorDB required.
"""
import sys
import os
import pytest
from unittest.mock import MagicMock, patch

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── Config Tests ──────────────────────────────────────────────────────────────

class TestConfig:
    def test_config_loads(self):
        import config
        assert config.FALKORDB_HOST is not None
        assert isinstance(config.FALKORDB_PORT, int)
        assert config.GRAPH_NAME is not None

    def test_config_status_does_not_expose_key(self):
        import config
        status = config.get_config_status()
        # Must not return the actual API key
        assert "google_api_key_configured" in status
        assert isinstance(status["google_api_key_configured"], bool)
        # The key value itself must not be in the dict
        for v in status.values():
            assert v != config.GOOGLE_API_KEY or config.GOOGLE_API_KEY is None

    def test_missing_api_key_returns_false(self):
        import config
        original = config.GOOGLE_API_KEY
        config.GOOGLE_API_KEY = None
        assert config.is_gemini_available() is False
        config.GOOGLE_API_KEY = original

    def test_placeholder_key_returns_false(self):
        import config
        original = config.GOOGLE_API_KEY
        config.GOOGLE_API_KEY = "your_google_api_key_here"
        assert config.is_gemini_available() is False
        config.GOOGLE_API_KEY = original


# ── Graph Service Tests (with mocked DB) ─────────────────────────────────────

class MockResultSet:
    def __init__(self, rows):
        self.result_set = rows


class TestGraphService:
    @patch("database.connection.get_graph")
    def test_get_alert_details_returns_dict(self, mock_get_graph):
        """get_alert_details should return a dict with expected keys."""
        mock_graph = MagicMock()
        mock_graph.query.return_value = MockResultSet([[
            "A-104", "Suspicious Outbound", "critical", "Network Anomaly",
            "2024-03-15T02:47:00Z", "open", "Description here",
            "D-001", "WORKSTATION-07", "workstation", "compromised_suspected",
            "U-001", "Marcus Chen", "Engineering", "high",
            "IP-001", "185.220.101.45", "malicious", "Netherlands",
            "INC-001", "Data Exfiltration", "critical", "active",
        ]])
        mock_get_graph.return_value = mock_graph

        from services.graph_service import get_alert_details
        result = get_alert_details("A-104")

        assert result is not None
        assert result["alert_id"] == "A-104"
        assert result["alert_severity"] == "critical"
        assert result["device_hostname"] == "WORKSTATION-07"
        assert result["user_name"] == "Marcus Chen"
        assert result["ip_reputation"] == "malicious"

    @patch("services.graph_service._run")
    def test_get_alert_details_missing_returns_none(self, mock_run):
        """An unknown alert ID should return None, not raise an exception."""
        mock_run.return_value = []
        import services.graph_service as gs
        result = gs.get_alert_details("A-NONEXISTENT")
        assert result is None

    @patch("services.graph_service._run")
    def test_find_related_alerts_via_ip_returns_list(self, mock_run):
        """find_related_alerts_via_ip should return a list of dicts."""
        mock_run.return_value = [
            ["A-106", "C2 Beacon", "high", "Malware", "2024-03-14T23:15:00Z", "open", "185.220.101.45", "malicious"],
        ]
        import services.graph_service as gs
        results = gs.find_related_alerts_via_ip("A-104")
        assert isinstance(results, list)
        assert len(results) == 1
        assert results[0]["alert_id"] == "A-106"
        assert results[0]["via_ip"] == "185.220.101.45"

    @patch("services.graph_service._run")
    def test_trace_incident_path_returns_dict(self, mock_run):
        """trace_incident_path should return the full multi-hop result."""
        mock_run.return_value = [[
            "A-104", "Suspicious Outbound", "critical",
            "D-001", "WORKSTATION-07", "workstation",
            "U-001", "Marcus Chen", "Engineering", "high",
            "IP-001", "185.220.101.45", "malicious", "Netherlands",
            "A-106", "C2 Beacon", "high",
            "INC-001", "Data Exfiltration", "critical", "active",
            "SVC-001", "Payment Processing Service", "critical", "Platform Engineering",
        ]]
        import services.graph_service as gs
        result = gs.trace_incident_path("A-104")
        assert result is not None
        assert result["incident_id"] == "INC-001"
        assert result["ip_reputation"] == "malicious"
        assert result["service_name"] == "Payment Processing Service"

    @patch("database.connection.get_graph")
    def test_database_stats_returns_expected_keys(self, mock_get_graph):
        """get_database_stats should return all expected metric keys."""
        mock_graph = MagicMock()
        mock_graph.query.return_value = MockResultSet([[42]])
        mock_get_graph.return_value = mock_graph

        from services.graph_service import get_database_stats
        stats = get_database_stats()

        expected_keys = [
            "total_nodes", "total_relationships", "alert_count",
            "open_incident_count", "investigation_count",
            "user_count", "device_count", "ip_count", "service_count",
        ]
        for key in expected_keys:
            assert key in stats


# ── Investigation Service Tests ───────────────────────────────────────────────

class TestInvestigationService:
    @patch("services.graph_service.get_alert_details")
    @patch("services.graph_service.investigate_device")
    @patch("services.graph_service.trace_incident_path")
    @patch("services.graph_service.find_related_alerts_via_device")
    @patch("services.graph_service.find_related_alerts_via_ip")
    @patch("services.graph_service.find_related_alerts_via_user")
    @patch("services.graph_service.get_affected_services")
    def test_run_graph_investigation_returns_structured_result(
        self, mock_services, mock_via_user, mock_via_ip, mock_via_device,
        mock_trace, mock_device, mock_alert
    ):
        """run_graph_investigation should return a dict with expected keys."""
        mock_alert.return_value = {
            "alert_id": "A-104", "alert_title": "Test", "alert_severity": "critical",
            "alert_category": "Network Anomaly", "alert_timestamp": "2024-03-15T02:47:00Z",
            "alert_status": "open", "alert_description": "desc",
            "device_id": "D-001", "device_hostname": "WORKSTATION-07",
            "device_type": "workstation", "device_status": "compromised_suspected",
            "user_id": "U-001", "user_name": "Marcus Chen",
            "user_department": "Engineering", "user_risk_level": "high",
            "ip_id": "IP-001", "ip_address": "185.220.101.45",
            "ip_reputation": "malicious", "ip_country": "Netherlands",
            "incident_id": "INC-001", "incident_title": "Data Exfiltration",
            "incident_severity": "critical", "incident_status": "active",
        }
        mock_device.return_value = {}
        mock_trace.return_value = {
            "incident_id": "INC-001", "incident_title": "Data Exfiltration",
            "incident_severity": "critical", "incident_status": "active",
            "device_id": "D-001", "hostname": "WORKSTATION-07", "device_type": "workstation",
            "user_id": "U-001", "user_name": "Marcus Chen", "department": "Engineering",
            "user_risk_level": "high", "ip_id": "IP-001", "ip_address": "185.220.101.45",
            "ip_reputation": "malicious", "ip_country": "Netherlands",
            "related_alert_id": "A-106", "related_alert_title": "C2 Beacon",
            "related_alert_severity": "high",
            "service_id": "SVC-001", "service_name": "Payment Processing",
            "service_criticality": "critical", "service_owner_team": "Platform Eng",
        }
        mock_via_device.return_value = [{"alert_id": "A-105", "title": "Port Scan", "severity": "high"}]
        mock_via_ip.return_value = [{"alert_id": "A-106", "title": "C2 Beacon", "severity": "high"}]
        mock_via_user.return_value = []
        mock_services.return_value = [{"service_id": "SVC-001", "name": "Payment", "criticality": "critical", "owner_team": "PE"}]

        from services.investigation_service import run_graph_investigation
        result = run_graph_investigation("A-104")

        assert "error" not in result
        assert result["alert_data"]["alert_id"] == "A-104"
        assert len(result["related_alerts_via_device"]) > 0
        assert len(result["related_alerts_via_ip"]) > 0
        assert result["incident_path"]["incident_id"] == "INC-001"

    @patch("services.graph_service.get_alert_details")
    def test_unknown_alert_returns_error(self, mock_alert):
        """An unknown alert ID should produce a clean error dict."""
        mock_alert.return_value = None

        from services.investigation_service import run_graph_investigation
        result = run_graph_investigation("A-NONEXISTENT")

        assert "error" in result
        assert "not found" in result["error"]


# ── Evidence Validation Tests ─────────────────────────────────────────────────

class TestEvidenceValidation:
    def test_evidence_record_requires_entity_id(self):
        """EvidenceRecord must have entity_id to be valid."""
        from models.schemas import EvidenceRecord
        ev = EvidenceRecord(
            evidence_id="EV-001",
            source_type="network_log",
            description="Test",
            observed_at="2024-03-15T02:47:00Z",
            entity_type="Alert",
            entity_id="A-104",
            is_inferred=False,
        )
        assert ev.entity_id == "A-104"
        assert ev.is_inferred is False

    def test_deterministic_investigation_returns_valid_result(self):
        """build_deterministic_investigation should return a valid InvestigationResult."""
        from unittest.mock import patch, MagicMock
        from services.investigation_service import build_deterministic_investigation
        from models.schemas import InvestigationResult

        with patch("services.graph_service.get_alert_details") as mock_alert, \
             patch("services.graph_service.investigate_device") as mock_device, \
             patch("services.graph_service.trace_incident_path") as mock_trace, \
             patch("services.graph_service.find_related_alerts_via_device") as mock_d, \
             patch("services.graph_service.find_related_alerts_via_ip") as mock_ip, \
             patch("services.graph_service.find_related_alerts_via_user") as mock_u, \
             patch("services.graph_service.get_affected_services") as mock_svc:

            mock_alert.return_value = {
                "alert_id": "A-104", "alert_title": "Suspicious Outbound",
                "alert_severity": "critical", "alert_category": "Network Anomaly",
                "alert_timestamp": "2024-03-15T02:47:00Z", "alert_status": "open",
                "alert_description": "test", "device_id": "D-001",
                "device_hostname": "WORKSTATION-07", "device_type": "workstation",
                "device_status": "ok", "user_id": "U-001", "user_name": "Marcus Chen",
                "user_department": "Engineering", "user_risk_level": "high",
                "ip_id": "IP-001", "ip_address": "185.220.101.45",
                "ip_reputation": "malicious", "ip_country": "Netherlands",
                "incident_id": "INC-001", "incident_title": "Data Exfiltration",
                "incident_severity": "critical", "incident_status": "active",
            }
            mock_device.return_value = {}
            mock_trace.return_value = {
                "incident_id": "INC-001", "incident_title": "Data Exfil",
                "incident_severity": "critical", "incident_status": "active",
                "device_id": "D-001", "hostname": "WORKSTATION-07", "device_type": "wks",
                "user_id": "U-001", "user_name": "Marcus Chen",
                "department": "Engineering", "user_risk_level": "high",
                "ip_id": "IP-001", "ip_address": "185.220.101.45",
                "ip_reputation": "malicious", "ip_country": "Netherlands",
                "related_alert_id": "A-106", "related_alert_title": "C2", "related_alert_severity": "high",
                "service_id": "SVC-001", "service_name": "Payment",
                "service_criticality": "critical", "service_owner_team": "PE",
            }
            mock_d.return_value = []
            mock_ip.return_value = []
            mock_u.return_value = []
            mock_svc.return_value = [{"service_id": "SVC-001", "name": "Payment", "criticality": "critical", "owner_team": "PE"}]

            result = build_deterministic_investigation("A-104")

            assert isinstance(result, InvestigationResult)
            assert len(result.confirmed_facts) > 0
            assert result.severity_assessment in ("critical", "high", "medium", "low", "unknown")
            # Evidence records should reference real entity IDs from queries
            for ev in result.supporting_evidence:
                assert ev.entity_id  # must have a real entity reference
                assert not ev.is_inferred  # these are from graph queries, not inferred

    def test_inferences_are_labeled(self):
        """All inferred statements must be marked [INFERRED]."""
        from unittest.mock import patch
        from services.investigation_service import build_deterministic_investigation

        with patch("services.graph_service.get_alert_details") as mock_alert, \
             patch("services.graph_service.investigate_device"), \
             patch("services.graph_service.trace_incident_path") as mock_trace, \
             patch("services.graph_service.find_related_alerts_via_device") as mock_d, \
             patch("services.graph_service.find_related_alerts_via_ip") as mock_ip, \
             patch("services.graph_service.find_related_alerts_via_user") as mock_u, \
             patch("services.graph_service.get_affected_services") as mock_svc:

            mock_alert.return_value = {
                "alert_id": "A-104", "alert_title": "T", "alert_severity": "critical",
                "alert_category": "C", "alert_timestamp": "T", "alert_status": "open",
                "alert_description": "D", "device_id": None, "device_hostname": None,
                "device_type": None, "device_status": None, "user_id": None, "user_name": None,
                "user_department": None, "user_risk_level": None, "ip_id": None,
                "ip_address": None, "ip_reputation": None, "ip_country": None,
                "incident_id": None, "incident_title": None, "incident_severity": None, "incident_status": None,
            }
            mock_trace.return_value = None
            mock_d.return_value = []
            mock_ip.return_value = []
            mock_u.return_value = []
            mock_svc.return_value = []

            result = build_deterministic_investigation("A-104")
            for inf in result.inferences:
                assert "[INFERRED]" in inf, f"Inference not labeled: {inf}"
