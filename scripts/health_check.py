#!/usr/bin/env python3
"""
GraphGuard Health Check.
Reports system status without exposing secrets.
Usage: python scripts/health_check.py
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def check_all():
    results = []
    all_ok = True

    print("=" * 50)
    print("GraphGuard Health Check")
    print("=" * 50)

    # 1. Config loaded
    try:
        import config
        cfg = config.get_config_status()
        print("\n[1] Configuration")
        print(f"    FalkorDB host: {cfg['falkordb_host']}:{cfg['falkordb_port']}")
        print(f"    Graph name: {cfg['graph_name']}")
        print(f"    Gemini configured: {cfg['google_api_key_configured']}")
        print(f"    Gemini model: {cfg['gemini_model']}")
        results.append(("Config loaded", True))
    except Exception as exc:
        print(f"    ✗ Config error: {exc}")
        results.append(("Config loaded", False))
        all_ok = False

    # 2. FalkorDB connection
    print("\n[2] FalkorDB Connection")
    try:
        from database.connection import check_connection
        ok, msg = check_connection()
        status = "[OK]" if ok else "[FAIL]"
        print(f"    {status} {msg}")
        results.append(("FalkorDB connection", ok))
        if not ok:
            all_ok = False
    except Exception as exc:
        print(f"    [FAIL] Exception: {exc}")
        results.append(("FalkorDB connection", False))
        all_ok = False

    # 3. Graph data
    print("\n[3] Graph Data")
    try:
        from services.graph_service import get_database_stats
        stats = get_database_stats()
        print(f"    Nodes: {stats['total_nodes']}")
        print(f"    Relationships: {stats['total_relationships']}")
        print(f"    Alerts: {stats['alert_count']}")
        has_data = stats['total_nodes'] > 0
        status = "[OK]" if has_data else "[WARN]"
        print(f"    {status} {'Graph seeded' if has_data else 'No data - run seed_demo.py'}")
        results.append(("Graph has data", has_data))
    except Exception as exc:
        print(f"    [FAIL] Exception: {exc}")
        results.append(("Graph data check", False))
        all_ok = False

    # 4. Key alert exists
    print("\n[4] Demo Alert (A-104)")
    try:
        from services.graph_service import get_alert_details
        alert = get_alert_details("A-104")
        if alert:
            print(f"    [OK] Alert A-104 found: {alert.get('alert_title','')[:50]}")
            results.append(("Demo alert A-104", True))
        else:
            print("    [WARN] Alert A-104 not found - run seed_demo.py")
            results.append(("Demo alert A-104", False))
    except Exception as exc:
        print(f"    [FAIL] Exception: {exc}")
        results.append(("Demo alert A-104", False))
        all_ok = False

    # 5. Multi-hop query test
    print("\n[5] Multi-hop Investigation Query")
    try:
        from services.graph_service import trace_incident_path
        path = trace_incident_path("A-104")
        if path and path.get("incident_id"):
            print(f"    [OK] 4-hop path found: A-104 -> {path.get('hostname','?')} -> {path.get('ip_address','?')} -> {path.get('incident_id','?')} -> {path.get('service_name','?')}")
            results.append(("Multi-hop query", True))
        elif path:
            print(f"    [WARN] Partial path found (no incident): {path}")
            results.append(("Multi-hop query", True))
        else:
            print("    [WARN] No path found - seed demo data first")
            results.append(("Multi-hop query", False))
    except Exception as exc:
        print(f"    [FAIL] Exception: {exc}")
        results.append(("Multi-hop query", False))
        all_ok = False

    # 6. Gemini check (non-blocking)
    print("\n[6] Gemini API")
    try:
        import config
        if config.is_gemini_available():
            print("    [OK] API key configured")
            results.append(("Gemini configured", True))
        else:
            print("    [WARN] API key not set - demo mode will use graph-only results")
            results.append(("Gemini configured", False))
    except Exception as exc:
        print(f"    [FAIL] Exception: {exc}")
        results.append(("Gemini configured", False))

    # Summary
    print("\n" + "=" * 50)
    passed = sum(1 for _, ok in results if ok)
    print(f"Health Check: {passed}/{len(results)} checks passed")
    for name, ok in results:
        print(f"  {'[OK]' if ok else '[FAIL]'} {name}")

    if not all_ok:
        print("\nSome checks failed. See messages above for remediation steps.")
    else:
        print("\nAll systems operational")

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(check_all())
