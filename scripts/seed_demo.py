#!/usr/bin/env python3
"""
GraphGuard Demo Data Seeder.
Usage: python scripts/seed_demo.py [--reset]
"""
import sys
import os
import argparse

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def main():
    parser = argparse.ArgumentParser(description="Seed GraphGuard demo data")
    parser.add_argument("--reset", action="store_true", help="⚠️ Delete ALL data before seeding")
    args = parser.parse_args()

    from database.connection import get_graph, check_connection

    # Check connection first
    ok, msg = check_connection()
    if not ok:
        print(f"[-] Cannot connect to FalkorDB: {msg}")
        print("\nTo start FalkorDB locally:")
        print("  docker run -p 6379:6379 falkordb/falkordb")
        sys.exit(1)

    print(f"[OK] FalkorDB connected: {msg}")

    if args.reset:
        print("\n[WARN] WARNING: This will DELETE ALL data in the graph!")
        confirm = input("Type 'yes' to confirm: ").strip()
        if confirm.lower() != "yes":
            print("Reset aborted.")
            sys.exit(0)
        from database.seed import reset_graph
        reset_graph(get_graph(), confirm=True)
        print("Graph cleared.")

    from database.seed import run_seed
    success = run_seed(verbose=True)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
