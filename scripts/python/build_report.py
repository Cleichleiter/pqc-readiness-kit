#!/usr/bin/env python3
"""
build_report.py

Placeholder for report generation.
Will combine local crypto inventory and TLS scan results
into human-readable outputs (HTML / CSV).

This version validates inputs and establishes structure only.
"""

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Build PQC readiness reports")
    parser.add_argument("--inventory", required=True, help="crypto_inventory.json")
    parser.add_argument("--tls-scan", required=False, help="tls_scan.json")
    parser.add_argument("--out-dir", required=True, help="Output directory")
    args = parser.parse_args()

    inventory_path = Path(args.inventory)
    out_dir = Path(args.out_dir)

    if not inventory_path.exists():
        raise FileNotFoundError(f"Inventory file not found: {inventory_path}")

    if args.tls_scan:
        tls_path = Path(args.tls_scan)
        if not tls_path.exists():
            raise FileNotFoundError(f"TLS scan file not found: {tls_path}")

    out_dir.mkdir(parents=True, exist_ok=True)

    with inventory_path.open("r", encoding="utf-8") as f:
        inventory = json.load(f)

    tls_data = None
    if args.tls_scan:
        with Path(args.tls_scan).open("r", encoding="utf-8") as f:
            tls_data = json.load(f)

    # Stub output
    summary_path = out_dir / "report_stub.json"
    with summary_path.open("w", encoding="utf-8") as f:
        json.dump(
            {
                "status": "stub",
                "inventory_loaded": True,
                "tls_loaded": bool(tls_data),
                "note": "Report generation not implemented yet"
            },
            f,
            indent=2
        )

    print(f"Wrote: {summary_path}")


if __name__ == "__main__":
    main()
