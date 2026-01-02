#!/usr/bin/env python3
"""
build_report.py

Minimal report generator for PQC readiness.
Generates a basic HTML summary from crypto inventory data.
"""

import argparse
import json
from pathlib import Path
from datetime import datetime


def main() -> None:
    parser = argparse.ArgumentParser(description="Build PQC readiness report")
    parser.add_argument("--inventory", required=True, help="crypto_inventory.json")
    parser.add_argument("--out-dir", required=True, help="Output directory")
    args = parser.parse_args()

    inventory_path = Path(args.inventory)
    out_dir = Path(args.out_dir)

    if not inventory_path.exists():
        raise FileNotFoundError(f"Inventory file not found: {inventory_path}")

    out_dir.mkdir(parents=True, exist_ok=True)

    # IMPORTANT: utf-8-sig handles Windows BOM correctly
    with inventory_path.open("r", encoding="utf-8-sig") as f:
        inventory = json.load(f)

    certs = inventory.get("artifacts", {}).get("certificates", [])

    now = datetime.utcnow()
    counts_by_algo = {}
    expired = 0
    expiring_30 = 0

    for c in certs:
        algo = c.get("PublicKeyAlgorithm") or "Unknown"
        counts_by_algo[algo] = counts_by_algo.get(algo, 0) + 1

        not_after = c.get("NotAfter")
        if not_after:
            try:
                na = datetime.fromisoformat(not_after)
                if na < now:
                    expired += 1
                elif (na - now).days <= 30:
                    expiring_30 += 1
            except Exception:
                pass

    html = f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>PQC Readiness Summary</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 40px; }}
    h1, h2 {{ color: #333; }}
    table {{ border-collapse: collapse; margin-top: 10px; }}
    th, td {{ border: 1px solid #ccc; padding: 6px 10px; }}
    th {{ background-color: #f4f4f4; }}
  </style>
</head>
<body>

<h1>PQC Readiness Summary</h1>

<p><strong>Generated:</strong> {inventory.get("generatedAtUtc")}</p>
<p><strong>Host:</strong> {inventory.get("host", {}).get("computerName")}</p>
<p><strong>OS:</strong> {inventory.get("host", {}).get("osCaption")} ({inventory.get("host", {}).get("osVersion")})</p>

<h2>Certificate Inventory Overview</h2>

<table>
  <tr>
    <th>Public Key Algorithm</th>
    <th>Count</th>
  </tr>
  {''.join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in counts_by_algo.items())}
</table>

<h2>Hygiene Signals</h2>

<ul>
  <li>Expired certificates: {expired}</li>
  <li>Certificates expiring within 30 days: {expiring_30}</li>
</ul>

<p>This report provides a high-level summary only. Detailed findings are available in the CSV and JSON outputs.</p>

</body>
</html>
"""

    report_path = out_dir / "report.html"
    with report_path.open("w", encoding="utf-8") as f:
        f.write(html)

    print(f"Wrote: {report_path}")


if __name__ == "__main__":
    main()
