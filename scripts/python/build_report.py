#!/usr/bin/env python3
"""
build_report.py

Minimal report generator for PQC readiness.
Generates a basic HTML summary from crypto inventory data and optional TLS scan results.
"""

import argparse
import json
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional


def read_json(path: Path) -> Any:
    # Windows PowerShell JSON often includes a UTF-8 BOM; utf-8-sig handles both.
    with path.open("r", encoding="utf-8-sig") as f:
        return json.load(f)


def safe_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build PQC readiness report")
    parser.add_argument("--inventory", required=True, help="crypto_inventory.json")
    parser.add_argument("--tls-scan", required=False, help="tls_scan.json (optional)")
    parser.add_argument("--out-dir", required=True, help="Output directory")
    args = parser.parse_args()

    inventory_path = Path(args.inventory)
    out_dir = Path(args.out_dir)

    if not inventory_path.exists():
        raise FileNotFoundError(f"Inventory file not found: {inventory_path}")

    tls_path: Optional[Path] = None
    tls_results: Optional[List[Dict[str, Any]]] = None
    if args.tls_scan:
        tls_path = Path(args.tls_scan)
        if not tls_path.exists():
            raise FileNotFoundError(f"TLS scan file not found: {tls_path}")
        tls_results = read_json(tls_path)

    out_dir.mkdir(parents=True, exist_ok=True)

    inventory = read_json(inventory_path)

    certs = inventory.get("artifacts", {}).get("certificates", [])

    now = datetime.utcnow()
    counts_by_algo: Dict[str, int] = {}
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

    # Build TLS table rows (if present)
    tls_section_html = ""
    if tls_results is not None:
        rows = []
        for r in tls_results:
            host = r.get("host")
            port = r.get("port")
            success = r.get("success", False)
            protocol = r.get("protocol")
            cipher_suite = r.get("cipher_suite")
            cert = r.get("certificate") or {}
            cert_not_after = cert.get("not_after") or cert.get("notAfter")
            err = r.get("error")

            rows.append(
                "<tr>"
                f"<td>{safe_str(host)}:{safe_str(port)}</td>"
                f"<td>{'true' if success else 'false'}</td>"
                f"<td>{safe_str(protocol)}</td>"
                f"<td>{safe_str(cipher_suite)}</td>"
                f"<td>{safe_str(cert_not_after)}</td>"
                f"<td>{safe_str(err)}</td>"
                "</tr>"
            )

        tls_section_html = f"""
<h2>TLS Endpoint Summary</h2>

<table>
  <tr>
    <th>Target</th>
    <th>Success</th>
    <th>Protocol</th>
    <th>Cipher Suite</th>
    <th>Cert Not After</th>
    <th>Error</th>
  </tr>
  {''.join(rows)}
</table>
"""

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
    th, td {{ border: 1px solid #ccc; padding: 6px 10px; vertical-align: top; }}
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

{tls_section_html}

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
