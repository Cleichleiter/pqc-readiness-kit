#!/usr/bin/env python3
"""
build_report.py

Minimal report generator for PQC readiness.
Generates:
- report.html (basic HTML summary + optional TLS + optional Top Findings table)
- report_summary.csv (flat metrics export for exec / backlog tooling)

Inputs:
- crypto_inventory.json (required)
- tls_scan.json (optional)
- findings.csv (optional)
"""

import argparse
import csv
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


def parse_iso_datetime(value: str) -> Optional[datetime]:
    """
    Best-effort ISO datetime parsing.
    PowerShell JSON output is typically ISO 8601; if not, we skip.
    """
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


def read_findings_csv(path: Path, limit: int = 25) -> List[Dict[str, str]]:
    """
    Read findings.csv and return up to `limit` rows.
    BOM-safe and tolerant of common CSV variants.
    """
    if not path.exists():
        raise FileNotFoundError(f"Findings CSV file not found: {path}")

    rows: List[Dict[str, str]] = []

    # utf-8-sig handles BOM; newline="" is important for csv module on Windows
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Normalize None values to empty string for HTML rendering
            normalized = {k: (v if v is not None else "") for k, v in row.items()}
            rows.append(normalized)
            if len(rows) >= limit:
                break

    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Build PQC readiness report")
    parser.add_argument("--inventory", required=True, help="crypto_inventory.json")
    parser.add_argument("--tls-scan", required=False, help="tls_scan.json (optional)")
    parser.add_argument("--findings", required=False, help="findings.csv (optional)")
    parser.add_argument("--out-dir", required=True, help="Output directory")
    args = parser.parse_args()

    inventory_path = Path(args.inventory)
    out_dir = Path(args.out_dir)

    if not inventory_path.exists():
        raise FileNotFoundError(f"Inventory file not found: {inventory_path}")

    tls_results: Optional[List[Dict[str, Any]]] = None
    if args.tls_scan:
        tls_path = Path(args.tls_scan)
        if not tls_path.exists():
            raise FileNotFoundError(f"TLS scan file not found: {tls_path}")
        tls_results = read_json(tls_path)

    findings_rows: Optional[List[Dict[str, str]]] = None
    if args.findings:
        findings_path = Path(args.findings)
        findings_rows = read_findings_csv(findings_path, limit=25)

    out_dir.mkdir(parents=True, exist_ok=True)

    inventory = read_json(inventory_path)

    host = inventory.get("host", {}) or {}
    host_name = host.get("computerName")
    os_caption = host.get("osCaption")
    os_version = host.get("osVersion")

    certs = inventory.get("artifacts", {}).get("certificates", []) or []

    now = datetime.utcnow()

    counts_by_algo: Dict[str, int] = {}
    expired = 0
    expiring_30 = 0

    for c in certs:
        algo = c.get("PublicKeyAlgorithm") or "Unknown"
        counts_by_algo[algo] = counts_by_algo.get(algo, 0) + 1

        not_after = c.get("NotAfter")
        if not_after:
            na = parse_iso_datetime(not_after)
            if na:
                if na < now:
                    expired += 1
                elif (na - now).days <= 30:
                    expiring_30 += 1

    # TLS metrics (optional)
    tls_total = 0
    tls_success = 0
    tls_fail = 0

    tls_section_html = ""
    if tls_results is not None:
        tls_total = len(tls_results)
        tls_success = sum(1 for r in tls_results if r.get("success") is True)
        tls_fail = tls_total - tls_success

        rows: List[str] = []
        for r in tls_results:
            thost = r.get("host")
            tport = r.get("port")
            success = r.get("success", False)
            protocol = r.get("protocol")
            cipher_suite = r.get("cipher_suite")
            cert = r.get("certificate") or {}

            cert_not_after = cert.get("not_after") or cert.get("notAfter")
            err = r.get("error")

            rows.append(
                "<tr>"
                f"<td>{safe_str(thost)}:{safe_str(tport)}</td>"
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

    # Findings table (optional)
    findings_section_html = ""
    if findings_rows is not None:
        if len(findings_rows) == 0:
            findings_section_html = """
<h2>Top Findings</h2>
<p>No findings were present in the provided CSV.</p>
"""
        else:
            # Choose a reasonable subset of columns for display, if present.
            preferred_cols = [
                "Severity",
                "Category",
                "Title",
                "Asset",
                "Evidence",
                "Recommendation",
            ]

            available_cols = list(findings_rows[0].keys())
            cols = [c for c in preferred_cols if c in available_cols]
            if not cols:
                # Fall back to first N columns if preferred columns aren't present
                cols = available_cols[:6]

            header_html = "".join(f"<th>{safe_str(c)}</th>" for c in cols)

            row_html_parts: List[str] = []
            for r in findings_rows:
                tds = []
                for c in cols:
                    # Basic HTML escaping for angle brackets to avoid broken markup
                    v = safe_str(r.get(c, ""))
                    v = v.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    tds.append(f"<td>{v}</td>")
                row_html_parts.append("<tr>" + "".join(tds) + "</tr>")

            findings_section_html = f"""
<h2>Top Findings (Preview)</h2>

<p>This section shows the first 25 rows from the provided <strong>findings.csv</strong>. Use the CSV for the full backlog and sorting.</p>

<table>
  <tr>
    {header_html}
  </tr>
  {''.join(row_html_parts)}
</table>
"""

    # HTML report
    html = f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>PQC Readiness Summary</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 40px; }}
    h1, h2 {{ color: #333; }}
    table {{ border-collapse: collapse; margin-top: 10px; width: 100%; }}
    th, td {{ border: 1px solid #ccc; padding: 6px 10px; vertical-align: top; }}
    th {{ background-color: #f4f4f4; text-align: left; }}
    td {{ word-break: break-word; }}
  </style>
</head>
<body>

<h1>PQC Readiness Summary</h1>

<p><strong>Generated:</strong> {inventory.get("generatedAtUtc")}</p>
<p><strong>Host:</strong> {safe_str(host_name)}</p>
<p><strong>OS:</strong> {safe_str(os_caption)} ({safe_str(os_version)})</p>

<h2>Certificate Inventory Overview</h2>

<table>
  <tr>
    <th>Public Key Algorithm</th>
    <th>Count</th>
  </tr>
  {''.join(f"<tr><td>{safe_str(k)}</td><td>{v}</td></tr>" for k, v in counts_by_algo.items())}
</table>

<h2>Hygiene Signals</h2>

<ul>
  <li>Total certificates: {len(certs)}</li>
  <li>Expired certificates: {expired}</li>
  <li>Certificates expiring within 30 days: {expiring_30}</li>
</ul>

{tls_section_html}

{findings_section_html}

<p>This report provides a high-level summary only. Detailed findings are available in the CSV and JSON outputs.</p>

</body>
</html>
"""

    report_path = out_dir / "report.html"
    with report_path.open("w", encoding="utf-8") as f:
        f.write(html)

    # CSV summary export
    summary_rows: List[Dict[str, str]] = []
    summary_rows.append({"Metric": "GeneratedAtUtc", "Value": safe_str(inventory.get("generatedAtUtc"))})
    summary_rows.append({"Metric": "Host.ComputerName", "Value": safe_str(host_name)})
    summary_rows.append({"Metric": "Host.OSCaption", "Value": safe_str(os_caption)})
    summary_rows.append({"Metric": "Host.OSVersion", "Value": safe_str(os_version)})

    summary_rows.append({"Metric": "Certificates.Total", "Value": str(len(certs))})
    summary_rows.append({"Metric": "Certificates.Expired", "Value": str(expired)})
    summary_rows.append({"Metric": "Certificates.ExpiringWithin30Days", "Value": str(expiring_30)})

    for algo in sorted(counts_by_algo.keys(), key=lambda x: (x is None, str(x).lower())):
        summary_rows.append({"Metric": f"Certificates.ByAlgorithm.{algo}", "Value": str(counts_by_algo[algo])})

    summary_rows.append({"Metric": "TLSScan.Provided", "Value": "true" if tls_results is not None else "false"})
    summary_rows.append({"Metric": "TLSScan.EndpointsTotal", "Value": str(tls_total)})
    summary_rows.append({"Metric": "TLSScan.Success", "Value": str(tls_success)})
    summary_rows.append({"Metric": "TLSScan.Fail", "Value": str(tls_fail)})

    summary_rows.append({"Metric": "FindingsCSV.Provided", "Value": "true" if findings_rows is not None else "false"})
    summary_rows.append({"Metric": "FindingsCSV.TopRowsEmbedded", "Value": str(len(findings_rows) if findings_rows is not None else 0)})

    summary_path = out_dir / "report_summary.csv"
    with summary_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["Metric", "Value"])
        writer.writeheader()
        writer.writerows(summary_rows)

    print(f"Wrote: {report_path}")
    print(f"Wrote: {summary_path}")


if __name__ == "__main__":
    main()
