#!/usr/bin/env python3
"""
scan_tls.py

Read-only TLS endpoint scanner.
Collects certificate chain metadata and negotiated public-key details
without aggressive probing.

Intended for PQC readiness inventory, not vulnerability scanning.
"""

import argparse
import json
import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, Any, List


def scan_target(host: str, port: int, timeout: int) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "host": host,
        "port": port,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "success": False,
    }

    context = ssl.create_default_context()

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()

                result.update({
                    "success": True,
                    "protocol": ssock.version(),
                    "cipher_suite": cipher[0] if cipher else None,
                    "key_exchange": cipher[1] if cipher else None,
                    "cipher_bits": cipher[2] if cipher else None,
                    "certificate": {
                        "subject": cert.get("subject"),
                        "issuer": cert.get("issuer"),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "serial_number": cert.get("serialNumber"),
                        "signature_algorithm": cert.get("signatureAlgorithm"),
                    }
                })

    except Exception as exc:
        result["error"] = str(exc)

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only TLS endpoint scanner")
    parser.add_argument("--targets", required=True, help="JSON file with host:port targets")
    parser.add_argument("--out", required=True, help="Output JSON file")
    parser.add_argument("--timeout", type=int, default=5, help="Socket timeout (seconds)")
    args = parser.parse_args()

    with open(args.targets, "r", encoding="utf-8") as f:
        targets: List[Dict[str, Any]] = json.load(f)

    results: List[Dict[str, Any]] = []

    for t in targets:
        host = t.get("host")
        port = int(t.get("port", 443))
        if not host:
            continue

        results.append(scan_target(host, port, args.timeout))

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"Wrote: {args.out}")


if __name__ == "__main__":
    main()
