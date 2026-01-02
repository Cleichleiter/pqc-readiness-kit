Python Utilities



This directory contains Python-based utilities used for read-only, network-facing cryptographic discovery.



These scripts are intentionally scoped and do not perform active vulnerability scanning.



TLS Endpoint Scanner



File: scan\_tls.py



The TLS scanner inspects externally reachable TLS endpoints and records:



Negotiated TLS protocol version



Cipher suite and key exchange metadata



Certificate validity period and signature algorithm



Timestamped results for inventory correlation



The scanner uses standard TLS handshakes only and avoids cipher enumeration, downgrade attempts, or aggressive probing.



Input Format



The scanner expects a JSON file containing a list of targets:



Hostname



TCP port (default 443)



An example input file is provided:



configs/tls\_targets.example.json



Running the Scanner



From the repository root:



python scripts/python/scan\_tls.py --targets configs/tls\_targets.json --out reports/tls\_scan.json





Generated output files are runtime artifacts and should not be committed to source control.



Intended Use



This utility supports:



Cryptographic dependency discovery



Identification of public-key usage in exposed services



Post-quantum readiness planning



It is not intended to replace full TLS assessment or compliance tooling.

