pqc-readiness-kit

A practical, automation-first toolkit for discovering cryptographic dependencies and preparing organizations for post-quantum cryptography (PQC) migration.

This repository focuses on inventory, visibility, and prioritization—not enforcement or speculative cryptographic deployment.

Purpose

Post-quantum readiness is primarily a data and dependency problem, not an algorithm problem.

Organizations cannot plan a responsible migration to post-quantum cryptography without first understanding:

Where cryptography exists

Which systems rely on public-key algorithms

Which data requires long-term confidentiality

Which dependencies are owned internally versus vendor-managed

This toolkit provides a defensible, read-only cryptographic inventory to support that planning.

Design Principles

Read-only by default
No configuration changes, no enforcement, no credential storage.

Automation-friendly
Scriptable, repeatable, and suitable for local execution or pipelines.

Platform-native sources first
Uses Windows certificate stores, SCHANNEL configuration, IIS bindings, and standard TLS handshakes.

Preparation, not compliance
Findings represent inventory and prioritization signals, not audit results.

Conservative claims
Avoids overpromising PQC guarantees or timelines.

Repository Structure
pqc-readiness-kit/
├─ README.md
├─ LICENSE
├─ docs/
│  ├─ README.md
│  ├─ methodology.md
│  ├─ threat-model.md
│  └─ pqc-readiness-playbook.md
├─ configs/
│  ├─ targets.example.yml
│  ├─ scoring.example.yml
│  └─ tls_targets.example.json
├─ scripts/
│  ├─ pwsh/
│  │  ├─ Invoke-CryptoInventory.ps1
│  │  ├─ Collect-WindowsCerts.ps1
│  │  ├─ Collect-TlsConfig.ps1
│  │  ├─ Collect-IISBindings.ps1
│  │  ├─ Collect-WinRMListeners.ps1
│  │  └─ Collect-OpenSSHConfig.ps1
│  └─ python/
│     ├─ scan_tls.py
│     ├─ build_report.py
│     └─ README.md
├─ schema/
│  └─ crypto_inventory.schema.json
├─ samples/
│  ├─ README.md
│  └─ sample_outputs/
└─ reports/
   ├─ README.md
   └─ .gitkeep

Step 1: Windows Cryptographic Inventory

The PowerShell inventory collects cryptographic metadata from a Windows host, including:

Certificate stores (LocalMachine and CurrentUser)

Public-key algorithms and key sizes (best-effort)

Signature hash algorithms

TLS protocol posture (SCHANNEL)

IIS HTTPS bindings (optional)

WinRM listeners (optional)

Windows OpenSSH configuration (optional)

Configuration

Create local config files from the provided examples:

configs\targets.yml

configs\scoring.yml

Example files are committed; local versions are ignored by Git.

Run the inventory

From the repository root:

.\scripts\pwsh\Invoke-CryptoInventory.ps1 `
  -TargetsConfig .\configs\targets.yml `
  -ScoringConfig .\configs\scoring.yml `
  -OutputPath .\reports `
  -IncludeIIS `
  -IncludeWinRM `
  -IncludeOpenSSH

Outputs

reports\crypto_inventory.json
Full structured cryptographic inventory

reports\findings.csv
Prioritized backlog derived from hygiene and PQC relevance scoring

Generated outputs are runtime artifacts and should not be committed.

Optional: TLS Endpoint Scan (Read-Only)

The toolkit includes a Python-based TLS scanner for externally reachable services.

It collects:

Negotiated TLS protocol version

Cipher suite and key exchange metadata

Certificate validity and signature algorithm

It does not perform cipher enumeration, downgrade attempts, or active probing.

Input format

Example input file:

configs\tls_targets.example.json

Create a local tls_targets.json for testing (ignored by Git).

Run the TLS scan

From the repository root:

python .\scripts\python\scan_tls.py --targets .\configs\tls_targets.json --out .\reports\tls_scan.json

Optional: Report Builder (Stub)

A report builder entry point exists to combine inventory artifacts into shareable outputs.

The current implementation:

Validates inputs

Establishes output structure

Writes a stub file only

It does not yet generate HTML or CSV reports.

Run from the repository root:

python .\scripts\python\build_report.py `
  --inventory .\reports\crypto_inventory.json `
  --tls-scan .\reports\tls_scan.json `
  --out-dir .\reports

Documentation

Supporting documentation lives under docs/:

Methodology — how data is collected and interpreted

Threat Model — scope and assumptions around quantum risk

PQC Readiness Playbook — practical next steps for planning

Start with docs/README.md for an overview.

What This Toolkit Is Not

A vulnerability scanner

A compliance or audit tool

A post-quantum cryptography implementation

A guarantee against future cryptographic compromise

It is a preparation and visibility tool.

License

MIT License. See LICENSE for details.