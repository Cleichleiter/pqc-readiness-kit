A Windows-first, automation-focused toolkit for inventorying cryptographic dependencies and identifying post-quantum–relevant exposure.

This repository is an inventory and prioritization tool, not a security control. It is designed to help organizations understand where cryptography is used today, what types of algorithms and keys are present, and which findings should be addressed immediately versus tracked for future migration planning.

Purpose

Post-quantum readiness is fundamentally a visibility problem.

Before an organization can responsibly plan or sequence a transition to post-quantum cryptography, it must first be able to answer:

Where cryptography is in use

Which public-key algorithms and key sizes are present

Which uses are tied to long-lived confidentiality

Which issues represent hygiene gaps versus strategic risk

This project addresses that foundational discovery problem.

Design Principles

Windows-first
Focused on Windows environments using native APIs and configuration sources.

Read-only execution
No configuration changes, enforcement actions, or remediation steps are performed.

Automation-friendly
Designed for repeatable execution and future pipeline integration.

Least-privilege aware
No credential storage and minimal privilege assumptions.

Actionable output
Produces structured data and a prioritized backlog suitable for engineering and security planning.

Scope (Step 1)
Windows Cryptographic Inventory

The toolkit collects cryptographic metadata locally using PowerShell and native Windows interfaces.

Collected data includes:

Certificate stores

LocalMachine and CurrentUser

Subject, Issuer, Thumbprint

Public key algorithm and key size

Signature hash algorithm

Enhanced Key Usage (EKU)

Validity period

TLS posture (SCHANNEL)

Enabled protocol versions (coarse)

Cipher suite policy (if configured)

IIS bindings (when IIS is installed)

HTTPS bindings and associated certificate thumbprints

WinRM listeners

HTTP and HTTPS listener configuration

Windows OpenSSH posture (when installed)

Host key configuration (best-effort inspection)

All collection is read-only.

Out of Scope

This repository does not:

Implement post-quantum cryptography

Modify system configuration

Perform vulnerability exploitation

Scan networks or endpoints remotely

Claim quantum resistance or compliance

It is intentionally scoped to inventory and prioritization.

Repository Structure (Step 1)

The repository is organized to clearly separate documentation, configuration, collection scripts, schemas, and generated outputs.

pqc-readiness-kit/

docs/

methodology.md

threat-model.md

pqc-readiness-playbook.md

configs/

targets.example.yml

scoring.example.yml

scripts/

pwsh/

Invoke-CryptoInventory.ps1

Collect-WindowsCerts.ps1

Collect-TlsConfig.ps1

Collect-IISBindings.ps1

Collect-WinRMListeners.ps1

Collect-OpenSSHConfig.ps1

schema/

crypto_inventory.schema.json

reports/

.gitkeep

Execution Model

All commands are executed from the repository root.

The repository contains:

PowerShell collection scripts

Configuration files

Documentation and schemas

It does not include:

Scheduled tasks

Orchestration wrappers

CI/CD pipelines

Step 1 — Run Windows Cryptographic Inventory
Prerequisites

PowerShell 7.x recommended

YAML support available (ConvertFrom-Yaml)

Local administrative access improves coverage but is not strictly required

Configuration

Create working configuration files by copying the examples:

configs/targets.example.yml → configs/targets.yml

configs/scoring.example.yml → configs/scoring.yml

Adjust values to reflect your environment and risk tolerance.

Execute Inventory

Run the inventory from the repository root:

pwsh -File .\scripts\pwsh\Invoke-CryptoInventory.ps1 `
  -TargetsConfig .\configs\targets.yml `
  -ScoringConfig .\configs\scoring.yml `
  -OutputPath .\reports `
  -IncludeIIS `
  -IncludeWinRM `
  -IncludeOpenSSH

Outputs

The following artifacts are generated under the reports directory:

crypto_inventory.json
Complete structured cryptographic inventory.

findings.csv
Prioritized remediation backlog suitable for sorting and filtering.

Scoring Overview

Scoring is configurable and intentionally conservative:

Presence of public-key cryptography (RSA, ECC, DH) increases post-quantum relevance

Weak or deprecated cryptography increases urgency

Expired or near-expiry certificates increase priority

Long-lived confidentiality requirements raise overall risk

All thresholds and weights are defined in configs/scoring.yml.

Security Considerations

Read-only execution

No credentials stored

No secrets collected

Suitable for regulated and audited environments

License

Select an open-source license appropriate for your intended distribution. MIT and Apache 2.0 are commonly used for tooling repositories.