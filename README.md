pqc-readiness-kit

pqc-readiness-kit is an automation-first toolkit that helps organizations inventory cryptographic dependencies and prioritize post-quantum cryptography (PQC) readiness.

This project focuses on discovery, classification, and decision support—not cryptographic enforcement. It is designed to answer a practical question most organizations cannot currently answer with confidence:

Where are we using quantum-relevant cryptography, and which dependencies matter first?

What this project does

Discovers cryptographic usage across Windows systems and services

Identifies quantum-relevant public-key dependencies (RSA, ECC, DH)

Highlights weak or legacy cryptographic hygiene

Produces machine-readable and executive-friendly reports

Generates a prioritized remediation backlog

What this project does not do

Implement or enforce PQC algorithms

Predict quantum timelines

Replace vendor cryptographic roadmaps

Perform invasive or exploitative scanning

Quantum readiness is treated as a data and dependency problem before it is a cryptography problem.

For methodology and interpretation guidance, see:

docs/methodology.md