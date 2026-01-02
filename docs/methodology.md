Methodology

Purpose



The pqc-readiness-kit is an automation-first toolkit designed to help organizations inventory cryptographic dependencies and prioritize post-quantum cryptography (PQC) readiness efforts.



This project does not attempt to implement or enforce PQC algorithms. Instead, it focuses on discovery, classification, and decision support.



Quantum readiness is a data and dependency problem before it is a cryptography problem.



Scope



This toolkit addresses three core questions:



Where is cryptography used across systems and services?



Which cryptographic mechanisms are quantum-relevant?



Which dependencies require near-term action based on exposure and data longevity?



Discovery Approach

Endpoint and Server Inventory (Windows)



The toolkit performs read-only discovery of:



Certificate stores (machine and user)



Key algorithm



Key size



Signature hash



EKU



Expiry



TLS configuration



Enabled protocol versions



Cipher suite policy



Service bindings



IIS HTTPS bindings



WinRM listeners



RDP TLS posture



SSH configuration



Key types and algorithms (Windows OpenSSH)



No cryptographic material is exported or modified.



Network-Facing TLS Discovery (Optional)



TLS endpoint scanning performs certificate-only inspection:



Certificate chain metadata



Public key algorithm and size



Expiration dates



Supported protocol versions (coarse)



The scanner avoids active exploitation techniques and aggressive probing.



Quantum Relevance Classification



The toolkit uses technology-class classification, not speculative attack timelines.



Quantum-Relevant (Public-Key)



RSA



ECC (ECDSA, ECDH)



Diffie-Hellman



These algorithms are vulnerable to Shor’s algorithm in a sufficiently capable quantum environment.



Quantum-Resistant (Symmetric / Hash)



AES



SHA-2 / SHA-3



These remain viable with adjusted key sizes under Grover’s algorithm.



Risk Factors Considered



Findings are prioritized using the following signals:



Exposure



Internet-facing vs internal



Cryptographic hygiene



Weak key sizes



Deprecated hash algorithms



Legacy protocol support



Data longevity



Long-lived confidentiality requirements



Operational coupling



Hard-coded or vendor-embedded crypto



The output is a prioritized remediation backlog, not a compliance score.



Outputs



The toolkit generates:



crypto\_inventory.json

Canonical machine-readable inventory



findings.csv

Sortable remediation backlog



report.html

Executive and engineering-friendly summary



Safety and Operational Guidance



Read-only by default



No credential storage



Supports least-privilege execution



Intended for environments you own or are authorized to assess



Limitations



Does not assess PQC algorithm implementations



Does not replace vendor cryptographic roadmaps



Does not determine quantum timelines



The toolkit is a planning accelerator, not a cryptographic enforcement mechanism.

