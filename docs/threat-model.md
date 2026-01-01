Threat Model



This document describes the threat assumptions and risk framing used by the pqc-readiness-kit. It is intended to clarify scope, avoid overclaiming, and ensure findings are interpreted correctly.



Threats in Scope

Harvest Now, Decrypt Later (HNDL)



The primary long-term risk addressed by this toolkit is harvest now, decrypt later:



Encrypted traffic or data is captured today



Decryption occurs in the future once large-scale cryptographically relevant quantum computers are available



Public-key cryptography used for key exchange or digital signatures is the primary exposure vector



This risk is especially relevant for:



Data with long confidentiality requirements



Archived encrypted communications



Long-lived credentials or certificates



Cryptographic Dependency Risk



Even without quantum adversaries, organizations face risk from:



Unknown cryptographic dependencies



Legacy algorithms remaining in production



Weak or expired certificates still referenced by services



Hard-coded algorithm assumptions in applications



This toolkit treats cryptographic sprawl and opacity as a risk multiplier.



Threats Out of Scope



This toolkit does not attempt to model or detect:



Active exploitation or intrusion



Side-channel attacks



Insider threats



Malware or persistence mechanisms



Misuse of valid credentials



Those risks require different tooling and operational controls.



Assumptions



The threat model makes the following assumptions:



Cryptographically relevant quantum computers are not yet available



Organizations have limited visibility into where cryptography is used



Migration to post-quantum cryptography will be incremental and vendor-driven



Symmetric cryptography remains viable with appropriate key lengths



Risk Interpretation Guidance



Presence of RSA or ECC does not imply immediate vulnerability

It indicates future migration relevance.



Weak cryptographic hygiene does represent current risk

Issues such as SHA-1, weak keys, or expired certificates should be remediated regardless of quantum timelines.



Inventory findings are inputs to planning, not conclusions

They should inform architecture decisions, vendor engagement, and roadmap sequencing.



Intended Audience



This threat model is written for:



Security engineers



Infrastructure and platform teams



Architects and technical leadership



Risk and compliance stakeholders



It is intentionally conservative and avoids speculative claims.

