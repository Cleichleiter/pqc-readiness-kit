PQC Readiness Playbook



This playbook provides practical guidance for interpreting outputs from the pqc-readiness-kit and translating inventory results into actionable next steps.



The intent is to support measured, defensible preparation for post-quantum cryptography—not immediate migration.



How to Use This Playbook



Run the Windows cryptographic inventory.



Review findings.csv to understand hygiene and relevance signals.



Classify findings into short-term remediation versus long-term tracking.



Use the inventory to inform vendor discussions and roadmap planning.



This playbook assumes no post-quantum cryptography is being deployed yet.



Phase 1: Cryptographic Hygiene (Do Now)



These actions reduce risk today and simplify future migration.



Prioritize Immediate Remediation



Address findings related to:



SHA-1 signature algorithms



Weak public key sizes



Expired or near-expiry certificates



Certificates with unclear ownership or purpose



These issues represent current operational and security risk, independent of quantum timelines.



Reduce Cryptographic Sprawl



Use the inventory to:



Identify duplicate or unused certificates



Remove certificates no longer referenced by services



Consolidate certificate issuance practices



Document ownership for each certificate and service



Reducing sprawl lowers migration complexity later.



Phase 2: Identify Post-Quantum–Relevant Dependencies



Not all cryptography needs the same urgency.



Focus on Public-Key Usage



Pay particular attention to:



RSA and ECC used for key exchange or signatures



Certificates tied to externally exposed services



Certificates protecting long-lived data or archives



These represent future migration pressure points.



Classify by Data Longevity



Ask for each identified dependency:



How long must the protected data remain confidential?



Is the data archived or transient?



Can encryption be re-applied later if needed?



Long-lived confidentiality increases priority for post-quantum planning.



Phase 3: Vendor and Platform Readiness



Most post-quantum migration will be vendor-driven.



Use the inventory to:



Identify platforms and products relying on RSA/ECC



Track vendor statements on PQC support



Document expected timelines for algorithm agility



Flag systems with hard-coded or inflexible cryptographic assumptions



The goal is visibility, not immediate replacement.



Phase 4: Prepare for Algorithm Agility



Before deploying new algorithms, organizations should ensure:



Cryptographic configuration is centralized where possible



Algorithms and key sizes are configurable, not hard-coded



Certificate lifetimes align with expected migration timelines



Teams understand where cryptography is enforced versus inherited



Algorithm agility is often a prerequisite for PQC adoption.



What Not to Do



Do not attempt ad-hoc PQC deployments



Do not replace cryptography without vendor support



Do not treat inventory findings as compliance failures



Do not assume all RSA/ECC usage must be eliminated immediately



Preparation is about sequencing and readiness, not urgency-driven change.



Outcome of This Playbook



Following this playbook should result in:



Cleaner cryptographic posture today



Reduced future migration complexity



Informed vendor engagement



A defensible, documented approach to post-quantum readiness



This playbook is intentionally conservative and designed to evolve as standards and vendor support mature.

