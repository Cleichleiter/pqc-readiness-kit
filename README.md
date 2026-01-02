\# pqc-readiness-kit



\*\*pqc-readiness-kit\*\* is an automation-first toolkit that helps organizations \*\*inventory cryptographic dependencies\*\* and \*\*prioritize post-quantum cryptography (PQC) readiness\*\*.



This project focuses on \*\*discovery, classification, and decision support\*\* — not cryptographic enforcement. It is designed to answer a practical question most organizations cannot currently answer with confidence:



> \*\*Where are we using quantum-relevant cryptography, and which dependencies matter first?\*\*



---



\## What this project does



\- Discovers cryptographic usage across Windows systems and services  

\- Identifies quantum-relevant public-key dependencies (RSA, ECC, DH)  

\- Highlights weak or legacy cryptographic hygiene  

\- Produces machine-readable and executive-friendly reports  

\- Generates a prioritized remediation backlog  



---



\## What this project does \*\*not\*\* do



\- Implement or enforce PQC algorithms  

\- Predict quantum timelines  

\- Replace vendor cryptographic roadmaps  

\- Perform invasive or exploitative scanning  



Quantum readiness is treated as a \*\*data and dependency problem before it is a cryptography problem\*\*.



For methodology and interpretation guidance, see:

\- \[`docs/methodology.md`](docs/methodology.md)



---



\## Roadmap and Project Status



This project is \*\*active but stable\*\*.



The current focus is maintaining a reliable, well-documented baseline for cryptographic inventory and post-quantum readiness planning. The existing functionality is considered complete for the initial problem scope.



Future enhancements may be added incrementally based on real-world use cases, including:



\- Active Directory Certificate Services (AD CS) inventory  

\- Expanded SSH key and crypto discovery on non-Windows platforms  

\- Vendor and product roadmap tracking for PQC migration planning  

\- Refinements to scoring and prioritization models  



There is no fixed timeline for these additions. Any future work will prioritize \*\*correctness, safety, and clarity\*\* over feature expansion.



