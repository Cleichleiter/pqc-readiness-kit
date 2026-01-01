Methodology



This document describes the collection approach, data sources, and interpretation logic used by the pqc-readiness-kit.



The goal of this toolkit is to provide a defensible, repeatable cryptographic inventory that supports post-quantum readiness planning without altering system configuration or introducing operational risk.



Guiding Principles



Read-only collection

All data is gathered without modifying system state.



Native data sources

Wherever possible, inventory is derived from Windows-native APIs, certificate providers, and registry configuration.



Best-effort posture assessment

Some cryptographic properties vary by provider and platform. The toolkit captures what is reliably available and avoids unsafe assumptions.



Preparation, not enforcement

Findings represent inventory and prioritization signals, not compliance assertions.



Data Sources

Certificate Inventory



Certificates are collected from the following stores:



LocalMachine\\My



LocalMachine\\Root



LocalMachine\\CA



CurrentUser\\My



For each certificate, the toolkit records:



Subject and Issuer



Thumbprint and Serial Number



Validity period



Public key algorithm and key size (best-effort)



Signature hash algorithm



Enhanced Key Usage (EKU)



Private key presence indicator



Key size detection is performed using multiple fallback methods to support different cryptographic providers and PowerShell versions.



TLS Configuration (SCHANNEL)



TLS posture is inferred from registry configuration under:



HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols



The toolkit records protocol enablement for both client and server roles when present.



Cipher suite policy is captured from Group Policy configuration if defined. Absence of a policy does not imply insecure defaults; it indicates that system defaults are in use.



IIS Bindings



When IIS is installed and management tools are available, the toolkit enumerates site bindings to identify:



HTTPS endpoints



Certificate thumbprints associated with bindings



SNI and SSL flag configuration (when accessible)



This data is used to correlate certificates with externally exposed services.



WinRM Listeners



WinRM listener configuration is captured using read-only enumeration. Listener data is preserved in raw form to avoid misinterpretation across Windows versions and policy configurations.



Windows OpenSSH



When the OpenSSH Server feature is present, the toolkit performs a best-effort inspection of sshd\_config to capture:



Host key declarations



Explicit algorithm constraints, if configured



The toolkit does not attempt to validate runtime key material or active sessions.



Interpretation Notes



Absence of data does not imply absence of cryptography

Some services rely on implicit defaults or dynamically negotiated parameters.



Key size values may be null

This occurs when providers do not expose size information in a consistent manner. Null values are preserved rather than guessed.



Inventory does not equal vulnerability

Findings identify where cryptography exists, not whether it is exploitable.



Intended Use



This methodology supports:



Cryptographic hygiene assessment



Post-quantum migration planning



Asset and dependency discovery



Engineering backlog prioritization



It is not intended to replace formal cryptographic validation or compliance audits.

