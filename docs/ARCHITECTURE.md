# TrustLens Technical Architecture & Security Methodology

**Problem Statement:** AI-Powered Web Threat Detection & Digital Trust Intelligence  
**Domains:** Artificial Intelligence · Cybersecurity · Web3  
**Project Name:** TrustLens  

---

## 1. System Architecture Overview

TrustLens combines **Cybersecurity Analysis**, **Explainable Artificial Intelligence**, and **Decentralized Web3 Ledger Commitments** to detect digital deception and establish tamper-evident threat intelligence.

```
+-------------------------------------------------------------------------------+
|                                 TrustLens UI                                  |
|         (React 19 + TypeScript + Tailwind CSS Enterprise Dashboard)           |
+---------------------------------------+---------------------------------------+
                                        |  REST API / JSON
                                        v
+-------------------------------------------------------------------------------+
|                                FastAPI Backend                                |
+-------------------------------------------------------------------------------+
|  [SSRF Boundary Guard] Blocks RFC1918, loopbacks (127.0.0.1) & cloud metadata |
+-------------------------------------------------------------------------------+
|  Module 1: URL & Domain Analysis   -> Typosquatting, Homoglyphs, Entropy, DNS |
|  Module 2: TLS Web Trust Inspector -> Chain audit, key size, eMudhra advisory |
|  Module 3: AI Scam Analyzer        -> NLP vectors, urgent vs fraud separation |
|  Module 4: Threat Correlator       -> Multi-incident graph (IP, NS, Brand)    |
|  Module 5: Passive Security Audit  -> 6-key structured defensive assessment   |
|  Module 6: Web3 Threat Registry    -> Canonical SHA-256 fingerprinting        |
|  Database: SQLite (trustlens.db)   -> Relational persistence for all telemetry |
+---------------------------------------+---------------------------------------+
                                        |  Cryptographic Fingerprints Only (No PII)
                                        v
+-------------------------------------------------------------------------------+
|                        ThreatRegistry.sol (Smart Contract)                    |
|             (EVM / Sepolia - On-chain Verifiable Integrity & Disputes)        |
+-------------------------------------------------------------------------------+
```

---

## 2. Core Functional Modules & Methodology

### Module 1: Intelligent URL and Website Analysis
- **Normalization:** Converts input into canonical format (`scheme://hostname:port/path`).
- **Homoglyph & Punycode:** Detects Internationalized Domain Names (`xn--`) and character substitution attacks (e.g., `paypa1` mimicking `paypal`).
- **Typosquatting Detection:** Evaluates tokenized Levenshtein distance against known high-value targets (Chase, PayPal, Google, etc.).
- **Shannon Entropy:** Computes character frequency entropy to detect algorithmically generated domains (DGA).
- **Subdomain Depth & TLD Assessment:** Flags disposable phishing TLDs (`.xyz`, `.top`, `.buzz`, `.fit`) and deep subdomains.
- **Safe Redirection Tracing:** Traverses HTTP `3xx` redirects with strict hop limits without executing client-side scripts.
- **DNS Characteristics:** Resolves IPv4 (A), IPv6 (AAAA), Mail Exchangers (MX), Authoritative Nameservers (NS), and TXT records for SPF and DMARC anti-spoofing policies.

### Module 2: TLS Certificate and Web Trust Analysis
- **Handshake Inspection:** Extracts leaf certificate and certificate chain directly via SNI.
- **Expiration & Future-Dating:** Validates certificate validity dates and remaining active days.
- **Identity Matching:** Verifies Subject Alternative Names (SANs) and Common Name (CN) against requested hostname.
- **Cryptographic Robustness:** Flags weak RSA keys (< 2048-bit), obsolete curves, and legacy signature algorithms (SHA-1, MD5).
- **Distrusted CA Advisory (eMudhra Incident):** Cross-references issuing Certificate Authorities against known compromise advisories (including the **eMudhra** key-generation incident).
- **Certificate Transparency:** Queries `crt.sh` and embedded Signed Certificate Timestamps (SCT).
- **Digital Trust Axiom:** Enforces clear user disclaimer: *“A valid TLS certificate guarantees only encrypted transit; it does NOT prove the website is legitimate or safe.”*

### Module 3: AI-Powered Scam and Message Analysis
- **Behavioral Vectors:** Identifies urgency manipulation, financial windfalls, authority impersonation, and non-standard payment methods (gift cards, crypto transfers).
- **Entity Extraction:** Isolates embedded links, email addresses, phone numbers, and crypto wallet addresses (BTC, ETH/EVM).
- **Strict Distinction:** Adheres strictly to the requirement: *"A message should not be labelled fraudulent solely because it contains urgent or persuasive language."* Persuasive language alone remains `Suspicious` or `Low Risk`; verified technical evidence (credential solicitation, blacklisted links) is required for `High Risk`.
- **Prompt Injection Defense:** Treats message input as untrusted data using lexical boundary isolation, neutralizing developer-override directives.

### Module 4: Intelligent Threat Correlation
- Correlates submitted threat indicators across user reports.
- Links incidents sharing hosting IP addresses, Autonomous System Numbers (ASN), authoritative nameservers, or targeted brands.
- Produces AI narrative summaries grounded in deterministic connections.

### Module 5: Website Security Assessment
- Performs safe, passive defensive HTTP header inspection:
  - `Strict-Transport-Security (HSTS)`
  - `Content-Security-Policy (CSP)`
  - `X-Frame-Options` (Clickjacking mitigation)
  - `X-Content-Type-Options` (MIME sniffing defense)
  - `Referrer-Policy` & `Permissions-Policy`
  - Server banner leak detection (`Server`, `X-Powered-By`).
- **Strict 6-Key Requirement:** Every finding contains:
  1. `identified_security_issue`
  2. `technical_evidence`
  3. `potential_impact`
  4. `severity_classification`
  5. `recommended_remediation`
  6. `relevant_limitations`

### Module 6: Decentralized Threat Intelligence (Web3)
- **Strict Privacy Guarantee:** Raw URLs, personal information, emails, and message text **remain off-chain**.
- **Cryptographic Commitment:** Canonicalizes normalized findings into an immutable SHA-256 fingerprint registered on `ThreatRegistry.sol`.
- **Independent Verification:** Allows third parties and automated systems to verify report integrity, submission timestamp, and dispute status on-chain.
- **Community Disputes:** Enables decentralized dispute tracking (`disputeReport`) to flag false positives and maintain registry accountability.

---

## 3. Threat Classification Framework

| Classification | Definition |
| :--- | :--- |
| **Low Risk** | No significant malicious indicators identified across all checks. |
| **Suspicious** | One or more indicators require heightened scrutiny. |
| **High Risk** | Multiple significant indicators suggest an active security threat. |
| **Confirmed Malicious** | Corroborated by authoritative threat intelligence or verified evidence. |
| **Inconclusive** | Insufficient telemetry or blocked verification source. |
