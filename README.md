<div align="center">
  <img src="frontend/public/logo.png" alt="TrustLens Logo" width="120" />
  <h1>TrustLens</h1>
  <p><strong>AI-Powered Web Threat Detection & Digital Trust Intelligence</strong></p>
  <p><em>Real-time defense against phishing websites, SSL/TLS compromises, and social engineering scam messages.</em></p>
</div>

---

## 🌟 What is TrustLens?

Most modern cyber threats don't attack computer code directly—they exploit human trust through fake websites, lookalike domains, deceptive SSL certificates, and social engineering messages (SMS and emails).

**TrustLens** is an all-in-one digital trust and security intelligence platform. Instead of giving you an opaque "safe" or "unsafe" binary answer, TrustLens **breaks down exactly why a link or message is dangerous**, provides transparent evidence, and records tamper-proof cryptographic proofs on a decentralized blockchain ledger.

---

## 🚀 Key Features

- **🌐 Deep URL & Phishing Inspection**
  - **Domain Typosquatting:** Flags brand impersonations (e.g. `paypa1.com` or `chase-security-login.xyz`).
  - **Homoglyphs & Punycode:** Spots deceptive lookalike characters from international alphabets (`xn--`).
  - **Entropy & DGA Analysis:** Uses Shannon entropy algorithms to catch algorithmically generated scam domains.
  - **Safe Redirection Traversal:** Safely follows redirect hops without executing harmful scripts.
  - **SSRF Shield:** Blocks requests targeting internal IPs, loopbacks (`127.0.0.1`), private subnets, and cloud metadata (`169.254.169.254`).

- **🔒 SSL/TLS Certificate & Web Security Inspector**
  - **Certificate Trust Chains:** Checks expiration dates, Subject Alternative Names (SANs), and cryptographic key strength (flags weak RSA < 2048-bit).
  - **Compromised CA Awareness:** Cross-checks with Certificate Transparency logs and known distrusted Certificate Authorities (e.g. eMudhra advisory).
  - **Defensive HTTP Headers:** Assesses `HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, and `Permissions-Policy`.

- **🤖 AI Scam & Social Engineering Analyzer**
  - **Psychological Pattern Detection:** Scans emails, SMS texts, and fake support messages for artificial urgency, panic triggers, and authority impersonation.
  - **Smart Evidence Separation:** Urgent business language alone is never labeled fraudulent without verifiable technical proof (credential harvesting, malicious links, fake contact details).
  - **Entity Extraction:** Automatically extracts embedded URLs, emails, phone numbers, and crypto wallet addresses (Bitcoin, Ethereum/EVM).
  - **Prompt Injection Defense:** Defends against adversarial override attempts in submitted text.

- **📱 QR Code Scam & Quishing Inspector**
  - **Fake Payment & Mule VPA Detection:** Flags tampered UPI / payment stickers routing funds to personal VPAs under fake municipal or merchant names.
  - **Quishing / Cloaked Phishing Links:** Unmasks shortened URLs (`bit.ly`, `tinyurl`), typosquatted login portals, and direct APK/installer sideloading links.
  - **Rogue Wi-Fi Honeypots:** Spots unencrypted Evil Twin network profiles (`WIFI:S:...;T:nopass;`) mimicking airports, hotels, and cafes.
  - **Client-Side Decoding:** Decodes images via HTML5 Canvas + jsQR client-side with clipboard paste (`Ctrl+V`) support and zero image data leakage.

- **⛓️ Web3 On-Chain Threat Registry**
  - **Decentralized Verification:** Anchors tamper-proof security reports to a Solidity smart contract (`ThreatRegistry.sol`).
  - **Strict Privacy Guarantee:** Personal data, emails, and raw URLs are **never sent to the blockchain**. Only canonical SHA-256 / Keccak-256 cryptographic fingerprints are recorded.
  - **Community Dispute Portal:** Allows independent verification and decentralized disputes for flagged reports.

- **🧩 Real-Time Browser Extension**
  - Chromium-compatible Manifest V3 extension for Google Chrome, Microsoft Edge, and Brave.
  - Real-time page safety analysis, DOM link inspection (detects insecure HTTP links and login forms), and right-click context menu shortcuts.

- **📊 SQLite Database & History**
  - Zero-configuration local database (`backend/trustlens.db`) automatically recording scan history, incident metrics, and blockchain commitments.

---

## 🏗️ Project Architecture

```
TrustLens/
├── backend/
│   ├── app/
│   │   ├── core/
│   │   │   └── ssrf.py               # Destination IP check & SSRF defense
│   │   ├── db/
│   │   │   └── database.py           # SQLite persistence for incidents, commitments & audit logs
│   │   ├── services/
│   │   │   ├── url_analyzer.py       # Typosquatting, homoglyphs, DGA entropy, redirects
│   │   │   ├── tls_analyzer.py       # Cert chains, SANs, weak crypto, eMudhra advisory
│   │   │   ├── header_scanner.py     # Passive defensive HTTP security headers
│   │   │   ├── threat_intel.py       # URLhaus & PhishTank threat feeds
│   │   │   ├── ai_scam_detector.py   # AI social engineering & prompt injection defense
│   │   │   ├── qr_analyzer.py        # QR Quishing, payment tampering & rogue Wi-Fi analysis
│   │   │   ├── threat_correlator.py  # Cross-incident campaign grouping
│   │   │   └── web3_service.py       # Cryptographic hashing & on-chain commitments
│   │   └── main.py                   # FastAPI REST API
│   ├── requirements.txt              # Python backend dependencies
│   └── tests/
│       └── test_trustlens.py         # Automated pytest test suite (15 passing tests)
├── contracts/
│   └── ThreatRegistry.sol            # Solidity smart contract for on-chain integrity
├── frontend/                         # Modern React 19 + TypeScript + Tailwind CSS UI
│   ├── src/
│   │   ├── components/
│   │   │   ├── Navbar.tsx            # Clean enterprise header with official logo
│   │   │   ├── PresetBar.tsx         # 1-Click benchmark evaluation test cases
│   │   │   ├── UrlScannerTab.tsx     # Deep URL & TLS inspection interface
│   │   │   ├── ScamAnalyzerTab.tsx   # AI scam & text threat analyzer
│   │   │   ├── QrScannerTab.tsx      # QR Code scam & Quishing detection interface
│   │   │   ├── Web3RegistryTab.tsx   # Independent on-chain verifier & disputes
│   │   │   └── ThreatFeedTab.tsx     # Campaign correlation & incident stream
│   │   ├── services/api.ts
│   │   └── App.tsx
│   └── public/logo.png               # Official TrustLens logo
├── extension/                        # Manifest V3 Chromium browser extension
│   ├── manifest.json
│   ├── background.js                 # Service worker: context menus & dynamic badge
│   ├── content.js                    # In-page link telemetry & DOM inspector
│   ├── popup.html                    # Multi-tab popup (URL, Scam NLP, Web3 Verify)
│   ├── popup.css
│   └── popup.js
├── start_backend.bat                 # 1-click launcher for FastAPI backend
├── start_frontend.bat                # 1-click launcher for React dashboard
└── run_tests.bat                     # 1-click launcher for automated test suite
```

---

## ⚡ Quick Start & Run Instructions

### 📋 Prerequisites
Make sure you have the following installed:
- **Python 3.10+** (Tested on Python 3.10, 3.11, 3.12, and 3.13)
- **Node.js 18+** & **npm**

---

### Option A: Quick 1-Click Launchers (Windows)

TrustLens provides smart, self-healing batch scripts in the project root:

1. **Start the Backend:** Double-click `start_backend.bat`  
   *(Automatically creates `venv`, installs `requirements.txt` if missing, and runs FastAPI on `http://127.0.0.1:8000`)*
2. **Start the Frontend:** Double-click `start_frontend.bat`  
   *(Automatically runs `npm install` if `node_modules` is missing, and starts the React Dashboard on `http://localhost:5173`)*
3. **Run Unit Tests:** Double-click `run_tests.bat`  
   *(Verifies test dependencies and executes all 14 unit tests in ~1.5s)*

---

### Option B: Step-by-Step Manual Setup (Cross-Platform)

#### 1. Backend Setup & Dependencies

Open a terminal in the project root folder:

```bash
# 1. Create a Python virtual environment (if not already created)
python -m venv venv

# 2. Activate the virtual environment
# On Windows (Command Prompt / PowerShell):
.\venv\Scripts\activate
# On macOS / Linux:
source venv/bin/activate

# 3. Install all required dependencies from requirements.txt
pip install -r backend/requirements.txt

# 4. Start the FastAPI backend server
# On Windows:
set PYTHONPATH=backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

# On macOS / Linux:
PYTHONPATH=backend python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

- **Backend API:** `http://127.0.0.1:8000`  
- **Interactive Swagger Documentation:** `http://127.0.0.1:8000/docs`  
- **Database:** The SQLite database (`backend/trustlens.db`) initializes automatically on startup.

---

#### 2. Frontend Setup & Dashboard

Open a new terminal window:

```bash
# 1. Navigate to the frontend directory
cd frontend

# 2. Install Node dependencies
npm install

# 3. Start the Vite development server
npm run dev
```

- **Frontend Dashboard:** `http://localhost:5173`

---

### 3. Browser Extension Installation (Chrome / Edge / Brave)

1. Open your Chromium-based browser (Chrome, Edge, Brave, Opera).
2. Go to the extensions manager:
   - In Chrome: `chrome://extensions/`
   - In Edge: `edge://extensions/`
3. Toggle on **Developer mode** (top-right corner).
4. Click **Load unpacked**.
5. Select the `extension/` folder located inside the TrustLens project directory.
6. The TrustLens shield icon will appear in your toolbar!
   - Click the icon to view in-page link telemetry and scan the active tab.
   - Right-click any link on the web and choose **Inspect Link with TrustLens**.
   - Highlight any text or SMS on a web page, right-click, and choose **Analyze Selected Text for Scams**.

---

#### 4. Run Automated Unit Tests

Ensure the Python virtual environment is activated, then run:

```bash
# On Windows:
.\run_tests.bat

# Or manually on any platform:
set PYTHONPATH=backend
python -m pytest backend/tests -v
```
---

## 🧪 Live Evaluation Benchmarks

TrustLens includes a **1-Click Benchmark Test Bar** right at the top of the dashboard for instant demonstration:

| Type | Test Target | Key Indicators Evaluated |
| :--- | :--- | :--- |
| **Benign** | `https://www.google.com` | High trust score, valid Google Trust Services TLS, clean reputation |
| **Benign** | `https://github.com` | HSTS Preloaded, Grade A+ defensive headers, established domain age |
| **Benign** | `https://www.wikipedia.org` | Non-profit baseline, robust security configuration, trusted root |
| **Suspicious** | `https://paypal-security-update.account-verification.xyz` | Brand typosquatting, high-risk `.xyz` TLD, multi-subdomain spoofing |
| **Malicious** | `https://secure-login-chase-update.com` | Phishing threat intel match, credential theft campaign correlation |
| **Malicious** | *Bank Impersonation SMS* | Urgent account lock lure, fake call-to-action, credential solicitation |

---

## 🛠️ Technology Stack

| Domain | Technology Used | Description |
| :--- | :--- | :--- |
| **Backend** | Python 3, FastAPI, Uvicorn | High-throughput asynchronous REST API |
| **Frontend** | React 19, TypeScript, Vite, Tailwind CSS | Formal enterprise dark dashboard (zero neon glows) |
| **Database** | SQLite (`trustlens.db`) | Relational persistence for scan history, threats & on-chain proofs |
| **AI & NLP** | Custom Heuristics, Shannon Entropy | Psychological manipulation detection, prompt injection defense |
| **URL Intelligence** | URLhaus, PhishTank feeds | Real-time threat feed matching and domain reputation checks |
| **Web Security** | Python `ssl`, `socket`, `dnspython` | Deep TLS chain inspection, DNS records, defensive HTTP headers |
| **Blockchain** | Solidity `^0.8.20` | EVM smart contract (`contracts/ThreatRegistry.sol`) |
| **Browser Extension** | Manifest V3 | Real-time page protection, DOM analyzer & context menus |

---

## 📜 Smart Contract Specification

* **Contract File:** `contracts/ThreatRegistry.sol`
* **Solidity Version:** `^0.8.20` (EVM Compatible)
* **Zero PII Guarantee:** Never stores raw URLs or user data on-chain. Stores only cryptographic fingerprints.
* **Core Functions:**
  - `registerReport(bytes32 _reportHash, bytes32 _indicatorHash, ThreatLevel _threatLevel, string calldata _category)`
  - `verifyReport(bytes32 _reportHash)` — Returns verification status, timestamp, threat level, and dispute count.
  - `disputeReport(bytes32 _reportHash, string calldata _reason)` — Enables community governance.

---

## 🛡️ License

Built for **HackMatrix** by **ByteCoders**.  
Licensed under the [MIT License](LICENSE).
Built for **HackMatrix** by **ByteCoders**.  
Licensed under the [MIT License](LICENSE).
