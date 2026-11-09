import asyncio
import re
import hashlib
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, parse_qs, unquote

from app.core.ssrf import validate_target_url
from app.services.url_analyzer import (
    inspect_url_structure,
    trace_redirects_safely,
    TARGET_BRANDS,
    SUSPICIOUS_TLDS
)
from app.services.threat_intel import check_threat_intelligence
from app.services.ai_scam_detector import analyze_message_content

# Known URL shorteners often used in Quishing to obscure the destination
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "ow.ly",
    "rebrand.ly", "rb.gy", "shorturl.at", "qr.link", "qrco.de", "qr-code.link"
}

# Dangerous mobile download extensions
EXECUTABLE_EXTENSIONS = {
    ".apk", ".exe", ".bat", ".cmd", ".msi", ".dmg", ".vbs", ".ps1", ".jar"
}

# Consumer payment handles frequently exploited by fraudsters claiming to be official merchants
COMMON_CONSUMER_VPA_HANDLES = {
    "okaxis", "okhdfcbank", "okicici", "oksbi", "ybl", "ibl", "axl", "paytm"
}

OFFICIAL_MERCHANT_KEYWORDS = [
    "parking", "traffic", "police", "municipal", "corporation", "challan",
    "electricity", "utility", "board", "water", "toll", "tax", "govt",
    "government", "official", "support", "helpdesk", "refund", "department"
]

def classify_qr_type(raw_data: str) -> str:
    """Classifies the primary scheme or intent encoded inside the QR code."""
    data = (raw_data or "").strip()
    lower = data.lower()
    
    if lower.startswith("http://") or lower.startswith("https://") or lower.startswith("www."):
        return "URL"
    if lower.startswith("upi://pay"):
        return "PAYMENT_UPI"
    if lower.startswith("bitcoin:") or lower.startswith("ethereum:") or lower.startswith("solana:"):
        return "PAYMENT_CRYPTO"
    if lower.startswith("wifi:"):
        return "WIFI_CONFIG"
    if lower.startswith("smsto:") or lower.startswith("sms:") or lower.startswith("tel:"):
        return "TELEPHONY_SMS"
    if lower.startswith("market://") or any(lower.endswith(ext) for ext in EXECUTABLE_EXTENSIONS):
        return "APP_DOWNLOAD"
    return "PLAIN_TEXT"

def parse_wifi_config(payload: str) -> Dict[str, Any]:
    """Parses standard WIFI: QR code payloads (WIFI:S:ssid;T:WPA;P:password;H:false;;)."""
    clean = payload[5:] if payload.lower().startswith("wifi:") else payload
    tokens = clean.split(";")
    config = {
        "ssid": "Unknown",
        "auth_type": "nopass",
        "has_password": False,
        "is_hidden": False
    }
    for token in tokens:
        if token.startswith("S:"):
            config["ssid"] = token[2:]
        elif token.startswith("T:"):
            config["auth_type"] = token[2:].upper()
        elif token.startswith("P:"):
            config["has_password"] = len(token[2:]) > 0
        elif token.startswith("H:"):
            config["is_hidden"] = token[2:].lower() == "true"
    return config

def parse_upi_payload(payload: str) -> Dict[str, Any]:
    """Parses UPI payment QR URI (upi://pay?pa=...&pn=...&am=...)."""
    parsed = urlparse(payload)
    params = parse_qs(parsed.query)
    
    vpa = params.get("pa", [""])[0]
    name = params.get("pn", [""])[0]
    amount = params.get("am", [""])[0]
    currency = params.get("cu", ["INR"])[0]
    merchant_code = params.get("mc", [""])[0]
    note = params.get("tn", [""])[0]
    
    return {
        "payee_vpa": vpa,
        "payee_name": name,
        "amount": amount,
        "currency": currency,
        "merchant_code": merchant_code,
        "note": note
    }

async def analyze_qr_payload(raw_payload: str, skip_network: bool = False) -> Dict[str, Any]:
    """
    Performs comprehensive forensic threat detection on a QR code payload:
    1. Quishing / Phishing URL detection (Entropy, Typosquatting, Homoglyphs, Redirection)
    2. Payment QR tampering (UPI mule VPAs, fake municipal / merchant spoofing)
    3. Rogue Wi-Fi honeypot detection (Evil Twin / unencrypted public SSID impersonation)
    4. Sideloading / malicious APK downloads
    5. Social engineering & prompt injection defense
    """
    payload = (raw_payload or "").strip()
    if not payload:
        return {
            "payload": "",
            "payload_type": "EMPTY",
            "overall_risk": "Clean",
            "risk_score": 0,
            "evidence": [],
            "summary": "No payload detected.",
            "recommendations": ["Ensure QR code is clear and properly scanned."],
            "sha256_hash": hashlib.sha256(b"").hexdigest()
        }

    payload_type = classify_qr_type(payload)
    evidence: List[Dict[str, Any]] = []
    risk_score = 0
    extracted_details: Dict[str, Any] = {}
    quishing_category = "Benign Payload"

    # ---------------------------------------------------------
    # Case 1: Web URL / Quishing Vector
    # ---------------------------------------------------------
    if payload_type == "URL":
        quishing_category = "Web Link / Quishing Analysis"
        url = payload if (payload.startswith("http://") or payload.startswith("https://")) else f"https://{payload}"
        
        # Check SSRF safety
        if not skip_network:
            is_safe, host, ssrf_err = validate_target_url(url)
            if not is_safe:
                evidence.append({
                    "severity": "CRITICAL",
                    "code": "SSRF_BLOCKED",
                    "title": "Private / Internal Address Target",
                    "description": f"QR code encodes a private or loopback destination ({host}): {ssrf_err}",
                    "weight": 50
                })
                risk_score += 50
        else:
            parsed_test = urlparse(url)
            host = parsed_test.hostname or ""
            if host.lower() in {"localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254"}:
                evidence.append({
                    "severity": "CRITICAL",
                    "code": "SSRF_BLOCKED",
                    "title": "Private / Internal Address Target",
                    "description": f"QR code encodes a private or loopback destination ({host})",
                    "weight": 50
                })
                risk_score += 50
        
        # Inspect URL structure
        structure = inspect_url_structure(url)
        risk_score += structure.get("risk_score", 0)
        for ind in structure.get("indicators", []):
            evidence.append({
                "severity": "HIGH" if ind.get("score_impact", 0) >= 25 or ind.get("severity") in ("HIGH", "CRITICAL") else "MEDIUM",
                "code": ind.get("code", "URL_RISK"),
                "title": ind.get("title", ind.get("name", "URL Indicator")),
                "description": ind.get("description", ""),
                "weight": ind.get("score_impact", 10)
            })

        parsed = urlparse(url)
        domain = parsed.hostname or ""
        
        # Check URL Shortener evasion
        if domain.lower() in URL_SHORTENERS:
            evidence.append({
                "severity": "HIGH",
                "code": "QR_SHORTENER_OBFUSCATION",
                "title": "URL Shortener Cloaking",
                "description": f"QR uses URL shortener '{domain}' to conceal the true landing destination.",
                "weight": 25
            })
            risk_score += 25
            quishing_category = "Cloaked Quishing URL"

        # Check direct executable / APK download
        if any(parsed.path.lower().endswith(ext) for ext in EXECUTABLE_EXTENSIONS):
            evidence.append({
                "severity": "CRITICAL",
                "code": "DIRECT_BINARY_DOWNLOAD",
                "title": "Direct Executable / APK Download",
                "description": f"QR directly prompts download of an executable installer '{parsed.path}'.",
                "weight": 45
            })
            risk_score += 45
            quishing_category = "Malicious App Sideloading"

        # Trace redirects safely
        redirect_chain = []
        if not skip_network:
            try:
                redirect_chain = await asyncio.wait_for(trace_redirects_safely(url), timeout=2.5)
            except Exception:
                redirect_chain = []

        extracted_details = {
            "url": url,
            "domain": domain,
            "protocol": parsed.scheme,
            "entropy": structure.get("entropy", 0.0),
            "redirect_hops": len(redirect_chain),
            "final_destination": redirect_chain[-1]["url"] if redirect_chain else url
        }

        # Check threat intelligence
        try:
            if not skip_network:
                threat_intel = await asyncio.wait_for(check_threat_intelligence(domain, url), timeout=2.5)
            else:
                from app.services.threat_intel import VERIFIED_THREAT_SIGNATURES
                matched = any(td in domain.lower() for td in VERIFIED_THREAT_SIGNATURES)
                threat_intel = {"matched": matched}
            if threat_intel.get("matched"):
                evidence.append({
                    "severity": "CRITICAL",
                    "code": "VERIFIED_THREAT_FEED",
                    "title": "Blacklisted Phishing / Threat Feed",
                    "description": f"Domain {domain} is flagged in authoritative threat intelligence: {threat_intel.get('description', 'Known threat entity')}",
                    "weight": 50
                })
                risk_score += 50
                quishing_category = "Confirmed Quishing Attack"
        except Exception:
            pass

    # ---------------------------------------------------------
    # Case 2: UPI Payment Tampering / Mule VPA Swapping
    # ---------------------------------------------------------
    elif payload_type == "PAYMENT_UPI":
        quishing_category = "UPI Payment QR Inspection"
        upi_data = parse_upi_payload(payload)
        extracted_details = upi_data
        vpa = upi_data["payee_vpa"].lower()
        name = upi_data["payee_name"].lower()
        vpa_handle = vpa.split("@")[-1] if "@" in vpa else ""
        
        # Check for fake merchant spoofing:
        # e.g., Name says "Municipal Traffic Police" or "Parking Authority", but VPA is personal (@ybl, @okaxis)
        has_official_keyword = any(kw in name for kw in OFFICIAL_MERCHANT_KEYWORDS)
        is_consumer_vpa = vpa_handle in COMMON_CONSUMER_VPA_HANDLES
        has_no_merchant_code = not upi_data["merchant_code"]

        if has_official_keyword and is_consumer_vpa and has_no_merchant_code:
            evidence.append({
                "severity": "CRITICAL",
                "code": "UPI_MERCHANT_SPOOFING",
                "title": "Deceptive Merchant Name Mismatch",
                "description": f"Display name claims official authority ('{upi_data['payee_name']}'), but routes funds to an unverified consumer VPA ('{vpa}').",
                "weight": 45
            })
            risk_score += 45
            quishing_category = "Payment QR Tampering (Mule VPA)"

        # Check for pre-filled unexpected high transaction amounts
        try:
            amt = float(upi_data["amount"])
            if amt > 2000.0:
                evidence.append({
                    "severity": "MEDIUM",
                    "code": "HIGH_PRESET_AMOUNT",
                    "title": "High Pre-filled Payment Amount",
                    "description": f"QR requests an immediate auto-filled transfer of {upi_data['currency']} {amt:.2f}.",
                    "weight": 15
                })
                risk_score += 15
        except (ValueError, TypeError):
            pass

        if not vpa:
            evidence.append({
                "severity": "HIGH",
                "code": "MALFORMED_UPI_VPA",
                "title": "Missing or Malformed Payee VPA",
                "description": "UPI payment payload lacks a valid virtual payment address (pa).",
                "weight": 30
            })
            risk_score += 30

    # ---------------------------------------------------------
    # Case 3: Cryptocurrency Wallet / Drainer Vector
    # ---------------------------------------------------------
    elif payload_type == "PAYMENT_CRYPTO":
        quishing_category = "Cryptocurrency Payment QR"
        parsed = urlparse(payload)
        crypto_type = parsed.scheme.upper()
        crypto_address = parsed.path
        extracted_details = {
            "crypto_type": crypto_type,
            "address": crypto_address,
            "query": parsed.query
        }
        
        # Check for suspicious smart contract function calls or token approval data
        if "data=" in parsed.query.lower() or "approve" in parsed.query.lower():
            evidence.append({
                "severity": "CRITICAL",
                "code": "CRYPTO_DRAINER_APPROVAL",
                "title": "Suspicious Token Approval Intent",
                "description": "QR encodes an external contract invocation or token approval signature.",
                "weight": 50
            })
            risk_score += 50
            quishing_category = "Malicious Crypto Drainer"

    # ---------------------------------------------------------
    # Case 4: Rogue Wi-Fi Honeypot (Evil Twin)
    # ---------------------------------------------------------
    elif payload_type == "WIFI_CONFIG":
        quishing_category = "Wi-Fi Access Profile"
        wifi_data = parse_wifi_config(payload)
        extracted_details = wifi_data
        ssid = wifi_data["ssid"].lower()
        auth_type = wifi_data["auth_type"]

        # Evil twin honeypot: Public airport/hotel/bank SSID without encryption
        public_brand_match = any(b in ssid for b in ["airport", "free", "guest", "starbucks", "hotel", "metro", "bank", "rail"])
        if auth_type in ("NOPASS", "") and public_brand_match:
            evidence.append({
                "severity": "HIGH",
                "code": "WIFI_HONEYPOT_PROFILE",
                "title": "Unencrypted Public Honeypot Risk",
                "description": f"QR advertises an unencrypted network ('{wifi_data['ssid']}') mimicking a public Wi-Fi brand without WPA/WPA2 security.",
                "weight": 40
            })
            risk_score += 40
            quishing_category = "Rogue Wi-Fi Honeypot"

    # ---------------------------------------------------------
    # Case 5: Automated Telephony / SMS Intent
    # ---------------------------------------------------------
    elif payload_type == "TELEPHONY_SMS":
        quishing_category = "Telephony / SMS Trigger"
        extracted_details = {"raw": payload}
        # Flag premium SMS or toll fraud
        if any(payload.startswith(pfx) for pfx in ["tel:+882", "tel:+881", "tel:1900", "smsto:+882"]):
            evidence.append({
                "severity": "HIGH",
                "code": "PREMIUM_RATE_FRAUD",
                "title": "International Premium-Rate Destination",
                "description": "QR attempts to automatically dial or SMS a known satellite or high-cost toll number.",
                "weight": 40
            })
            risk_score += 40
            quishing_category = "Premium Toll Fraud"

    # ---------------------------------------------------------
    # Case 6: Plain Text / Social Engineering
    # ---------------------------------------------------------
    else:
        quishing_category = "Text / Information Content"
        nlp_analysis = analyze_message_content(payload)
        risk_score += nlp_analysis.get("risk_score", 0)
        extracted_details = {
            "length": len(payload),
            "preview": payload[:120] + ("..." if len(payload) > 120 else "")
        }
        for ind in nlp_analysis.get("indicators", []):
            evidence.append({
                "severity": "HIGH" if ind.get("score_impact", 0) >= 30 else "MEDIUM",
                "code": ind.get("code", "NLP_INDICATOR"),
                "title": ind.get("name", "Social Engineering Trigger"),
                "description": ind.get("description", ""),
                "weight": ind.get("score_impact", 10)
            })

    # Bound risk score between 0 and 100
    risk_score = min(max(risk_score, 0), 100)
    
    # Classify overall risk level based on score & critical forensic evidence
    has_critical = any(ind.get("severity") == "CRITICAL" for ind in evidence)
    has_high = any(ind.get("severity") == "HIGH" for ind in evidence)

    if risk_score >= 70 or has_critical:
        overall_risk = "Confirmed Malicious" if (risk_score >= 75 or has_critical) else "High Risk"
        risk_score = max(risk_score, 75 if overall_risk == "Confirmed Malicious" else 60)
    elif risk_score >= 35 or has_high:
        overall_risk = "High Risk"
        risk_score = max(risk_score, 55)
    elif risk_score >= 15:
        overall_risk = "Suspicious"
        risk_score = max(risk_score, 25)
    else:
        overall_risk = "Clean"

    # Generate tailored mitigation guidance
    recommendations: List[str] = []
    if overall_risk in ("Confirmed Malicious", "High Risk"):
        if payload_type == "URL":
            recommendations.append("Do not open this link or input login credentials, OTPs, or bank details.")
            recommendations.append("Verify the organization's official domain directly through a trusted search engine.")
        elif payload_type == "PAYMENT_UPI":
            recommendations.append("Do not approve this transaction. The recipient name does not match an authentic merchant.")
            recommendations.append("Report physical sticker tampering to local staff or law enforcement.")
        elif payload_type == "WIFI_CONFIG":
            recommendations.append("Do not connect your device. Rogue Wi-Fi networks can intercept unencrypted traffic.")
        else:
            recommendations.append("Exercise extreme caution. Do not trust unsolicited instructions inside this QR code.")
    else:
        recommendations.append("Payload structure appears standard. Verify destination before submitting sensitive information.")

    # Generate tamper-proof cryptographic fingerprint
    report_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    return {
        "payload": payload,
        "payload_type": payload_type,
        "quishing_category": quishing_category,
        "overall_risk": overall_risk,
        "risk_score": risk_score,
        "evidence": evidence,
        "details": extracted_details,
        "recommendations": recommendations,
        "sha256_hash": report_hash
    }
