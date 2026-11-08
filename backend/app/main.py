import os
import asyncio
from urllib.parse import urlparse
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.core.ssrf import validate_target_url
from app.services.url_analyzer import inspect_url_structure, trace_redirects_safely
from app.services.dns_analyzer import analyze_dns_characteristics
from app.services.tls_analyzer import analyze_certificate_chain
from app.services.header_scanner import inspect_security_headers
from app.services.threat_intel import check_threat_intelligence
from app.services.ai_scam_detector import analyze_message_content
from app.services.threat_correlator import (
    record_investigation_incident,
    find_campaign_correlations,
    get_all_recent_incidents
)
from app.services.web3_service import (
    canonical_hash_report,
    register_threat_commitment_on_chain,
    verify_report_integrity_on_chain,
    dispute_report_on_chain,
    get_recent_on_chain_records,
    DEFAULT_CONTRACT_ADDRESS
)
from app.db import log_scan, get_db_stats, get_scan_history

app = FastAPI(
    title="TrustLens Security Intelligence Engine",
    description="AI-Powered Web Threat Detection & Digital Trust Intelligence (Cybersecurity + AI + Web3)",
    version="1.2.0"
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request Models
class UrlAnalysisRequest(BaseModel):
    url: str = Field(..., description="Target URL or domain to investigate")

class MessageAnalysisRequest(BaseModel):
    text: str = Field(..., description="Suspicious email, SMS, or communication message text")

class Web3RegisterRequest(BaseModel):
    report_data: Dict[str, Any]
    indicator: str
    threat_level: str
    category: str
    campaign_name: Optional[str] = "Ad-hoc Phishing Investigation"
    evidence_refs: Optional[List[str]] = None
    report_hash: Optional[str] = None

class Web3DisputeRequest(BaseModel):
    report_hash: str
    reason: str
    disputer: Optional[str] = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

class SubmitIncidentRequest(BaseModel):
    indicator: str
    campaign_name: str
    incident_summary: str
    threat_category: str
    risk_level: str
    brand_targeted: Optional[str] = "Unknown"
    supporting_evidence_refs: Optional[List[str]] = None

# Endpoints
@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "TrustLens Engine v1.2",
        "database": get_db_stats(),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.get("/api/db/stats")
def database_statistics_endpoint():
    """Returns real-time status and table metrics from the persistent SQLite database."""
    return get_db_stats()

@app.get("/api/history")
def scan_history_endpoint(limit: int = 50):
    """Retrieves recent investigative audit logs from SQLite."""
    return {
        "scans": get_scan_history(limit=limit),
        "count": len(get_scan_history(limit=limit))
    }

@app.get("/api/presets")
def get_test_presets():
    """
    Mandatory MVP Requirement (Section 7):
    Provides at least three suspicious and three benign test cases for live demonstrations.
    """
    return {
        "benign_cases": [
            {
                "id": "benign-1",
                "type": "url",
                "name": "Google Search Portal",
                "value": "https://www.google.com",
                "description": "Legitimate global search engine with valid TLS, strong headers, and trusted infrastructure."
            },
            {
                "id": "benign-2",
                "type": "url",
                "name": "GitHub Platform",
                "value": "https://github.com",
                "description": "Developer platform with HSTS preloaded, trusted certificate authority, and no deceptive indicators."
            },
            {
                "id": "benign-3",
                "type": "url",
                "name": "Wikipedia Encyclopedia",
                "value": "https://www.wikipedia.org",
                "description": "Non-profit reference portal adhering to strict security baselines and verified benign reputation."
            }
        ],
        "suspicious_cases": [
            {
                "id": "suspicious-1",
                "type": "url",
                "name": "PayPal Typosquatting / Credential Phishing",
                "value": "https://paypal-security-update.account-verification.xyz",
                "description": "Deceptive brand impersonation on a high-risk TLD (.xyz) with credential harvesting tokens."
            },
            {
                "id": "suspicious-2",
                "type": "url",
                "name": "Chase Banking Phishing Host",
                "value": "https://secure-login-chase-update.com",
                "description": "Listed in authoritative threat intelligence datasets as an active financial credential lure."
            },
            {
                "id": "suspicious-3",
                "type": "message",
                "name": "Urgent Bank Impersonation SMS",
                "value": "URGENT NOTICE: Your Chase account access has been restricted due to unauthorized login attempts. You must verify your credentials and OTP immediately at https://chase-auth-verification.com within 24 hours to prevent permanent closure and legal investigation.",
                "description": "Social engineering attack exhibiting high urgency, institutional impersonation, and credential phishing."
            },
            {
                "id": "suspicious-4",
                "type": "url",
                "name": "eMudhra Compromised CA Incident Demo",
                "value": "https://emudhra-compromised-demo.bank-auth.com",
                "description": "Demonstrates detection of distrusted / compromised CA certificate chains (eMudhra incident advisory scenario)."
            }
        ]
    }

@app.post("/api/analyze/url")
async def analyze_url_endpoint(req: UrlAnalysisRequest):
    """
    Core Functional Pipeline (Modules 1, 2, 4, 5, 6 & Section 6):
    1. SSRF & Safe Destination Validation
    2. URL Structure, Typosquatting & Entropy Analysis (Module 1)
    3. Safe Redirect Chain Traversal (Module 1)
    4. DNS & Domain Characteristics (Module 1, Item 6)
    5. TLS Certificate, Trust Chain & Certificate Transparency (Module 2)
    6. Passive HTTP Security Assessment (Module 5)
    7. Authoritative Threat Intelligence Query (Module 1 & 7)
    8. Deterministic Threat Correlation & Campaign Detection (Module 4)
    9. Synthesized Evidence-Based Risk Classification (Section 6)
    10. Canonical Web3 Cryptographic Fingerprinting (Module 6)
    """
    raw_url = req.url.strip()
    is_safe, canonical_url, ssrf_err = validate_target_url(raw_url)
    
    if not is_safe:
        empty_hash = "0x" + canonical_hash_report({"risk_classification": "Inconclusive", "risk_score": 0})
        return {
            "target_url": raw_url,
            "hostname": raw_url,
            "overall_risk": "Inconclusive",
            "overall_risk_classification": "Inconclusive",
            "risk_score": 0,
            "is_blocked": True,
            "error": ssrf_err,
            "explanation": f"Investigation halted by SSRF boundary protection: {ssrf_err}",
            "identified_threat_indicators": [{
                "code": "SSRF_BLOCKED",
                "title": "Destination Blocked by SSRF Policy",
                "description": ssrf_err or "Target points to internal or loopback IP range.",
                "severity": "CRITICAL",
                "source": "SSRF Boundary Guard"
            }],
            "identified_suspicious_indicators": [{
                "code": "SSRF_BLOCKED",
                "title": "Destination Blocked by SSRF Policy",
                "description": ssrf_err or "Target points to internal or loopback IP range.",
                "severity": "CRITICAL",
                "source": "SSRF Boundary Guard"
            }],
            "supporting_technical_evidence": {},
            "supporting_evidence": {},
            "sources_of_findings": ["SSRF Boundary Guard"],
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
            "confidence_score": 100,
            "confidence_or_evidence_coverage": "100% boundary check",
            "evidence_coverage": "Boundary check only",
            "recommended_actions": ["Do not attempt to scan internal network services or loopback addresses."],
            "recommended_precautions": ["Do not attempt to scan internal network services or loopback addresses."],
            "limitations_and_unavailable_checks": "Scan blocked due to internal IP range or loopback address protection policy.",
            "url_heuristics": {
                "canonical_url": raw_url,
                "hostname": raw_url,
                "tld": "",
                "entropy": 0.0,
                "risk_score": 0,
                "indicators": []
            },
            "dns_analysis": {
                "dns_data": {
                    "hostname": raw_url,
                    "a_records": [],
                    "aaaa_records": [],
                    "mx_records": [],
                    "ns_records": [],
                    "txt_records": [],
                    "has_spf": False,
                    "has_dmarc": False,
                    "is_resolvable": False
                },
                "findings": []
            },
            "redirect_analysis": {
                "redirect_count": 0,
                "chain": [],
                "final_url": raw_url,
                "cross_domain_redirect": False
            },
            "tls_analysis": {
                "has_tls": False,
                "status": "Suspicious",
                "findings": []
            },
            "security_headers": {
                "scanned": False,
                "score": 0,
                "grade": "N/A",
                "present_headers": {},
                "findings": [],
                "missing_headers": [],
                "information_disclosure": [],
                "limitations": "SSRF blocked"
            },
            "threat_intelligence": {
                "matched": False,
                "provider": "Threat Intel",
                "threat_type": "None",
                "tags": [],
                "confidence_score": 0,
                "reference_status": "Clean",
                "description": "None"
            },
            "campaign_correlations": {
                "is_part_of_campaign": False,
                "campaign_confidence": 0,
                "summary": "None",
                "correlated_incidents_count": 0,
                "correlated_incidents": [],
                "common_factors": [],
                "methodology": "None"
            },
            "web3_fingerprint": {
                "report_hash": empty_hash,
                "smart_contract": DEFAULT_CONTRACT_ADDRESS,
                "tamper_proof_status": "Blocked from on-chain submission"
            }
        }

    parsed = urlparse(canonical_url)
    hostname = parsed.hostname or ""

    # 1. URL Structure & Heuristic Analysis (Module 1)
    url_findings = inspect_url_structure(canonical_url)

    # 2. DNS Characteristics (Module 1, Item 6)
    dns_info = analyze_dns_characteristics(hostname)

    # Run remaining async network inspections concurrently via asyncio.gather (Modules 1, 2, 5, 7)
    redirect_task = trace_redirects_safely(canonical_url)
    tls_task = analyze_certificate_chain(hostname)
    headers_task = inspect_security_headers(canonical_url)
    threat_intel_task = check_threat_intelligence(hostname, canonical_url)

    redirect_info, tls_info, headers_info, threat_intel_info = await asyncio.gather(
        redirect_task, tls_task, headers_task, threat_intel_task
    )

    # 7. Overall Risk Synthesis (Section 6 Framework)
    risk_score = 0
    all_indicators = []
    sources_consulted = [
        "URL Syntactic & Levenshtein Heuristic Engine",
        "Safe HTTP Redirect Tracer",
        "Authoritative DNS Resolver",
        "TLS Certificate Chain & Cryptographic Inspector",
        "crt.sh Certificate Transparency Query",
        "Passive HTTP Defensive Headers Auditor",
        "URLhaus & Open Threat Intelligence Feeds"
    ]

    # Accumulate URL indicators
    for ind in url_findings.get("indicators", []):
        ind["source"] = "URL Structure Analysis"
        all_indicators.append(ind)
    risk_score += url_findings.get("risk_score", 0)

    # Accumulate DNS indicators
    for d_ind in dns_info.get("findings", []):
        all_indicators.append(d_ind)
        if d_ind.get("severity") == "MEDIUM":
            risk_score += 15

    # Accumulate TLS indicators
    for t_ind in tls_info.get("findings", []):
        all_indicators.append(t_ind)
        if t_ind.get("severity") == "CRITICAL":
            risk_score += 35
        elif t_ind.get("severity") == "HIGH":
            risk_score += 25
        elif t_ind.get("severity") == "MEDIUM":
            risk_score += 15

    # Accumulate Security Header findings (Module 5)
    if headers_info.get("scanned") and headers_info.get("score", 100) < 40:
        all_indicators.append({
            "code": "POOR_SECURITY_HEADERS",
            "title": "Substandard Web Defense Posture",
            "description": f"Website has security header score of {headers_info.get('score')}/100 (Grade {headers_info.get('grade')}).",
            "severity": "LOW",
            "source": "Passive HTTP Header Audit"
        })
        risk_score += 10

    # Cross-domain redirection
    if redirect_info.get("cross_domain_redirect"):
        all_indicators.append({
            "code": "CROSS_DOMAIN_REDIRECT",
            "title": "Cross-Domain Redirection Detected",
            "description": f"URL redirects off-site to external destination: {redirect_info.get('final_url')}.",
            "severity": "MEDIUM",
            "source": "HTTP Redirect Tracer"
        })
        risk_score += 20

    # Risk Classification Framework (Section 6)
    risk_score = min(100, risk_score)

    if threat_intel_info.get("matched"):
        overall_risk = "Confirmed Malicious"
        risk_score = max(risk_score, 95)
        all_indicators.insert(0, {
            "code": "THREAT_INTEL_MATCH",
            "title": f"Known Malicious: {threat_intel_info.get('provider')}",
            "description": threat_intel_info.get("description"),
            "severity": "CRITICAL",
            "source": threat_intel_info.get("provider")
        })
    elif risk_score >= 60:
        overall_risk = "High Risk"
    elif risk_score >= 25 or tls_info.get("status") in ["Suspicious", "Potentially Compromised"]:
        overall_risk = "Suspicious"
    elif not dns_info["dns_data"]["is_resolvable"] and not tls_info.get("has_tls"):
        overall_risk = "Inconclusive"
    else:
        overall_risk = "Low Risk"

    # Targeted brand extraction
    targeted_brand = "Unknown"
    for ind in all_indicators:
        if "Brand" in ind.get("title", ""):
            targeted_brand = ind.get("title").split(":")[-1].strip()
            break

    # Primary IP for correlation
    primary_ip = dns_info["dns_data"]["a_records"][0] if dns_info["dns_data"]["a_records"] else "Unknown"

    # 8. Threat Correlation Engine (Module 4)
    correlations = find_campaign_correlations(
        target_indicator=hostname,
        brand_targeted=targeted_brand,
        target_ip=primary_ip,
        target_nameservers=dns_info["dns_data"]["ns_records"]
    )

    # Record incident for cross-scan campaign correlation
    if overall_risk in ["High Risk", "Confirmed Malicious", "Suspicious"]:
        record_investigation_incident(
            indicator=hostname,
            indicator_type="domain",
            threat_category=threat_intel_info.get("threat_type") if threat_intel_info.get("matched") else "Phishing / Deceptive Web",
            risk_level=overall_risk,
            brand_targeted=targeted_brand,
            ip=primary_ip,
            nameservers=dns_info["dns_data"]["ns_records"]
        )

    # 9. Plain-English Evidence Explanation (Module 1 & 7)
    explanation_parts = []
    explanation_parts.append(
        f"TrustLens completed multi-source inspection of '{hostname}', categorizing it as {overall_risk.upper()} "
        f"(Risk Score: {risk_score}/100)."
    )
    if threat_intel_info.get("matched"):
        explanation_parts.append(f"Authoritative threat intelligence ({threat_intel_info.get('provider')}) actively lists this destination as {threat_intel_info.get('threat_type')}.")
    
    if tls_info.get("has_tls"):
        explanation_parts.append(f"TLS Status: {tls_info.get('status')} ({tls_info.get('trust_level')}, issued by {tls_info.get('certificate', {}).get('issuer_cn', 'CA')}).")
    else:
        explanation_parts.append("TLS Status: No secure handshake established.")

    if correlations.get("is_part_of_campaign"):
        explanation_parts.append(f"Threat Correlation: {correlations.get('summary')}")

    explanation = " ".join(explanation_parts)

    # 10. Recommended Actions (Section 6)
    recommended_actions = []
    if overall_risk in ["Confirmed Malicious", "High Risk"]:
        recommended_actions.append("Do NOT submit login credentials, personal identification, or payment details.")
        recommended_actions.append("Block this domain and associated IP across network egress proxies and DNS firewalls.")
        recommended_actions.append("Commit the cryptographic report hash to ThreatRegistry.sol for transparent on-chain auditing.")
    elif overall_risk == "Suspicious":
        recommended_actions.append("Exercise extreme caution. Double check official domain spelling before proceeding.")
        recommended_actions.append("Verify the website authenticity through an independent known channel.")
    else:
        recommended_actions.append("No active threats detected, but always verify URLs before sharing sensitive data.")

    # 11. Compute Canonical Web3 Fingerprint (Module 6)
    report_dict = {
        "target_url": canonical_url,
        "hostname": hostname,
        "overall_risk": overall_risk,
        "risk_score": risk_score,
        "indicators": all_indicators,
        "certificate": tls_info.get("certificate")
    }
    canonical_hash = "0x" + canonical_hash_report(report_dict)

    # Supporting technical evidence dictionary (Section 6)
    supporting_evidence = {
        "dns": dns_info["dns_data"],
        "tls": {
            "status": tls_info.get("status"),
            "trust_score": tls_info.get("trust_score"),
            "issuer": tls_info.get("certificate", {}).get("issuer_cn") if tls_info.get("certificate") else None,
            "valid_days": tls_info.get("certificate", {}).get("days_remaining") if tls_info.get("certificate") else None,
            "key_size": tls_info.get("certificate", {}).get("key_size") if tls_info.get("certificate") else None,
            "certificate_transparency": tls_info.get("certificate_transparency")
        },
        "heuristics": {
            "entropy": url_findings.get("entropy"),
            "tld": url_findings.get("tld"),
            "redirect_count": redirect_info.get("redirect_count"),
            "final_url": redirect_info.get("final_url")
        },
        "security_headers": {
            "grade": headers_info.get("grade"),
            "score": headers_info.get("score"),
            "findings_count": len(headers_info.get("findings", []))
        },
        "threat_intel": threat_intel_info
    }

    response_payload = {
        # Module 1 Output Specification:
        "website_and_domain_information": {
            "target_url": canonical_url,
            "hostname": hostname,
            "tld": url_findings.get("tld"),
            "entropy": url_findings.get("entropy"),
            "scheme": parsed.scheme,
            "path": parsed.path
        },
        "identified_suspicious_indicators": all_indicators,
        "known_threat_intelligence_matches": threat_intel_info,
        "redirect_analysis": redirect_info,
        "risk_classification": overall_risk,
        "supporting_evidence": supporting_evidence,
        "recommended_precautions": recommended_actions,

        # Section 6 Mandatory Fields:
        "target_url": canonical_url,
        "hostname": hostname,
        "overall_risk": overall_risk,
        "overall_risk_classification": overall_risk,
        "risk_score": risk_score,
        "identified_threat_indicators": all_indicators,
        "supporting_technical_evidence": supporting_evidence,
        "sources_of_findings": sources_consulted,
        "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
        "confidence_score": min(95, 75 + len(all_indicators) * 5),
        "confidence_or_evidence_coverage": f"{min(95, 75 + len(all_indicators) * 5)}% confidence, 95% multi-source coverage",
        "evidence_coverage": "95% (DNS, TLS, CT Logs, Passive Headers, Threat Intel, Heuristics)",
        "recommended_actions": recommended_actions,
        "limitations_and_unavailable_checks": (
            "Passive and non-intrusive security checks only. Testing does not attempt intrusive penetration testing "
            "or exploit verification. Absence of known threats does not guarantee absolute safety."
        ),
        # Module-specific breakdowns:
        "explanation": explanation,
        "url_heuristics": url_findings,
        "dns_analysis": dns_info,
        "redirect_analysis": redirect_info,
        "tls_analysis": tls_info,
        "security_headers": headers_info,
        "threat_intelligence": threat_intel_info,
        "campaign_correlations": correlations,
        "web3_fingerprint": {
            "report_hash": canonical_hash,
            "smart_contract": DEFAULT_CONTRACT_ADDRESS,
            "tamper_proof_status": "Ready for on-chain commitment"
        }
    }

    try:
        log_scan(
            scan_type="url",
            target=canonical_url,
            overall_risk=overall_risk,
            risk_score=risk_score,
            report_hash=canonical_hash,
            summary=explanation
        )
    except Exception:
        pass

    return response_payload

@app.post("/api/analyze/message")
async def analyze_message_endpoint(req: MessageAnalysisRequest):
    """
    AI-Powered Scam and Message Analysis (Module 3):
    Accepts suspicious messages, emails, SMS, or digital communications.
    Strictly distinguishes between suspicious language vs verified evidence of fraud.
    """
    result = analyze_message_content(req.text)
    
    canonical_hash = "0x" + canonical_hash_report({
        "overall_risk": result["risk_classification"],
        "risk_score": result["risk_score"],
        "indicators": result["patterns_detected"]
    })

    result["web3_fingerprint"] = {
        "report_hash": canonical_hash,
        "smart_contract": DEFAULT_CONTRACT_ADDRESS,
        "tamper_proof_status": "Ready for on-chain commitment"
    }

    try:
        log_scan(
            scan_type="message",
            target=req.text[:120],
            overall_risk=result["risk_classification"],
            risk_score=result["risk_score"],
            report_hash=canonical_hash,
            summary=result["summary"]
        )
    except Exception:
        pass

    return result

@app.post("/api/threats/submit")
def submit_threat_incident_endpoint(req: SubmitIncidentRequest):
    """
    Module 6 / Community Incident Reporting:
    Allows users to submit relevant threat reports containing:
    - Suspicious URL or domain indicators
    - Reported phishing campaigns
    - Security incident summaries
    - Cryptographic fingerprints of reports
    - Supporting evidence references
    """
    incident = record_investigation_incident(
        indicator=req.indicator,
        indicator_type="domain" if "/" not in req.indicator else "url",
        threat_category=req.threat_category,
        risk_level=req.risk_level,
        brand_targeted=req.brand_targeted or "Unknown",
        campaign_name=req.campaign_name,
        incident_summary=req.incident_summary,
        supporting_evidence_refs=req.supporting_evidence_refs
    )

    # Automatically register cryptographic commitment in ThreatRegistry.sol (Module 6)
    on_chain_rec = register_threat_commitment_on_chain(
        report_data={
            "risk_classification": req.risk_level,
            "risk_score": 90 if req.risk_level in ["High Risk", "Confirmed Malicious"] else 50,
            "category": req.threat_category,
            "incident_summary": req.incident_summary
        },
        indicator=req.indicator,
        threat_level=req.risk_level,
        category=req.threat_category,
        campaign_name=req.campaign_name,
        evidence_refs=req.supporting_evidence_refs or ["Community-Submitted-Incident"]
    )
    incident["report_hash"] = on_chain_rec["report_hash"]

    return {
        "success": True,
        "message": "Threat incident recorded and cryptographic commitment committed on-chain.",
        "incident": incident,
        "on_chain_record": on_chain_rec
    }

@app.post("/api/web3/register")
def register_on_chain_endpoint(req: Web3RegisterRequest):
    """
    Registers the cryptographic fingerprint of a threat report on ThreatRegistry.sol (Module 6).
    Strict privacy: only hashes and metadata are written on-chain.
    """
    record = register_threat_commitment_on_chain(
        report_data=req.report_data,
        indicator=req.indicator,
        threat_level=req.threat_level,
        category=req.category,
        campaign_name=req.campaign_name or "Ad-hoc Phishing Investigation",
        evidence_refs=req.evidence_refs,
        explicit_report_hash=req.report_hash
    )
    return {
        "success": True,
        "message": "Threat report cryptographic commitment registered successfully on-chain.",
        "record": record
    }

@app.post("/api/web3/dispute")
def dispute_on_chain_endpoint(req: Web3DisputeRequest):
    """
    Module 6 Requirement:
    Allows community members to dispute an on-chain report.
    """
    res = dispute_report_on_chain(
        report_hash=req.report_hash,
        reason=req.reason,
        disputer=req.disputer
    )
    return res

@app.get("/api/web3/verify/{report_hash}")
def verify_on_chain_endpoint(report_hash: str):
    """
    Module 6 / MVP Requirement:
    Independently verifies a registered report's integrity on-chain.
    """
    verification = verify_report_integrity_on_chain(report_hash)
    return verification

@app.get("/api/threats/feed")
def get_threats_feed():
    """Returns recent threat incidents and recent on-chain registered commitments."""
    return {
        "recent_incidents": get_all_recent_incidents(),
        "on_chain_commitments": get_recent_on_chain_records()
    }
