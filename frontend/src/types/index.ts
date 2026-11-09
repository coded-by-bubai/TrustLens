export type RiskClassification = 
  | 'Low Risk' 
  | 'Suspicious' 
  | 'High Risk' 
  | 'Confirmed Malicious' 
  | 'Inconclusive';

export interface ThreatIndicator {
  code: string;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  source?: string;
  brand?: string;
  distance?: number;
}

export interface DnsData {
  hostname: string;
  a_records: string[];
  aaaa_records: string[];
  mx_records: string[];
  ns_records: string[];
  txt_records: string[];
  has_spf: boolean;
  has_dmarc: boolean;
  is_resolvable: boolean;
}

export interface DnsAnalysisResult {
  dns_data: DnsData;
  findings: ThreatIndicator[];
}

export interface CertificateInfo {
  subject_cn: string | null;
  subject_org: string | null;
  issuer_cn: string | null;
  issuer_org: string | null;
  issuer_country: string | null;
  valid_from: string;
  valid_to: string;
  days_remaining: number;
  is_expired: boolean;
  san_count: number;
  sans_sample: string[];
  key_type: string;
  key_size: number;
  signature_algorithm: string;
  is_self_signed: boolean;
  has_embedded_sct: boolean;
}

export interface CertificateTransparencyResult {
  queried: boolean;
  source: string;
  total_certificates_logged: number;
  recent_entries: Array<{
    id: number;
    issuer_name: string;
    common_name: string;
    entry_timestamp: string;
    not_before: string;
    not_after: string;
  }>;
  status: string;
}

export interface TlsAnalysisResult {
  has_tls: boolean;
  status: 'Valid' | 'Suspicious' | 'Potentially Compromised';
  trust_level?: string;
  trust_score?: number;
  tls_version?: string;
  cipher_suite?: string;
  certificate?: CertificateInfo;
  certificate_transparency?: CertificateTransparencyResult;
  findings: ThreatIndicator[];
  critical_caveat?: string;
  error?: string;
}

export interface SecurityAssessmentFinding {
  identified_security_issue: string;
  technical_evidence: string;
  potential_impact: string;
  severity_classification: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  recommended_remediation: string;
  relevant_limitations: string;
}

export type Module5Finding = SecurityAssessmentFinding;

export interface SecurityHeadersResult {
  scanned: boolean;
  score: number;
  grade: string;
  present_headers: Record<string, string>;
  findings: SecurityAssessmentFinding[];
  missing_headers: Array<{
    header: string;
    severity: string;
    impact: string;
    recommendation: string;
  }>;
  information_disclosure: Array<{
    identified_security_issue: string;
    technical_evidence: string;
    potential_impact: string;
    severity_classification: string;
    recommended_remediation: string;
    relevant_limitations: string;
  }>;
  limitations: string;
  error?: string;
}

export interface ThreatIntelResult {
  matched: boolean;
  provider: string;
  threat_type: string;
  tags: string[];
  confidence_score: number;
  reference_status: string;
  description: string;
}

export interface RedirectHop {
  hop: number;
  url: string;
  status_code: number;
  location?: string;
  error?: string;
}

export interface RedirectAnalysisResult {
  redirect_count: number;
  chain: RedirectHop[];
  final_url: string;
  cross_domain_redirect: boolean;
}

export interface CampaignCorrelationResult {
  is_part_of_campaign: boolean;
  campaign_confidence: number;
  summary: string;
  correlated_incidents_count: number;
  correlated_incidents: Array<{
    incident_id: string;
    indicator: string;
    campaign_name: string;
    threat_category: string;
    risk_level: string;
    timestamp: string;
    report_hash: string;
    deterministic_links: string[];
  }>;
  common_factors: string[];
  methodology: string;
}

export interface Web3Fingerprint {
  report_hash: string;
  smart_contract: string;
  tamper_proof_status: string;
}

export interface UrlAnalysisResponse {
  // Section 6 Mandatory Fields:
  target_url: string;
  hostname: string;
  overall_risk: RiskClassification;
  risk_score: number;
  identified_threat_indicators: ThreatIndicator[];
  supporting_technical_evidence: Record<string, any>;
  sources_of_findings: string[];
  analysis_timestamp: string;
  confidence_score: number;
  evidence_coverage: string;
  recommended_actions: string[];
  limitations_and_unavailable_checks: string;
  
  // Specific Module Results:
  explanation: string;
  url_heuristics: {
    canonical_url: string;
    hostname: string;
    tld: string;
    entropy: number;
    risk_score: number;
    indicators: ThreatIndicator[];
  };
  dns_analysis: DnsAnalysisResult;
  redirect_analysis: RedirectAnalysisResult;
  tls_analysis: TlsAnalysisResult;
  security_headers: SecurityHeadersResult;
  threat_intelligence: ThreatIntelResult;
  campaign_correlations: CampaignCorrelationResult;
  web3_fingerprint: Web3Fingerprint;
  
  is_blocked?: boolean;
  error?: string;
}

export interface MessageAnalysisResponse {
  risk_classification: RiskClassification;
  risk_score: number;
  summary: string;
  distinction_rationale: string;
  verified_evidence_of_fraud: string[];
  has_only_urgent_language: boolean;
  patterns_detected: Array<{
    category: string;
    title: string;
    impact: string;
    matched_terms: string[];
    severity: string;
    is_fraud_evidence: boolean;
  }>;
  extracted_entities: {
    urls: string[];
    emails: string[];
    phones: string[];
    crypto_wallets: string[];
  };
  correlated_url_threats: Array<{
    url: string;
    hostname: string;
    threat_intel_match: boolean;
    threat_type: string;
    risk_score: number;
    indicators: string[];
  }>;
  prompt_injection_flag: boolean;
  recommendations: string[];
  methodology: string;
  web3_fingerprint: Web3Fingerprint;
}

export interface OnChainCommitmentRecord {
  report_hash: string;
  indicator_hash: string;
  reporter: string;
  contract_address: string;
  transaction_hash: string;
  block_number: number;
  timestamp: number;
  iso_timestamp: string;
  threat_level: string;
  category: string;
  campaign_name?: string;
  evidence_refs?: string[];
  dispute_count: number;
  disputes?: Array<{
    disputer: string;
    reason: string;
    timestamp: string;
  }>;
  is_verified: boolean;
  is_revoked: boolean;
  network: string;
}

export interface QrEvidenceItem {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  code: string;
  title: string;
  description: string;
  weight: number;
}

export interface QrAnalysisResponse {
  payload: string;
  payload_type: string;
  quishing_category: string;
  overall_risk: 'Clean' | 'Suspicious' | 'High Risk' | 'Confirmed Malicious';
  risk_score: number;
  evidence: QrEvidenceItem[];
  details: Record<string, any>;
  recommendations: string[];
  sha256_hash: string;
  web3_fingerprint?: {
    report_hash: string;
    smart_contract: string;
    tamper_proof_status: string;
  };
}

export interface PresetItem {
  id: string;
  type: 'url' | 'message' | 'qr';
  name: string;
  value: string;
  description: string;
}
