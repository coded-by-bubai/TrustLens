import type {
  UrlAnalysisResponse,
  MessageAnalysisResponse,
  OnChainCommitmentRecord,
  PresetItem
} from '../types';

const rawEnvUrl = (import.meta.env.VITE_API_BASE_URL as string)?.trim();
function getApiBaseUrl(): string {
  if (rawEnvUrl) {
    let url = rawEnvUrl;
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = `https://${url}`;
    }
    return url.replace(/\/+$/, '');
  }
  if (typeof window !== 'undefined' && window.location.hostname === 'localhost' && window.location.port === '5173') {
    return 'http://127.0.0.1:8000';
  }
  return '';
}

const API_BASE_URL = getApiBaseUrl();

export async function fetchPresets(): Promise<{ benign_cases: PresetItem[]; suspicious_cases: PresetItem[] }> {
  try {
    const res = await fetch(`${API_BASE_URL}/api/presets`);
    if (!res.ok) throw new Error('Failed to load presets');
    return await res.json();
  } catch (err) {
    console.error('Error fetching presets:', err);
    return {
      benign_cases: [
        { id: 'benign-1', type: 'url', name: 'Google Search Portal', value: 'https://www.google.com', description: 'Legitimate search engine' },
        { id: 'benign-2', type: 'url', name: 'GitHub Platform', value: 'https://github.com', description: 'Developer code hosting' },
        { id: 'benign-3', type: 'url', name: 'Wikipedia Encyclopedia', value: 'https://www.wikipedia.org', description: 'Global encyclopedia' }
      ],
      suspicious_cases: [
        { id: 'suspicious-1', type: 'url', name: 'PayPal Typosquatting / Credential Phishing', value: 'https://paypal-security-update.account-verification.xyz', description: 'Brand typosquatting on .xyz TLD' },
        { id: 'suspicious-2', type: 'url', name: 'Chase Banking Phishing Host', value: 'https://secure-login-chase-update.com', description: 'Matched in threat intelligence database' },
        { id: 'suspicious-3', type: 'message', name: 'Urgent Bank Impersonation SMS', value: 'URGENT NOTICE: Your Chase account access has been restricted due to unauthorized login attempts. You must verify your credentials and OTP immediately at https://chase-auth-verification.com within 24 hours to prevent permanent closure.', description: 'Urgency & credential harvesting SMS' }
      ]
    };
  }
}

export async function analyzeUrl(url: string): Promise<UrlAnalysisResponse> {
  const res = await fetch(`${API_BASE_URL}/api/analyze/url`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url })
  });
  if (!res.ok) {
    let errMsg = `Analysis request failed (${res.status} ${res.statusText})`;
    try {
      const errData = await res.json();
      if (errData && errData.detail) {
        errMsg = typeof errData.detail === 'string' ? errData.detail : JSON.stringify(errData.detail);
      }
    } catch {
      // ignore
    }
    throw new Error(errMsg);
  }
  return await res.json();
}

export async function analyzeMessage(text: string): Promise<MessageAnalysisResponse> {
  const res = await fetch(`${API_BASE_URL}/api/analyze/message`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text })
  });
  if (!res.ok) {
    let errMsg = `Message analysis failed (${res.status} ${res.statusText})`;
    try {
      const errData = await res.json();
      if (errData && errData.detail) {
        errMsg = typeof errData.detail === 'string' ? errData.detail : JSON.stringify(errData.detail);
      }
    } catch {
      // ignore
    }
    throw new Error(errMsg);
  }
  return await res.json();
}

export async function registerOnChain(
  reportData: Record<string, unknown>,
  indicator: string,
  threatLevel: string,
  category: string,
  campaignName?: string,
  evidenceRefs?: string[],
  reportHash?: string
): Promise<{ success: boolean; message: string; record: OnChainCommitmentRecord }> {
  const res = await fetch(`${API_BASE_URL}/api/web3/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      report_data: reportData,
      indicator,
      threat_level: threatLevel,
      category,
      campaign_name: campaignName,
      evidence_refs: evidenceRefs,
      report_hash: reportHash
    })
  });
  if (!res.ok) throw new Error('Failed to register report on-chain');
  return await res.json();
}

export async function verifyOnChain(reportHash: string) {
  const res = await fetch(`${API_BASE_URL}/api/web3/verify/${encodeURIComponent(reportHash)}`);
  if (!res.ok) throw new Error('Failed to query on-chain verification');
  return await res.json();
}

export async function disputeOnChain(reportHash: string, reason: string) {
  const res = await fetch(`${API_BASE_URL}/api/web3/dispute`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ report_hash: reportHash, reason })
  });
  if (!res.ok) throw new Error('Failed to submit dispute');
  return await res.json();
}

export async function submitThreatIncident(incident: {
  indicator: string;
  campaign_name: string;
  incident_summary: string;
  threat_category: string;
  risk_level: string;
  brand_targeted?: string;
  supporting_evidence_refs?: string[];
}) {
  const res = await fetch(`${API_BASE_URL}/api/threats/submit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(incident)
  });
  if (!res.ok) throw new Error('Failed to submit incident');
  return await res.json();
}

export async function fetchThreatFeed() {
  const res = await fetch(`${API_BASE_URL}/api/threats/feed`);
  if (!res.ok) throw new Error('Failed to fetch threat intelligence feed');
  return await res.json();
}
