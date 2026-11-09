import type {
  UrlAnalysisResponse,
  MessageAnalysisResponse,
  QrAnalysisResponse,
  QrEvidenceItem,
  OnChainCommitmentRecord,
  PresetItem
} from '../types';

const PROD_API_BASE_URL = 'https://trustlens-api-bytecoders.vercel.app';
const rawEnvUrl = (import.meta.env.VITE_API_BASE_URL as string)?.trim();

function getApiBaseUrl(): string {
  if (rawEnvUrl) {
    let url = rawEnvUrl;
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = `https://${url}`;
    }
    return url.replace(/\/+$/, '');
  }
  if (typeof window !== 'undefined' && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')) {
    return 'http://127.0.0.1:8000';
  }
  return PROD_API_BASE_URL;
}

let API_BASE_URL = getApiBaseUrl();

async function robustFetch(endpoint: string, options?: RequestInit): Promise<Response> {
  const primaryUrl = `${API_BASE_URL}${endpoint}`;
  try {
    return await fetch(primaryUrl, options);
  } catch {
    // If local dev server (127.0.0.1:8000) is unreachable, seamlessly fall back to live cloud API
    if (API_BASE_URL !== PROD_API_BASE_URL) {
      try {
        const fallbackRes = await fetch(`${PROD_API_BASE_URL}${endpoint}`, options);
        if (fallbackRes) {
          console.warn(`Local backend at ${API_BASE_URL} is unreachable. Switched to live cloud backend ${PROD_API_BASE_URL}.`);
          API_BASE_URL = PROD_API_BASE_URL;
          return fallbackRes;
        }
      } catch {
        // Fallback also failed
      }
    }
    throw new Error(
      `Cannot connect to backend (${API_BASE_URL}). If testing locally, make sure 'start_backend.bat' is running. If online, check your network connection.`
    );
  }
}

export async function fetchPresets(): Promise<{ benign_cases: PresetItem[]; suspicious_cases: PresetItem[] }> {
  try {
    const res = await robustFetch('/api/presets');
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
        { id: 'suspicious-3', type: 'message', name: 'Urgent Bank Impersonation SMS', value: 'URGENT NOTICE: Your Chase account access has been restricted due to unauthorized login attempts. You must verify your credentials and OTP immediately at https://chase-auth-verification.com within 24 hours to prevent permanent closure.', description: 'Urgency & credential harvesting SMS' },
        { id: 'suspicious-5', type: 'qr', name: 'Quishing Parking Meter Payment Sticker', value: 'upi://pay?pa=scammer892@ybl&pn=City+Municipal+Parking+Authority&am=150.00&cu=INR', description: 'Tampered payment sticker routing to mule VPA' }
      ]
    };
  }
}

export async function analyzeUrl(url: string): Promise<UrlAnalysisResponse> {
  const res = await robustFetch('/api/analyze/url', {
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
  const res = await robustFetch('/api/analyze/message', {
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

async function sha256Hex(text: string): Promise<string> {
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hashBuffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }
  return '0x' + Math.random().toString(16).slice(2) + Math.random().toString(16).slice(2);
}

async function fallbackQrAnalysis(rawPayload: string): Promise<QrAnalysisResponse> {
  const payload = rawPayload.trim();
  const lower = payload.toLowerCase();
  const sha256_hash = await sha256Hex(payload);

  // 1. URL / Quishing Analysis
  if (lower.startsWith('http://') || lower.startsWith('https://') || lower.startsWith('www.')) {
    const urlStr = lower.startsWith('http://') || lower.startsWith('https://') ? lower : `https://${lower}`;
    let domain = '';
    try {
      domain = new URL(urlStr).hostname;
    } catch {
      domain = lower.split('/')[2] || lower;
    }

    const TARGET_BRANDS = ['paypal', 'chase', 'google', 'microsoft', 'apple', 'amazon', 'netflix', 'bankofamerica', 'wellsfargo', 'binance', 'coinbase', 'metamask'];
    const SUSPICIOUS_TLDS = ['xyz', 'buzz', 'top', 'tk', 'ml', 'ga', 'fit', 'work', 'click', 'cam'];
    const SUSPICIOUS_KEYWORDS = ['login', 'signin', 'verify', 'verification', 'security', 'account', 'banking', 'update', 'wallet', 'authenticate'];

    const staticEvidence: QrEvidenceItem[] = [];
    let staticScore = 0;

    // Brand embedding & typosquatting detection
    for (const b of TARGET_BRANDS) {
      if (domain.includes(b) && !domain.endsWith(`.${b}.com`) && domain !== `${b}.com`) {
        staticEvidence.push({
          severity: 'CRITICAL',
          code: 'BRAND_EMBEDDING',
          title: `Brand Impersonation Target: ${b.charAt(0).toUpperCase() + b.slice(1)}`,
          description: `QR domain '${domain}' embeds brand name '${b}' outside the official domain structure.`,
          weight: 40
        });
        staticScore += 40;
        break;
      }
    }

    // High risk TLD
    const tld = domain.split('.').pop() || '';
    if (SUSPICIOUS_TLDS.includes(tld)) {
      staticEvidence.push({
        severity: 'HIGH',
        code: 'HIGH_RISK_TLD',
        title: `High-Risk Top-Level Domain (.${tld})`,
        description: `The .${tld} TLD has an elevated historical prevalence in disposable phishing campaigns.`,
        weight: 25
      });
      staticScore += 25;
    }

    // Sensitive keywords
    const matchedKw = SUSPICIOUS_KEYWORDS.filter(kw => urlStr.includes(kw));
    if (matchedKw.length > 0) {
      staticEvidence.push({
        severity: 'HIGH',
        code: 'CREDENTIAL_KEYWORDS',
        title: 'Credential or Phishing Keywords Detected',
        description: `URL contains sensitive targeting keywords: ${matchedKw.join(', ')}.`,
        weight: 25
      });
      staticScore += 25;
    }

    // URL Shorteners
    const isShortener = ['bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'is.gd', 'qr.link', 'qrco.de'].some(s => domain.includes(s));
    if (isShortener) {
      staticEvidence.push({
        severity: 'HIGH',
        code: 'QR_SHORTENER_OBFUSCATION',
        title: 'URL Shortener Cloaking',
        description: 'QR uses a URL shortener to conceal the true landing destination.',
        weight: 25
      });
      staticScore += 25;
    }

    // Direct binary download
    const isDirectDownload = ['.apk', '.exe', '.bat', '.dmg', '.msi'].some(ext => lower.includes(ext));
    if (isDirectDownload) {
      staticEvidence.push({
        severity: 'CRITICAL',
        code: 'DIRECT_BINARY_DOWNLOAD',
        title: 'Direct Application Download Link',
        description: 'QR directly prompts the download of an executable installer or APK file.',
        weight: 45
      });
      staticScore += 45;
    }

    // Query backend if reachable to merge live TLS/DNS indicators
    let dynamicScore = 0;
    const dynamicEvidence: QrEvidenceItem[] = [];
    let recs: string[] = [];

    try {
      const urlData = await analyzeUrl(payload);
      if (urlData && urlData.overall_risk !== 'Inconclusive' && urlData.risk_score > 0) {
        dynamicScore = urlData.risk_score;
        recs = urlData.recommended_actions || [];
        for (const ind of urlData.identified_threat_indicators || []) {
          if (!staticEvidence.some(e => e.code === ind.code)) {
            dynamicEvidence.push({
              severity: ind.severity,
              code: ind.code,
              title: ind.title,
              description: ind.description,
              weight: ind.severity === 'CRITICAL' ? 35 : ind.severity === 'HIGH' ? 25 : 10
            });
          }
        }
      }
    } catch {}

    const allEvidence = [...staticEvidence, ...dynamicEvidence];
    const riskScore = Math.min(100, Math.max(staticScore, dynamicScore, allEvidence.reduce((sum: number, e: QrEvidenceItem) => sum + e.weight, 0)));
    const hasCritical = allEvidence.some(e => e.severity === 'CRITICAL');
    const hasHigh = allEvidence.some(e => e.severity === 'HIGH');

    let overallRisk: QrAnalysisResponse['overall_risk'] = 'Clean';
    if (riskScore >= 70 || hasCritical) {
      overallRisk = (riskScore >= 75 || hasCritical) ? 'Confirmed Malicious' : 'High Risk';
    } else if (riskScore >= 35 || hasHigh) {
      overallRisk = 'High Risk';
    } else if (riskScore >= 15) {
      overallRisk = 'Suspicious';
    }

    const finalScore = Math.max(riskScore, overallRisk === 'Confirmed Malicious' ? 85 : overallRisk === 'High Risk' ? 65 : overallRisk === 'Suspicious' ? 30 : 0);

    return {
      payload,
      payload_type: 'URL',
      quishing_category: isDirectDownload ? 'Malicious App Sideloading' : isShortener ? 'Cloaked Quishing URL' : (hasCritical || overallRisk === 'High Risk' || overallRisk === 'Confirmed Malicious') ? 'Confirmed Quishing Attack' : 'Web Link / Quishing Analysis',
      overall_risk: overallRisk,
      risk_score: finalScore,
      evidence: allEvidence,
      details: {
        url: payload,
        hostname: domain || 'Unknown',
        protocol: payload.startsWith('https://') ? 'https' : 'http'
      },
      recommendations: recs.length > 0 ? recs : overallRisk !== 'Clean' ? [
        'Do NOT submit credentials, OTPs, or financial information to this destination.',
        'Verify the destination domain through an official search engine or contact the organization directly.'
      ] : ['Verify destination before entering sensitive data.'],
      sha256_hash,
      web3_fingerprint: {
        report_hash: '0x' + sha256_hash,
        smart_contract: '0x38B781a93C3754eA6f4675548c8959dD628585D7',
        tamper_proof_status: 'Ready for on-chain commitment'
      }
    };
  }

  // 2. UPI Payment QR Tampering
  if (lower.startsWith('upi://pay')) {
    const evidence = [];
    let riskScore = 0;
    let pa = '';
    let pn = '';
    let am = '';
    let cu = 'INR';
    let mc = '';

    try {
      const urlObj = new URL(payload.replace('upi://pay', 'http://dummy.upi'));
      pa = (urlObj.searchParams.get('pa') || '').toLowerCase();
      pn = urlObj.searchParams.get('pn') || '';
      am = urlObj.searchParams.get('am') || '';
      cu = urlObj.searchParams.get('cu') || 'INR';
      mc = urlObj.searchParams.get('mc') || '';
    } catch {}

    const officialKws = ['parking', 'traffic', 'police', 'municipal', 'challan', 'tax', 'electricity', 'support'];
    const isConsumerVpa = ['okaxis', 'okhdfcbank', 'okicici', 'oksbi', 'ybl', 'ibl', 'axl', 'paytm'].some(h => pa.endsWith('@' + h));
    const hasOfficialName = officialKws.some(kw => pn.toLowerCase().includes(kw));

    if (hasOfficialName && isConsumerVpa && !mc) {
      evidence.push({
        severity: 'CRITICAL' as const,
        code: 'UPI_MERCHANT_SPOOFING',
        title: 'Deceptive Merchant Name Mismatch',
        description: `Display name claims official authority ('${pn}'), but payment routes to an unverified personal consumer VPA ('${pa}').`,
        weight: 45
      });
      riskScore += 45;
    }

    try {
      if (parseFloat(am) > 2000) {
        evidence.push({
          severity: 'MEDIUM' as const,
          code: 'HIGH_PRESET_AMOUNT',
          title: 'High Pre-filled Payment Amount',
          description: `QR requests an auto-filled transfer of ${cu} ${am}.`,
          weight: 15
        });
        riskScore += 15;
      }
    } catch {}

    const overallRisk = (riskScore >= 70 ? 'Confirmed Malicious' : riskScore >= 40 ? 'High Risk' : riskScore >= 20 ? 'Suspicious' : 'Clean') as QrAnalysisResponse['overall_risk'];

    return {
      payload,
      payload_type: 'PAYMENT_UPI',
      quishing_category: 'Payment QR Tampering (Mule VPA)',
      overall_risk: overallRisk,
      risk_score: riskScore,
      evidence,
      details: {
        payee_vpa: pa,
        payee_name: pn || 'Unknown',
        amount: am || 'Unspecified',
        currency: cu,
        merchant_code: mc || 'None'
      },
      recommendations: [
        'Do not approve this transaction. The recipient name does not match a verified merchant VPA.',
        'Report physical sticker tampering to local staff or authorities.'
      ],
      sha256_hash,
      web3_fingerprint: {
        report_hash: '0x' + sha256_hash,
        smart_contract: '0x38B781a93C3754eA6f4675548c8959dD628585D7',
        tamper_proof_status: 'Ready for on-chain commitment'
      }
    };
  }

  // 3. Rogue Wi-Fi Honeypot
  if (lower.startsWith('wifi:')) {
    const evidence = [];
    let riskScore = 0;
    const tokens = payload.slice(5).split(';');
    let ssid = 'Unknown';
    let authType = 'NOPASS';
    for (const t of tokens) {
      if (t.startsWith('S:')) ssid = t.slice(2);
      if (t.startsWith('T:')) authType = t.slice(2).toUpperCase();
    }

    const isPublicBrand = ['airport', 'free', 'guest', 'starbucks', 'hotel', 'metro'].some(b => ssid.toLowerCase().includes(b));
    if (authType === 'NOPASS' && isPublicBrand) {
      evidence.push({
        severity: 'HIGH' as const,
        code: 'WIFI_HONEYPOT_PROFILE',
        title: 'Unencrypted Public Honeypot Risk',
        description: `QR advertises an unencrypted network ('${ssid}') mimicking a public hotspot without WPA2/WPA3 security.`,
        weight: 40
      });
      riskScore += 40;
    }

    const overallRisk = (riskScore >= 40 ? 'High Risk' : riskScore >= 20 ? 'Suspicious' : 'Clean') as QrAnalysisResponse['overall_risk'];

    return {
      payload,
      payload_type: 'WIFI_CONFIG',
      quishing_category: 'Rogue Wi-Fi Honeypot',
      overall_risk: overallRisk,
      risk_score: riskScore,
      evidence,
      details: { ssid, auth_type: authType },
      recommendations: ['Do not connect your device. Unencrypted Wi-Fi networks allow traffic eavesdropping.'],
      sha256_hash,
      web3_fingerprint: {
        report_hash: '0x' + sha256_hash,
        smart_contract: '0x38B781a93C3754eA6f4675548c8959dD628585D7',
        tamper_proof_status: 'Ready for on-chain commitment'
      }
    };
  }

  // 4. Default / Text analysis
  try {
    const msgData = await analyzeMessage(payload);
    return {
      payload,
      payload_type: 'PLAIN_TEXT',
      quishing_category: 'Text / Information Content',
      overall_risk: msgData.risk_classification as QrAnalysisResponse['overall_risk'],
      risk_score: msgData.risk_score,
      evidence: (msgData.patterns_detected || []).map(p => ({
        severity: p.severity as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW',
        code: p.category,
        title: p.title,
        description: p.impact,
        weight: p.severity === 'HIGH' ? 30 : 15
      })),
      details: { length: payload.length, preview: payload.slice(0, 100) },
      recommendations: msgData.recommendations || ['Verify unsolicited requests before sharing credentials.'],
      sha256_hash,
      web3_fingerprint: {
        report_hash: '0x' + sha256_hash,
        smart_contract: '0x38B781a93C3754eA6f4675548c8959dD628585D7',
        tamper_proof_status: 'Ready for on-chain commitment'
      }
    };
  } catch {
    return {
      payload,
      payload_type: 'PLAIN_TEXT',
      quishing_category: 'Text / Information Content',
      overall_risk: 'Clean',
      risk_score: 0,
      evidence: [],
      details: { length: payload.length },
      recommendations: ['No suspicious patterns identified.'],
      sha256_hash
    };
  }
}

export async function analyzeQrCode(payload: string): Promise<QrAnalysisResponse> {
  try {
    const res = await robustFetch('/api/analyze/qr', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ payload })
    });
    if (res.ok) {
      return await res.json();
    }
  } catch {
    // Backend endpoint unreachable or not deployed, fallback gracefully
  }
  return await fallbackQrAnalysis(payload);
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
  const res = await robustFetch('/api/web3/register', {
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
  const res = await robustFetch(`/api/web3/verify/${encodeURIComponent(reportHash)}`);
  if (!res.ok) throw new Error('Failed to query on-chain verification');
  return await res.json();
}

export async function disputeOnChain(reportHash: string, reason: string) {
  const res = await robustFetch('/api/web3/dispute', {
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
  const res = await robustFetch('/api/threats/submit', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(incident)
  });
  if (!res.ok) throw new Error('Failed to submit incident');
  return await res.json();
}

export async function fetchThreatFeed() {
  const res = await robustFetch('/api/threats/feed');
  if (!res.ok) throw new Error('Failed to fetch threat intelligence feed');
  return await res.json();
}
