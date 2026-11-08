// TrustLens Advanced Browser Extension Inspector

document.addEventListener('DOMContentLoaded', async () => {
  const API_BASE = 'http://127.0.0.1:8000';

  // Navigation Tab Elements
  const tabUrlBtn = document.getElementById('tabUrlBtn');
  const tabScamBtn = document.getElementById('tabScamBtn');
  const tabWeb3Btn = document.getElementById('tabWeb3Btn');
  const viewUrl = document.getElementById('viewUrl');
  const viewScam = document.getElementById('viewScam');
  const viewWeb3 = document.getElementById('viewWeb3');

  // Backend Status Pill
  const backendStatusPill = document.getElementById('backendStatusPill');

  // URL Tab Elements
  const targetUrlEl = document.getElementById('targetUrl');
  const httpsBadge = document.getElementById('httpsBadge');
  const statTotalLinks = document.getElementById('statTotalLinks');
  const statExternalLinks = document.getElementById('statExternalLinks');
  const statInsecureLinks = document.getElementById('statInsecureLinks');
  const scanBtn = document.getElementById('scanBtn');
  const btnText = document.getElementById('btnText');
  const resultsCard = document.getElementById('resultsCard');
  const riskBadge = document.getElementById('riskBadge');
  const riskScore = document.getElementById('riskScore');
  const tlsStatus = document.getElementById('tlsStatus');
  const headersGrade = document.getElementById('headersGrade');
  const intelStatus = document.getElementById('intelStatus');
  const entropyVal = document.getElementById('entropyVal');
  const explanationText = document.getElementById('explanationText');
  const indicatorsContainer = document.getElementById('indicatorsContainer');
  const indicatorsList = document.getElementById('indicatorsList');
  const web3Hash = document.getElementById('web3Hash');
  const commitWeb3Btn = document.getElementById('commitWeb3Btn');
  const commitSuccessBanner = document.getElementById('commitSuccessBanner');

  // Scam Tab Elements
  const scamTextInput = document.getElementById('scamTextInput');
  const analyzeScamBtn = document.getElementById('analyzeScamBtn');
  const scamBtnText = document.getElementById('scamBtnText');
  const scamResultsCard = document.getElementById('scamResultsCard');
  const scamRiskBadge = document.getElementById('scamRiskBadge');
  const scamRiskScore = document.getElementById('scamRiskScore');
  const scamRationale = document.getElementById('scamRationale');
  const extractedEntities = document.getElementById('extractedEntities');
  const scamSummary = document.getElementById('scamSummary');

  // Web3 Tab Elements
  const web3QueryInput = document.getElementById('web3QueryInput');
  const verifyHashBtn = document.getElementById('verifyHashBtn');
  const verifyBtnText = document.getElementById('verifyBtnText');
  const web3ResultsCard = document.getElementById('web3ResultsCard');
  const web3VerificationStatus = document.getElementById('web3VerificationStatus');
  const w3Block = document.getElementById('w3Block');
  const w3ThreatLevel = document.getElementById('w3ThreatLevel');
  const w3Disputes = document.getElementById('w3Disputes');
  const w3Contract = document.getElementById('w3Contract');

  let currentTabUrl = '';
  let activeScanResult = null;

  // 1. Tab Navigation Logic
  function switchTab(activeView, activeBtn) {
    [viewUrl, viewScam, viewWeb3].forEach((v) => v.classList.add('hidden'));
    [tabUrlBtn, tabScamBtn, tabWeb3Btn].forEach((b) => b.classList.remove('active'));
    activeView.classList.remove('hidden');
    activeBtn.classList.add('active');
  }

  tabUrlBtn.addEventListener('click', () => switchTab(viewUrl, tabUrlBtn));
  tabScamBtn.addEventListener('click', () => switchTab(viewScam, tabScamBtn));
  tabWeb3Btn.addEventListener('click', () => switchTab(viewWeb3, tabWeb3Btn));

  // Check if text was forwarded from context menu
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get(['pendingScamText'], (res) => {
      if (res && res.pendingScamText) {
        scamTextInput.value = res.pendingScamText;
        switchTab(viewScam, tabScamBtn);
        chrome.storage.local.remove(['pendingScamText']);
      }
    });
  }

  // 2. Health Check
  async function checkBackendHealth() {
    try {
      const res = await fetch(`${API_BASE}/api/health`);
      if (res.ok) {
        backendStatusPill.textContent = 'ONLINE';
        backendStatusPill.classList.remove('offline');
      } else {
        throw new Error();
      }
    } catch {
      backendStatusPill.textContent = 'BACKEND OFFLINE';
      backendStatusPill.classList.add('offline');
    }
  }
  checkBackendHealth();

  // 3. Detect Active Tab and In-Page Link Telemetry
  if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.query) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0] && tabs[0].url) {
        currentTabUrl = tabs[0].url;
        targetUrlEl.textContent = currentTabUrl;

        // Protocol badge
        if (currentTabUrl.startsWith('https://')) {
          httpsBadge.textContent = 'HTTPS';
          httpsBadge.classList.remove('insecure');
        } else {
          httpsBadge.textContent = 'INSECURE HTTP';
          httpsBadge.classList.add('insecure');
        }

        // Query content script for link stats
        if (tabs[0].id) {
          chrome.tabs.sendMessage(tabs[0].id, { action: 'getPageStats' }, (response) => {
            if (response) {
              statTotalLinks.textContent = response.totalLinks || 0;
              statExternalLinks.textContent = response.externalLinks || 0;
              statInsecureLinks.textContent = response.insecureHttpLinks || 0;
            }
          });
        }
      } else {
        setFallbackUrl();
      }
    });
  } else {
    setFallbackUrl();
  }

  function setFallbackUrl() {
    targetUrlEl.textContent = 'https://paypal-security-update.account-verification.xyz';
    currentTabUrl = targetUrlEl.textContent;
    statTotalLinks.textContent = '14';
    statExternalLinks.textContent = '6';
    statInsecureLinks.textContent = '2';
  }

  // 4. URL Scan Action
  scanBtn.addEventListener('click', async () => {
    if (!currentTabUrl) return;

    scanBtn.disabled = true;
    btnText.textContent = 'Auditing Security Vectors...';
    resultsCard.classList.add('hidden');
    commitSuccessBanner.classList.add('hidden');

    try {
      const response = await fetch(`${API_BASE}/api/analyze/url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: currentTabUrl })
      });

      if (!response.ok) {
        throw new Error(`Server returned HTTP ${response.status}`);
      }

      const data = await response.json();
      activeScanResult = data;

      // Populate UI
      riskScore.textContent = `${data.risk_score}/100`;
      riskBadge.textContent = data.overall_risk.toUpperCase();

      // Badge Styling
      riskBadge.className = 'badge';
      if (data.overall_risk === 'Confirmed Malicious') {
        riskBadge.classList.add('badge-confirmed');
      } else if (data.overall_risk === 'High Risk') {
        riskBadge.classList.add('badge-high');
      } else if (data.overall_risk === 'Suspicious') {
        riskBadge.classList.add('badge-suspicious');
      } else {
        riskBadge.classList.add('badge-low');
      }

      tlsStatus.textContent = data.tls_analysis ? data.tls_analysis.status : 'N/A';
      headersGrade.textContent = data.security_headers ? data.security_headers.grade : 'N/A';
      intelStatus.textContent = data.threat_intelligence && data.threat_intelligence.matched ? 'MATCHED' : 'CLEAN';
      entropyVal.textContent = data.url_heuristics ? `${data.url_heuristics.entropy}` : '--';
      explanationText.textContent = data.explanation || 'Automated inspection complete.';

      // Threat indicators tags
      indicatorsList.innerHTML = '';
      if (data.identified_suspicious_indicators && data.identified_suspicious_indicators.length > 0) {
        indicatorsContainer.classList.remove('hidden');
        data.identified_suspicious_indicators.forEach((ind) => {
          const tag = document.createElement('span');
          tag.className = 'tag-badge';
          tag.textContent = typeof ind === 'string' ? ind : (ind.title || ind.code);
          indicatorsList.appendChild(tag);
        });
      } else {
        indicatorsContainer.classList.add('hidden');
      }

      // Web3 fingerprint
      if (data.web3_fingerprint) {
        web3Hash.textContent = `SHA-256: ${data.web3_fingerprint.report_hash.slice(0, 20)}...`;
      }

      resultsCard.classList.remove('hidden');
    } catch (err) {
      explanationText.textContent = `Inspection error: ${err.message}. Ensure backend is running at http://127.0.0.1:8000.`;
      resultsCard.classList.remove('hidden');
    } finally {
      scanBtn.disabled = false;
      btnText.textContent = 'Run Security Analysis';
    }
  });

  // 5. One-Click Commit to Web3 Ledger
  commitWeb3Btn.addEventListener('click', async () => {
    if (!activeScanResult) return;
    commitWeb3Btn.disabled = true;
    commitWeb3Btn.textContent = 'Transacting on EVM Contract...';

    try {
      const response = await fetch(`${API_BASE}/api/web3/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          indicator: activeScanResult.website_and_domain_information?.hostname || currentTabUrl,
          report_data: activeScanResult,
          threat_level: activeScanResult.overall_risk,
          category: activeScanResult.category || 'Phishing',
          campaign_name: 'Extension In-Browser Discovery',
          report_hash: activeScanResult.web3_fingerprint?.report_hash
        })
      });

      if (!response.ok) throw new Error('Failed to commit on-chain');
      const data = await response.json();
      
      commitSuccessBanner.textContent = `✓ Recorded! Block #${data.record.block_number} • Tx: ${data.record.transaction_hash.slice(0, 14)}...`;
      commitSuccessBanner.classList.remove('hidden');
    } catch (e) {
      alert(`Web3 registration failed: ${e.message}`);
    } finally {
      commitWeb3Btn.disabled = false;
      commitWeb3Btn.textContent = 'Commit Fingerprint to On-Chain Ledger';
    }
  });

  // 6. AI Scam & Text Analyzer
  analyzeScamBtn.addEventListener('click', async () => {
    const text = scamTextInput.value.trim();
    if (!text) return;

    analyzeScamBtn.disabled = true;
    scamBtnText.textContent = 'Evaluating Social Engineering NLP...';
    scamResultsCard.classList.add('hidden');

    try {
      const response = await fetch(`${API_BASE}/api/analyze/message`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: text })
      });

      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();

      scamRiskScore.textContent = `${data.risk_score}/100`;
      scamRiskBadge.textContent = data.risk_classification.toUpperCase();
      scamRiskBadge.className = 'badge';
      if (data.risk_classification === 'Confirmed Malicious' || data.risk_classification === 'High Risk') {
        scamRiskBadge.classList.add('badge-high');
      } else if (data.risk_classification === 'Suspicious') {
        scamRiskBadge.classList.add('badge-suspicious');
      } else {
        scamRiskBadge.classList.add('badge-low');
      }

      scamRationale.textContent = data.distinction_rationale;
      scamSummary.textContent = data.summary;

      // Extracted entities
      extractedEntities.innerHTML = '';
      const allEnts = [
        ...(data.extracted_entities?.urls || []),
        ...(data.extracted_entities?.emails || []),
        ...(data.extracted_entities?.phones || []),
        ...(data.extracted_entities?.crypto_wallets || [])
      ];

      if (allEnts.length > 0) {
        allEnts.forEach((e) => {
          const pill = document.createElement('span');
          pill.className = 'entity-pill';
          pill.textContent = e;
          extractedEntities.appendChild(pill);
        });
      } else {
        extractedEntities.innerHTML = '<span style="color:#64748b;font-size:10px;">None detected</span>';
      }

      scamResultsCard.classList.remove('hidden');
    } catch (e) {
      alert(`Scam analysis failed: ${e.message}`);
    } finally {
      analyzeScamBtn.disabled = false;
      scamBtnText.textContent = 'Analyze Message with AI NLP';
    }
  });

  // 7. Web3 Hash Verifier
  verifyHashBtn.addEventListener('click', async () => {
    const hash = web3QueryInput.value.trim();
    if (!hash) return;

    verifyHashBtn.disabled = true;
    verifyBtnText.textContent = 'Querying Smart Contract...';
    web3ResultsCard.classList.add('hidden');

    try {
      const response = await fetch(`${API_BASE}/api/web3/verify/${encodeURIComponent(hash)}`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();

      if (data.verified) {
        web3VerificationStatus.textContent = '✓ TAMPER-EVIDENT PROOF VERIFIED';
        web3VerificationStatus.className = 'web3-status-box verified';
        w3Block.textContent = `#${data.record.block_number}`;
        w3ThreatLevel.textContent = data.record.threat_level;
        w3Disputes.textContent = data.record.dispute_count;
        w3Contract.textContent = data.record.contract_address;
      } else {
        web3VerificationStatus.textContent = '✕ UNREGISTERED OR MODIFIED RECORD';
        web3VerificationStatus.className = 'web3-status-box unregistered';
        w3Block.textContent = '--';
        w3ThreatLevel.textContent = 'Not Found';
        w3Disputes.textContent = '0';
        w3Contract.textContent = '--';
      }

      web3ResultsCard.classList.remove('hidden');
    } catch (e) {
      alert(`Verification failed: ${e.message}`);
    } finally {
      verifyHashBtn.disabled = false;
      verifyBtnText.textContent = 'Verify On-Chain Integrity';
    }
  });
});
