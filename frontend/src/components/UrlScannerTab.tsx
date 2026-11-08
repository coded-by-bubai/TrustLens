import React, { useState } from 'react';
import {
  Search,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Lock,
  ArrowRight,
  Layers,
  FileCode,
  Blocks,
  XCircle,
  HelpCircle,
  Activity,
  Cpu,
  CheckCircle2,
  Globe
} from 'lucide-react';
import type { UrlAnalysisResponse, RiskClassification, OnChainCommitmentRecord } from '../types';
import { registerOnChain } from '../services/api';

interface UrlScannerTabProps {
  urlInput: string;
  setUrlInput: (val: string) => void;
  onScan: () => void;
  isLoading: boolean;
  result: UrlAnalysisResponse | null;
  error: string | null;
}

export const UrlScannerTab: React.FC<UrlScannerTabProps> = ({
  urlInput,
  setUrlInput,
  onScan,
  isLoading,
  result,
  error
}) => {
  const [activeSubTab, setActiveSubTab] = useState<'overview' | 'dns' | 'tls' | 'headers' | 'redirects' | 'web3'>('overview');
  const [isRegisteringWeb3, setIsRegisteringWeb3] = useState(false);
  const [web3Commitment, setWeb3Commitment] = useState<OnChainCommitmentRecord | null>(null);

  const handleWeb3Register = async () => {
    if (!result) return;
    setIsRegisteringWeb3(true);
    try {
      const response = await registerOnChain(
        result as unknown as Record<string, unknown>,
        result.hostname,
        result.overall_risk,
        result.threat_intelligence.matched ? result.threat_intelligence.threat_type : 'Web Security Threat',
        result.campaign_correlations.is_part_of_campaign ? 'Coordinated Multi-Domain Phishing' : 'Ad-hoc Threat Scan',
        result.sources_of_findings,
        result.web3_fingerprint?.report_hash
      );
      setWeb3Commitment(response.record);
    } catch (e) {
      console.error(e);
      alert('Failed to register on-chain commitment.');
    } finally {
      setIsRegisteringWeb3(false);
    }
  };

  const getRiskBadge = (risk: RiskClassification) => {
    switch (risk) {
      case 'Confirmed Malicious':
        return (
          <span className="px-2.5 py-1 rounded-md text-xs font-semibold bg-red-950/80 text-red-300 border border-red-800 flex items-center space-x-1.5">
            <XCircle className="w-3.5 h-3.5 text-red-400" />
            <span>CONFIRMED MALICIOUS</span>
          </span>
        );
      case 'High Risk':
        return (
          <span className="px-2.5 py-1 rounded-md text-xs font-semibold bg-orange-950/80 text-orange-300 border border-orange-800 flex items-center space-x-1.5">
            <ShieldAlert className="w-3.5 h-3.5 text-orange-400" />
            <span>HIGH RISK</span>
          </span>
        );
      case 'Suspicious':
        return (
          <span className="px-2.5 py-1 rounded-md text-xs font-semibold bg-amber-950/80 text-amber-300 border border-amber-800 flex items-center space-x-1.5">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
            <span>SUSPICIOUS</span>
          </span>
        );
      case 'Low Risk':
        return (
          <span className="px-2.5 py-1 rounded-md text-xs font-semibold bg-emerald-950/80 text-emerald-300 border border-emerald-800 flex items-center space-x-1.5">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>LOW RISK</span>
          </span>
        );
      default:
        return (
          <span className="px-2.5 py-1 rounded-md text-xs font-semibold bg-slate-800 text-slate-300 border border-slate-700 flex items-center space-x-1.5">
            <HelpCircle className="w-3.5 h-3.5 text-slate-400" />
            <span>INCONCLUSIVE</span>
          </span>
        );
    }
  };

  return (
    <div className="space-y-5">
      {/* Search Input Bar */}
      <div className="bg-[#0f172a] p-4 rounded-xl border border-slate-800 shadow-sm">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            onScan();
          }}
          className="flex flex-col sm:flex-row gap-3"
        >
          <div className="relative flex-1">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="Enter URL or domain to investigate (e.g. paypal-security-update.account-verification.xyz)"
              className="w-full bg-slate-900 border border-slate-750 rounded-lg pl-10 pr-4 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 font-mono"
            />
          </div>
          <button
            type="submit"
            disabled={isLoading || !urlInput.trim()}
            className="px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-medium text-sm transition-colors shadow-sm disabled:opacity-50 flex items-center justify-center space-x-2 shrink-0"
          >
            {isLoading ? (
              <>
                <Activity className="w-4 h-4 animate-spin text-white" />
                <span>Investigating...</span>
              </>
            ) : (
              <>
                <ShieldAlert className="w-4 h-4" />
                <span>Investigate Target</span>
              </>
            )}
          </button>
        </form>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="p-3.5 rounded-lg bg-red-950/40 border border-red-800 text-red-200 text-xs sm:text-sm flex items-center space-x-2.5">
          <XCircle className="w-4 h-4 text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* SSRF Block Banner */}
      {result && result.is_blocked && (
        <div className="p-4 rounded-lg bg-red-950/50 border border-red-800 text-red-200 text-sm flex items-start space-x-3">
          <ShieldAlert className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div>
            <div className="font-semibold text-red-300">SSRF Policy Guard Activated</div>
            <p className="text-xs text-red-200 mt-0.5">{result.explanation}</p>
            <div className="text-[11px] text-red-400 mt-1">
              Internal network ranges (RFC1918), loopbacks (127.0.0.1, localhost), and cloud metadata IP (169.254.169.254) are strictly disallowed.
            </div>
          </div>
        </div>
      )}

      {/* Results View */}
      {result && (
        <div className="space-y-5">
          {/* Main Assessment Header Card (Section 6 Requirements) */}
          <div className="bg-[#0f172a] rounded-xl p-5 sm:p-6 border border-slate-800 shadow-sm">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-5 border-b border-slate-800">
              <div>
                <div className="flex flex-wrap items-center gap-2.5 mb-1.5">
                  <h2 className="text-lg font-bold font-mono text-white truncate max-w-xl">
                    {result.hostname}
                  </h2>
                  {getRiskBadge(result.overall_risk)}
                </div>
                <div className="text-xs text-slate-400 flex flex-wrap gap-x-3 gap-y-1">
                  <span>Target: <span className="text-slate-300 font-mono">{result.target_url}</span></span>
                  <span>•</span>
                  <span>Confidence: <span className="text-emerald-400 font-medium">{result.confidence_score}%</span></span>
                  <span>•</span>
                  <span>Coverage: <span className="text-slate-300">{result.evidence_coverage}</span></span>
                </div>
              </div>

              {/* Risk Score Indicator */}
              <div className="flex items-center space-x-3.5 bg-slate-900 px-4 py-2.5 rounded-lg border border-slate-800 self-start lg:self-auto">
                <div className="text-right">
                  <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                    Threat Index
                  </div>
                  <div className="text-xl font-bold font-mono text-white">
                    {result.risk_score}
                    <span className="text-xs font-normal text-slate-500"> / 100</span>
                  </div>
                </div>
                <div className="w-11 h-11 rounded-full border-2 border-slate-700 flex items-center justify-center relative">
                  <div
                    className={`w-full h-full rounded-full border-2 ${
                      result.risk_score >= 60
                        ? 'border-red-500'
                        : result.risk_score >= 25
                        ? 'border-amber-500'
                        : 'border-emerald-500'
                    }`}
                  ></div>
                  <span className="absolute font-semibold text-[11px] font-mono">{result.risk_score}</span>
                </div>
              </div>
            </div>

            {/* Plain-English Evidence Explanation */}
            <div className="pt-4 space-y-1.5">
              <div className="flex items-center space-x-1.5 text-slate-300 text-xs font-semibold uppercase tracking-wider">
                <Cpu className="w-3.5 h-3.5 text-blue-400" />
                <span>Security Assessment Findings Summary</span>
              </div>
              <p className="text-xs sm:text-sm text-slate-300 leading-relaxed bg-slate-900 p-3.5 rounded-lg border border-slate-800">
                {result.explanation}
              </p>
            </div>

            {/* Sub-Tabs Navigation */}
            <div className="flex flex-wrap gap-1.5 pt-5 mt-4 border-t border-slate-800">
              <button
                onClick={() => setActiveSubTab('overview')}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors flex items-center space-x-1.5 ${
                  activeSubTab === 'overview'
                    ? 'bg-blue-600 text-white'
                    : 'bg-slate-900 text-slate-300 hover:bg-slate-800 border border-slate-800'
                }`}
              >
                <Layers className="w-3.5 h-3.5" />
                <span>Indicators ({result.identified_threat_indicators.length})</span>
              </button>

              <button
                onClick={() => setActiveSubTab('dns')}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors flex items-center space-x-1.5 ${
                  activeSubTab === 'dns'
                    ? 'bg-blue-600 text-white'
                    : 'bg-slate-900 text-slate-300 hover:bg-slate-800 border border-slate-800'
                }`}
              >
                <Globe className="w-3.5 h-3.5" />
                <span>DNS Intelligence</span>
              </button>

              <button
                onClick={() => setActiveSubTab('tls')}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors flex items-center space-x-1.5 ${
                  activeSubTab === 'tls'
                    ? 'bg-blue-600 text-white'
                    : 'bg-slate-900 text-slate-300 hover:bg-slate-800 border border-slate-800'
                }`}
              >
                <Lock className="w-3.5 h-3.5" />
                <span>TLS Trust ({result.tls_analysis.status})</span>
              </button>

              <button
                onClick={() => setActiveSubTab('headers')}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors flex items-center space-x-1.5 ${
                  activeSubTab === 'headers'
                    ? 'bg-blue-600 text-white'
                    : 'bg-slate-900 text-slate-300 hover:bg-slate-800 border border-slate-800'
                }`}
              >
                <FileCode className="w-3.5 h-3.5" />
                <span>Security Assessment</span>
              </button>

              <button
                onClick={() => setActiveSubTab('redirects')}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors flex items-center space-x-1.5 ${
                  activeSubTab === 'redirects'
                    ? 'bg-blue-600 text-white'
                    : 'bg-slate-900 text-slate-300 hover:bg-slate-800 border border-slate-800'
                }`}
              >
                <ArrowRight className="w-3.5 h-3.5" />
                <span>Redirects ({result.redirect_analysis.redirect_count} hops)</span>
              </button>

              <button
                onClick={() => setActiveSubTab('web3')}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors flex items-center space-x-1.5 ${
                  activeSubTab === 'web3'
                    ? 'bg-blue-600 text-white'
                    : 'bg-slate-900 text-slate-300 hover:bg-slate-800 border border-slate-800'
                }`}
              >
                <Blocks className="w-3.5 h-3.5" />
                <span>Web3 Provenance</span>
              </button>
            </div>
          </div>

          {/* Sub-Tab 1: Indicators & Heuristics */}
          {activeSubTab === 'overview' && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div className="bg-[#0f172a] p-3.5 rounded-lg border border-slate-800">
                  <span className="text-[11px] text-slate-400 block mb-0.5">Shannon Entropy (DGA)</span>
                  <span className="text-lg font-bold font-mono text-white">
                    {result.url_heuristics.entropy}{' '}
                    <span className="text-xs font-normal text-slate-400">
                      {result.url_heuristics.entropy > 3.8 ? '(High - Likely Random)' : '(Normal)'}
                    </span>
                  </span>
                </div>

                <div className="bg-[#0f172a] p-3.5 rounded-lg border border-slate-800">
                  <span className="text-[11px] text-slate-400 block mb-0.5">Top-Level Domain (TLD)</span>
                  <span className="text-lg font-bold font-mono text-white">
                    .{result.url_heuristics.tld || 'com'}
                  </span>
                </div>

                <div className="bg-[#0f172a] p-3.5 rounded-lg border border-slate-800">
                  <span className="text-[11px] text-slate-400 block mb-0.5">Threat Intel Match</span>
                  <span className={`text-sm font-semibold font-mono ${result.threat_intelligence.matched ? 'text-red-400' : 'text-emerald-400'}`}>
                    {result.threat_intelligence.matched ? result.threat_intelligence.provider : 'Clean in Known Feeds'}
                  </span>
                </div>
              </div>

              {/* Indicators List */}
              <div className="bg-[#0f172a] p-5 rounded-xl border border-slate-800">
                <h3 className="text-sm font-semibold text-white mb-3 flex items-center space-x-2">
                  <ShieldAlert className="w-4 h-4 text-slate-400" />
                  <span>Identified Threat Indicators ({result.identified_threat_indicators.length})</span>
                </h3>

                {result.identified_threat_indicators.length === 0 ? (
                  <p className="text-xs text-emerald-400">
                    ✓ No suspicious or malicious indicators were identified within the available checks.
                  </p>
                ) : (
                  <div className="space-y-2">
                    {result.identified_threat_indicators.map((ind, idx) => (
                      <div
                        key={idx}
                        className={`p-3 rounded-lg border flex items-start space-x-3 ${
                          ind.severity === 'CRITICAL'
                            ? 'bg-red-950/30 border-red-800 text-red-200'
                            : ind.severity === 'HIGH'
                            ? 'bg-orange-950/30 border-orange-800 text-orange-200'
                            : ind.severity === 'MEDIUM'
                            ? 'bg-amber-950/30 border-amber-800 text-amber-200'
                            : 'bg-slate-900 border-slate-800 text-slate-300'
                        }`}
                      >
                        <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-current" />
                        <div className="flex-1">
                          <div className="flex items-center justify-between">
                            <span className="font-semibold text-xs text-white">{ind.title}</span>
                            <div className="flex items-center space-x-2">
                              {ind.source && (
                                <span className="text-[10px] text-slate-400">
                                  {ind.source}
                                </span>
                              )}
                              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-black/40 border border-slate-700 font-bold">
                                {ind.severity}
                              </span>
                            </div>
                          </div>
                          <p className="text-xs mt-1 text-slate-300 leading-normal">{ind.description}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Recommended Actions */}
              <div className="bg-[#0f172a] p-5 rounded-xl border border-slate-800">
                <h3 className="text-xs uppercase tracking-wider font-semibold text-slate-300 mb-2">Recommended Precautions</h3>
                <ul className="space-y-1.5 text-xs text-slate-300">
                  {result.recommended_actions.map((act, i) => (
                    <li key={i} className="flex items-center space-x-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-blue-500"></span>
                      <span>{act}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Section 6 Limitations Disclosure */}
              <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-400">
                <span className="text-slate-300 font-semibold block mb-0.5">Limitations & Verification Coverage:</span>
                {result.limitations_and_unavailable_checks}
              </div>
            </div>
          )}

          {/* Sub-Tab 2: DNS & Domain Intelligence */}
          {activeSubTab === 'dns' && (
            <div className="space-y-4">
              <div className="bg-[#0f172a] p-5 rounded-xl border border-slate-800 space-y-4">
                <div className="flex justify-between items-center pb-3 border-b border-slate-800">
                  <h3 className="text-sm font-semibold text-white flex items-center space-x-2">
                    <Globe className="w-4 h-4 text-blue-400" />
                    <span>DNS Characteristics & Domain Records</span>
                  </h3>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold ${
                    result.dns_analysis.dns_data.is_resolvable
                      ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                      : 'bg-red-950 text-red-300 border border-red-800'
                  }`}>
                    {result.dns_analysis.dns_data.is_resolvable ? 'ACTIVE DNS' : 'UNRESOLVABLE'}
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-mono">
                  {/* IPv4 A Records */}
                  <div className="p-3 bg-slate-900 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block mb-1 font-sans text-[11px]">IPv4 (A Records)</span>
                    {result.dns_analysis.dns_data.a_records.length > 0 ? (
                      result.dns_analysis.dns_data.a_records.map((ip, i) => (
                        <span key={i} className="block text-white font-semibold">{ip}</span>
                      ))
                    ) : (
                      <span className="text-slate-500">None</span>
                    )}
                  </div>

                  {/* Mail Exchangers (MX) */}
                  <div className="p-3 bg-slate-900 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block mb-1 font-sans text-[11px]">Mail Servers (MX)</span>
                    {result.dns_analysis.dns_data.mx_records.length > 0 ? (
                      result.dns_analysis.dns_data.mx_records.slice(0, 2).map((mx, i) => (
                        <span key={i} className="block text-white truncate">{mx}</span>
                      ))
                    ) : (
                      <span className="text-amber-400 font-medium">None Configured</span>
                    )}
                  </div>

                  {/* Name Servers (NS) */}
                  <div className="p-3 bg-slate-900 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block mb-1 font-sans text-[11px]">Authoritative NS</span>
                    {result.dns_analysis.dns_data.ns_records.length > 0 ? (
                      result.dns_analysis.dns_data.ns_records.slice(0, 2).map((ns, i) => (
                        <span key={i} className="block text-white truncate">{ns}</span>
                      ))
                    ) : (
                      <span className="text-slate-500">None</span>
                    )}
                  </div>

                  {/* SPF & DMARC Spoofing Protection */}
                  <div className="p-3 bg-slate-900 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block mb-1 font-sans text-[11px]">Email Authentication</span>
                    <div className="space-y-1">
                      <div className="flex items-center space-x-1.5">
                        <span className="text-slate-400">SPF:</span>
                        <span className={result.dns_analysis.dns_data.has_spf ? 'text-emerald-400 font-semibold' : 'text-amber-400 font-semibold'}>
                          {result.dns_analysis.dns_data.has_spf ? 'Configured' : 'Missing'}
                        </span>
                      </div>
                      <div className="flex items-center space-x-1.5">
                        <span className="text-slate-400">DMARC:</span>
                        <span className={result.dns_analysis.dns_data.has_dmarc ? 'text-emerald-400 font-semibold' : 'text-amber-400 font-semibold'}>
                          {result.dns_analysis.dns_data.has_dmarc ? 'Enforced' : 'Missing'}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Sub-Tab 3: TLS & Certificate Analysis */}
          {activeSubTab === 'tls' && (
            <div className="space-y-4">
              {result.tls_analysis.has_tls ? (
                <>
                  <div className="bg-[#0f172a] p-5 rounded-xl border border-slate-800">
                    <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 pb-4 border-b border-slate-800">
                      <div>
                        <span className="text-xs text-slate-400">TLS Configuration Assessment</span>
                        <div className="text-base font-bold text-white flex items-center space-x-2">
                          <Lock className="w-4 h-4 text-emerald-400" />
                          <span>Status: {result.tls_analysis.status}</span>
                          <span className="text-xs px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 font-mono">
                            Trust Score: {result.tls_analysis.trust_score}/100
                          </span>
                        </div>
                      </div>
                      <div className="text-right text-xs font-mono text-slate-400">
                        Protocol: <span className="text-slate-200">{result.tls_analysis.tls_version}</span> | Cipher: <span className="text-slate-200">{result.tls_analysis.cipher_suite}</span>
                      </div>
                    </div>

                    {/* Certificate Details Grid */}
                    {result.tls_analysis.certificate && (
                      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 pt-4 text-xs font-mono">
                        <div className="p-3 bg-slate-900 rounded-lg border border-slate-800">
                          <span className="text-slate-400 block mb-1 font-sans text-[11px]">Common Name (CN)</span>
                          <span className="text-white font-semibold truncate block">
                            {result.tls_analysis.certificate.subject_cn || 'None'}
                          </span>
                        </div>

                        <div className="p-3 bg-slate-900 rounded-lg border border-slate-800">
                          <span className="text-slate-400 block mb-1 font-sans text-[11px]">Issuing CA</span>
                          <span className="text-white font-semibold truncate block">
                            {result.tls_analysis.certificate.issuer_cn || result.tls_analysis.certificate.issuer_org || 'Unknown CA'}
                          </span>
                        </div>

                        <div className="p-3 bg-slate-900 rounded-lg border border-slate-800">
                          <span className="text-slate-400 block mb-1 font-sans text-[11px]">Public Key & Signature</span>
                          <span className="text-white font-semibold">
                            {result.tls_analysis.certificate.key_type} {result.tls_analysis.certificate.key_size}-bit ({result.tls_analysis.certificate.signature_algorithm})
                          </span>
                        </div>

                        <div className="p-3 bg-slate-900 rounded-lg border border-slate-800">
                          <span className="text-slate-400 block mb-1 font-sans text-[11px]">Valid Days Remaining</span>
                          <span className={`font-semibold ${result.tls_analysis.certificate.is_expired ? 'text-red-400' : 'text-emerald-400'}`}>
                            {result.tls_analysis.certificate.is_expired ? 'EXPIRED' : `${result.tls_analysis.certificate.days_remaining} Days`}
                          </span>
                        </div>

                        <div className="p-3 bg-slate-900 rounded-lg border border-slate-800">
                          <span className="text-slate-400 block mb-1 font-sans text-[11px]">SAN Domains Count</span>
                          <span className="text-white font-semibold">
                            {result.tls_analysis.certificate.san_count} Alternative Names
                          </span>
                        </div>

                        <div className="p-3 bg-slate-900 rounded-lg border border-slate-800">
                          <span className="text-slate-400 block mb-1 font-sans text-[11px]">Certificate Transparency</span>
                          <span className="text-white font-semibold">
                            {result.tls_analysis.certificate_transparency?.status || 'Active in Logs'}
                          </span>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Mandatory Problem Statement Caveat Banner */}
                  <div className="p-3.5 rounded-lg bg-amber-950/40 border border-amber-800 text-amber-200 text-xs flex items-start space-x-2.5">
                    <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-semibold">Digital Trust Axiom:</span>{' '}
                      {result.tls_analysis.critical_caveat}
                    </div>
                  </div>
                </>
              ) : (
                <div className="p-5 rounded-lg bg-red-950/40 border border-red-800 text-red-200 text-sm">
                  <div className="font-semibold mb-1">No Valid TLS Certificate Encountered</div>
                  <p className="text-xs text-red-300">{result.tls_analysis.error}</p>
                </div>
              )}
            </div>
          )}

          {/* Sub-Tab 4: Website Security Assessment */}
          {activeSubTab === 'headers' && (
            <div className="space-y-4">
              <div className="bg-[#0f172a] p-5 rounded-xl border border-slate-800">
                <div className="flex justify-between items-center pb-4 border-b border-slate-800">
                  <div>
                    <span className="text-xs text-slate-400">Website Defensive Posture</span>
                    <div className="text-2xl font-bold font-mono text-white flex items-center space-x-2.5">
                      <span className={`${
                        result.security_headers.score >= 80 ? 'text-emerald-400' : result.security_headers.score >= 50 ? 'text-amber-400' : 'text-red-400'
                      }`}>
                        {result.security_headers.grade}
                      </span>
                      <span className="text-xs font-normal text-slate-400 font-sans">
                        ({result.security_headers.score} / 100 points)
                      </span>
                    </div>
                  </div>
                </div>

                {/* Structured Defensive Findings */}
                <div className="mt-4 space-y-2.5">
                  <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                    Detailed Security Findings ({result.security_headers.findings?.length || 0})
                  </h4>

                  {result.security_headers.findings?.map((f, i) => (
                    <div key={i} className="p-3.5 bg-slate-900 rounded-lg border border-slate-800 space-y-1.5 text-xs font-sans">
                      <div className="flex justify-between items-center">
                        <span className="font-semibold text-white">{f.identified_security_issue}</span>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                          f.severity_classification === 'HIGH'
                            ? 'bg-red-950 text-red-300 border border-red-800'
                            : f.severity_classification === 'MEDIUM'
                            ? 'bg-amber-950 text-amber-300 border border-amber-800'
                            : 'bg-slate-800 text-slate-300'
                        }`}>
                          {f.severity_classification}
                        </span>
                      </div>
                      
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-slate-300 pt-1">
                        <div>
                          <span className="text-slate-400 block text-[11px]">Technical Evidence:</span>
                          <span className="text-slate-200 font-mono text-[11px]">{f.technical_evidence}</span>
                        </div>
                        <div>
                          <span className="text-slate-400 block text-[11px]">Potential Impact:</span>
                          <span className="text-slate-200 text-[11px]">{f.potential_impact}</span>
                        </div>
                      </div>

                      <div className="pt-1 border-t border-slate-800 text-slate-300">
                        <span className="text-slate-400 block text-[11px]">Recommended Remediation:</span>
                        <span className="text-blue-300 text-[11px]">{f.recommended_remediation}</span>
                      </div>
                      <div className="pt-0.5 text-slate-400 text-[10px]">
                        <span className="text-slate-500 block">Relevant Limitations:</span>
                        <span>{f.relevant_limitations}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Sub-Tab 5: Redirect Chain */}
          {activeSubTab === 'redirects' && (
            <div className="bg-[#0f172a] p-5 rounded-xl border border-slate-800">
              <h3 className="text-sm font-semibold text-white mb-3 flex items-center space-x-2">
                <ArrowRight className="w-4 h-4 text-blue-400" />
                <span>Redirect Path & Safe Hop Traversal</span>
              </h3>

              {result.redirect_analysis.cross_domain_redirect && (
                <div className="p-3 mb-3.5 rounded-lg bg-orange-950/40 border border-orange-800 text-orange-200 text-xs flex items-center space-x-2">
                  <AlertTriangle className="w-4 h-4 text-orange-400 shrink-0" />
                  <span>Cross-domain redirection detected: Initial URL redirects to a different host.</span>
                </div>
              )}

              <div className="space-y-2">
                {result.redirect_analysis.chain.map((hop, i) => (
                  <div key={i} className="p-3 bg-slate-900 rounded-lg border border-slate-800 flex items-center space-x-3 text-xs">
                    <div className="w-6 h-6 rounded bg-slate-800 text-slate-300 font-mono flex items-center justify-center font-semibold text-[11px]">
                      #{hop.hop}
                    </div>
                    <div className="flex-1 font-mono truncate">
                      <div className="text-white truncate">{hop.url}</div>
                      {hop.location && (
                        <div className="text-slate-400 text-[11px] flex items-center space-x-1 mt-0.5">
                          <span>Redirects to:</span>
                          <span className="text-blue-300 truncate">{hop.location}</span>
                        </div>
                      )}
                    </div>
                    <div className="text-right">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold ${
                        hop.status_code >= 300 && hop.status_code < 400
                          ? 'bg-amber-950 text-amber-300 border border-amber-800'
                          : hop.status_code === 200
                          ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                          : 'bg-slate-800 text-slate-300'
                      }`}>
                        HTTP {hop.status_code || 'ERR'}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Sub-Tab 6: Web3 Decentralized Threat Intelligence */}
          {activeSubTab === 'web3' && (
            <div className="bg-[#0f172a] p-5 rounded-xl border border-slate-800 space-y-4">
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 pb-3 border-b border-slate-800">
                <div>
                  <h3 className="text-sm font-semibold text-white flex items-center space-x-2">
                    <Blocks className="w-4 h-4 text-emerald-400" />
                    <span>Cryptographic Threat Report Commitment</span>
                  </h3>
                  <span className="text-xs text-slate-400 font-mono">
                    Smart Contract: <span className="text-slate-300">{result.web3_fingerprint.smart_contract}</span>
                  </span>
                </div>
                <div className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                  Zero PII On-Chain
                </div>
              </div>

              {/* SHA-256 Digest Card */}
              <div className="p-3.5 bg-slate-900 rounded-lg border border-slate-800 font-mono text-xs">
                <span className="text-slate-400 block mb-1 font-sans text-[11px]">Deterministic SHA-256 Report Digest:</span>
                <span className="text-emerald-300 font-semibold break-all select-all">
                  {result.web3_fingerprint.report_hash}
                </span>
              </div>

              {/* Action Button */}
              {!web3Commitment ? (
                <button
                  onClick={handleWeb3Register}
                  disabled={isRegisteringWeb3}
                  className="w-full py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-medium text-xs uppercase tracking-wider transition-colors shadow-sm flex items-center justify-center space-x-2 disabled:opacity-50"
                >
                  {isRegisteringWeb3 ? (
                    <>
                      <Activity className="w-4 h-4 animate-spin" />
                      <span>Recording On-Chain...</span>
                    </>
                  ) : (
                    <>
                      <Blocks className="w-4 h-4" />
                      <span>Commit Cryptographic Hash To ThreatRegistry.sol</span>
                    </>
                  )}
                </button>
              ) : (
                <div className="p-3.5 rounded-lg bg-emerald-950/30 border border-emerald-800 text-xs font-mono space-y-1.5">
                  <div className="flex items-center space-x-2 text-emerald-400 font-semibold">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Cryptographic Commitment Recorded On-Chain</span>
                  </div>
                  <div className="text-slate-300 space-y-0.5 text-[11px]">
                    <div>Tx Hash: <span className="text-blue-300 break-all">{web3Commitment.transaction_hash}</span></div>
                    <div>Block: <span className="text-white">#{web3Commitment.block_number}</span></div>
                    <div>Recorded: <span className="text-slate-300">{web3Commitment.iso_timestamp}</span></div>
                    <div>Network: <span className="text-emerald-300">{web3Commitment.network}</span></div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
