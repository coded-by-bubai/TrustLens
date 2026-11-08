import React, { useState } from 'react';
import {
  Brain,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Link,
  Mail,
  Phone,
  Wallet,
  Blocks,
  Activity,
  ShieldCheck,
  Info,
  MessageSquareCode,
  Fingerprint,
  FileSearch
} from 'lucide-react';
import type { MessageAnalysisResponse, RiskClassification, OnChainCommitmentRecord } from '../types';
import { analyzeMessage, registerOnChain } from '../services/api';

interface ScamAnalyzerTabProps {
  messageInput: string;
  setMessageInput: (val: string) => void;
}

export const ScamAnalyzerTab: React.FC<ScamAnalyzerTabProps> = ({
  messageInput,
  setMessageInput
}) => {
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<MessageAnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isRegisteringWeb3, setIsRegisteringWeb3] = useState(false);
  const [web3Commitment, setWeb3Commitment] = useState<OnChainCommitmentRecord | null>(null);

  const handleAnalyze = async () => {
    if (!messageInput.trim()) return;
    setIsLoading(true);
    setError(null);
    setWeb3Commitment(null);
    try {
      const data = await analyzeMessage(messageInput);
      setResult(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Message analysis failed');
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      handleAnalyze();
    }
  };

  const handleWeb3Register = async () => {
    if (!result) return;
    setIsRegisteringWeb3(true);
    try {
      const response = await registerOnChain(
        result as unknown as Record<string, unknown>,
        'Suspicious Communication Message',
        result.risk_classification,
        'Social Engineering Scam',
        'Social Engineering Phishing Campaign',
        undefined,
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
          <span className="px-3 py-1 rounded text-xs font-mono font-medium bg-red-950/80 text-red-300 border border-red-800 flex items-center space-x-1.5">
            <ShieldAlert className="w-4 h-4 text-red-400" />
            <span>CONFIRMED MALICIOUS</span>
          </span>
        );
      case 'High Risk':
        return (
          <span className="px-3 py-1 rounded text-xs font-mono font-medium bg-orange-950/80 text-orange-300 border border-orange-800 flex items-center space-x-1.5">
            <ShieldAlert className="w-4 h-4 text-orange-400" />
            <span>HIGH RISK SCAM</span>
          </span>
        );
      case 'Suspicious':
        return (
          <span className="px-3 py-1 rounded text-xs font-mono font-medium bg-amber-950/80 text-amber-300 border border-amber-800 flex items-center space-x-1.5">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            <span>SUSPICIOUS PATTERNS</span>
          </span>
        );
      case 'Low Risk':
        return (
          <span className="px-3 py-1 rounded text-xs font-mono font-medium bg-emerald-950/80 text-emerald-300 border border-emerald-800 flex items-center space-x-1.5">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>LOW RISK</span>
          </span>
        );
      default:
        return (
          <span className="px-3 py-1 rounded text-xs font-mono font-medium bg-slate-800 text-slate-300 border border-slate-700 flex items-center space-x-1.5">
            <HelpCircle className="w-4 h-4 text-slate-400" />
            <span>INCONCLUSIVE</span>
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Input Form */}
      <div className="bg-[#0f172a] p-6 rounded-xl border border-slate-800 space-y-4">
        <div>
          <h2 className="text-base font-semibold text-white flex items-center space-x-2">
            <Brain className="w-5 h-5 text-blue-400" />
            <span>AI-Powered Scam & Social Engineering Detector</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Submit suspicious emails, SMS texts, phishing lures, or fake support messages for NLP behavioral inspection.
          </p>
        </div>

        <textarea
          rows={5}
          value={messageInput}
          onChange={(e) => setMessageInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Paste suspicious text here... Example: 'URGENT: Your bank account will be suspended in 24 hours. Verify your password and OTP immediately at https://chase-auth-verification.com'"
          className="w-full bg-[#090d16] border border-slate-800 rounded-lg p-4 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 font-mono resize-y"
        ></textarea>

        <div className="flex flex-col sm:flex-row justify-between items-center gap-3">
          <div className="flex items-center space-x-2 text-xs text-slate-400">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>Prompt-Injection Hardened • PII Kept Off-Chain (Press Ctrl+Enter to Analyze)</span>
          </div>

          <button
            onClick={handleAnalyze}
            disabled={isLoading || !messageInput.trim()}
            className="w-full sm:w-auto px-6 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-medium text-xs tracking-wider transition-colors disabled:opacity-50 flex items-center justify-center space-x-2"
          >
            {isLoading ? (
              <>
                <Activity className="w-4 h-4 animate-spin" />
                <span>Evaluating Behavioral Vectors...</span>
              </>
            ) : (
              <>
                <Brain className="w-4 h-4" />
                <span>Analyze Message</span>
              </>
            )}
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-lg bg-red-950/40 border border-red-800 text-red-200 text-sm flex items-center space-x-3">
          <XCircle className="w-5 h-5 text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Placeholder State (Shown Before Clicking Analyze) */}
      {!result && !isLoading && !error && (
        <div className="bg-[#0f172a] p-10 rounded-xl border border-slate-800 text-center space-y-6">
          <div className="mx-auto w-12 h-12 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-center text-blue-400">
            <MessageSquareCode className="w-6 h-6" />
          </div>

          <div className="max-w-md mx-auto space-y-2">
            <h3 className="text-sm font-semibold text-white">Awaiting Message Analysis</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Enter or paste message content in the editor above and click <span className="text-blue-400 font-medium">Analyze Message</span> to initiate behavioral threat detection, entity extraction, and risk assessment.
            </p>
          </div>

          {/* Capability Highlights */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-4 max-w-3xl mx-auto text-left">
            <div className="p-4 rounded-lg bg-[#090d16] border border-slate-800 space-y-1.5">
              <div className="flex items-center space-x-2 text-blue-400 text-xs font-semibold">
                <FileSearch className="w-4 h-4" />
                <span>Social Engineering</span>
              </div>
              <p className="text-xs text-slate-400 leading-normal">
                Detects urgency pressure, fear manipulation, authority impersonation, and fake account suspension warnings.
              </p>
            </div>

            <div className="p-4 rounded-lg bg-[#090d16] border border-slate-800 space-y-1.5">
              <div className="flex items-center space-x-2 text-emerald-400 text-xs font-semibold">
                <Fingerprint className="w-4 h-4" />
                <span>Fraud Distinction</span>
              </div>
              <p className="text-xs text-slate-400 leading-normal">
                Strictly differentiates benign persuasive phrasing from verified technical evidence of deceptive credential solicitation.
              </p>
            </div>

            <div className="p-4 rounded-lg bg-[#090d16] border border-slate-800 space-y-1.5">
              <div className="flex items-center space-x-2 text-amber-400 text-xs font-semibold">
                <Blocks className="w-4 h-4" />
                <span>Entity & Web3 Proof</span>
              </div>
              <p className="text-xs text-slate-400 leading-normal">
                Extracts links, emails, and crypto addresses, allowing one-click cryptographic commitment on the decentralized ledger.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Analysis Results (Only visible after clicking Analyze Message) */}
      {result && (
        <div className="space-y-6">
          {/* Header Card */}
          <div className="bg-[#0f172a] p-6 rounded-xl border border-slate-800">
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 pb-4 border-b border-slate-800">
              <div>
                <span className="text-xs text-slate-400 uppercase tracking-wider font-mono">Threat Classification</span>
                <div className="flex items-center space-x-3 mt-1.5">
                  {getRiskBadge(result.risk_classification)}
                  {result.prompt_injection_flag && (
                    <span className="px-2.5 py-0.5 rounded text-xs font-mono font-medium bg-red-950 text-red-400 border border-red-800">
                      Adversarial Prompt Injection Neutralized
                    </span>
                  )}
                </div>
              </div>

              <div className="text-right">
                <span className="text-xs text-slate-400 uppercase tracking-wider font-mono">Risk Score</span>
                <div className="text-2xl font-bold font-mono text-white mt-0.5">
                  {result.risk_score}
                  <span className="text-xs text-slate-400 font-normal"> / 100</span>
                </div>
              </div>
            </div>

            {/* Distinction Banner */}
            <div className="mt-4 p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
              <div className="flex items-center space-x-2 text-blue-400 font-mono text-xs font-semibold uppercase tracking-wider">
                <Info className="w-4 h-4 text-blue-400" />
                <span>AI Language Analysis & Fraud Evidence Distinction</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                {result.distinction_rationale}
              </p>
              {result.has_only_urgent_language && (
                <div className="p-2.5 rounded bg-amber-950/30 border border-amber-900/60 text-amber-300 text-xs">
                  Important: Message contains urgent or persuasive language, but is not labeled fraudulent without verified technical evidence.
                </div>
              )}
            </div>

            {/* Assessment Summary */}
            <div className="pt-4 space-y-2">
              <span className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider">
                Assessment Summary
              </span>
              <p className="text-sm text-slate-200 leading-relaxed bg-[#090d16] p-4 rounded-lg border border-slate-800">
                {result.summary}
              </p>
            </div>
          </div>

          {/* Verified Evidence of Fraud */}
          {result.verified_evidence_of_fraud && result.verified_evidence_of_fraud.length > 0 && (
            <div className="bg-[#0f172a] p-5 rounded-xl border border-red-900/50 space-y-3">
              <h3 className="text-sm font-semibold text-red-400 flex items-center space-x-2">
                <ShieldAlert className="w-4 h-4 text-red-400" />
                <span>Verified Technical Evidence of Fraud ({result.verified_evidence_of_fraud.length})</span>
              </h3>
              <div className="space-y-1.5">
                {result.verified_evidence_of_fraud.map((ev, idx) => (
                  <div key={idx} className="p-2.5 rounded bg-red-950/30 border border-red-900/50 text-xs font-mono text-red-200 flex items-center space-x-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-red-400"></span>
                    <span>{ev}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Social Engineering Vectors */}
          <div className="bg-[#0f172a] p-6 rounded-xl border border-slate-800">
            <h3 className="text-sm font-semibold text-white mb-4 flex items-center space-x-2">
              <Brain className="w-4 h-4 text-blue-400" />
              <span>Identified Social Engineering Vectors ({result.patterns_detected.length})</span>
            </h3>

            {result.patterns_detected.length === 0 ? (
              <p className="text-xs text-emerald-400">
                ✓ No high-pressure manipulation tactics or credential phishing signatures detected.
              </p>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {result.patterns_detected.map((pat, idx) => (
                  <div
                    key={idx}
                    className="p-4 rounded-lg bg-[#090d16] border border-slate-800 space-y-2"
                  >
                    <div className="flex justify-between items-center">
                      <span className="text-xs font-semibold text-white">{pat.title}</span>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                        pat.is_fraud_evidence
                          ? 'bg-red-950/80 text-red-300 border border-red-800 font-medium'
                          : 'bg-slate-800 text-slate-300 border border-slate-700'
                      }`}>
                        {pat.is_fraud_evidence ? 'FRAUD EVIDENCE' : 'SUSPICIOUS PATTERN'}
                      </span>
                    </div>
                    <p className="text-xs text-slate-300">{pat.impact}</p>
                    <div className="pt-1">
                      <span className="text-[11px] font-mono text-slate-400 block mb-1">Trigger Phrases:</span>
                      <div className="flex flex-wrap gap-1.5">
                        {pat.matched_terms.map((term, tIdx) => (
                          <span
                            key={tIdx}
                            className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700"
                          >
                            "{term}"
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Extracted Indicators */}
          <div className="bg-[#0f172a] p-6 rounded-xl border border-slate-800">
            <h3 className="text-sm font-semibold text-white mb-4 flex items-center space-x-2">
              <Link className="w-4 h-4 text-blue-400" />
              <span>Extracted Technical Indicators & Correlated Threat Intel</span>
            </h3>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs font-mono">
              {/* URLs */}
              <div className="p-3.5 bg-[#090d16] rounded-lg border border-slate-800">
                <div className="flex items-center space-x-1.5 text-blue-400 mb-2 font-semibold">
                  <Link className="w-3.5 h-3.5" />
                  <span>Links ({result.extracted_entities.urls.length})</span>
                </div>
                {result.extracted_entities.urls.length > 0 ? (
                  <div className="space-y-1">
                    {result.extracted_entities.urls.map((u, i) => (
                      <span key={i} className="block text-slate-300 truncate" title={u}>
                        {u}
                      </span>
                    ))}
                  </div>
                ) : (
                  <span className="text-slate-500">None detected</span>
                )}
              </div>

              {/* Emails */}
              <div className="p-3.5 bg-[#090d16] rounded-lg border border-slate-800">
                <div className="flex items-center space-x-1.5 text-emerald-400 mb-2 font-semibold">
                  <Mail className="w-3.5 h-3.5" />
                  <span>Emails ({result.extracted_entities.emails.length})</span>
                </div>
                {result.extracted_entities.emails.length > 0 ? (
                  <div className="space-y-1">
                    {result.extracted_entities.emails.map((e, i) => (
                      <span key={i} className="block text-slate-300 truncate">{e}</span>
                    ))}
                  </div>
                ) : (
                  <span className="text-slate-500">None detected</span>
                )}
              </div>

              {/* Phone Numbers */}
              <div className="p-3.5 bg-[#090d16] rounded-lg border border-slate-800">
                <div className="flex items-center space-x-1.5 text-amber-400 mb-2 font-semibold">
                  <Phone className="w-3.5 h-3.5" />
                  <span>Phone Numbers ({result.extracted_entities.phones.length})</span>
                </div>
                {result.extracted_entities.phones.length > 0 ? (
                  <div className="space-y-1">
                    {result.extracted_entities.phones.map((p, i) => (
                      <span key={i} className="block text-slate-300 truncate">{p}</span>
                    ))}
                  </div>
                ) : (
                  <span className="text-slate-500">None detected</span>
                )}
              </div>

              {/* Crypto Wallets */}
              <div className="p-3.5 bg-[#090d16] rounded-lg border border-slate-800">
                <div className="flex items-center space-x-1.5 text-slate-300 mb-2 font-semibold">
                  <Wallet className="w-3.5 h-3.5 text-blue-400" />
                  <span>Crypto Wallets ({result.extracted_entities.crypto_wallets.length})</span>
                </div>
                {result.extracted_entities.crypto_wallets.length > 0 ? (
                  <div className="space-y-1">
                    {result.extracted_entities.crypto_wallets.map((w, i) => (
                      <span key={i} className="block text-slate-300 truncate font-mono text-[11px]">{w}</span>
                    ))}
                  </div>
                ) : (
                  <span className="text-slate-500">None detected</span>
                )}
              </div>
            </div>
          </div>

          {/* Actionable Recommendations */}
          <div className="bg-[#0f172a] p-5 rounded-xl border border-slate-800 space-y-3">
            <h3 className="text-sm font-semibold text-blue-400">Protective Precautions</h3>
            <ul className="space-y-1.5 text-xs text-slate-300">
              {result.recommendations.map((rec, i) => (
                <li key={i} className="flex items-center space-x-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-blue-500"></span>
                  <span>{rec}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* On-Chain Web3 Registration Option */}
          <div className="bg-[#0f172a] p-5 rounded-xl border border-slate-800 space-y-3">
            <div className="flex justify-between items-center">
              <span className="text-xs font-semibold text-white flex items-center space-x-2">
                <Blocks className="w-4 h-4 text-blue-400" />
                <span>Web3 Cryptographic Proof</span>
              </span>
              <span className="text-xs font-mono text-slate-400">
                Hash: {result.web3_fingerprint.report_hash.slice(0, 16)}...
              </span>
            </div>

            {!web3Commitment ? (
              <button
                onClick={handleWeb3Register}
                disabled={isRegisteringWeb3}
                className="w-full py-2.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 font-medium text-xs tracking-wider transition-colors flex items-center justify-center space-x-2"
              >
                {isRegisteringWeb3 ? (
                  <Activity className="w-4 h-4 animate-spin text-blue-400" />
                ) : (
                  <Blocks className="w-4 h-4 text-blue-400" />
                )}
                <span>Record Scam Fingerprint on ThreatRegistry.sol</span>
              </button>
            ) : (
              <div className="p-3 rounded-lg bg-emerald-950/30 border border-emerald-800 text-xs font-mono text-emerald-300 flex items-center space-x-2">
                <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
                <span>Recorded! Tx: {web3Commitment.transaction_hash.slice(0, 20)}... (Block #{web3Commitment.block_number})</span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
