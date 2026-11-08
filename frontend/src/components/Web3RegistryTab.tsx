import React, { useState, useEffect } from 'react';
import {
  Blocks,
  Search,
  CheckCircle2,
  XCircle,
  Activity,
  FileCheck2,
  Lock,
  Layers,
  AlertOctagon,
  PlusCircle,
  Send
} from 'lucide-react';
import { verifyOnChain, fetchThreatFeed, disputeOnChain, submitThreatIncident } from '../services/api';
import type { OnChainCommitmentRecord } from '../types';

export const Web3RegistryTab: React.FC = () => {
  const [queryHash, setQueryHash] = useState('');
  const [isVerifying, setIsVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState<any>(null);
  const [recentRecords, setRecentRecords] = useState<OnChainCommitmentRecord[]>([]);

  // Dispute state
  const [disputingHash, setDisputingHash] = useState<string | null>(null);
  const [disputeReason, setDisputeReason] = useState('');
  const [isSubmittingDispute, setIsSubmittingDispute] = useState(false);

  // Submit report modal state
  const [showSubmitModal, setShowSubmitModal] = useState(false);
  const [newIndicator, setNewIndicator] = useState('');
  const [newCampaign, setNewCampaign] = useState('');
  const [newSummary, setNewSummary] = useState('');
  const [newCategory, setNewCategory] = useState('Phishing');
  const [newThreatLevel, setNewThreatLevel] = useState('High Risk');
  const [isSubmittingReport, setIsSubmittingReport] = useState(false);

  useEffect(() => {
    loadRecentFeed();
  }, []);

  const loadRecentFeed = async () => {
    try {
      const feed = await fetchThreatFeed();
      if (feed && feed.on_chain_commitments) {
        setRecentRecords(feed.on_chain_commitments);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleVerify = async (hashToVerify?: string) => {
    const target = hashToVerify || queryHash;
    if (!target.trim()) return;
    setIsVerifying(true);
    setVerificationResult(null);
    try {
      const res = await verifyOnChain(target.trim());
      setVerificationResult(res);
    } catch (err: any) {
      setVerificationResult({
        verified: false,
        status: 'ERROR',
        message: err.message || 'Verification failed.'
      });
    } finally {
      setIsVerifying(false);
    }
  };

  const handleDispute = async (reportHash: string) => {
    if (!disputeReason.trim()) return;
    setIsSubmittingDispute(true);
    try {
      const res = await disputeOnChain(reportHash, disputeReason.trim());
      if (res.success) {
        alert('Dispute successfully registered on-chain!');
        setDisputingHash(null);
        setDisputeReason('');
        loadRecentFeed();
        if (verificationResult?.record?.report_hash?.toLowerCase() === reportHash.toLowerCase()) {
          handleVerify(reportHash);
        }
      }
    } catch (err) {
      console.error(err);
      alert('Failed to submit dispute.');
    } finally {
      setIsSubmittingDispute(false);
    }
  };

  const handleCreateReport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIndicator.trim() || !newSummary.trim()) return;
    setIsSubmittingReport(true);
    try {
      await submitThreatIncident({
        indicator: newIndicator.trim(),
        campaign_name: newCampaign.trim() || 'Community Phishing Report',
        incident_summary: newSummary.trim(),
        threat_category: newCategory,
        risk_level: newThreatLevel,
        supporting_evidence_refs: ['Community-Submitted-Incident']
      });
      alert('Report submitted to decentralized intelligence feed!');
      setShowSubmitModal(false);
      setNewIndicator('');
      setNewCampaign('');
      setNewSummary('');
      loadRecentFeed();
    } catch (err) {
      console.error(err);
      alert('Failed to submit community threat incident.');
    } finally {
      setIsSubmittingReport(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-[#0f172a] p-6 rounded-xl border border-slate-800">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
          <div>
            <div className="flex items-center space-x-2">
              <Blocks className="w-5 h-5 text-blue-400" />
              <h2 className="text-base font-semibold text-white">
                Decentralized Threat Intelligence Registry
              </h2>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Smart Contract: <span className="font-mono text-slate-300">ThreatRegistry.sol</span> (EVM Compatible) • Tamper-evident cryptographic commitments.
            </p>
          </div>

          <div className="flex items-center space-x-3">
            <button
              onClick={() => setShowSubmitModal(true)}
              className="px-3.5 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-medium flex items-center space-x-1.5 transition-colors"
            >
              <PlusCircle className="w-3.5 h-3.5" />
              <span>Submit Threat Incident</span>
            </button>

            <div className="flex items-center space-x-1.5 bg-[#090d16] px-3 py-2 rounded-lg border border-slate-800 text-xs font-mono text-slate-400">
              <Lock className="w-3.5 h-3.5 text-blue-400" />
              <span>Zero-PII On-Chain</span>
            </div>
          </div>
        </div>
      </div>

      {/* Independent Verification Search (Section 7 Requirement) */}
      <div className="bg-[#0f172a] p-6 rounded-xl border border-slate-800 space-y-4">
        <div>
          <span className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider block">
            Independent Verification Portal
          </span>
          <p className="text-xs text-slate-400 mt-0.5">
            Verify the authenticity, timestamp, and tamper-resistance of any TrustLens report by its SHA-256 digest.
          </p>
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleVerify();
          }}
          className="flex flex-col sm:flex-row gap-3"
        >
          <div className="relative flex-1">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input
              type="text"
              value={queryHash}
              onChange={(e) => setQueryHash(e.target.value)}
              placeholder="Paste 64-char hex report hash (e.g. 0x8a7f2...)"
              className="w-full bg-[#090d16] border border-slate-800 rounded-lg pl-10 pr-4 py-2.5 text-xs text-slate-100 placeholder-slate-500 font-mono focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
            />
          </div>
          <button
            type="submit"
            disabled={isVerifying || !queryHash.trim()}
            className="px-6 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-medium text-xs tracking-wider transition-colors disabled:opacity-50 flex items-center justify-center space-x-2 shrink-0"
          >
            {isVerifying ? (
              <>
                <Activity className="w-4 h-4 animate-spin" />
                <span>Querying Smart Contract...</span>
              </>
            ) : (
              <>
                <FileCheck2 className="w-4 h-4" />
                <span>Verify Proof</span>
              </>
            )}
          </button>
        </form>

        {/* Verification Query Result */}
        {verificationResult && (
          <div className="pt-4 border-t border-slate-800">
            {verificationResult.verified ? (
              <div className="p-5 rounded-lg bg-emerald-950/30 border border-emerald-800 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2 text-emerald-400 font-mono font-semibold text-sm">
                    <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                    <span>REPORT INTEGRITY VERIFIED (TAMPER-EVIDENT)</span>
                  </div>
                  <div className="flex items-center space-x-2 font-mono text-[11px]">
                    <span className="px-2.5 py-0.5 rounded bg-emerald-950/80 border border-emerald-800 text-emerald-300">
                      Block #{verificationResult.record.block_number}
                    </span>
                    {verificationResult.record.dispute_count > 0 && (
                      <span className="px-2.5 py-0.5 rounded bg-amber-950/80 text-amber-300 border border-amber-800">
                        {verificationResult.record.dispute_count} Active Dispute(s)
                      </span>
                    )}
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono text-slate-300 pt-2">
                  <div className="p-3 bg-[#090d16] rounded-lg border border-slate-800">
                    <span className="text-slate-500 block mb-1">Report Hash Commitment</span>
                    <span className="text-emerald-400 break-all select-all font-medium">
                      {verificationResult.record.report_hash}
                    </span>
                  </div>

                  <div className="p-3 bg-[#090d16] rounded-lg border border-slate-800">
                    <span className="text-slate-500 block mb-1">Indicator Hash (Privacy-Preserved)</span>
                    <span className="text-blue-400 break-all select-all font-medium">
                      {verificationResult.record.indicator_hash}
                    </span>
                  </div>

                  <div className="p-3 bg-[#090d16] rounded-lg border border-slate-800">
                    <span className="text-slate-500 block mb-1">Transaction Hash</span>
                    <span className="text-slate-300 break-all select-all">
                      {verificationResult.record.transaction_hash}
                    </span>
                  </div>

                  <div className="p-3 bg-[#090d16] rounded-lg border border-slate-800">
                    <span className="text-slate-500 block mb-1">Registered Timestamp</span>
                    <span className="text-slate-300">
                      {verificationResult.record.iso_timestamp}
                    </span>
                  </div>
                </div>

                <div className="flex flex-wrap items-center justify-between pt-2 text-xs font-mono text-slate-400">
                  <span>Smart Contract: <span className="text-slate-300">{verificationResult.record.contract_address}</span></span>
                  <button
                    onClick={() => setDisputingHash(verificationResult.record.report_hash)}
                    className="text-amber-400 hover:text-amber-300 underline text-xs"
                  >
                    File On-Chain Dispute ↗
                  </button>
                </div>
              </div>
            ) : (
              <div className="p-4 rounded-lg bg-red-950/30 border border-red-800 text-red-200 text-xs font-mono flex items-start space-x-3">
                <XCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
                <div>
                  <div className="font-semibold">UNREGISTERED OR MODIFIED RECORD</div>
                  <p className="mt-1 text-slate-400">
                    {verificationResult.message} No cryptographic commitment matching this fingerprint was found on-chain.
                  </p>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Dispute Modal / Box */}
      {disputingHash && (
        <div className="p-5 rounded-xl bg-amber-950/20 border border-amber-800/80 space-y-3 font-mono text-xs">
          <div className="flex justify-between items-center text-amber-300 font-semibold">
            <span className="flex items-center space-x-2">
              <AlertOctagon className="w-4 h-4" />
              <span>Register Community Dispute against Report</span>
            </span>
            <button onClick={() => setDisputingHash(null)} className="text-slate-400 hover:text-white">✕</button>
          </div>
          <p className="text-slate-400">
            Target Hash: <span className="text-slate-200 break-all">{disputingHash}</span>
          </p>
          <input
            type="text"
            value={disputeReason}
            onChange={(e) => setDisputeReason(e.target.value)}
            placeholder="State factual dispute reason (e.g. false positive, legitimate corporate staging domain)"
            className="w-full bg-[#090d16] border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-amber-600"
          />
          <div className="flex justify-end space-x-2">
            <button
              onClick={() => setDisputingHash(null)}
              className="px-3.5 py-1.5 rounded-lg bg-slate-800 text-slate-300 text-xs hover:bg-slate-700"
            >
              Cancel
            </button>
            <button
              onClick={() => handleDispute(disputingHash)}
              disabled={isSubmittingDispute || !disputeReason.trim()}
              className="px-4 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-700 text-white font-medium text-xs disabled:opacity-50"
            >
              {isSubmittingDispute ? 'Transacting on-chain...' : 'Submit Dispute'}
            </button>
          </div>
        </div>
      )}

      {/* Community Submit Report Modal */}
      {showSubmitModal && (
        <div className="bg-[#0f172a] p-6 rounded-xl border border-slate-700 space-y-4 font-mono text-xs">
          <div className="flex justify-between items-center pb-3 border-b border-slate-800">
            <h3 className="text-sm font-semibold text-white flex items-center space-x-2">
              <PlusCircle className="w-4 h-4 text-blue-400" />
              <span>Submit Threat Incident to Decentralized Registry</span>
            </h3>
            <button onClick={() => setShowSubmitModal(false)} className="text-slate-400 hover:text-white">✕</button>
          </div>

          <form onSubmit={handleCreateReport} className="space-y-3">
            <div>
              <label className="text-slate-400 block mb-1">Suspicious URL / Domain Indicator:</label>
              <input
                type="text"
                required
                value={newIndicator}
                onChange={(e) => setNewIndicator(e.target.value)}
                placeholder="e.g. secure-login-suspicious.com"
                className="w-full bg-[#090d16] border border-slate-800 rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-blue-500"
              />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="text-slate-400 block mb-1">Reported Campaign Name:</label>
                <input
                  type="text"
                  value={newCampaign}
                  onChange={(e) => setNewCampaign(e.target.value)}
                  placeholder="e.g. Credential Harvesting Wave"
                  className="w-full bg-[#090d16] border border-slate-800 rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Category & Severity:</label>
                <div className="flex gap-2">
                  <select
                    value={newCategory}
                    onChange={(e) => setNewCategory(e.target.value)}
                    className="bg-[#090d16] border border-slate-800 rounded-lg p-2.5 text-xs text-white flex-1 focus:outline-none focus:border-blue-500"
                  >
                    <option value="Phishing">Phishing</option>
                    <option value="Scam">Scam</option>
                    <option value="CertificateTrust">Certificate Vulnerability</option>
                    <option value="Malware">Malware</option>
                  </select>
                  <select
                    value={newThreatLevel}
                    onChange={(e) => setNewThreatLevel(e.target.value)}
                    className="bg-[#090d16] border border-slate-800 rounded-lg p-2.5 text-xs text-white flex-1 focus:outline-none focus:border-blue-500"
                  >
                    <option value="Confirmed Malicious">Confirmed Malicious</option>
                    <option value="High Risk">High Risk</option>
                    <option value="Suspicious">Suspicious</option>
                  </select>
                </div>
              </div>
            </div>

            <div>
              <label className="text-slate-400 block mb-1">Security Incident Summary & Evidence References:</label>
              <textarea
                rows={3}
                required
                value={newSummary}
                onChange={(e) => setNewSummary(e.target.value)}
                placeholder="Observed deceptive form attempting to steal credentials. SHA-256 fingerprint generated off-chain."
                className="w-full bg-[#090d16] border border-slate-800 rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-blue-500"
              ></textarea>
            </div>

            <div className="flex justify-end space-x-2 pt-2">
              <button
                type="button"
                onClick={() => setShowSubmitModal(false)}
                className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isSubmittingReport}
                className="px-6 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-medium flex items-center space-x-1.5 disabled:opacity-50"
              >
                <Send className="w-3.5 h-3.5" />
                <span>{isSubmittingReport ? 'Submitting...' : 'Register Incident'}</span>
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Live On-Chain Registry Log */}
      <div className="bg-[#0f172a] p-6 rounded-xl border border-slate-800 space-y-4">
        <div className="flex justify-between items-center">
          <h3 className="text-sm font-semibold text-white flex items-center space-x-2">
            <Layers className="w-4 h-4 text-blue-400" />
            <span>On-Chain Threat Log Ledger ({recentRecords.length} Commitments)</span>
          </h3>
          <button
            onClick={loadRecentFeed}
            className="text-xs font-mono text-blue-400 hover:text-blue-300 transition-colors"
          >
            Refresh Ledger
          </button>
        </div>

        {recentRecords.length === 0 ? (
          <div className="p-8 text-center text-xs font-mono text-slate-400 bg-[#090d16] rounded-lg border border-slate-800">
            No on-chain threat reports recorded yet. Perform a scan and click "Commit Cryptographic Hash" to register one.
          </div>
        ) : (
          <div className="space-y-3">
            {recentRecords.map((rec, idx) => (
              <div
                key={idx}
                className="p-4 rounded-lg bg-[#090d16] border border-slate-800 hover:border-slate-700 transition-colors font-mono text-xs flex flex-col md:flex-row justify-between items-start md:items-center gap-3"
              >
                <div className="space-y-1">
                  <div className="flex items-center space-x-2">
                    <span className="font-semibold text-slate-200 truncate max-w-md">
                      {rec.report_hash}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-medium ${
                      rec.threat_level === 'Confirmed Malicious'
                        ? 'bg-red-950/80 text-red-300 border border-red-800'
                        : rec.threat_level === 'High Risk'
                        ? 'bg-orange-950/80 text-orange-300 border border-orange-800'
                        : 'bg-amber-950/80 text-amber-300 border border-amber-800'
                    }`}>
                      {rec.threat_level}
                    </span>
                    {rec.dispute_count > 0 && (
                      <span className="px-2 py-0.5 rounded text-[10px] bg-amber-950/80 text-amber-300 border border-amber-800">
                        {rec.dispute_count} Dispute(s)
                      </span>
                    )}
                  </div>
                  <div className="text-slate-400 text-[11px] flex items-center space-x-3">
                    <span>Block: #{rec.block_number}</span>
                    <span>•</span>
                    <span>{rec.iso_timestamp}</span>
                    <span>•</span>
                    <span>Campaign: {rec.campaign_name || 'Standard Threat'}</span>
                  </div>
                </div>

                <div className="flex items-center space-x-2 shrink-0">
                  <button
                    onClick={() => {
                      setQueryHash(rec.report_hash);
                      handleVerify(rec.report_hash);
                    }}
                    className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-blue-400 text-[11px] border border-slate-700 transition-colors"
                  >
                    Verify
                  </button>
                  <button
                    onClick={() => setDisputingHash(rec.report_hash)}
                    className="px-2.5 py-1.5 rounded bg-amber-950/40 hover:bg-amber-950 text-amber-300 text-[11px] border border-amber-800/80 transition-colors"
                  >
                    Dispute
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
