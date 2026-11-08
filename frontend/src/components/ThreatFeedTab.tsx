import React, { useState, useEffect } from 'react';
import { Database, Network, Layers, RefreshCw } from 'lucide-react';
import { fetchThreatFeed } from '../services/api';

export const ThreatFeedTab: React.FC = () => {
  const [feedData, setFeedData] = useState<{ recent_incidents: any[]; on_chain_commitments: any[] }>({
    recent_incidents: [],
    on_chain_commitments: []
  });
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    loadFeed();
  }, []);

  const loadFeed = async () => {
    setIsLoading(true);
    try {
      const data = await fetchThreatFeed();
      setFeedData(data);
    } catch (e) {
      console.error(e);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-[#0f172a] p-6 rounded-xl border border-slate-800">
        <div className="flex justify-between items-center">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center space-x-2">
              <Network className="w-5 h-5 text-blue-400" />
              <span>Threat Correlation & Distributed Intelligence Feed</span>
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Multi-source incident graph tracking shared infrastructure, typosquatting clusters, and recurring campaign targets.
            </p>
          </div>
          <button
            onClick={loadFeed}
            disabled={isLoading}
            className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 hover:text-white transition-colors disabled:opacity-50"
            title="Refresh Feed"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Campaign Correlation Visualizer */}
      <div className="bg-[#0f172a] p-6 rounded-xl border border-slate-800 space-y-4">
        <h3 className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider flex items-center space-x-2">
          <Layers className="w-4 h-4 text-blue-400" />
          <span>Active Campaign Infrastructure Clusters</span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Cluster 1: Chase Impersonation */}
          <div className="p-4 bg-[#090d16] rounded-lg border border-slate-800 space-y-3 font-mono text-xs">
            <div className="flex justify-between items-center">
              <span className="font-semibold text-red-300">Campaign #1: Banking Credential Harvesting</span>
              <span className="px-2 py-0.5 rounded bg-red-950/80 text-red-300 border border-red-800 text-[10px] font-medium">
                HIGH CONFIDENCE (92%)
              </span>
            </div>
            <div className="text-slate-300 text-[11px] space-y-1">
              <div>Targeted Institution: <span className="text-white font-semibold">JPMorgan Chase</span></div>
              <div>Shared Host IP: <span className="text-blue-400">198.51.100.22 (AS13335)</span></div>
              <div>Registrar: <span className="text-slate-400">NameCheap Inc.</span></div>
            </div>
            <div className="pt-2 border-t border-slate-800">
              <span className="text-slate-500 block mb-1.5 text-[10px] uppercase">Correlated Domains:</span>
              <div className="flex flex-wrap gap-1.5">
                <span className="px-2 py-1 bg-slate-900 rounded text-[11px] text-slate-300 border border-slate-800">
                  chase-auth-verification.com
                </span>
                <span className="px-2 py-1 bg-slate-900 rounded text-[11px] text-slate-300 border border-slate-800">
                  secure-chase-update-login.net
                </span>
              </div>
            </div>
          </div>

          {/* Cluster 2: PayPal Typosquatting */}
          <div className="p-4 bg-[#090d16] rounded-lg border border-slate-800 space-y-3 font-mono text-xs">
            <div className="flex justify-between items-center">
              <span className="font-semibold text-amber-300">Campaign #2: E-Commerce / Payment Gateway</span>
              <span className="px-2 py-0.5 rounded bg-amber-950/80 text-amber-300 border border-amber-800 text-[10px] font-medium">
                ACTIVE CAMPAIGN
              </span>
            </div>
            <div className="text-slate-300 text-[11px] space-y-1">
              <div>Targeted Institution: <span className="text-white font-semibold">PayPal</span></div>
              <div>Shared Pattern: <span className="text-blue-400">Homoglyph / Typosquat Subdomain Embedding</span></div>
              <div>High-Risk TLD: <span className="text-amber-300">.xyz / .buzz</span></div>
            </div>
            <div className="pt-2 border-t border-slate-800">
              <span className="text-slate-500 block mb-1.5 text-[10px] uppercase">Correlated Domains:</span>
              <div className="flex flex-wrap gap-1.5">
                <span className="px-2 py-1 bg-slate-900 rounded text-[11px] text-slate-300 border border-slate-800">
                  paypal-security-update.account-verification.xyz
                </span>
                <span className="px-2 py-1 bg-slate-900 rounded text-[11px] text-slate-300 border border-slate-800">
                  paypal-account-security-alert.org
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Chronological Incident Stream */}
      <div className="bg-[#0f172a] p-6 rounded-xl border border-slate-800 space-y-4">
        <h3 className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider flex items-center space-x-2">
          <Database className="w-4 h-4 text-blue-400" />
          <span>Real-Time Incident Stream ({feedData.recent_incidents.length} Records)</span>
        </h3>

        <div className="space-y-2">
          {feedData.recent_incidents.map((inc, i) => (
            <div
              key={i}
              className="p-3 bg-[#090d16] rounded-lg border border-slate-800 font-mono text-xs flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 hover:border-slate-700 transition-colors"
            >
              <div className="flex items-center space-x-3">
                <span className={`px-2 py-0.5 rounded text-[10px] font-medium ${
                  inc.risk_level === 'Confirmed Malicious'
                    ? 'bg-red-950/80 text-red-300 border border-red-800'
                    : inc.risk_level === 'High Risk'
                    ? 'bg-orange-950/80 text-orange-300 border border-orange-800'
                    : 'bg-amber-950/80 text-amber-300 border border-amber-800'
                }`}>
                  {inc.risk_level}
                </span>
                <span className="text-white font-medium">{inc.indicator}</span>
                {inc.brand_targeted !== 'Unknown' && (
                  <span className="text-slate-500 text-[11px] hidden md:inline">
                    (Target: {inc.brand_targeted})
                  </span>
                )}
              </div>

              <div className="text-slate-400 text-[11px] flex items-center space-x-2">
                <span>{inc.threat_category}</span>
                <span>•</span>
                <span>{new Date(inc.timestamp).toLocaleTimeString()}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
