import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { PresetBar } from './components/PresetBar';
import { UrlScannerTab } from './components/UrlScannerTab';
import { ScamAnalyzerTab } from './components/ScamAnalyzerTab';
import { QrScannerTab } from './components/QrScannerTab';
import { Web3RegistryTab } from './components/Web3RegistryTab';
import { ThreatFeedTab } from './components/ThreatFeedTab';
import { fetchPresets, analyzeUrl } from './services/api';
import type { UrlAnalysisResponse, PresetItem } from './types';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<string>('url');
  const [urlInput, setUrlInput] = useState<string>('https://paypal-security-update.account-verification.xyz');
  const [messageInput, setMessageInput] = useState<string>(
    'URGENT NOTICE: Your Chase account access has been restricted due to unauthorized login attempts. You must verify your credentials and OTP immediately at https://chase-auth-verification.com within 24 hours to prevent permanent closure.'
  );
  const [qrInput, setQrInput] = useState<string>('');
  
  const [presets, setPresets] = useState<{ benign_cases: PresetItem[]; suspicious_cases: PresetItem[] }>({
    benign_cases: [],
    suspicious_cases: []
  });

  const [isLoadingUrl, setIsLoadingUrl] = useState<boolean>(false);
  const [urlResult, setUrlResult] = useState<UrlAnalysisResponse | null>(null);
  const [urlError, setUrlError] = useState<string | null>(null);

  // Load presets on mount
  useEffect(() => {
    fetchPresets().then(setPresets).catch(console.error);
  }, []);

  const triggerScan = async (urlToScan?: string) => {
    const target = (urlToScan || urlInput).trim();
    if (!target) return;
    setIsLoadingUrl(true);
    setUrlError(null);
    try {
      const data = await analyzeUrl(target);
      setUrlResult(data);
    } catch (err: unknown) {
      setUrlError(err instanceof Error ? err.message : 'Analysis request failed.');
    } finally {
      setIsLoadingUrl(false);
    }
  };

  const handleSelectPreset = (preset: PresetItem) => {
    if (preset.type === 'url') {
      setUrlInput(preset.value);
      setActiveTab('url');
      triggerScan(preset.value);
    } else if (preset.type === 'message') {
      setMessageInput(preset.value);
      setActiveTab('scam');
    } else if (preset.type === 'qr') {
      setQrInput(preset.value);
      setActiveTab('qr');
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#090d16] text-slate-100 font-sans selection:bg-blue-600 selection:text-white">
      {/* Top Navigation */}
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} />

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        
        {/* Preset Evaluation Bar for Judges */}
        <PresetBar
          presets={presets}
          onSelectPreset={handleSelectPreset}
          isLoading={isLoadingUrl}
        />

        {/* Tab 1: URL Scanner */}
        {activeTab === 'url' && (
          <UrlScannerTab
            urlInput={urlInput}
            setUrlInput={setUrlInput}
            onScan={() => triggerScan()}
            isLoading={isLoadingUrl}
            result={urlResult}
            error={urlError}
          />
        )}

        {/* Tab 2: AI Scam & Message Analyzer */}
        {activeTab === 'scam' && (
          <ScamAnalyzerTab
            messageInput={messageInput}
            setMessageInput={setMessageInput}
          />
        )}

        {/* Tab 3: QR Code Scam & Quishing Inspector */}
        {activeTab === 'qr' && (
          <QrScannerTab initialPayload={qrInput} />
        )}

        {/* Tab 3: Web3 Registry */}
        {activeTab === 'web3' && (
          <Web3RegistryTab />
        )}

        {/* Tab 4: Threat Intelligence Feed */}
        {activeTab === 'threats' && (
          <ThreatFeedTab />
        )}

      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 py-6 text-xs text-slate-400 bg-[#090d16] mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row justify-between items-center gap-3">
          <div className="flex items-center space-x-2.5">
            <img src="/logo.png" alt="TrustLens" className="w-5 h-5 object-contain" />
            <span className="font-semibold text-white">TrustLens</span>
            <span>•</span>
            <span>AI-Powered Web Threat Detection & Digital Trust Intelligence</span>
          </div>
          <div className="text-slate-500 text-xs">
            <span>© 2026 TrustLens. All rights reserved.</span>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default App;
