import React from 'react';
import { ShieldAlert, Cpu, Database, Blocks, QrCode } from 'lucide-react';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
}

export const Navbar: React.FC<NavbarProps> = ({ activeTab, setActiveTab }) => {
  return (
    <header className="sticky top-0 z-50 border-b border-slate-800 bg-[#090d16]/95 backdrop-blur-sm">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          
          {/* Logo & Branding */}
          <div className="flex items-center space-x-3 cursor-pointer select-none" onClick={() => setActiveTab('url')}>
            <img
              src="/logo.png"
              alt="TrustLens Logo"
              className="w-10 h-10 object-contain drop-shadow-sm transition-transform hover:scale-105"
            />
            <div>
              <span className="font-bold text-xl sm:text-2xl text-white tracking-tight block leading-tight">
                TrustLens
              </span>
              <p className="text-[11px] text-slate-400 hidden sm:block">
                Web Threat Detection & Digital Trust Platform
              </p>
            </div>
          </div>

          {/* Navigation Tabs */}
          <nav className="flex items-center space-x-1 sm:space-x-1.5">
            <button
              onClick={() => setActiveTab('url')}
              className={`px-3 py-1.5 rounded-lg text-xs sm:text-sm font-medium transition-colors flex items-center space-x-1.5 ${
                activeTab === 'url'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <ShieldAlert className="w-4 h-4" />
              <span>URL Scanner</span>
            </button>

            <button
              onClick={() => setActiveTab('scam')}
              className={`px-3 py-1.5 rounded-lg text-xs sm:text-sm font-medium transition-colors flex items-center space-x-1.5 ${
                activeTab === 'scam'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Cpu className="w-4 h-4" />
              <span>AI Scam Analysis</span>
            </button>

            <button
              onClick={() => setActiveTab('qr')}
              className={`px-3 py-1.5 rounded-lg text-xs sm:text-sm font-medium transition-colors flex items-center space-x-1.5 ${
                activeTab === 'qr'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <QrCode className="w-4 h-4" />
              <span>QR Scanner</span>
            </button>

            <button
              onClick={() => setActiveTab('web3')}
              className={`px-3 py-1.5 rounded-lg text-xs sm:text-sm font-medium transition-colors flex items-center space-x-1.5 ${
                activeTab === 'web3'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Blocks className="w-4 h-4" />
              <span>Web3 Registry</span>
            </button>

            <button
              onClick={() => setActiveTab('threats')}
              className={`px-3 py-1.5 rounded-lg text-xs sm:text-sm font-medium transition-colors flex items-center space-x-1.5 ${
                activeTab === 'threats'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Database className="w-4 h-4" />
              <span className="hidden md:inline">Threat Feed</span>
            </button>
          </nav>

          {/* System Telemetry Badges */}
          <div className="hidden lg:flex items-center space-x-2.5 text-xs text-slate-400">
            <div className="flex items-center space-x-1.5 bg-slate-900 px-2.5 py-1 rounded-md border border-slate-800">
              <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
              <span className="text-slate-300 font-medium">Intel Active</span>
            </div>
            <div className="flex items-center space-x-1.5 bg-slate-900 px-2.5 py-1 rounded-md border border-slate-800">
              <span className="w-2 h-2 rounded-full bg-blue-500"></span>
              <span className="text-slate-300 font-medium">SSRF Guard</span>
            </div>
          </div>

        </div>
      </div>
    </header>
  );
};
