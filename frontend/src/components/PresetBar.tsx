import React from 'react';
import { CheckCircle2, AlertTriangle, ArrowRight, Bookmark } from 'lucide-react';
import type { PresetItem } from '../types';

interface PresetBarProps {
  presets: {
    benign_cases: PresetItem[];
    suspicious_cases: PresetItem[];
  };
  onSelectPreset: (preset: PresetItem) => void;
  isLoading: boolean;
}

export const PresetBar: React.FC<PresetBarProps> = ({ presets, onSelectPreset, isLoading }) => {
  return (
    <div className="bg-[#0f172a] rounded-xl p-4 border border-slate-800 shadow-sm">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-1 mb-3">
        <div className="flex items-center space-x-2">
          <Bookmark className="w-4 h-4 text-slate-400" />
          <span className="text-xs uppercase tracking-wider font-semibold text-slate-300">
            Benchmark Evaluation Test Cases
          </span>
        </div>
        <span className="text-xs text-slate-400">
          Click any preset to run a reproducible benchmark scenario
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {/* Benign Presets */}
        <div className="bg-slate-900/80 rounded-lg p-3 border border-slate-800">
          <div className="flex items-center space-x-1.5 mb-2 text-slate-300 text-xs font-semibold">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" />
            <span>Benign Baseline Scenarios</span>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {presets.benign_cases.map((caseItem) => (
              <button
                key={caseItem.id}
                disabled={isLoading}
                onClick={() => onSelectPreset(caseItem)}
                className="px-2.5 py-1.5 rounded-md bg-slate-800 hover:bg-slate-750 border border-slate-700 hover:border-slate-600 text-xs text-slate-200 transition-colors flex items-center space-x-1.5 disabled:opacity-50"
                title={caseItem.description}
              >
                <ArrowRight className="w-3 h-3 text-slate-400" />
                <span className="font-medium">{caseItem.name}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Suspicious Presets */}
        <div className="bg-slate-900/80 rounded-lg p-3 border border-slate-800">
          <div className="flex items-center space-x-1.5 mb-2 text-slate-300 text-xs font-semibold">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
            <span>Suspicious & Malicious Scenarios</span>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {presets.suspicious_cases.map((caseItem) => (
              <button
                key={caseItem.id}
                disabled={isLoading}
                onClick={() => onSelectPreset(caseItem)}
                className="px-2.5 py-1.5 rounded-md bg-slate-800 hover:bg-slate-750 border border-slate-700 hover:border-slate-600 text-xs text-slate-200 transition-colors flex items-center space-x-1.5 disabled:opacity-50"
                title={caseItem.description}
              >
                <ArrowRight className="w-3 h-3 text-slate-400" />
                <span className="font-medium">{caseItem.name}</span>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
