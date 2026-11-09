import React, { useState, useRef, useEffect, useCallback } from 'react';
import { 
  QrCode, 
  Upload, 
  AlertTriangle, 
  ShieldCheck, 
  ShieldAlert, 
  CheckCircle, 
  Wifi, 
  CreditCard, 
  Smartphone, 
  Globe, 
  FileText, 
  Lock, 
  Copy, 
  Check, 
  Blocks,
  RefreshCw
} from 'lucide-react';
import jsQR from 'jsqr';
import { analyzeQrCode, registerOnChain } from '../services/api';
import type { QrAnalysisResponse } from '../types';

interface QrScannerTabProps {
  initialPayload?: string;
}

export const QrScannerTab: React.FC<QrScannerTabProps> = ({ initialPayload }) => {
  const [payloadInput, setPayloadInput] = useState<string>(initialPayload || '');
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [isDecoding, setIsDecoding] = useState<boolean>(false);
  const [scanResult, setScanResult] = useState<QrAnalysisResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState<boolean>(false);
  const [isRegisteringWeb3, setIsRegisteringWeb3] = useState<boolean>(false);
  const [web3SuccessMessage, setWeb3SuccessMessage] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  const performAnalysis = useCallback(async (payload: string) => {
    const trimmed = payload.trim();
    if (!trimmed) {
      setErrorMessage('Please enter or scan a valid QR code payload.');
      return;
    }

    setIsScanning(true);
    setErrorMessage(null);
    setWeb3SuccessMessage(null);

    try {
      const res = await analyzeQrCode(trimmed);
      setScanResult(res);
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : 'QR forensic analysis failed.');
    } finally {
      setIsScanning(false);
    }
  }, []);

  // Synchronize incoming preset selection
  useEffect(() => {
    if (initialPayload) {
      setPayloadInput(initialPayload);
      performAnalysis(initialPayload);
    }
  }, [initialPayload, performAnalysis]);

  // Decode QR code from HTML image element using jsQR
  const decodeImageElement = useCallback((img: HTMLImageElement) => {
    setIsDecoding(true);
    setErrorMessage(null);

    try {
      const canvas = canvasRef.current || document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      if (!ctx) {
        throw new Error('Could not initialize canvas context for image decoding.');
      }

      canvas.width = img.naturalWidth || img.width;
      canvas.height = img.naturalHeight || img.height;
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);

      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const decoder = (typeof jsQR === 'function' ? jsQR : (jsQR as any)?.default) as typeof jsQR;
      if (!decoder) {
        throw new Error('QR decoder engine could not be initialized.');
      }
      const code = decoder(imageData.data, imageData.width, imageData.height, {
        inversionAttempts: 'attemptBoth'
      });

      if (code && code.data) {
        setPayloadInput(code.data);
        performAnalysis(code.data);
      } else {
        setErrorMessage('No valid QR code pattern detected in the uploaded image. Please ensure the QR code is clear, well-lit, and not cropped.');
      }
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : 'Failed to decode QR image.');
    } finally {
      setIsDecoding(false);
    }
  }, [performAnalysis]);

  // Handle file input upload
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.type.startsWith('image/')) {
      setErrorMessage('Please upload a valid image file (PNG, JPG, WebP).');
      return;
    }

    const reader = new FileReader();
    reader.onload = (event) => {
      const dataUrl = event.target?.result as string;
      setImagePreview(dataUrl);

      const img = new Image();
      img.onload = () => decodeImageElement(img);
      img.src = dataUrl;
    };
    reader.readAsDataURL(file);
  };

  // Handle Drag-and-drop
  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    const file = e.dataTransfer.files?.[0];
    if (file && file.type.startsWith('image/')) {
      const reader = new FileReader();
      reader.onload = (event) => {
        const dataUrl = event.target?.result as string;
        setImagePreview(dataUrl);

        const img = new Image();
        img.onload = () => decodeImageElement(img);
        img.src = dataUrl;
      };
      reader.readAsDataURL(file);
    }
  };

  // Handle clipboard paste (Ctrl+V)
  useEffect(() => {
    const handlePaste = (e: ClipboardEvent) => {
      const items = e.clipboardData?.items;
      if (!items) return;

      for (let i = 0; i < items.length; i++) {
        if (items[i].type.indexOf('image') !== -1) {
          const blob = items[i].getAsFile();
          if (blob) {
            const reader = new FileReader();
            reader.onload = (event) => {
              const dataUrl = event.target?.result as string;
              setImagePreview(dataUrl);

              const img = new Image();
              img.onload = () => decodeImageElement(img);
              img.src = dataUrl;
            };
            reader.readAsDataURL(blob);
          }
          break;
        }
      }
    };

    window.addEventListener('paste', handlePaste);
    return () => window.removeEventListener('paste', handlePaste);
  }, [decodeImageElement]);

  // Register on-chain
  const handleRegisterOnChain = async () => {
    if (!scanResult) return;
    setIsRegisteringWeb3(true);
    setWeb3SuccessMessage(null);

    try {
      const res = await registerOnChain(
        {
          quishing_category: scanResult.quishing_category,
          overall_risk: scanResult.overall_risk,
          risk_score: scanResult.risk_score,
          indicators: scanResult.evidence.map(e => e.code)
        },
        scanResult.payload,
        scanResult.overall_risk,
        scanResult.quishing_category,
        'QR Code Threat Investigation',
        scanResult.evidence.map(e => e.title),
        scanResult.sha256_hash
      );
      setWeb3SuccessMessage(`Anchored on-chain in Block #${res.record.block_number} (Tx: ${res.record.transaction_hash.slice(0, 10)}...)`);
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : 'Web3 registration failed.');
    } finally {
      setIsRegisteringWeb3(false);
    }
  };

  const copyHashToClipboard = () => {
    if (!scanResult) return;
    navigator.clipboard.writeText(scanResult.sha256_hash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  const getPayloadTypeIcon = (type: string) => {
    switch (type) {
      case 'URL':
        return <Globe className="w-4 h-4 text-blue-400" />;
      case 'PAYMENT_UPI':
        return <CreditCard className="w-4 h-4 text-emerald-400" />;
      case 'WIFI_CONFIG':
        return <Wifi className="w-4 h-4 text-amber-400" />;
      case 'APP_DOWNLOAD':
        return <Smartphone className="w-4 h-4 text-purple-400" />;
      default:
        return <FileText className="w-4 h-4 text-slate-400" />;
    }
  };

  const getRiskBadge = (risk: string) => {
    switch (risk) {
      case 'Confirmed Malicious':
        return 'bg-red-950/80 text-red-300 border-red-800';
      case 'High Risk':
        return 'bg-orange-950/80 text-orange-300 border-orange-800';
      case 'Suspicious':
        return 'bg-amber-950/80 text-amber-300 border-amber-800';
      default:
        return 'bg-emerald-950/80 text-emerald-300 border-emerald-800';
    }
  };

  return (
    <div className="space-y-6">
      {/* Hidden canvas for client-side decoding */}
      <canvas ref={canvasRef} className="hidden" />

      {/* Main Scanner Box */}
      <div className="bg-[#0f172a] p-6 rounded-xl border border-slate-800 shadow-sm space-y-5">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2">
          <div>
            <h2 className="text-lg font-semibold text-white flex items-center space-x-2">
              <QrCode className="w-5 h-5 text-blue-400" />
              <span>QR Code Scam & Quishing Inspector</span>
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Detect fake payment stickers, malicious redirects, unencrypted honeypot Wi-Fi, and covert Quishing links embedded in QR images.
            </p>
          </div>
          <span className="text-[11px] font-mono px-2.5 py-1 rounded bg-slate-900 border border-slate-700 text-slate-300">
            Client-Side Decoded • Zero Leakage
          </span>
        </div>

        {/* Upload & Dropzone Area */}
        <div 
          onDragOver={(e) => e.preventDefault()}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className="border-2 border-dashed border-slate-700 hover:border-blue-500/80 bg-[#090d16]/70 rounded-xl p-6 text-center cursor-pointer transition-all group"
        >
          <input 
            type="file" 
            ref={fileInputRef} 
            onChange={handleFileUpload} 
            accept="image/*" 
            className="hidden" 
          />

          <div className="flex flex-col items-center justify-center space-y-3">
            {imagePreview ? (
              <div className="relative group/preview">
                <img 
                  src={imagePreview} 
                  alt="QR Code Upload Preview" 
                  className="w-32 h-32 object-contain rounded-lg border border-slate-700 bg-black/40 p-2 shadow-inner"
                />
                <div className="absolute inset-0 bg-slate-950/80 rounded-lg flex items-center justify-center opacity-0 group-hover/preview:opacity-100 transition-opacity">
                  <span className="text-xs text-slate-200 flex items-center space-x-1">
                    <RefreshCw className="w-3.5 h-3.5" />
                    <span>Change Image</span>
                  </span>
                </div>
              </div>
            ) : (
              <div className="w-14 h-14 rounded-full bg-slate-800/80 border border-slate-700 flex items-center justify-center text-slate-400 group-hover:text-blue-400 group-hover:border-blue-500/50 transition-colors">
                <Upload className="w-6 h-6" />
              </div>
            )}

            <div>
              <p className="text-sm font-medium text-slate-200">
                {imagePreview ? 'QR Code Image Loaded' : 'Drop QR code image here, paste from clipboard (Ctrl+V), or browse'}
              </p>
              <p className="text-xs text-slate-500 mt-0.5">
                Supports PNG, JPG, WebP, GIF • Decoded instantly via HTML5 Canvas
              </p>
            </div>
          </div>
        </div>

        {/* Decoded / Manual Payload Input */}
        <div className="space-y-2">
          <label className="text-xs font-mono text-slate-400 block">
            Decoded QR Content / URI Payload:
          </label>
          <div className="flex flex-col sm:flex-row gap-2">
            <input 
              type="text"
              value={payloadInput}
              onChange={(e) => setPayloadInput(e.target.value)}
              placeholder="e.g. upi://pay?pa=... or https://paypal-security-update.account-verification.xyz"
              className="flex-1 bg-[#090d16] border border-slate-700 rounded-lg px-3.5 py-2 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500 font-mono"
            />
            <button
              onClick={() => performAnalysis(payloadInput)}
              disabled={isScanning || isDecoding || !payloadInput.trim()}
              className="px-5 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-slate-800 disabled:text-slate-500 text-white rounded-lg text-sm font-medium transition-colors flex items-center justify-center space-x-2"
            >
              {isScanning ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Analyzing...</span>
                </>
              ) : (
                <>
                  <ShieldAlert className="w-4 h-4" />
                  <span>Scan Payload</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Quick Benchmark Presets */}
        <div className="pt-2 border-t border-slate-800/80 space-y-2">
          <span className="text-[11px] font-mono text-slate-400 block">
            1-Click Quishing Benchmark Scenarios:
          </span>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => {
                const val = 'https://paypal-security-update.account-verification.xyz/login';
                setPayloadInput(val);
                performAnalysis(val);
              }}
              className="px-2.5 py-1.5 rounded-md bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs text-slate-300 hover:text-white transition-colors flex items-center space-x-1.5"
            >
              <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
              <span>Fake Banking Quishing</span>
            </button>
            <button
              type="button"
              onClick={() => {
                const val = 'upi://pay?pa=scammer892@ybl&pn=City+Municipal+Parking+Authority&am=150.00&cu=INR';
                setPayloadInput(val);
                performAnalysis(val);
              }}
              className="px-2.5 py-1.5 rounded-md bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs text-slate-300 hover:text-white transition-colors flex items-center space-x-1.5"
            >
              <CreditCard className="w-3.5 h-3.5 text-amber-400" />
              <span>Mule UPI Parking Sticker</span>
            </button>
            <button
              type="button"
              onClick={() => {
                const val = 'WIFI:S:Free_Airport_HighSpeed_WiFi;T:nopass;P:;;';
                setPayloadInput(val);
                performAnalysis(val);
              }}
              className="px-2.5 py-1.5 rounded-md bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs text-slate-300 hover:text-white transition-colors flex items-center space-x-1.5"
            >
              <Wifi className="w-3.5 h-3.5 text-amber-400" />
              <span>Rogue Airport Wi-Fi</span>
            </button>
            <button
              type="button"
              onClick={() => {
                const val = 'https://www.google.com/safety';
                setPayloadInput(val);
                performAnalysis(val);
              }}
              className="px-2.5 py-1.5 rounded-md bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs text-slate-300 hover:text-white transition-colors flex items-center space-x-1.5"
            >
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              <span>Legitimate Security QR</span>
            </button>
          </div>
        </div>

        {/* Error notification */}
        {errorMessage && (
          <div className="p-3 bg-red-950/60 border border-red-800/80 rounded-lg text-xs text-red-300 flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{errorMessage}</span>
          </div>
        )}
      </div>

      {/* Analysis Results */}
      {scanResult && (
        <div className="space-y-6 animate-fadeIn">
          {/* Header Summary Banner */}
          <div className="bg-[#0f172a] p-6 rounded-xl border border-slate-800 shadow-sm space-y-4">
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 pb-4 border-b border-slate-800">
              <div className="flex items-center space-x-3">
                <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                  {getPayloadTypeIcon(scanResult.payload_type)}
                </div>
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="font-semibold text-white text-base">
                      {scanResult.quishing_category}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${getRiskBadge(scanResult.overall_risk)}`}>
                      {scanResult.overall_risk}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 font-mono mt-0.5">
                    Payload Format: {scanResult.payload_type}
                  </p>
                </div>
              </div>

              {/* Threat Score Gauge */}
              <div className="flex items-center space-x-3 bg-slate-900/80 px-4 py-2 rounded-lg border border-slate-800">
                <div className="text-right">
                  <span className="text-[10px] uppercase font-mono text-slate-500 block">Threat Score</span>
                  <span className={`text-xl font-bold font-mono ${
                    scanResult.risk_score >= 70 ? 'text-red-400' :
                    scanResult.risk_score >= 40 ? 'text-orange-400' :
                    scanResult.risk_score >= 20 ? 'text-amber-400' : 'text-emerald-400'
                  }`}>
                    {scanResult.risk_score}/100
                  </span>
                </div>
              </div>
            </div>

            {/* Decoded Content Viewer */}
            <div className="space-y-1.5">
              <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block">
                Extracted Raw Content:
              </span>
              <div className="p-3 bg-[#090d16] rounded-lg border border-slate-800 text-xs font-mono text-slate-300 break-all select-all">
                {scanResult.payload}
              </div>
            </div>

            {/* Extracted Structural Parameters */}
            {Object.keys(scanResult.details || {}).length > 0 && (
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5 pt-2">
                {Object.entries(scanResult.details).map(([key, val]) => (
                  <div key={key} className="p-2.5 bg-slate-900/60 rounded-lg border border-slate-800/80">
                    <span className="text-[10px] font-mono text-slate-500 uppercase block">
                      {key.replace(/_/g, ' ')}
                    </span>
                    <span className="text-xs font-mono text-slate-200 truncate block mt-0.5" title={String(val)}>
                      {String(val)}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Forensic Evidence Grid */}
          <div className="bg-[#0f172a] p-6 rounded-xl border border-slate-800 shadow-sm space-y-4">
            <h3 className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider flex items-center space-x-2">
              <ShieldAlert className="w-4 h-4 text-blue-400" />
              <span>Forensic Evidence Findings ({scanResult.evidence.length})</span>
            </h3>

            {scanResult.evidence.length > 0 ? (
              <div className="space-y-3">
                {scanResult.evidence.map((item, idx) => (
                  <div 
                    key={idx}
                    className={`p-3.5 rounded-lg border text-xs space-y-1.5 ${
                      item.severity === 'CRITICAL' 
                        ? 'bg-red-950/20 border-red-900/50' 
                        : item.severity === 'HIGH' 
                        ? 'bg-orange-950/20 border-orange-900/50'
                        : 'bg-amber-950/20 border-amber-900/50'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-white flex items-center space-x-1.5">
                        <AlertTriangle className={`w-3.5 h-3.5 ${
                          item.severity === 'CRITICAL' ? 'text-red-400' :
                          item.severity === 'HIGH' ? 'text-orange-400' : 'text-amber-400'
                        }`} />
                        <span>{item.title}</span>
                      </span>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded uppercase font-semibold ${
                        item.severity === 'CRITICAL' ? 'bg-red-900/60 text-red-200' :
                        item.severity === 'HIGH' ? 'bg-orange-900/60 text-orange-200' : 'bg-amber-900/60 text-amber-200'
                      }`}>
                        {item.severity} (+{item.weight} pts)
                      </span>
                    </div>
                    <p className="text-slate-300 text-[11px] leading-relaxed">
                      {item.description}
                    </p>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-4 bg-emerald-950/20 border border-emerald-900/50 rounded-lg flex items-center space-x-3 text-emerald-300 text-xs">
                <CheckCircle className="w-5 h-5 text-emerald-400 shrink-0" />
                <span>Zero malicious or deceptive indicators detected in this QR payload. Structure conforms to expected standards.</span>
              </div>
            )}
          </div>

          {/* Actionable Recommendations & Web3 Anchoring */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Mitigation Steps */}
            <div className="bg-[#0f172a] p-6 rounded-xl border border-slate-800 space-y-3">
              <h3 className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider flex items-center space-x-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <span>Actionable Recommendations</span>
              </h3>
              <ul className="space-y-2">
                {scanResult.recommendations.map((rec, i) => (
                  <li key={i} className="text-xs text-slate-300 flex items-start space-x-2">
                    <span className="text-blue-400 font-bold">•</span>
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Cryptographic Proof & Web3 Ledger */}
            <div className="bg-[#0f172a] p-6 rounded-xl border border-slate-800 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider flex items-center space-x-2">
                  <Lock className="w-4 h-4 text-purple-400" />
                  <span>Tamper-Proof Audit Proof</span>
                </h3>
                <span className="text-[10px] font-mono text-purple-300 bg-purple-950/60 px-2 py-0.5 rounded border border-purple-800">
                  SHA-256 Proof
                </span>
              </div>

              <div className="space-y-1.5">
                <span className="text-[10px] font-mono text-slate-500 uppercase">Cryptographic Fingerprint:</span>
                <div className="flex items-center space-x-2 p-2 bg-[#090d16] rounded border border-slate-800">
                  <span className="text-[11px] font-mono text-slate-400 truncate flex-1">
                    {scanResult.sha256_hash}
                  </span>
                  <button
                    onClick={copyHashToClipboard}
                    className="p-1 text-slate-400 hover:text-white transition-colors"
                    title="Copy Hash"
                  >
                    {copiedHash ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>

              {web3SuccessMessage ? (
                <div className="p-3 bg-emerald-950/50 border border-emerald-800 rounded-lg text-xs text-emerald-300 flex items-center space-x-2">
                  <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>{web3SuccessMessage}</span>
                </div>
              ) : (
                <button
                  onClick={handleRegisterOnChain}
                  disabled={isRegisteringWeb3}
                  className="w-full py-2 px-3 bg-purple-600 hover:bg-purple-500 disabled:bg-slate-800 disabled:text-slate-500 text-white rounded-lg text-xs font-medium transition-colors flex items-center justify-center space-x-1.5"
                >
                  <Blocks className="w-3.5 h-3.5" />
                  <span>{isRegisteringWeb3 ? 'Anchoring to Smart Contract...' : 'Anchor Report to Web3 Registry'}</span>
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
