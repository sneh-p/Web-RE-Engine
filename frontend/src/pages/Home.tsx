import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Code,
  Binary,
  Globe,
  Smartphone,
  Layers,
  Zap,
  ArrowRight,
  Terminal,
  Sparkles,
  Puzzle,
} from 'lucide-react';
import { FileUpload } from '../components/shared/FileUpload';
import {
  submitFileUpload,
  submitBrowserAnalysis,
  submitEvmAnalysis,
  submitAutoAnalysis,
  submitBulkAnalysis,
  submitExtensionFromStore,
} from '../api/client';
import type { AnalysisType } from '@shared/types.js';

type TargetType = AnalysisType | 'auto';

export const Home: React.FC = () => {
  const navigate = useNavigate();
  const [selectedType, setSelectedType] = useState<TargetType>('auto');
  const [file, setFile] = useState<File | null>(null);
  const [files, setFiles] = useState<File[]>([]);

  // Form states for specialized tools
  const [url, setUrl] = useState('');
  const [evmSource, setEvmSource] = useState<'bytecode' | 'address'>('bytecode');
  const [evmValue, setEvmValue] = useState('');
  const [nativeProvider, setNativeProvider] = useState<'auto' | 'ghidra' | 'hopper'>('auto');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [extSource, setExtSource] = useState<'file' | 'store'>('file');
  const [extStoreRef, setExtStoreRef] = useState('');
  const [extBrowser, setExtBrowser] = useState<'chrome' | 'firefox'>('chrome');

  const targets: {
    type: TargetType;
    name: string;
    desc: string;
    icon: React.ComponentType<{ className?: string }>;
    badge: string;
  }[] = [
    {
      type: 'auto',
      name: 'Auto-detect',
      desc: 'Automatically sniff magic bytes for APK, .NET, Native (PE/ELF/Mach-O), or JavaScript.',
      icon: Sparkles,
      badge: 'Auto',
    },
    {
      type: 'javascript',
      name: 'JavaScript / Electron',
      desc: 'Inspect ASAR archives, packaged JS, IPC boundaries and module graphs.',
      icon: Code,
      badge: 'Zero-config',
    },
    {
      type: 'native' as AnalysisType,
      name: 'Native Binaries',
      desc: 'Disassemble ELF, PE, Mach-O binaries with radare2, unpack UPX/PyInstaller/installers, scan with YARA.',
      icon: Binary,
      badge: 'radare2 / YARA',
    },
    {
      type: 'browser' as AnalysisType,
      name: 'Web Applications',
      desc: 'Analyze live websites, network traffic, scripts, cookies via Playwright CDP.',
      icon: Globe,
      badge: 'Playwright',
    },
    {
      type: 'evm' as AnalysisType,
      name: 'EVM Bytecode',
      desc: 'Disassemble smart contracts, decode function selectors and control flow.',
      icon: Zap,
      badge: 'Built-in',
    },
    {
      type: 'android' as AnalysisType,
      name: 'Android APK',
      desc: 'Decompile manifest, components, permissions, native .so libraries.',
      icon: Smartphone,
      badge: 'Apktool',
    },
    {
      type: 'dotnet' as AnalysisType,
      name: '.NET Assemblies',
      desc: 'Inspect managed code, CIL types, P/Invoke native boundaries.',
      icon: Layers,
      badge: 'ILSpy',
    },
    {
      type: 'extension' as AnalysisType,
      name: 'Browser Extensions',
      desc: 'Chrome/Edge .crx, Firefox .xpi or a store link: permissions, risky code, exfiltration and a risk score.',
      icon: Puzzle,
      badge: 'Static',
    },
  ];

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);

    try {
      let job;
      if (selectedType === 'auto' && files.length > 1) {
        const { jobs, rejected } = await submitBulkAnalysis(files);
        if (rejected.length > 0) {
          setError(
            `${jobs.length} job(s) started. Not analyzed: ${rejected.map((r) => r.fileName).join(', ')} (unsupported file type).`
          );
          return;
        }
        navigate('/jobs');
        return;
      } else if (selectedType === 'auto') {
        if (!file) throw new Error('Please select a file to analyze');
        job = await submitAutoAnalysis(file);
      } else if (selectedType === 'javascript' || selectedType === 'dotnet' || selectedType === 'android') {
        if (!file) throw new Error('Please select a file to analyze');
        job = await submitFileUpload(selectedType, file);
      } else if (selectedType === 'native') {
        if (!file) throw new Error('Please select a binary to analyze');
        job = await submitFileUpload('native', file, { provider: nativeProvider });
      } else if (selectedType === 'browser') {
        if (!url) throw new Error('Please enter a target URL');
        job = await submitBrowserAnalysis({
          type: 'browser',
          url,
          captureNetworkTraffic: true,
          captureScreenshot: true,
        });
      } else if (selectedType === 'extension') {
        if (extSource === 'store') {
          if (!extStoreRef.trim()) throw new Error('Enter a store URL or extension id');
          job = await submitExtensionFromStore(extStoreRef.trim(), extBrowser);
        } else {
          if (!file) throw new Error('Please select an extension package');
          job = await submitFileUpload('extension', file);
        }
      } else if (selectedType === 'evm') {
        if (!evmValue) throw new Error('Please enter EVM bytecode or contract address');
        job = await submitEvmAnalysis({
          type: 'evm',
          source: evmSource,
          value: evmValue,
        });
      }

      if (job) {
        navigate(`/jobs/${job.id}`);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to start analysis');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto py-10 px-6 space-y-10">
      {/* Hero section */}
      <div className="text-center space-y-3">
        <h1 className="text-3xl md:text-4xl font-extrabold text-white tracking-tight">
          Web RE Engine
        </h1>
        <p className="text-rea-muted max-w-2xl mx-auto text-sm md:text-base">
          Understand how software features work down to the bytecode and binary level.
          Powered by rea-agents workflows, static heuristics, and deep analysis engines.
        </p>
      </div>

      {/* Target Selector Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {targets.map((t) => {
          const Icon = t.icon;
          const isSelected = selectedType === t.type;
          return (
            <button
              key={t.type}
              type="button"
              onClick={() => {
                setSelectedType(t.type);
                setFile(null);
                setFiles([]);
                setError(null);
              }}
              className={`p-5 rounded-xl border text-left transition flex flex-col justify-between space-y-4 ${
                isSelected
                  ? 'border-rea-accent bg-rea-surface ring-1 ring-rea-accent shadow-lg shadow-rea-accent/5'
                  : 'border-rea-border bg-rea-surface/40 hover:border-rea-muted hover:bg-rea-surface'
              }`}
            >
              <div className="flex items-start justify-between w-full">
                <div
                  className={`p-2.5 rounded-lg ${
                    isSelected ? 'bg-rea-accent text-white' : 'bg-rea-bg text-rea-muted'
                  }`}
                >
                  <Icon className="w-5 h-5" />
                </div>
                <span className="text-[10px] font-mono uppercase bg-rea-bg px-2 py-0.5 rounded border border-rea-border text-rea-muted">
                  {t.badge}
                </span>
              </div>
              <div>
                <h3 className="font-semibold text-white text-sm">{t.name}</h3>
                <p className="text-xs text-rea-muted mt-1 leading-relaxed">{t.desc}</p>
              </div>
            </button>
          );
        })}
      </div>

      {/* Input Form based on selected analysis type */}
      <form onSubmit={handleSubmit} className="p-6 bg-rea-surface border border-rea-border rounded-2xl space-y-6">
        <div className="border-b border-rea-border pb-4">
          <h2 className="text-lg font-bold text-white flex items-center space-x-2">
            <span>Configure {targets.find((t) => t.type === selectedType)?.name} Analysis</span>
          </h2>
          <p className="text-xs text-rea-muted mt-1">
            Specify the input artifact or target destination for inspection.
          </p>
        </div>

        {error && (
          <div className="p-3 bg-red-950/40 border border-red-800 rounded-lg text-xs text-red-300">
            {error}
          </div>
        )}

        {/* File Upload targets */}
        {(selectedType === 'auto' ||
          selectedType === 'javascript' ||
          selectedType === 'native' ||
          selectedType === 'dotnet' ||
          selectedType === 'android') && (
          <div className="space-y-4">
            <FileUpload
              onFileSelect={setFile}
              selectedFile={file}
              onFilesSelect={selectedType === 'auto' ? setFiles : undefined}
              selectedCount={selectedType === 'auto' ? files.length : 0}
              description={
                selectedType === 'auto'
                  ? 'Upload one or more files (APK, PE/.NET, ELF, Mach-O, CRX/XPI, ZIP, ASAR, TAR, JS/TS) — up to 50 at once'
                  : selectedType === 'javascript'
                  ? 'Upload .js file, .asar bundle, or zip of extracted Electron application'
                  : selectedType === 'native'
                  ? 'Upload native executable (ELF, PE .exe/.dll, Mach-O binary)'
                  : selectedType === 'android'
                  ? 'Upload .apk package'
                  : 'Upload .NET assembly (.dll or .exe)'
              }
            />

            {selectedType === 'native' && (
              <div className="text-xs text-rea-muted">
                Engine is chosen automatically: radare2 (with the Ghidra decompiler when the r2ghidra plugin is
                installed), then objdump, then a static header parser.
              </div>
            )}
          </div>
        )}

        {/* Browser extension: upload or download from a store */}
        {selectedType === 'extension' && (
          <div className="space-y-4">
            <div className="flex space-x-2 text-xs">
              {(['file', 'store'] as const).map((src) => (
                <button
                  key={src}
                  type="button"
                  onClick={() => setExtSource(src)}
                  className={`px-3 py-1.5 rounded-lg border transition ${
                    extSource === src ? 'border-rea-accent text-white bg-rea-accent/20' : 'border-rea-border text-rea-muted hover:text-white'
                  }`}
                >
                  {src === 'file' ? 'Upload package' : 'From a store link'}
                </button>
              ))}
            </div>

            {extSource === 'file' ? (
              <FileUpload
                onFileSelect={setFile}
                selectedFile={file}
                description="Upload a .crx (Chrome/Edge), .xpi (Firefox) or a .zip of an unpacked extension"
              />
            ) : (
              <div className="space-y-2">
                <div className="flex space-x-2">
                  <select
                    value={extBrowser}
                    onChange={(e) => setExtBrowser(e.target.value as 'chrome' | 'firefox')}
                    className="bg-rea-bg border border-rea-border rounded-lg px-3 py-2.5 text-xs text-white focus:outline-none focus:border-rea-accent"
                  >
                    <option value="chrome">Chrome / Edge</option>
                    <option value="firefox">Firefox</option>
                  </select>
                  <input
                    type="text"
                    value={extStoreRef}
                    onChange={(e) => setExtStoreRef(e.target.value)}
                    placeholder={
                      extBrowser === 'chrome'
                        ? 'https://chromewebstore.google.com/detail/…/<32-letter id>  or the id'
                        : 'https://addons.mozilla.org/firefox/addon/<slug>/  or the slug'
                    }
                    className="flex-1 bg-rea-bg border border-rea-border rounded-lg px-4 py-2.5 text-sm text-white font-mono placeholder:text-rea-muted focus:outline-none focus:border-rea-accent"
                  />
                </div>
                <p className="text-xs text-rea-muted">
                  The server downloads the current version from the store; nothing is installed or executed.
                </p>
              </div>
            )}
          </div>
        )}

        {/* Browser Analysis input */}
        {selectedType === 'browser' && (
          <div className="space-y-3">
            <label className="text-xs font-semibold text-white block">Target URL</label>
            <div className="flex space-x-2">
              <input
                type="url"
                required
                placeholder="https://example.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="flex-1 bg-rea-bg border border-rea-border rounded-lg px-3 py-2 text-sm text-white placeholder-rea-muted focus:outline-none focus:border-rea-accent"
              />
            </div>
            <p className="text-[11px] text-rea-muted">
              Playwright will connect, record network exchanges, and extract scripts & cookies.
            </p>
          </div>
        )}

        {/* EVM Bytecode input */}
        {selectedType === 'evm' && (
          <div className="space-y-4">
            <div className="flex space-x-4 border-b border-rea-border pb-2 text-xs">
              <button
                type="button"
                onClick={() => setEvmSource('bytecode')}
                className={`font-semibold pb-1 ${
                  evmSource === 'bytecode'
                    ? 'border-b-2 border-rea-accent text-white'
                    : 'text-rea-muted'
                }`}
              >
                Raw Bytecode (Hex)
              </button>
              <button
                type="button"
                onClick={() => setEvmSource('address')}
                className={`font-semibold pb-1 ${
                  evmSource === 'address'
                    ? 'border-b-2 border-rea-accent text-white'
                    : 'text-rea-muted'
                }`}
              >
                Contract Address (RPC)
              </button>
            </div>

            <textarea
              required
              rows={4}
              placeholder={
                evmSource === 'bytecode'
                  ? '0x608060405234801561001057600080fd5b50...'
                  : '0xdAC17F958D2ee523a2206206994597C13D831ec7'
              }
              value={evmValue}
              onChange={(e) => setEvmValue(e.target.value)}
              className="w-full bg-rea-bg border border-rea-border rounded-lg p-3 text-xs font-mono text-white placeholder-rea-muted focus:outline-none focus:border-rea-accent"
            />
          </div>
        )}

        <div className="pt-2 flex justify-end">
          <button
            type="submit"
            disabled={isSubmitting}
            className="bg-rea-accent hover:bg-rea-accentHover text-white px-5 py-2.5 rounded-xl font-semibold text-sm transition flex items-center space-x-2 disabled:opacity-50"
          >
            {isSubmitting ? (
              <span>Queueing Analysis...</span>
            ) : (
              <>
                <span>Launch Analysis</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
};
