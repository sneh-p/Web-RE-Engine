import React, { useState } from 'react';
import {
  Fingerprint,
  Copy,
  Check,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  Eye,
  EyeOff,
  Globe,
  Mail,
  Key,
  Coins,
  Network,
  Binary,
  ShieldAlert,
} from 'lucide-react';
import type { AnalysisJob } from '@shared/types.js';
import { SignatureFindings } from './SignatureFindings';

interface OverviewPanelProps {
  job: AnalysisJob;
}

export const OverviewPanel: React.FC<OverviewPanelProps> = ({ job }) => {
  const { fingerprint, iocs, yara, capabilities } = job;
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [collapsedCategories, setCollapsedCategories] = useState<Record<string, boolean>>({});
  const [revealedSecrets, setRevealedSecrets] = useState<Record<string, boolean>>({});

  if (!fingerprint && !yara && !capabilities && (!iocs || Object.keys(iocs).length === 0)) {
    return null;
  }

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  const toggleCategory = (cat: string) => {
    setCollapsedCategories((prev) => ({ ...prev, [cat]: !prev[cat] }));
  };

  const toggleSecretReveal = (idx: string) => {
    setRevealedSecrets((prev) => ({ ...prev, [idx]: !prev[idx] }));
  };

  const maskSecret = (val: string): string => {
    if (val.length <= 8) return '••••••••';
    return `${val.slice(0, 4)}••••••••${val.slice(-4)}`;
  };

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB (${bytes.toLocaleString()} bytes)`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB (${bytes.toLocaleString()} bytes)`;
  };

  const categoryConfig: Record<string, { label: string; icon: React.ReactNode }> = {
    urls: { label: 'URLs', icon: <Globe className="w-3.5 h-3.5 text-blue-400" /> },
    domains: { label: 'Domains', icon: <Network className="w-3.5 h-3.5 text-cyan-400" /> },
    ipv4: { label: 'IPv4 Addresses', icon: <Network className="w-3.5 h-3.5 text-emerald-400" /> },
    emails: { label: 'Email Addresses', icon: <Mail className="w-3.5 h-3.5 text-indigo-400" /> },
    ethereum: { label: 'Ethereum Addresses', icon: <Coins className="w-3.5 h-3.5 text-purple-400" /> },
    bitcoin: { label: 'Bitcoin Addresses', icon: <Coins className="w-3.5 h-3.5 text-amber-400" /> },
    secrets: { label: 'Likely Secrets & Keys', icon: <Key className="w-3.5 h-3.5 text-rose-400" /> },
  };

  return (
    <div className="border border-rea-border rounded-xl bg-rea-surface overflow-hidden space-y-0 text-xs font-mono">
      {/* Panel Header */}
      <div className="px-4 py-2.5 bg-rea-surface border-b border-rea-border flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <Fingerprint className="w-4 h-4 text-rea-accent" />
          <span className="font-bold text-white text-xs tracking-wide">Job Overview & Indicators</span>
        </div>
        <span className="text-[10px] text-rea-muted uppercase tracking-wider">Static Telemetry</span>
      </div>

      <div className="p-4 space-y-6">
        {/* File Fingerprint */}
        {fingerprint && (
          <div className="space-y-3">
            <div className="text-[11px] font-bold text-white flex items-center space-x-2">
              <Binary className="w-3.5 h-3.5 text-emerald-400" />
              <span>File Fingerprint & Hashes</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 bg-rea-bg/60 p-3.5 rounded-lg border border-rea-border/60">
              {/* MD5 */}
              <div className="space-y-1">
                <span className="text-[10px] text-rea-muted block font-semibold uppercase">MD5</span>
                <div className="flex items-center justify-between bg-rea-surface px-2.5 py-1.5 rounded border border-rea-border">
                  <span className="text-white truncate font-mono text-[11px] mr-2">{fingerprint.md5}</span>
                  <button
                    onClick={() => handleCopy(fingerprint.md5, 'md5')}
                    title="Copy MD5"
                    className="text-rea-muted hover:text-white transition p-0.5 rounded"
                  >
                    {copiedId === 'md5' ? (
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                  </button>
                </div>
              </div>

              {/* SHA1 */}
              <div className="space-y-1">
                <span className="text-[10px] text-rea-muted block font-semibold uppercase">SHA1</span>
                <div className="flex items-center justify-between bg-rea-surface px-2.5 py-1.5 rounded border border-rea-border">
                  <span className="text-white truncate font-mono text-[11px] mr-2">{fingerprint.sha1}</span>
                  <button
                    onClick={() => handleCopy(fingerprint.sha1, 'sha1')}
                    title="Copy SHA1"
                    className="text-rea-muted hover:text-white transition p-0.5 rounded"
                  >
                    {copiedId === 'sha1' ? (
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                  </button>
                </div>
              </div>

              {/* SHA256 + VirusTotal link */}
              <div className="space-y-1 md:col-span-2">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] text-rea-muted font-semibold uppercase">SHA256</span>
                  <a
                    href={`https://www.virustotal.com/gui/file/${fingerprint.sha256}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[10px] text-rea-accent hover:underline inline-flex items-center space-x-1"
                  >
                    <span>Inspect on VirusTotal</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
                <div className="flex items-center justify-between bg-rea-surface px-2.5 py-1.5 rounded border border-rea-border">
                  <span className="text-white truncate font-mono text-[11px] mr-2">{fingerprint.sha256}</span>
                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => handleCopy(fingerprint.sha256, 'sha256')}
                      title="Copy SHA256"
                      className="text-rea-muted hover:text-white transition p-0.5 rounded"
                    >
                      {copiedId === 'sha256' ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                </div>
              </div>

              {/* File Size & Entropy */}
              <div className="flex items-center justify-between bg-rea-surface px-3 py-2 rounded border border-rea-border">
                <span className="text-rea-muted">File Size</span>
                <span className="text-white font-semibold">{formatSize(fingerprint.size)}</span>
              </div>

              <div className="flex items-center justify-between bg-rea-surface px-3 py-2 rounded border border-rea-border">
                <span className="text-rea-muted">Shannon Entropy</span>
                <div className="flex items-center space-x-2">
                  <span className="text-white font-semibold">{fingerprint.entropy.toFixed(4)} / 8.0</span>
                  {fingerprint.entropy > 7.2 ? (
                    <span className="px-1.5 py-0.5 rounded text-[10px] bg-red-950/60 border border-red-800 text-red-400 font-semibold flex items-center space-x-1">
                      <ShieldAlert className="w-3 h-3" />
                      <span>High</span>
                    </span>
                  ) : (
                    <span className="px-1.5 py-0.5 rounded text-[10px] bg-emerald-950/60 border border-emerald-800 text-emerald-400">
                      Normal
                    </span>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* IOCs Section */}
        {iocs && Object.keys(iocs).length > 0 && (
          <div className="space-y-3">
            <div className="text-[11px] font-bold text-white flex items-center space-x-2">
              <Key className="w-3.5 h-3.5 text-rea-accent" />
              <span>Extracted Indicators of Compromise (IOCs)</span>
            </div>

            <div className="space-y-2">
              {Object.entries(iocs).map(([category, items]) => {
                if (!items || items.length === 0) return null;
                const isCollapsed = !!collapsedCategories[category];
                const conf = categoryConfig[category] || {
                  label: category,
                  icon: <Network className="w-3.5 h-3.5 text-rea-muted" />,
                };
                const isSecretCategory = category === 'secrets';

                return (
                  <div
                    key={category}
                    className="border border-rea-border rounded-lg bg-rea-bg/60 overflow-hidden"
                  >
                    {/* Category Header */}
                    <button
                      type="button"
                      onClick={() => toggleCategory(category)}
                      className="w-full px-3.5 py-2.5 flex items-center justify-between bg-rea-surface/50 hover:bg-rea-surface transition text-left"
                    >
                      <div className="flex items-center space-x-2.5">
                        {conf.icon}
                        <span className="font-bold text-white text-xs">{conf.label}</span>
                        <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-rea-surface border border-rea-border text-rea-accent font-semibold">
                          {items.length}
                        </span>
                      </div>
                      <div className="text-rea-muted">
                        {isCollapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                      </div>
                    </button>

                    {/* Category Items List */}
                    {!isCollapsed && (
                      <div className="p-2 space-y-1 max-h-60 overflow-y-auto divide-y divide-rea-border/30">
                        {items.map((item, idx) => {
                          const itemKey = `${category}-${idx}`;
                          const isRevealed = !!revealedSecrets[itemKey];

                          return (
                            <div
                              key={idx}
                              className="py-1.5 px-2 flex items-center justify-between hover:bg-rea-surface/40 rounded transition group"
                            >
                              <span className="truncate mr-3 text-rea-text font-mono text-xs">
                                {isSecretCategory ? (isRevealed ? item : maskSecret(item)) : item}
                              </span>

                              <div className="flex items-center space-x-1.5 flex-shrink-0">
                                {isSecretCategory && (
                                  <button
                                    onClick={() => toggleSecretReveal(itemKey)}
                                    title={isRevealed ? 'Mask secret' : 'Reveal secret'}
                                    className="p-1 rounded text-rea-muted hover:text-white hover:bg-rea-surface transition"
                                  >
                                    {isRevealed ? (
                                      <EyeOff className="w-3.5 h-3.5 text-amber-400" />
                                    ) : (
                                      <Eye className="w-3.5 h-3.5" />
                                    )}
                                  </button>
                                )}

                                <button
                                  onClick={() => handleCopy(item, itemKey)}
                                  title="Copy"
                                  className="p-1 rounded text-rea-muted hover:text-white hover:bg-rea-surface transition"
                                >
                                  {copiedId === itemKey ? (
                                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                                  ) : (
                                    <Copy className="w-3.5 h-3.5" />
                                  )}
                                </button>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        <SignatureFindings yara={yara} capabilities={capabilities} />
      </div>
    </div>
  );
};
