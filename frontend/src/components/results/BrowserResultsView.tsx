import React, { useState } from 'react';
import { Globe, ArrowDownRight, Code2, Cookie as CookieIcon } from 'lucide-react';
import type { BrowserResult } from '@shared/types.js';

interface BrowserResultsViewProps {
  result: BrowserResult;
}

export const BrowserResultsView: React.FC<BrowserResultsViewProps> = ({ result }) => {
  const [activeTab, setActiveTab] = useState<'network' | 'scripts' | 'cookies'>('network');

  return (
    <div className="space-y-6">
      <div className="p-4 rounded-xl border border-rea-border bg-rea-surface flex items-center justify-between">
        <div>
          <div className="flex items-center space-x-2">
            <Globe className="w-4 h-4 text-rea-accent" />
            <h4 className="text-sm font-semibold text-white">{result.url}</h4>
          </div>
          {result.title && <p className="text-xs text-rea-muted mt-1">{result.title}</p>}
        </div>

        <div className="flex space-x-4 text-xs font-mono">
          <div>
            <span className="text-rea-muted">Requests: </span>
            <span className="text-white font-bold">{result.networkRequests.length}</span>
          </div>
          <div>
            <span className="text-rea-muted">Scripts: </span>
            <span className="text-white font-bold">{result.scriptSources.length}</span>
          </div>
        </div>
      </div>

      {result.screenshot && (
        <div className="rounded-xl border border-rea-border overflow-hidden bg-rea-surface">
          <div className="p-2 border-b border-rea-border bg-rea-bg/50 text-xs font-mono text-rea-muted">
            Page Viewport Capture
          </div>
          <img
            src={`data:image/png;base64,${result.screenshot}`}
            alt="Page Screenshot"
            className="w-full max-h-[300px] object-cover object-top"
          />
        </div>
      )}

      {/* Tabs */}
      <div className="flex border-b border-rea-border space-x-4">
        <button
          onClick={() => setActiveTab('network')}
          className={`pb-2.5 text-sm font-medium transition flex items-center space-x-2 ${
            activeTab === 'network'
              ? 'border-b-2 border-rea-accent text-white'
              : 'text-rea-muted hover:text-white'
          }`}
        >
          <ArrowDownRight className="w-4 h-4" />
          <span>Network ({result.networkRequests.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('scripts')}
          className={`pb-2.5 text-sm font-medium transition flex items-center space-x-2 ${
            activeTab === 'scripts'
              ? 'border-b-2 border-rea-accent text-white'
              : 'text-rea-muted hover:text-white'
          }`}
        >
          <Code2 className="w-4 h-4" />
          <span>Scripts ({result.scriptSources.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('cookies')}
          className={`pb-2.5 text-sm font-medium transition flex items-center space-x-2 ${
            activeTab === 'cookies'
              ? 'border-b-2 border-rea-accent text-white'
              : 'text-rea-muted hover:text-white'
          }`}
        >
          <CookieIcon className="w-4 h-4" />
          <span>Cookies ({result.cookies.length})</span>
        </button>
      </div>

      {activeTab === 'network' && (
        <div className="space-y-1.5 max-h-[450px] overflow-y-auto">
          {result.networkRequests.map((req, idx) => (
            <div
              key={idx}
              className="p-2.5 bg-rea-surface rounded-lg border border-rea-border flex items-center justify-between text-xs font-mono"
            >
              <div className="flex items-center space-x-3 overflow-hidden mr-4">
                <span className="font-bold text-rea-accent uppercase">{req.method}</span>
                <span className="text-white truncate">{req.url}</span>
              </div>
              <div className="flex items-center space-x-3 flex-shrink-0">
                {req.statusCode && (
                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                      req.statusCode < 300
                        ? 'bg-emerald-950/80 text-emerald-400'
                        : req.statusCode < 400
                        ? 'bg-blue-950/80 text-blue-400'
                        : 'bg-red-950/80 text-red-400'
                    }`}
                  >
                    {req.statusCode}
                  </span>
                )}
                {req.size !== undefined && (
                  <span className="text-rea-muted text-[11px]">
                    {(req.size / 1024).toFixed(1)} KB
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {activeTab === 'scripts' && (
        <div className="space-y-2 max-h-[450px] overflow-y-auto font-mono text-xs">
          {result.scriptSources.map((s, idx) => (
            <div
              key={idx}
              className="p-3 bg-rea-surface rounded-lg border border-rea-border flex items-center justify-between"
            >
              <span className="text-white truncate mr-4">{s.url}</span>
              {s.sourceMapped && (
                <span className="text-[10px] bg-purple-950/80 text-purple-400 border border-purple-800 px-1.5 py-0.5 rounded">
                  SOURCEMAP
                </span>
              )}
            </div>
          ))}
        </div>
      )}

      {activeTab === 'cookies' && (
        <div className="space-y-2 max-h-[450px] overflow-y-auto font-mono text-xs">
          {result.cookies.map((c, idx) => (
            <div
              key={idx}
              className="p-3 bg-rea-surface rounded-lg border border-rea-border flex items-center justify-between"
            >
              <div>
                <span className="text-white font-bold">{c.name}</span>
                <span className="text-rea-muted text-[11px] block">{c.domain}</span>
              </div>
              <div className="flex space-x-1.5">
                {c.httpOnly && (
                  <span className="text-[10px] bg-amber-950/80 text-amber-400 border border-amber-800 px-1.5 py-0.5 rounded">
                    HTTPOnly
                  </span>
                )}
                {c.secure && (
                  <span className="text-[10px] bg-emerald-950/80 text-emerald-400 border border-emerald-800 px-1.5 py-0.5 rounded">
                    Secure
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
