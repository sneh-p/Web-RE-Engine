import React, { useState } from 'react';
import { Package, ArrowRight, Layers, Code } from 'lucide-react';
import type { JavaScriptResult } from '@shared/types.js';

interface JavaScriptResultsViewProps {
  result: JavaScriptResult;
  onSelectModule?: (path: string) => void;
}

export const JavaScriptResultsView: React.FC<JavaScriptResultsViewProps> = ({
  result,
  onSelectModule,
}) => {
  const [activeTab, setActiveTab] = useState<'modules' | 'imports' | 'electron'>('modules');

  return (
    <div className="space-y-6">
      {/* Summary card */}
      <div className="p-4 rounded-xl border border-rea-border bg-rea-surface">
        <h4 className="text-sm font-semibold text-white mb-1">Analysis Overview</h4>
        <p className="text-sm text-rea-muted">{result.summary}</p>
        <div className="mt-3 flex flex-wrap gap-4 text-xs font-mono">
          <div>
            <span className="text-rea-muted">Modules: </span>
            <span className="text-white font-bold">{result.modules.length}</span>
          </div>
          <div>
            <span className="text-rea-muted">Imports: </span>
            <span className="text-white font-bold">{result.imports.length}</span>
          </div>
          <div>
            <span className="text-rea-muted">Entry Points: </span>
            <span className="text-white font-bold">{result.entryPoints.length}</span>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-rea-border space-x-4">
        <button
          onClick={() => setActiveTab('modules')}
          className={`pb-2.5 text-sm font-medium transition flex items-center space-x-2 ${
            activeTab === 'modules'
              ? 'border-b-2 border-rea-accent text-white'
              : 'text-rea-muted hover:text-white'
          }`}
        >
          <Package className="w-4 h-4" />
          <span>Modules ({result.modules.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('imports')}
          className={`pb-2.5 text-sm font-medium transition flex items-center space-x-2 ${
            activeTab === 'imports'
              ? 'border-b-2 border-rea-accent text-white'
              : 'text-rea-muted hover:text-white'
          }`}
        >
          <ArrowRight className="w-4 h-4" />
          <span>Import Graph ({result.imports.length})</span>
        </button>

        {result.electronBoundaries && result.electronBoundaries.length > 0 && (
          <button
            onClick={() => setActiveTab('electron')}
            className={`pb-2.5 text-sm font-medium transition flex items-center space-x-2 ${
              activeTab === 'electron'
                ? 'border-b-2 border-rea-accent text-white'
                : 'text-rea-muted hover:text-white'
            }`}
          >
            <Layers className="w-4 h-4" />
            <span>Electron IPC ({result.electronBoundaries.length})</span>
          </button>
        )}
      </div>

      {/* Content based on tab */}
      {activeTab === 'modules' && (
        <div className="space-y-2 max-h-[450px] overflow-y-auto pr-2">
          {result.modules.map((m) => (
            <div
              key={m.id}
              onClick={() => onSelectModule && onSelectModule(m.path)}
              className="p-3 bg-rea-surface rounded-lg border border-rea-border flex items-center justify-between text-sm hover:border-rea-muted cursor-pointer transition"
            >
              <div className="flex items-center space-x-2.5">
                <Code className="w-4 h-4 text-rea-muted" />
                <span className="font-mono text-xs text-white">{m.path}</span>
                {m.isEntry && (
                  <span className="text-[10px] bg-emerald-950/80 text-emerald-400 border border-emerald-800 px-1.5 py-0.5 rounded font-mono">
                    ENTRY
                  </span>
                )}
                {m.isElectronMain && (
                  <span className="text-[10px] bg-blue-950/80 text-blue-400 border border-blue-800 px-1.5 py-0.5 rounded font-mono">
                    MAIN
                  </span>
                )}
                {m.isElectronRenderer && (
                  <span className="text-[10px] bg-purple-950/80 text-purple-400 border border-purple-800 px-1.5 py-0.5 rounded font-mono">
                    RENDERER
                  </span>
                )}
              </div>
              <span className="text-xs text-rea-muted font-mono">
                {m.size > 0 ? `${(m.size / 1024).toFixed(1)} KB` : ''}
              </span>
            </div>
          ))}
        </div>
      )}

      {activeTab === 'imports' && (
        <div className="space-y-2 max-h-[450px] overflow-y-auto pr-2">
          {result.imports.map((edge, idx) => (
            <div
              key={idx}
              className="p-3 bg-rea-surface rounded-lg border border-rea-border flex items-center justify-between text-xs font-mono hover:border-rea-muted transition"
            >
              <div className="flex items-center space-x-3 text-rea-text">
                <span className="text-white">{edge.from}</span>
                <ArrowRight className="w-3.5 h-3.5 text-rea-muted flex-shrink-0" />
                <span className="text-emerald-400">{edge.to}</span>
              </div>
              {edge.isDynamic && (
                <span className="text-[10px] bg-amber-950/60 text-amber-400 border border-amber-800 px-1.5 py-0.5 rounded">
                  DYNAMIC
                </span>
              )}
            </div>
          ))}
        </div>
      )}

      {activeTab === 'electron' && result.electronBoundaries && (
        <div className="space-y-2">
          {result.electronBoundaries.map((b, idx) => (
            <div
              key={idx}
              className="p-3 bg-rea-surface rounded-lg border border-rea-border flex items-center justify-between text-xs font-mono"
            >
              <div className="flex items-center space-x-2">
                <span className="text-purple-400 font-bold">{b.type}</span>
                {b.channel && <span className="text-white">"{b.channel}"</span>}
              </div>
              <span className="text-rea-muted">
                {b.location.file}:{b.location.line}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
