import React, { useState } from 'react';
import Editor from '@monaco-editor/react';
import {
  Smartphone,
  Shield,
  Layers,
  FileCode,
  Search,
  CheckCircle2,
  AlertCircle,
  Copy,
  Check,
  Package,
} from 'lucide-react';
import type { AndroidResult, AndroidClass } from '@shared/types.js';

interface AndroidResultsViewProps {
  result: AndroidResult;
  onExploreWorkspace?: () => void;
}

export const AndroidResultsView: React.FC<AndroidResultsViewProps> = ({
  result,
  onExploreWorkspace,
}) => {
  const [activeTab, setActiveTab] = useState<'classes' | 'manifest' | 'components'>('classes');
  const [selectedClass, setSelectedClass] = useState<AndroidClass | null>(
    result.classes.length > 0 ? result.classes[0] : null
  );
  const [classFilter, setClassFilter] = useState('');
  const [copied, setCopied] = useState(false);

  const filteredClasses = result.classes.filter((c) =>
    c.name.toLowerCase().includes(classFilter.toLowerCase())
  );

  const handleCopy = (text?: string) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Overview Cards */}
      <div className="p-4 rounded-xl border border-rea-border bg-rea-surface grid grid-cols-2 md:grid-cols-4 gap-4 text-xs font-mono">
        <div>
          <span className="text-rea-muted block">Package Name</span>
          <span className="text-white font-bold text-sm truncate block">{result.packageName}</span>
        </div>
        <div>
          <span className="text-rea-muted block">Version / SDK</span>
          <span className="text-white font-bold text-sm">
            {result.version} {result.targetSdk ? `(API ${result.targetSdk})` : ''}
          </span>
        </div>
        <div>
          <span className="text-rea-muted block">Permissions</span>
          <span className="text-emerald-400 font-bold text-sm">{result.permissions.length}</span>
        </div>
        <div>
          <span className="text-rea-muted block">Decompiled Classes</span>
          <span className="text-emerald-400 font-bold text-sm">{result.classes.length}</span>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-rea-border space-x-4">
        <button
          onClick={() => setActiveTab('classes')}
          className={`pb-2.5 text-sm font-medium transition flex items-center space-x-2 ${
            activeTab === 'classes'
              ? 'border-b-2 border-rea-accent text-white'
              : 'text-rea-muted hover:text-white'
          }`}
        >
          <FileCode className="w-4 h-4" />
          <span>Java / Kotlin Sources ({result.classes.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('manifest')}
          className={`pb-2.5 text-sm font-medium transition flex items-center space-x-2 ${
            activeTab === 'manifest'
              ? 'border-b-2 border-rea-accent text-white'
              : 'text-rea-muted hover:text-white'
          }`}
        >
          <Shield className="w-4 h-4" />
          <span>Permissions & Security ({result.permissions.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('components')}
          className={`pb-2.5 text-sm font-medium transition flex items-center space-x-2 ${
            activeTab === 'components'
              ? 'border-b-2 border-rea-accent text-white'
              : 'text-rea-muted hover:text-white'
          }`}
        >
          <Layers className="w-4 h-4" />
          <span>App Components ({result.activities.length + result.services.length})</span>
        </button>
      </div>

      {/* Classes Decompiled Code Explorer */}
      {activeTab === 'classes' && (
        <div className="border border-rea-border rounded-xl bg-rea-surface overflow-hidden flex flex-col md:flex-row h-[600px]">
          {/* Class Sidebar */}
          <div className="w-full md:w-80 border-b md:border-b-0 md:border-r border-rea-border flex flex-col bg-rea-bg/60">
            <div className="p-2 border-b border-rea-border">
              <div className="relative">
                <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-rea-muted" />
                <input
                  type="text"
                  placeholder="Filter Java classes..."
                  value={classFilter}
                  onChange={(e) => setClassFilter(e.target.value)}
                  className="w-full bg-rea-bg border border-rea-border rounded pl-8 pr-2 py-1 text-xs text-white placeholder-rea-muted focus:outline-none focus:border-rea-accent"
                />
              </div>
            </div>

            <div className="flex-1 overflow-y-auto p-1.5 space-y-0.5">
              {filteredClasses.length === 0 ? (
                <div className="p-4 text-xs text-rea-muted text-center">No matching classes</div>
              ) : (
                filteredClasses.map((cls, idx) => {
                  const isSelected = selectedClass?.name === cls.name;
                  return (
                    <div
                      key={idx}
                      onClick={() => setSelectedClass(cls)}
                      className={`flex items-center space-x-2 py-1.5 px-2 rounded cursor-pointer text-xs font-mono transition ${
                        isSelected
                          ? 'bg-rea-accent/20 border-l-2 border-rea-accent text-white font-bold'
                          : 'text-rea-muted hover:text-white hover:bg-rea-surface'
                      }`}
                    >
                      <FileCode className="w-3.5 h-3.5 text-rea-accent flex-shrink-0" />
                      <span className="truncate">{cls.name}</span>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Monaco Editor displaying Java Decompiled Code */}
          <div className="flex-1 flex flex-col min-w-0 bg-rea-bg">
            <div className="px-4 py-2 border-b border-rea-border bg-rea-surface flex items-center justify-between">
              <div className="flex items-center space-x-2 truncate">
                <span className="text-xs font-mono text-white font-medium truncate">
                  {selectedClass?.name || 'Select a class'}
                </span>
                <span className="text-[10px] bg-rea-bg border border-rea-border px-1.5 py-0.5 rounded text-rea-muted font-mono uppercase">
                  {selectedClass?.smaliCode ? 'Smali' : 'Java (JADX)'}
                </span>
              </div>

              <button
                onClick={() => handleCopy(selectedClass?.decompiledCode || selectedClass?.smaliCode)}
                className="p-1.5 rounded hover:bg-rea-border/60 text-rea-muted hover:text-white transition flex items-center space-x-1 text-xs"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span className="text-[11px]">{copied ? 'Copied' : 'Copy'}</span>
              </button>
            </div>

            <div className="flex-1 relative">
              <Editor
                height="100%"
                theme="vs-dark"
                language={selectedClass?.smaliCode ? 'plaintext' : 'java'}
                value={
                  selectedClass?.decompiledCode ||
                  selectedClass?.smaliCode ||
                  '// No decompiled source code available for this class.'
                }
                options={{
                  readOnly: true,
                  minimap: { enabled: true },
                  fontSize: 12,
                  fontFamily: "'JetBrains Mono', monospace",
                  scrollBeyondLastLine: false,
                  lineNumbers: 'on',
                  folding: true,
                }}
              />
            </div>
          </div>
        </div>
      )}

      {/* Permissions Tab */}
      {activeTab === 'manifest' && (
        <div className="space-y-3">
          <div className="text-xs font-semibold text-white">Declared Android Permissions</div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 font-mono text-xs">
            {result.permissions.map((perm, idx) => (
              <div
                key={idx}
                className="p-2.5 rounded-lg border border-rea-border bg-rea-surface flex items-center space-x-2"
              >
                <Shield className="w-4 h-4 text-amber-400 flex-shrink-0" />
                <span className="text-white truncate">{perm}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Components Tab */}
      {activeTab === 'components' && (
        <div className="space-y-4">
          <div>
            <h4 className="text-xs font-bold text-white uppercase font-mono mb-2">
              Activities ({result.activities.length})
            </h4>
            <div className="space-y-1.5 font-mono text-xs">
              {result.activities.map((act, idx) => (
                <div
                  key={idx}
                  className="p-2.5 rounded bg-rea-surface border border-rea-border flex items-center justify-between"
                >
                  <span className="text-white">{act.name}</span>
                  {act.exported && (
                    <span className="text-[10px] bg-red-950/80 text-red-400 border border-red-800 px-1.5 py-0.5 rounded">
                      EXPORTED
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>

          <div>
            <h4 className="text-xs font-bold text-white uppercase font-mono mb-2">
              Services ({result.services.length})
            </h4>
            <div className="space-y-1.5 font-mono text-xs">
              {result.services.map((srv, idx) => (
                <div
                  key={idx}
                  className="p-2.5 rounded bg-rea-surface border border-rea-border flex items-center justify-between"
                >
                  <span className="text-white">{srv.name}</span>
                  {srv.exported && (
                    <span className="text-[10px] bg-red-950/80 text-red-400 border border-red-800 px-1.5 py-0.5 rounded">
                      EXPORTED
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
