import React, { useState } from 'react';
import { Boxes, ChevronDown, ChevronRight, FolderTree } from 'lucide-react';
import type { DotNetResult } from '@shared/types.js';

interface DotNetResultsViewProps {
  result: DotNetResult;
  hasDecompiledSource: boolean;
  onExploreWorkspace: () => void;
}

const kindStyle: Record<string, string> = {
  class: 'text-sky-300',
  interface: 'text-violet-300',
  struct: 'text-amber-300',
  enum: 'text-emerald-300',
  delegate: 'text-rose-300',
};

export const DotNetResultsView: React.FC<DotNetResultsViewProps> = ({ result, hasDecompiledSource, onExploreWorkspace }) => {
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const typeCount = result.namespaces.reduce((n, ns) => n + ns.types.length, 0);

  return (
    <div className="border border-rea-border rounded-xl bg-rea-surface overflow-hidden text-xs font-mono">
      <div className="px-4 py-2.5 border-b border-rea-border flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <Boxes className="w-4 h-4 text-rea-accent" />
          <span className="font-bold text-white tracking-wide">.NET Assembly</span>
          <span className="text-rea-muted">
            {typeCount} types · {result.namespaces.length} namespaces · {result.targetFramework}
          </span>
        </div>
        {hasDecompiledSource && (
          <button
            onClick={onExploreWorkspace}
            className="flex items-center space-x-1.5 px-2.5 py-1 rounded border border-rea-border hover:bg-rea-border/60 text-rea-text hover:text-white transition"
          >
            <FolderTree className="w-3.5 h-3.5" />
            <span>Browse decompiled C#</span>
          </button>
        )}
      </div>

      {result.namespaces.length === 0 ? (
        <div className="px-4 py-3 text-rea-muted">No types were recovered from this assembly.</div>
      ) : (
        <div className="max-h-[32rem] overflow-y-auto divide-y divide-rea-border/40">
          {result.namespaces.map((ns) => (
            <div key={ns.name}>
              <button
                type="button"
                onClick={() => setOpen((prev) => ({ ...prev, [ns.name]: !prev[ns.name] }))}
                className="w-full px-4 py-2 flex items-center justify-between hover:bg-rea-bg/60 text-left"
              >
                <span className="text-white truncate">{ns.name}</span>
                <span className="flex items-center space-x-2 text-rea-muted">
                  <span>{ns.types.length}</span>
                  {open[ns.name] ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                </span>
              </button>
              {open[ns.name] && (
                <div className="px-6 pb-2 space-y-0.5">
                  {ns.types.map((t) => (
                    <div key={t.fullName} className="flex space-x-3">
                      <span className={`w-16 flex-shrink-0 ${kindStyle[t.kind] ?? 'text-rea-muted'}`}>{t.kind}</span>
                      <span className="text-rea-text truncate">{t.name}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
