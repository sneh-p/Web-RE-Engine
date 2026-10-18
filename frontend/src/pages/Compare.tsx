import React, { useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { ChevronLeft, Loader2, Equal, Plus, Minus, ChevronDown, ChevronRight } from 'lucide-react';
import { compareJobs, type SetDiff } from '../api/client';

const SECTION_LABELS: Record<string, string> = {
  imports: 'Imports',
  exports: 'Exports',
  functions: 'Functions',
  sections: 'Sections',
  strings: 'Strings',
  pythonModules: 'Third-party Python modules',
  permissions: 'Android permissions',
  components: 'Android components',
  classes: 'Classes',
  modules: 'JavaScript modules',
  types: '.NET types',
  requests: 'Network requests',
  scripts: 'Scripts',
  selectors: 'Function selectors',
  yaraRules: 'YARA rules matched',
  capabilities: 'capa capabilities',
  hostPermissions: 'Site access',
  contentScriptTargets: 'Content script targets',
  extensionApis: 'Extension APIs',
  findings: 'Code findings',
  version: 'Name and version',
  updateUrl: 'Update URL',
};

const label = (key: string) => SECTION_LABELS[key] ?? (key.startsWith('iocs.') ? `IOCs: ${key.slice(5)}` : key);

const DiffSection: React.FC<{ name: string; diff: SetDiff }> = ({ name, diff }) => {
  const changed = diff.added.length + diff.removed.length;
  const [open, setOpen] = useState(changed > 0 && changed <= 40);
  return (
    <div className="border border-rea-border rounded-lg bg-rea-surface overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="w-full px-4 py-2.5 flex items-center justify-between text-left hover:bg-rea-bg/40"
      >
        <span className="text-white font-semibold text-xs">{label(name)}</span>
        <span className="flex items-center space-x-3 text-[11px] font-mono">
          <span className="text-emerald-400">+{diff.added.length}</span>
          <span className="text-red-400">−{diff.removed.length}</span>
          <span className="text-rea-muted">{diff.common} same</span>
          {open ? <ChevronDown className="w-3.5 h-3.5 text-rea-muted" /> : <ChevronRight className="w-3.5 h-3.5 text-rea-muted" />}
        </span>
      </button>
      {open && changed > 0 && (
        <div className="border-t border-rea-border max-h-72 overflow-y-auto font-mono text-[11px] px-4 py-2 space-y-0.5">
          {diff.added.map((v) => (
            <div key={`+${v}`} className="flex space-x-2 text-emerald-300">
              <Plus className="w-3 h-3 flex-shrink-0 mt-0.5" />
              <span className="break-all">{v}</span>
            </div>
          ))}
          {diff.removed.map((v) => (
            <div key={`-${v}`} className="flex space-x-2 text-red-300">
              <Minus className="w-3 h-3 flex-shrink-0 mt-0.5" />
              <span className="break-all">{v}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export const Compare: React.FC = () => {
  const [params] = useSearchParams();
  const a = params.get('a') ?? '';
  const b = params.get('b') ?? '';
  const { data, isLoading, error } = useQuery({
    queryKey: ['compare', a, b],
    queryFn: () => compareJobs(a, b),
    enabled: !!a && !!b,
  });

  const sections = data ? Object.entries(data.sections).sort(([, x], [, y]) => y.added.length + y.removed.length - (x.added.length + x.removed.length)) : [];

  return (
    <div className="max-w-5xl mx-auto py-10 px-6 space-y-6">
      <Link to="/jobs" className="inline-flex items-center space-x-1 text-xs text-rea-muted hover:text-white transition">
        <ChevronLeft className="w-3.5 h-3.5" />
        <span>All Jobs</span>
      </Link>
      <h1 className="text-2xl font-extrabold text-white">Compare jobs</h1>

      {isLoading && <Loader2 className="w-8 h-8 text-rea-accent animate-spin mx-auto" />}
      {error && <div className="p-4 bg-red-950/40 border border-red-800 rounded-xl text-xs text-red-300">{(error as Error).message}</div>}

      {data && (
        <>
          <div className="grid md:grid-cols-2 gap-3 text-xs font-mono">
            {[
              { side: 'A (base)', j: data.a, color: 'text-red-300' },
              { side: 'B (compared)', j: data.b, color: 'text-emerald-300' },
            ].map(({ side, j, color }) => (
              <Link key={side} to={`/jobs/${j.id}`} className="p-3 rounded-xl border border-rea-border bg-rea-surface hover:border-rea-muted space-y-1 min-w-0">
                <div className={`font-bold ${color}`}>{side}</div>
                <div className="text-white truncate">{j.name}</div>
                <div className="text-rea-muted truncate">
                  {j.type} · {j.sha256 ? `${j.sha256.slice(0, 16)}…` : 'no hash'}
                </div>
              </Link>
            ))}
          </div>

          {data.identical && (
            <div className="flex items-center space-x-2 p-3 rounded-xl border border-sky-900 bg-sky-950/30 text-xs text-sky-300">
              <Equal className="w-4 h-4" />
              <span>Both jobs analyzed byte-identical files (same SHA-256); differences below come from the analysis itself.</span>
            </div>
          )}

          <p className="text-xs text-rea-muted">
            <span className="text-emerald-400">+</span> only in B, <span className="text-red-400">−</span> only in A.
          </p>

          <div className="space-y-2">
            {sections.map(([name, diff]) => (
              <DiffSection key={name} name={name} diff={diff} />
            ))}
          </div>

          {data.changedFunctions.length > 0 && (
            <div className="border border-rea-border rounded-lg bg-rea-surface p-4 space-y-2 text-xs font-mono">
              <div className="text-white font-semibold font-sans">Functions whose size changed ({data.changedFunctions.length})</div>
              <div className="max-h-72 overflow-y-auto space-y-0.5">
                {data.changedFunctions.map((f) => (
                  <div key={f.name} className="flex justify-between">
                    <span className="text-rea-text truncate mr-3">{f.name}</span>
                    <span className="text-rea-muted flex-shrink-0">
                      {f.sizeA} → {f.sizeB} bytes
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
};
