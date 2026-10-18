import React, { useState } from 'react';
import { ScanSearch, Crosshair, ChevronDown, ChevronRight } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import type { YaraResult, CapaResult, YaraMatch } from '@shared/types.js';
import { fetchStatus } from '../../api/client';

interface SignatureFindingsProps {
  yara?: YaraResult;
  capabilities?: CapaResult;
}

const SEVERITY_ORDER = ['high', 'medium', 'low'] as const;

const severityStyle: Record<string, string> = {
  high: 'bg-red-950/60 border-red-800 text-red-400',
  medium: 'bg-amber-950/60 border-amber-800 text-amber-400',
  low: 'bg-sky-950/60 border-sky-800 text-sky-400',
};

interface RuleGroup {
  rule: string;
  severity: string;
  description?: string;
  category?: string;
  matches: YaraMatch[];
}

// One rule often fires on many unpacked files; show it once with the file list underneath
function groupByRule(matches: YaraMatch[]): RuleGroup[] {
  const groups = new Map<string, RuleGroup>();
  for (const m of matches) {
    const severity = (m.meta.severity || 'low').toLowerCase();
    const g = groups.get(m.rule) ?? {
      rule: m.rule,
      severity: SEVERITY_ORDER.includes(severity as any) ? severity : 'low',
      description: m.meta.description,
      category: m.meta.category,
      matches: [],
    };
    g.matches.push(m);
    groups.set(m.rule, g);
  }
  return [...groups.values()].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity as any) - SEVERITY_ORDER.indexOf(b.severity as any) || a.rule.localeCompare(b.rule)
  );
}

export const SignatureFindings: React.FC<SignatureFindingsProps> = ({ yara, capabilities }) => {
  const [openRules, setOpenRules] = useState<Record<string, boolean>>({});
  // Same query key as the navbar, so this reuses the cached engine status
  const { data: engineStatus } = useQuery({ queryKey: ['engineStatus'], queryFn: fetchStatus, refetchInterval: 30000 });
  const groups = yara ? groupByRule(yara.matches) : [];

  if (!yara && !capabilities) return null;

  return (
    <>
      {yara && (
        <div className="space-y-3">
          <div className="text-[11px] font-bold text-white flex items-center space-x-2">
            <ScanSearch className="w-3.5 h-3.5 text-rea-accent" />
            <span>YARA Signature Matches</span>
            <span className="text-[10px] text-rea-muted font-normal">({yara.rulesLoaded} rule files)</span>
          </div>

          {groups.length === 0 ? (
            <div className="text-rea-muted bg-rea-bg/60 border border-rea-border rounded-lg px-3.5 py-2.5">
              No rules matched.
            </div>
          ) : (
            <div className="space-y-2">
              {groups.map((g) => {
                const isOpen = !!openRules[g.rule];
                return (
                  <div key={g.rule} className="border border-rea-border rounded-lg bg-rea-bg/60 overflow-hidden">
                    <button
                      type="button"
                      onClick={() => setOpenRules((prev) => ({ ...prev, [g.rule]: !prev[g.rule] }))}
                      className="w-full px-3.5 py-2.5 flex items-center justify-between bg-rea-surface/50 hover:bg-rea-surface transition text-left"
                    >
                      <div className="flex items-center space-x-2.5 min-w-0">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] border font-semibold uppercase ${severityStyle[g.severity]}`}>
                          {g.severity}
                        </span>
                        <span className="font-bold text-white text-xs truncate">{g.rule}</span>
                        {g.description && <span className="text-rea-muted truncate hidden md:inline">{g.description}</span>}
                      </div>
                      <div className="flex items-center space-x-2 text-rea-muted flex-shrink-0">
                        <span className="text-[10px]">
                          {g.matches.length} file{g.matches.length === 1 ? '' : 's'}
                        </span>
                        {isOpen ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                      </div>
                    </button>

                    {isOpen && (
                      <div className="p-3 space-y-3 max-h-80 overflow-y-auto">
                        {g.description && <div className="text-rea-text md:hidden">{g.description}</div>}
                        {g.matches.map((m, i) => (
                          <div key={`${m.file}-${i}`} className="space-y-1">
                            <div className="text-white truncate">{m.file}</div>
                            {m.strings.map((s, j) => (
                              <div key={j} className="flex space-x-3 text-[11px] pl-3">
                                <span className="text-rea-muted w-20 flex-shrink-0">0x{s.offset.toString(16)}</span>
                                <span className="text-rea-accent w-20 flex-shrink-0 truncate">{s.identifier}</span>
                                <span className="text-rea-text truncate">{s.data}</span>
                              </div>
                            ))}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          {yara.errors.length > 0 && (
            <ul className="text-[11px] text-amber-400 space-y-0.5">
              {yara.errors.map((e, i) => (
                <li key={i}>{e}</li>
              ))}
            </ul>
          )}
        </div>
      )}

      {capabilities && (
        <div className="space-y-3">
          <div className="text-[11px] font-bold text-white flex items-center space-x-2">
            <Crosshair className="w-3.5 h-3.5 text-rea-accent" />
            <span>Capabilities (capa)</span>
            {capabilities.target && <span className="text-[10px] text-rea-muted font-normal font-mono truncate">analyzed: {capabilities.target}</span>}
          </div>

          {capabilities.skipped ? (
            <div className="text-rea-muted bg-rea-bg/60 border border-rea-border rounded-lg px-3.5 py-2.5">capa skipped: {capabilities.skipped}</div>
          ) : capabilities.pending ? (
            <div className="flex items-center space-x-2 text-rea-muted bg-rea-bg/60 border border-rea-border rounded-lg px-3.5 py-2.5">
              <span className="w-2 h-2 rounded-full bg-sky-400 animate-pulse" />
              <span>capa is running in the background (large binaries can take several minutes); results will appear here.</span>
            </div>
          ) : !capabilities.available ? (
            <div className="text-rea-muted bg-rea-bg/60 border border-rea-border rounded-lg px-3.5 py-2.5">
              {engineStatus?.capa
                ? 'capa was not installed yet when this job ran. Re-run the job to detect capabilities.'
                : 'capa is not installed on the server, so capability detection was skipped.'}
            </div>
          ) : capabilities.error ? (
            <div className="text-amber-400 bg-rea-bg/60 border border-rea-border rounded-lg px-3.5 py-2.5">{capabilities.error}</div>
          ) : capabilities.capabilities.length === 0 ? (
            <div className="text-rea-muted bg-rea-bg/60 border border-rea-border rounded-lg px-3.5 py-2.5">
              No capabilities identified.
            </div>
          ) : (
            <div className="border border-rea-border rounded-lg bg-rea-bg/60 divide-y divide-rea-border/40 max-h-96 overflow-y-auto">
              {capabilities.capabilities.map((c, i) => (
                <div key={i} className="px-3.5 py-2 space-y-1">
                  <div className="flex items-center justify-between space-x-3">
                    <span className="text-white">{c.name}</span>
                    {c.namespace && <span className="text-[10px] text-rea-muted truncate">{c.namespace}</span>}
                  </div>
                  {(c.attack.length > 0 || c.mbc.length > 0) && (
                    <div className="flex flex-wrap gap-1.5">
                      {c.attack.map((a) => (
                        <span key={a} className="px-1.5 py-0.5 rounded text-[10px] border border-red-900 bg-red-950/40 text-red-300">
                          ATT&CK {a}
                        </span>
                      ))}
                      {c.mbc.map((m) => (
                        <span key={m} className="px-1.5 py-0.5 rounded text-[10px] border border-rea-border bg-rea-surface text-rea-muted">
                          MBC {m}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </>
  );
};
