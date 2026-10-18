import React, { useState } from 'react';
import { Puzzle, ShieldAlert, ChevronDown, ChevronRight, FileCode, Globe, Cog, AlertTriangle } from 'lucide-react';
import type { ExtensionResult, ExtensionPermission, RiskLevel } from '@shared/types.js';

interface ExtensionResultsViewProps {
  result: ExtensionResult;
  onOpenFile: (path: string) => void;
}

const riskStyle: Record<RiskLevel, string> = {
  critical: 'bg-red-950/70 border-red-700 text-red-300',
  high: 'bg-orange-950/60 border-orange-800 text-orange-300',
  medium: 'bg-amber-950/50 border-amber-800 text-amber-300',
  low: 'bg-rea-bg border-rea-border text-rea-muted',
};

const meterColor: Record<RiskLevel, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-amber-400',
  low: 'bg-emerald-500',
};

const Section: React.FC<{ title: string; icon: React.ReactNode; count?: number; defaultOpen?: boolean; children: React.ReactNode }> = ({
  title,
  icon,
  count,
  defaultOpen = true,
  children,
}) => {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="border border-rea-border rounded-xl bg-rea-surface overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="w-full px-4 py-2.5 flex items-center justify-between text-left hover:bg-rea-bg/40"
      >
        <span className="flex items-center space-x-2 text-white font-bold text-xs">
          {icon}
          <span>{title}</span>
          {count !== undefined && <span className="text-rea-muted font-normal">({count})</span>}
        </span>
        {open ? <ChevronDown className="w-4 h-4 text-rea-muted" /> : <ChevronRight className="w-4 h-4 text-rea-muted" />}
      </button>
      {open && <div className="border-t border-rea-border p-4 text-xs">{children}</div>}
    </div>
  );
};

const PermissionList: React.FC<{ items: ExtensionPermission[] }> = ({ items }) =>
  items.length === 0 ? (
    <p className="text-rea-muted">None declared.</p>
  ) : (
    <div className="space-y-1.5">
      {items.map((p) => (
        <div key={p.name} className="flex items-start space-x-3">
          <span className={`px-1.5 py-0.5 rounded border text-[10px] uppercase font-semibold w-16 text-center flex-shrink-0 ${riskStyle[p.risk]}`}>
            {p.risk}
          </span>
          <code className="text-white font-mono flex-shrink-0">{p.name}</code>
          {p.optional && <span className="text-[10px] text-rea-muted flex-shrink-0">optional</span>}
          <span className="text-rea-muted">{p.reason}</span>
        </div>
      ))}
    </div>
  );

export const ExtensionResultsView: React.FC<ExtensionResultsViewProps> = ({ result: r, onOpenFile }) => {
  const [openFinding, setOpenFinding] = useState<Record<string, boolean>>({});

  return (
    <div className="space-y-4">
      {/* Summary card */}
      <div className="border border-rea-border rounded-xl bg-rea-surface p-5 space-y-4">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-start space-x-3 min-w-0">
            <div className="p-2 rounded-lg bg-rea-bg border border-rea-border">
              <Puzzle className="w-5 h-5 text-rea-accent" />
            </div>
            <div className="min-w-0">
              <div className="text-white font-bold text-base truncate">
                {r.name} <span className="text-rea-muted font-mono text-sm">{r.version}</span>
              </div>
              <div className="text-xs text-rea-muted">
                {r.browser === 'unknown' ? 'Browser extension' : r.browser === 'chrome' ? 'Chrome / Edge extension' : 'Firefox add-on'} · Manifest V
                {r.manifestVersion} · {r.packageFormat.toUpperCase()}
                {r.extensionId ? ` · ${r.extensionId}` : ''}
              </div>
              {r.description && <p className="text-xs text-rea-text mt-1.5 line-clamp-2">{r.description}</p>}
            </div>
          </div>
          <div className="text-right flex-shrink-0">
            <span className={`inline-block px-2.5 py-1 rounded-lg border text-xs font-bold uppercase ${riskStyle[r.riskLevel]}`}>
              {r.riskLevel} risk
            </span>
            <div className="text-[11px] text-rea-muted mt-1">{r.riskScore}/100</div>
          </div>
        </div>
        <div className="h-1.5 bg-rea-bg rounded-full overflow-hidden">
          <div className={`h-full ${meterColor[r.riskLevel]}`} style={{ width: `${Math.max(2, r.riskScore)}%` }} />
        </div>
        {r.riskReasons.length > 0 && (
          <ul className="text-xs text-rea-text space-y-1 list-disc pl-5">
            {r.riskReasons.map((reason, i) => (
              <li key={i}>{reason}</li>
            ))}
          </ul>
        )}
        {r.offStoreUpdates && (
          <div className="flex items-center space-x-2 text-xs text-orange-300">
            <AlertTriangle className="w-4 h-4" />
            <span>
              Receives updates from <code>{r.updateUrl}</code>, outside the official store.
            </span>
          </div>
        )}
      </div>

      <Section title="Code findings" icon={<ShieldAlert className="w-4 h-4 text-red-400" />} count={r.findings.length}>
        {r.findings.length === 0 ? (
          <p className="text-rea-muted">No risky code patterns found in {r.filesScanned} files.</p>
        ) : (
          <div className="space-y-2">
            {r.findings.map((f) => (
              <div key={f.id} className="border border-rea-border rounded-lg bg-rea-bg/60">
                <button
                  type="button"
                  onClick={() => setOpenFinding((prev) => ({ ...prev, [f.id]: !prev[f.id] }))}
                  className="w-full px-3 py-2 flex items-center justify-between text-left"
                >
                  <span className="flex items-center space-x-2.5 min-w-0">
                    <span className={`px-1.5 py-0.5 rounded border text-[10px] uppercase font-semibold ${riskStyle[f.severity]}`}>{f.severity}</span>
                    <span className="text-white font-semibold truncate">{f.title}</span>
                  </span>
                  <span className="flex items-center space-x-2 text-rea-muted flex-shrink-0">
                    <span className="text-[10px]">{f.locations.length} location{f.locations.length === 1 ? '' : 's'}</span>
                    {openFinding[f.id] ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                  </span>
                </button>
                {openFinding[f.id] && (
                  <div className="px-3 pb-3 space-y-2">
                    <p className="text-rea-text">{f.description}</p>
                    {f.locations.map((loc, i) => (
                      <button
                        key={i}
                        type="button"
                        onClick={() => onOpenFile(loc.file)}
                        className="w-full text-left font-mono text-[11px] flex space-x-3 hover:bg-rea-surface rounded px-1.5 py-1"
                        title="Open in the Code & Artifact Explorer"
                      >
                        <span className="text-rea-accent flex-shrink-0">
                          {loc.file}:{loc.line}
                        </span>
                        <span className="text-rea-muted truncate">{loc.snippet}</span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </Section>

      <Section title="Permissions" icon={<ShieldAlert className="w-4 h-4 text-amber-400" />} count={r.permissions.length}>
        <PermissionList items={r.permissions} />
      </Section>

      <Section title="Site access" icon={<Globe className="w-4 h-4 text-sky-400" />} count={r.hostPermissions.length}>
        <PermissionList items={r.hostPermissions} />
      </Section>

      <Section title="Content scripts" icon={<FileCode className="w-4 h-4 text-violet-400" />} count={r.contentScripts.length} defaultOpen={r.contentScripts.length > 0}>
        {r.contentScripts.length === 0 ? (
          <p className="text-rea-muted">No content scripts: the extension does not inject code into pages through the manifest.</p>
        ) : (
          <div className="space-y-3">
            {r.contentScripts.map((cs, i) => (
              <div key={i} className="space-y-1">
                <div className="flex flex-wrap gap-1.5">
                  {cs.js.map((f) => (
                    <button key={f} type="button" onClick={() => onOpenFile(f)} className="font-mono text-rea-accent hover:underline">
                      {f}
                    </button>
                  ))}
                  {cs.css.map((f) => (
                    <span key={f} className="font-mono text-rea-muted">
                      {f}
                    </span>
                  ))}
                </div>
                <div className="text-rea-muted">
                  runs on <span className="text-white font-mono">{cs.matches.join(', ')}</span>
                  {cs.allFrames ? ' · all frames' : ''}
                  {cs.runAt ? ` · ${cs.runAt}` : ''}
                  {cs.world ? ` · ${cs.world} world` : ''}
                </div>
              </div>
            ))}
          </div>
        )}
      </Section>

      <Section title="Background, messaging and policy" icon={<Cog className="w-4 h-4 text-rea-muted" />} defaultOpen={false}>
        <dl className="grid grid-cols-[10rem_1fr] gap-x-4 gap-y-1.5">
          <dt className="text-rea-muted">Background</dt>
          <dd className="font-mono text-white">
            {r.background.kind}
            {r.background.files.length ? `: ${r.background.files.join(', ')}` : ''}
          </dd>
          <dt className="text-rea-muted">Externally connectable</dt>
          <dd className="font-mono text-white break-all">
            {r.externallyConnectable
              ? [...r.externallyConnectable.matches, ...r.externallyConnectable.ids.map((id) => `extension ${id}`)].join(', ') || '(empty)'
              : 'not declared'}
          </dd>
          <dt className="text-rea-muted">Web-accessible files</dt>
          <dd className="font-mono text-white break-all">{r.webAccessibleResources.join(', ') || 'none'}</dd>
          <dt className="text-rea-muted">Extension CSP</dt>
          <dd className="font-mono text-white break-all">{r.csp ?? 'browser default'}</dd>
          <dt className="text-rea-muted">Update URL</dt>
          <dd className="font-mono text-white break-all">{r.updateUrl ?? 'store default'}</dd>
          <dt className="text-rea-muted">Overrides</dt>
          <dd className="font-mono text-white">{r.overrides.join(', ') || 'none'}</dd>
        </dl>
        {r.obfuscatedFiles.length > 0 && (
          <div className="mt-3 space-y-1">
            <div className="text-orange-300 font-semibold">Obfuscated files</div>
            {r.obfuscatedFiles.map((o) => (
              <div key={o.file} className="font-mono">
                <button type="button" onClick={() => onOpenFile(o.file)} className="text-rea-accent hover:underline">
                  {o.file}
                </button>{' '}
                <span className="text-rea-muted">— {o.reason}</span>
              </div>
            ))}
          </div>
        )}
      </Section>

      <Section title="Extension APIs used" icon={<Puzzle className="w-4 h-4 text-rea-muted" />} count={r.apiUsage.length} defaultOpen={false}>
        {r.apiUsage.length === 0 ? (
          <p className="text-rea-muted">No chrome.* / browser.* API calls found.</p>
        ) : (
          <div className="font-mono space-y-0.5 max-h-80 overflow-y-auto">
            {r.apiUsage.map((a) => (
              <div key={a.api} className="flex justify-between gap-4">
                <span className="text-white">{a.api}</span>
                <span className="text-rea-muted truncate">
                  ×{a.count} in {a.files.join(', ')}
                </span>
              </div>
            ))}
          </div>
        )}
      </Section>
    </div>
  );
};
