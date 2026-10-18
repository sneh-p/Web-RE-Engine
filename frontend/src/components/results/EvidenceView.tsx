import React from 'react';
import { CheckCircle2, AlertTriangle, FileCode, Search, ShieldCheck } from 'lucide-react';
import type { Evidence } from '@shared/types.js';

interface EvidenceViewProps {
  evidence: Evidence[];
}

export const EvidenceView: React.FC<EvidenceViewProps> = ({ evidence }) => {
  if (!evidence || evidence.length === 0) {
    return (
      <div className="p-6 bg-rea-surface border border-rea-border rounded-xl text-center text-rea-muted">
        No evidence records generated for this job.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-md font-semibold text-white flex items-center space-x-2">
          <ShieldCheck className="w-5 h-5 text-rea-accent" />
          <span>Evidence Ledger ({evidence.length})</span>
        </h3>
        <span className="text-xs text-rea-muted">
          Web RE Engine verifies features by generating traceable evidence records
        </span>
      </div>

      <div className="grid gap-3">
        {evidence.map((ev, i) => (
          <div
            key={i}
            className="p-4 rounded-xl border border-rea-border bg-rea-surface flex flex-col space-y-2 hover:border-rea-muted transition"
          >
            <div className="flex items-start justify-between">
              <div className="flex items-center space-x-2">
                <span
                  className={`text-xs px-2 py-0.5 rounded font-mono uppercase font-semibold ${
                    ev.kind === 'code'
                      ? 'bg-blue-950/60 text-blue-400 border border-blue-800'
                      : ev.kind === 'pattern'
                      ? 'bg-purple-950/60 text-purple-400 border border-purple-800'
                      : ev.kind === 'network'
                      ? 'bg-cyan-950/60 text-cyan-400 border border-cyan-800'
                      : 'bg-emerald-950/60 text-emerald-400 border border-emerald-800'
                  }`}
                >
                  {ev.kind}
                </span>

                <span
                  className={`text-xs px-1.5 py-0.5 rounded font-mono ${
                    ev.confidence === 'high'
                      ? 'text-emerald-400 bg-emerald-950/30'
                      : ev.confidence === 'medium'
                      ? 'text-amber-400 bg-amber-950/30'
                      : 'text-rea-muted bg-rea-border/50'
                  }`}
                >
                  {ev.confidence} confidence
                </span>
              </div>

              {ev.location?.file && (
                <span className="text-xs text-rea-muted font-mono">
                  {ev.location.file}:{ev.location.line ?? 1}
                </span>
              )}
            </div>

            <p className="text-sm text-rea-text">{ev.description}</p>

            {ev.snippet && (
              <pre className="text-xs font-mono bg-rea-bg p-2.5 rounded border border-rea-border text-rea-text overflow-x-auto">
                {ev.snippet}
              </pre>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};
