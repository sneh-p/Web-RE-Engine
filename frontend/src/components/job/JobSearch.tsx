import React, { useState } from 'react';
import { Search, Loader2, X } from 'lucide-react';
import { searchJob, type SearchHit } from '../../api/client';

interface JobSearchProps {
  jobId: string;
  onOpenFile: (path: string) => void;
  onOpenFunction: (address: string) => void;
}

const kindStyle: Record<SearchHit['kind'], string> = {
  function: 'text-sky-300 border-sky-900',
  string: 'text-amber-300 border-amber-900',
  import: 'text-violet-300 border-violet-900',
  ioc: 'text-rose-300 border-rose-900',
  yara: 'text-red-300 border-red-900',
  file: 'text-emerald-300 border-emerald-900',
};

export const JobSearch: React.FC<JobSearchProps> = ({ jobId, onOpenFile, onOpenFunction }) => {
  const [q, setQ] = useState('');
  const [result, setResult] = useState<{ hits: SearchHit[]; truncated: boolean } | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = async () => {
    if (q.trim().length < 2) return;
    setLoading(true);
    setError(null);
    try {
      setResult(await searchJob(jobId, q.trim()));
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const open = (hit: SearchHit) => {
    if (hit.kind === 'file' && hit.target) onOpenFile(hit.target);
    else if (hit.kind === 'function' && hit.target) onOpenFunction(hit.target);
  };

  return (
    <div className="border border-rea-border rounded-xl bg-rea-surface text-xs">
      <div className="flex items-center px-3 py-2 space-x-2">
        <Search className="w-4 h-4 text-rea-muted" />
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && run()}
          placeholder="Search functions, pseudo-code, strings, imports, IOCs, YARA hits and extracted files…"
          className="flex-1 bg-transparent focus:outline-none text-white placeholder:text-rea-muted font-mono"
        />
        {loading && <Loader2 className="w-3.5 h-3.5 animate-spin text-rea-muted" />}
        {result && (
          <button onClick={() => setResult(null)} className="text-rea-muted hover:text-white" title="Clear results">
            <X className="w-3.5 h-3.5" />
          </button>
        )}
      </div>
      {error && <p className="px-3 pb-2 text-red-400">{error}</p>}
      {result && (
        <div className="border-t border-rea-border max-h-80 overflow-y-auto divide-y divide-rea-border/40 font-mono">
          {result.hits.length === 0 && <p className="px-3 py-2 text-rea-muted">No matches.</p>}
          {result.hits.map((hit, i) => {
            const clickable = (hit.kind === 'file' || hit.kind === 'function') && !!hit.target;
            return (
              <button
                key={i}
                type="button"
                disabled={!clickable}
                onClick={() => open(hit)}
                className="w-full text-left px-3 py-1.5 flex items-start space-x-3 enabled:hover:bg-rea-bg/60 disabled:cursor-default"
              >
                <span className={`px-1.5 rounded border text-[10px] uppercase flex-shrink-0 ${kindStyle[hit.kind]}`}>{hit.kind}</span>
                <span className="min-w-0">
                  <span className="text-white block truncate">
                    {hit.title}
                    {hit.line ? `:${hit.line}` : ''}
                  </span>
                  <span className="text-rea-muted block truncate">{hit.snippet}</span>
                </span>
              </button>
            );
          })}
          {result.truncated && <p className="px-3 py-1.5 text-rea-muted">Showing the first {result.hits.length} matches.</p>}
        </div>
      )}
    </div>
  );
};
