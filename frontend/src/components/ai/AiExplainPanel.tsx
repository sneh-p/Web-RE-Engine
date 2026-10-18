import React, { useEffect, useRef, useState } from 'react';
import { Sparkles, Loader2, Square, RotateCcw } from 'lucide-react';
import type { AiExplanation, ExplainScope } from '@shared/types.js';
import { streamExplanation } from '../../api/client';
import { renderSafeMarkdown } from '../../lib/markdown';
import { Link } from 'react-router-dom';

interface AiExplainPanelProps {
  jobId: string;
  scope: ExplainScope;
  // What is being explained, e.g. "this sample" or "fcn.140001000"
  label: string;
  existing?: AiExplanation;
  aiEnabled: boolean;
  onSaved: (key: string, explanation: AiExplanation) => void;
}

export const AiExplainPanel: React.FC<AiExplainPanelProps> = ({ jobId, scope, label, existing, aiEnabled, onSaved }) => {
  const [streamText, setStreamText] = useState('');
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  // A different function/file was selected: drop the in-progress stream for the old one
  const scopeKey = JSON.stringify(scope);
  useEffect(() => {
    abortRef.current?.abort();
    setStreamText('');
    setError(null);
    setRunning(false);
  }, [scopeKey]);

  const run = async () => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    setRunning(true);
    setError(null);
    setStreamText('');
    try {
      const { key, explanation } = await streamExplanation(jobId, scope, (t) => setStreamText((prev) => prev + t), controller.signal);
      onSaved(key, explanation);
      setStreamText('');
    } catch (err: any) {
      if (err.name !== 'AbortError') setError(err.message);
    } finally {
      setRunning(false);
    }
  };

  const shown = running || streamText ? streamText : existing?.text ?? '';

  return (
    <div className="border border-violet-900/60 rounded-xl bg-violet-950/10 overflow-hidden">
      <div className="px-4 py-2.5 border-b border-violet-900/50 flex items-center justify-between gap-3">
        <div className="flex items-center space-x-2 min-w-0">
          <Sparkles className="w-4 h-4 text-violet-400 flex-shrink-0" />
          <span className="font-bold text-white text-xs truncate">AI explanation · {label}</span>
        </div>
        <div className="flex items-center space-x-2 flex-shrink-0">
          {running ? (
            <button
              onClick={() => abortRef.current?.abort()}
              className="flex items-center space-x-1 text-xs px-2.5 py-1 rounded border border-rea-border text-rea-text hover:text-white"
            >
              <Square className="w-3 h-3" />
              <span>Stop</span>
            </button>
          ) : (
            <button
              onClick={run}
              disabled={!aiEnabled}
              title={aiEnabled ? undefined : 'Configure an AI provider in Settings to enable'}
              className="flex items-center space-x-1.5 text-xs px-2.5 py-1 rounded bg-violet-700 hover:bg-violet-600 text-white disabled:opacity-40 disabled:hover:bg-violet-700"
            >
              {existing ? <RotateCcw className="w-3 h-3" /> : <Sparkles className="w-3 h-3" />}
              <span>{existing ? 'Regenerate' : 'Explain with AI'}</span>
            </button>
          )}
        </div>
      </div>

      <div className="px-4 py-3 space-y-2">
        {!aiEnabled && !existing && (
          <p className="text-xs text-rea-muted">
            AI explanations are off. Choose a provider and add an API key in{' '}
            <Link to="/settings" className="text-violet-300 underline">
              Settings
            </Link>
            .
          </p>
        )}
        {aiEnabled && !shown && !running && !error && (
          <p className="text-xs text-rea-muted">
            Sends this job's analysis data (hashes, imports, strings, indicators, pseudo-code or file content) to the AI
            provider configured in Settings and explains what it does. Secrets found in the sample are masked before sending.
          </p>
        )}
        {running && !streamText && (
          <div className="flex items-center space-x-2 text-xs text-rea-muted">
            <Loader2 className="w-3.5 h-3.5 animate-spin" />
            <span>Analyzing…</span>
          </div>
        )}
        {error && <p className="text-xs text-red-400">{error}</p>}
        {shown && <div className="md-body" dangerouslySetInnerHTML={{ __html: renderSafeMarkdown(shown) }} />}
        {!running && existing && !streamText && (
          <p className="text-[10px] text-rea-muted pt-1">
            {existing.model} · {new Date(existing.createdAt).toLocaleString()}
            {existing.note ? ` · ${existing.note}` : ''}
          </p>
        )}
      </div>
    </div>
  );
};
