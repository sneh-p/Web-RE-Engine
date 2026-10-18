import React, { useEffect, useState } from 'react';
import { Tag, X, StickyNote, Check, Loader2 } from 'lucide-react';
import type { AnalysisJob } from '@shared/types.js';
import { updateJobMeta } from '../../api/client';

interface JobMetaEditorProps {
  job: AnalysisJob;
  onUpdated: (job: AnalysisJob) => void;
}

export const JobMetaEditor: React.FC<JobMetaEditorProps> = ({ job, onUpdated }) => {
  const [tagInput, setTagInput] = useState('');
  const [notes, setNotes] = useState(job.notes ?? '');
  const [saving, setSaving] = useState<'tags' | 'notes' | null>(null);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const tags = job.tags ?? [];

  useEffect(() => setNotes(job.notes ?? ''), [job.id]);

  const save = async (kind: 'tags' | 'notes', patch: { tags?: string[]; notes?: string }) => {
    setSaving(kind);
    setError(null);
    try {
      onUpdated(await updateJobMeta(job.id, patch));
      if (kind === 'notes') {
        setSaved(true);
        setTimeout(() => setSaved(false), 1500);
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setSaving(null);
    }
  };

  const addTag = () => {
    const t = tagInput.trim();
    if (!t || tags.includes(t)) return setTagInput('');
    setTagInput('');
    save('tags', { tags: [...tags, t] });
  };

  return (
    <div className="border border-rea-border rounded-xl bg-rea-surface px-4 py-3 space-y-3 text-xs">
      <div className="flex flex-wrap items-center gap-2">
        <Tag className="w-3.5 h-3.5 text-rea-muted" />
        {tags.map((t) => (
          <span key={t} className="flex items-center space-x-1 px-2 py-0.5 rounded-full bg-rea-bg border border-rea-border text-rea-text">
            <span>{t}</span>
            <button
              onClick={() => save('tags', { tags: tags.filter((x) => x !== t) })}
              className="text-rea-muted hover:text-white"
              title={`Remove tag ${t}`}
            >
              <X className="w-3 h-3" />
            </button>
          </span>
        ))}
        <input
          value={tagInput}
          onChange={(e) => setTagInput(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && addTag()}
          maxLength={40}
          placeholder={tags.length ? 'Add tag' : 'Add a tag, e.g. malware, triaged'}
          className="bg-transparent border-b border-rea-border focus:border-rea-accent focus:outline-none px-1 py-0.5 text-white placeholder:text-rea-muted w-44"
        />
        {saving === 'tags' && <Loader2 className="w-3.5 h-3.5 animate-spin text-rea-muted" />}
      </div>

      <div className="space-y-1.5">
        <div className="flex items-center justify-between">
          <span className="flex items-center space-x-1.5 text-rea-muted">
            <StickyNote className="w-3.5 h-3.5" />
            <span>Analyst notes (Markdown, included in reports)</span>
          </span>
          <button
            onClick={() => save('notes', { notes })}
            disabled={notes === (job.notes ?? '') || saving === 'notes'}
            className="flex items-center space-x-1 px-2.5 py-1 rounded bg-rea-accent hover:bg-rea-accentHover text-white disabled:opacity-40 disabled:hover:bg-rea-accent"
          >
            {saving === 'notes' ? <Loader2 className="w-3 h-3 animate-spin" /> : saved ? <Check className="w-3 h-3" /> : null}
            <span>{saved ? 'Saved' : 'Save notes'}</span>
          </button>
        </div>
        <textarea
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          maxLength={20000}
          rows={notes ? 5 : 2}
          placeholder="What did you find? Hypotheses, next steps…"
          className="w-full bg-rea-bg border border-rea-border rounded-lg px-3 py-2 font-mono text-rea-text placeholder:text-rea-muted focus:outline-none focus:border-rea-accent resize-y"
        />
      </div>
      {error && <p className="text-red-400">{error}</p>}
    </div>
  );
};
