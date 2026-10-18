import React, { useMemo, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link, useNavigate } from 'react-router-dom';
import { CheckCircle2, Clock, XCircle, Loader2, ArrowRight, Trash2, RotateCcw, GitCompare, Tag } from 'lucide-react';
import type { AnalysisJob } from '@shared/types.js';
import { fetchJobs, deleteJob, rerunJob } from '../api/client';

export const jobDisplayName = (job: AnalysisJob) =>
  'fileName' in job.input ? job.input.fileName : 'url' in job.input ? job.input.url : job.input.type === 'evm' ? job.input.value : '';

export const JobList: React.FC = () => {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [tagFilter, setTagFilter] = useState<string | null>(null);
  const [compareIds, setCompareIds] = useState<string[]>([]);
  const { data: jobs, isLoading, error } = useQuery({
    queryKey: ['jobs'],
    queryFn: fetchJobs,
    refetchInterval: 5000,
  });

  const deleteMutation = useMutation({
    mutationFn: deleteJob,
    onSuccess: (_data, id) => {
      setCompareIds((prev) => prev.filter((x) => x !== id));
      queryClient.invalidateQueries({ queryKey: ['jobs'] });
    },
  });

  const rerunMutation = useMutation({
    mutationFn: rerunJob,
    onSuccess: (newJob) => {
      queryClient.invalidateQueries({ queryKey: ['jobs'] });
      navigate(`/jobs/${newJob.id}`);
    },
  });

  const allTags = useMemo(() => [...new Set((jobs ?? []).flatMap((j) => j.tags ?? []))].sort(), [jobs]);
  const visible = (jobs ?? []).filter((j) => !tagFilter || j.tags?.includes(tagFilter));

  const toggleCompare = (id: string) =>
    setCompareIds((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id].slice(-2)));

  return (
    <div className="max-w-5xl mx-auto py-10 px-6 space-y-6">
      <div className="flex items-center justify-between border-b border-rea-border pb-4">
        <div>
          <h1 className="text-2xl font-extrabold text-white">Analysis History</h1>
          <p className="text-xs text-rea-muted mt-1">All submitted jobs, findings, and evidence ledgers.</p>
        </div>
        <div className="flex items-center space-x-2">
          <button
            type="button"
            disabled={compareIds.length !== 2}
            onClick={() => navigate(`/compare?a=${compareIds[0]}&b=${compareIds[1]}`)}
            className="flex items-center space-x-1.5 px-4 py-2 rounded-xl text-xs font-semibold border border-rea-border bg-rea-surface text-white hover:bg-rea-border transition disabled:opacity-40 disabled:hover:bg-rea-surface"
            title="Tick two completed jobs to compare them"
          >
            <GitCompare className="w-3.5 h-3.5" />
            <span>Compare ({compareIds.length}/2)</span>
          </button>
          <Link
            to="/"
            className="bg-rea-accent hover:bg-rea-accentHover text-white px-4 py-2 rounded-xl text-xs font-semibold transition"
          >
            New Analysis
          </Link>
        </div>
      </div>

      {allTags.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <Tag className="w-3.5 h-3.5 text-rea-muted" />
          {[null, ...allTags].map((t) => (
            <button
              key={t ?? '__all'}
              type="button"
              onClick={() => setTagFilter(t)}
              className={`px-2.5 py-0.5 rounded-full border transition ${
                tagFilter === t ? 'border-rea-accent text-white bg-rea-accent/20' : 'border-rea-border text-rea-muted hover:text-white'
              }`}
            >
              {t ?? 'All'}
            </button>
          ))}
        </div>
      )}

      {isLoading && (
        <div className="flex justify-center py-16">
          <Loader2 className="w-8 h-8 text-rea-accent animate-spin" />
        </div>
      )}

      {error && (
        <div className="p-4 bg-red-950/40 border border-red-800 rounded-xl text-xs text-red-300">
          Failed to load job history: {(error as any).message}
        </div>
      )}

      {jobs && jobs.length === 0 && (
        <div className="p-12 text-center bg-rea-surface border border-rea-border rounded-xl space-y-3">
          <p className="text-sm text-rea-muted">No analysis jobs executed yet.</p>
          <Link to="/" className="inline-block text-xs text-rea-accent hover:underline font-semibold">
            Start your first reverse engineering run &rarr;
          </Link>
        </div>
      )}

      {visible.length > 0 && (
        <div className="space-y-3">
          {visible.map((job) => (
            <Link
              key={job.id}
              to={`/jobs/${job.id}`}
              className="p-4 rounded-xl border border-rea-border bg-rea-surface hover:border-rea-muted transition flex items-center justify-between"
            >
              <div className="flex items-center space-x-4 min-w-0">
                <input
                  type="checkbox"
                  checked={compareIds.includes(job.id)}
                  disabled={job.status !== 'completed'}
                  onClick={(e) => e.stopPropagation()}
                  onChange={() => toggleCompare(job.id)}
                  title={job.status === 'completed' ? 'Select for comparison' : 'Only completed jobs can be compared'}
                  className="accent-rea-accent w-4 h-4 flex-shrink-0 disabled:opacity-30"
                />
                {job.status === 'completed' && <CheckCircle2 className="w-5 h-5 text-emerald-400 flex-shrink-0" />}
                {job.status === 'running' && <Loader2 className="w-5 h-5 text-blue-400 animate-spin flex-shrink-0" />}
                {job.status === 'queued' && <Clock className="w-5 h-5 text-amber-400 flex-shrink-0" />}
                {job.status === 'failed' && <XCircle className="w-5 h-5 text-red-400 flex-shrink-0" />}

                <div className="min-w-0">
                  <div className="flex items-center space-x-2 min-w-0">
                    <span className="font-mono text-sm text-white font-bold truncate">{jobDisplayName(job) || `#${job.id.slice(0, 8)}`}</span>
                    <span className="text-[10px] font-mono uppercase bg-rea-bg px-2 py-0.5 rounded border border-rea-border text-rea-muted flex-shrink-0">
                      {job.type}
                    </span>
                    {job.tags?.map((t) => (
                      <span key={t} className="text-[10px] px-2 py-0.5 rounded-full border border-rea-border text-rea-text flex-shrink-0">
                        {t}
                      </span>
                    ))}
                  </div>
                  <span className="text-xs text-rea-muted">
                    #{job.id.slice(0, 8)} · {new Date(job.createdAt).toLocaleString()}
                  </span>
                </div>
              </div>

              <div className="flex items-center space-x-3 text-xs text-rea-muted flex-shrink-0">
                <span className="capitalize">{job.status}</span>
                <button
                  type="button"
                  title="Re-run job"
                  aria-label="Re-run job"
                  onClick={(e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    rerunMutation.mutate(job.id);
                  }}
                  disabled={rerunMutation.isPending}
                  className="p-1.5 text-rea-muted hover:text-white hover:bg-rea-bg rounded-lg transition"
                >
                  <RotateCcw
                    className={`w-4 h-4 ${rerunMutation.isPending && rerunMutation.variables === job.id ? 'animate-spin text-rea-accent' : ''}`}
                  />
                </button>
                <button
                  type="button"
                  title="Delete job"
                  aria-label="Delete job"
                  onClick={(e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    // Rows shift up after a delete, so an unconfirmed click could hit the next job
                    const name = jobDisplayName(job) || job.id.slice(0, 8);
                    if (window.confirm(`Delete job "${name}" and its uploaded/extracted files? This cannot be undone.`)) {
                      deleteMutation.mutate(job.id);
                    }
                  }}
                  disabled={deleteMutation.isPending}
                  className="p-1.5 text-rea-muted hover:text-red-400 hover:bg-rea-bg rounded-lg transition"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
                <ArrowRight className="w-4 h-4 text-rea-muted" />
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
};
