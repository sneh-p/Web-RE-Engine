import React, { useEffect, useState, useRef } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  Loader2,
  CheckCircle2,
  XCircle,
  Clock,
  Terminal,
  ShieldCheck,
  ChevronLeft,
  FileCode,
  AlertCircle,
  RotateCcw,
  Download,
} from 'lucide-react';
import { fetchJob, fetchStatus, rerunJob, reportUrl } from '../api/client';
import { useWebSocket } from '../hooks/useWebSocket';
import { EvidenceView } from '../components/results/EvidenceView';
import { JavaScriptResultsView } from '../components/results/JavaScriptResultsView';
import { GhidraDisassemblyStudio } from '../components/results/GhidraDisassemblyStudio';
import { BrowserResultsView } from '../components/results/BrowserResultsView';
import { AndroidResultsView } from '../components/results/AndroidResultsView';
import { EvmResultsView } from '../components/results/EvmResultsView';
import { DotNetResultsView } from '../components/results/DotNetResultsView';
import { ExtensionResultsView } from '../components/results/ExtensionResultsView';
import { LimitationsView } from '../components/results/LimitationsView';
import { OverviewPanel } from '../components/results/OverviewPanel';
import { CodeExplorer } from '../components/shared/CodeExplorer';
import { JobMetaEditor } from '../components/job/JobMetaEditor';
import { JobSearch } from '../components/job/JobSearch';
import { AiExplainPanel } from '../components/ai/AiExplainPanel';
import type { AiExplanation, AnalysisJob } from '@shared/types.js';

export const JobDetails: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [job, setJob] = useState<AnalysisJob | null>(null);
  const [activeTab, setActiveTab] = useState<'findings' | 'explorer'>('findings');
  const [activeFilePath, setActiveFilePath] = useState<string | undefined>(undefined);
  const [isRerunning, setIsRerunning] = useState(false);
  const [focusAddress, setFocusAddress] = useState<string | undefined>(undefined);

  // Same query key as App, so this reuses the cached engine status
  const { data: engineStatus } = useQuery({ queryKey: ['engineStatus'], queryFn: fetchStatus, refetchInterval: 30000 });
  const aiEnabled = !!engineStatus?.ai;

  const saveExplanation = (key: string, explanation: AiExplanation) =>
    setJob((prev) => (prev ? { ...prev, explanations: { ...(prev.explanations ?? {}), [key]: explanation } } : prev));
  const logsEndRef = useRef<HTMLDivElement>(null);

  const handleRerun = async () => {
    if (!job) return;
    setIsRerunning(true);
    try {
      const newJob = await rerunJob(job.id);
      navigate(`/jobs/${newJob.id}`);
    } catch (err: any) {
      console.error('Failed to rerun job:', err);
    } finally {
      setIsRerunning(false);
    }
  };

  const { data: initialJob, isLoading } = useQuery({
    queryKey: ['job', id],
    queryFn: () => fetchJob(id!),
    enabled: !!id,
  });

  useEffect(() => {
    if (initialJob) setJob(initialJob);
  }, [initialJob]);

  // Connect WebSocket for live updates
  const { lastMessage } = useWebSocket(id);

  useEffect(() => {
    if (!lastMessage || !job) return;

    if (lastMessage.event === 'job:progress') {
      setJob((prev) =>
        prev
          ? {
              ...prev,
              progress: lastMessage.progress,
              logs: [...(prev.logs || []), `[Update] ${lastMessage.log}`],
            }
          : prev
      );
    } else if (lastMessage.event === 'job:completed') {
      setJob((prev) =>
        prev
          ? {
              ...prev,
              status: 'completed',
              progress: 100,
              result: lastMessage.result,
              fingerprint: lastMessage.fingerprint ?? prev.fingerprint,
              iocs: lastMessage.iocs ?? prev.iocs,
              yara: lastMessage.yara ?? prev.yara,
              capabilities: lastMessage.capabilities ?? prev.capabilities,
            }
          : prev
      );
    } else if (lastMessage.event === 'job:updated') {
      // Late results, e.g. capa finishing minutes after the job completed
      setJob((prev) => (prev ? { ...prev, ...lastMessage.patch } : prev));
    } else if (lastMessage.event === 'job:failed') {
      setJob((prev) =>
        prev
          ? {
              ...prev,
              status: 'failed',
              error: lastMessage.error,
            }
          : prev
      );
    }
  }, [lastMessage]);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [job?.logs]);

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-3">
        <Loader2 className="w-8 h-8 text-rea-accent animate-spin" />
        <span className="text-sm text-rea-muted">Loading job information...</span>
      </div>
    );
  }

  if (!job) {
    return (
      <div className="max-w-2xl mx-auto py-16 text-center space-y-4">
        <AlertCircle className="w-12 h-12 text-red-400 mx-auto" />
        <h2 className="text-xl font-bold text-white">Job not found</h2>
        <p className="text-sm text-rea-muted">The requested analysis job does not exist.</p>
        <Link
          to="/"
          className="inline-flex items-center space-x-2 text-rea-accent hover:underline text-sm font-semibold"
        >
          <ChevronLeft className="w-4 h-4" />
          <span>Return home</span>
        </Link>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto py-8 px-6 space-y-8">
      {/* Back button & Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-rea-border pb-6">
        <div className="space-y-1">
          <Link
            to="/jobs"
            className="inline-flex items-center space-x-1 text-xs text-rea-muted hover:text-white mb-2 transition"
          >
            <ChevronLeft className="w-3.5 h-3.5" />
            <span>All Jobs</span>
          </Link>
          <div className="flex items-center space-x-3">
            <h1 className="text-2xl font-extrabold text-white font-mono tracking-tight">
              Job #{job.id.slice(0, 8)}
            </h1>
            <span className="text-xs px-2 py-0.5 rounded font-mono uppercase bg-rea-surface border border-rea-border text-rea-muted">
              {job.type}
            </span>
          </div>
          <span className="text-xs text-rea-muted block">
            Created on {new Date(job.createdAt).toLocaleString()}
          </span>
        </div>

        {/* Status Badge & Actions */}
        <div className="flex items-center space-x-3">
          <button
            type="button"
            onClick={handleRerun}
            disabled={isRerunning}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-rea-surface hover:bg-rea-border border border-rea-border text-white text-xs font-semibold transition"
            title="Re-run analysis job"
          >
            <RotateCcw className={`w-3.5 h-3.5 ${isRerunning ? 'animate-spin text-rea-accent' : ''}`} />
            <span>Re-run</span>
          </button>

          {job.result &&
            (['md', 'pdf'] as const).map((fmt) => (
              <a
                key={fmt}
                href={reportUrl(job.id, fmt)}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-rea-surface hover:bg-rea-border border border-rea-border text-white text-xs font-semibold transition"
                title={`Download report as ${fmt === 'md' ? 'Markdown' : 'PDF'}`}
              >
                <Download className="w-3.5 h-3.5" />
                <span>{fmt === 'md' ? 'Markdown' : 'PDF'}</span>
              </a>
            ))}

          {job.status === 'running' && (
            <div className="flex items-center space-x-2 px-3 py-1.5 rounded-full bg-blue-950/60 border border-blue-800 text-blue-400 text-xs font-semibold">
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
              <span>Analyzing ({job.progress ?? 0}%)</span>
            </div>
          )}
          {job.status === 'queued' && (
            <div className="flex items-center space-x-2 px-3 py-1.5 rounded-full bg-amber-950/60 border border-amber-800 text-amber-400 text-xs font-semibold">
              <Clock className="w-3.5 h-3.5" />
              <span>Queued</span>
            </div>
          )}
          {job.status === 'completed' && (
            <div className="flex items-center space-x-2 px-3 py-1.5 rounded-full bg-emerald-950/60 border border-emerald-800 text-emerald-400 text-xs font-semibold">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>Analysis Completed</span>
            </div>
          )}
          {job.status === 'failed' && (
            <div className="flex items-center space-x-2 px-3 py-1.5 rounded-full bg-red-950/60 border border-red-800 text-red-400 text-xs font-semibold">
              <XCircle className="w-3.5 h-3.5" />
              <span>Analysis Failed</span>
            </div>
          )}
        </div>
      </div>

      {/* Progress bar for running jobs */}
      {job.status === 'running' && (
        <div className="w-full bg-rea-surface rounded-full h-1.5 overflow-hidden border border-rea-border">
          <div
            className="bg-rea-accent h-1.5 transition-all duration-300"
            style={{ width: `${job.progress ?? 10}%` }}
          />
        </div>
      )}

      {/* Live Logs / Terminal */}
      <div className="bg-rea-bg border border-rea-border rounded-xl overflow-hidden font-mono text-xs">
        <div className="bg-rea-surface px-4 py-2 border-b border-rea-border flex items-center justify-between text-rea-muted">
          <div className="flex items-center space-x-2">
            <Terminal className="w-3.5 h-3.5" />
            <span className="font-semibold text-white">Execution Trace & Agent Log</span>
          </div>
          <span>{job.logs?.length ?? 0} lines</span>
        </div>
        <div className="p-4 max-h-[160px] overflow-y-auto space-y-1 text-rea-text">
          {job.logs?.map((l, i) => (
            <div key={i} className="text-rea-muted">
              {l}
            </div>
          ))}
          {job.error && <div className="text-red-400 font-bold">{job.error}</div>}
          <div ref={logsEndRef} />
        </div>
      </div>

      {/* Results View */}
      {job.result && (
        <div className="space-y-6">
          <JobMetaEditor job={job} onUpdated={setJob} />

          <JobSearch
            jobId={job.id}
            onOpenFile={(path) => {
              setActiveFilePath(path);
              setActiveTab('explorer');
            }}
            onOpenFunction={(address) => {
              setFocusAddress(address);
              setActiveTab('findings');
            }}
          />

          {/* Main View Tabs */}
          <div className="flex border-b border-rea-border space-x-6 text-sm">
            <button
              onClick={() => setActiveTab('findings')}
              className={`pb-3 font-semibold transition flex items-center space-x-2 ${
                activeTab === 'findings'
                  ? 'border-b-2 border-rea-accent text-white'
                  : 'text-rea-muted hover:text-white'
              }`}
            >
              <FileCode className="w-4 h-4" />
              <span>Analysis Findings & Evidence</span>
            </button>

            <button
              onClick={() => setActiveTab('explorer')}
              className={`pb-3 font-semibold transition flex items-center space-x-2 ${
                activeTab === 'explorer'
                  ? 'border-b-2 border-rea-accent text-white'
                  : 'text-rea-muted hover:text-white'
              }`}
            >
              <Terminal className="w-4 h-4" />
              <span>Code & Artifact Explorer</span>
            </button>
          </div>

          {activeTab === 'findings' && (
            <div className="space-y-8">
              <OverviewPanel job={job} />

              <AiExplainPanel
                jobId={job.id}
                scope={{ scope: 'job' }}
                label="whole sample"
                existing={job.explanations?.job}
                aiEnabled={aiEnabled}
                onSaved={saveExplanation}
              />

              <div className="space-y-4">
                {job.result.type === 'javascript' && (
                  <JavaScriptResultsView
                    result={job.result}
                    onSelectModule={(modPath) => {
                      setActiveFilePath(modPath);
                      setActiveTab('explorer');
                    }}
                  />
                )}
                {job.result.type === 'native' && (
                  <GhidraDisassemblyStudio
                    result={job.result}
                    jobId={job.id}
                    extractedPath={job.extractedPath}
                    fileTree={job.fileTree}
                    onExploreWorkspace={() => setActiveTab('explorer')}
                    focusAddress={focusAddress}
                    renderFunctionTools={(fn) => (
                      <AiExplainPanel
                        jobId={job.id}
                        scope={{ scope: 'function', address: fn.address }}
                        label={fn.name}
                        existing={job.explanations?.[`fn:${fn.address}`]}
                        aiEnabled={aiEnabled}
                        onSaved={saveExplanation}
                      />
                    )}
                  />
                )}
                {job.result.type === 'android' && (
                  <AndroidResultsView
                    result={job.result}
                    onExploreWorkspace={() => setActiveTab('explorer')}
                  />
                )}
                {job.result.type === 'browser' && <BrowserResultsView result={job.result} />}
                {job.result.type === 'evm' && <EvmResultsView result={job.result} />}
                {job.result.type === 'extension' && (
                  <ExtensionResultsView
                    result={job.result}
                    onOpenFile={(file) => {
                      // Findings are relative to the extension root, which may be a subfolder of the workspace
                      const prefix = job.fileTree?.length === 1 && job.fileTree[0].type === 'directory' && !file.startsWith(job.fileTree[0].path) ? `${job.fileTree[0].path}/` : '';
                      setActiveFilePath(`${prefix}${file}`);
                      setActiveTab('explorer');
                    }}
                  />
                )}
                {job.result.type === 'dotnet' && (
                  <DotNetResultsView
                    result={job.result}
                    hasDecompiledSource={!!job.extractedPath}
                    onExploreWorkspace={() => setActiveTab('explorer')}
                  />
                )}
              </div>

              <LimitationsView limitations={job.result.limitations ?? []} />

              {job.result.evidence && <EvidenceView evidence={job.result.evidence} />}
            </div>
          )}

          {activeTab === 'explorer' && (
            <div className="space-y-4">
              <CodeExplorer
                jobId={job.id}
                initialTree={job.fileTree}
                defaultFilePath={activeFilePath}
                renderFileTools={
                  job.extractedPath
                    ? (path) => (
                        <AiExplainPanel
                          jobId={job.id}
                          scope={{ scope: 'file', path }}
                          label={path}
                          existing={job.explanations?.[`file:${path}`]}
                          aiEnabled={aiEnabled}
                          onSaved={saveExplanation}
                        />
                      )
                    : undefined
                }
              />
            </div>
          )}
        </div>
      )}
    </div>
  );
};
