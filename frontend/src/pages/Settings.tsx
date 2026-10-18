import React, { useEffect, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Sparkles, Loader2, CheckCircle2, XCircle, Trash2, KeyRound } from 'lucide-react';
import {
  fetchAiSettings,
  saveAiSettings,
  clearAiSettings,
  testAiSettings,
  type AiProvider,
  type AiSettingsUpdate,
} from '../api/client';

interface Preset {
  id: string;
  label: string;
  provider: AiProvider;
  baseUrl: string;
  modelHint: string;
  keyOptional?: boolean;
}

// Base URLs only; model ids change often, so they are typed in (the Anthropic default is filled in)
const PRESETS: Preset[] = [
  { id: 'anthropic', label: 'Anthropic (Claude)', provider: 'anthropic', baseUrl: '', modelHint: 'claude-opus-5-5' },
  { id: 'openai', label: 'OpenAI', provider: 'openai', baseUrl: 'https://api.openai.com/v1', modelHint: 'model id from your OpenAI account' },
  { id: 'gemini', label: 'Google Gemini', provider: 'openai', baseUrl: 'https://generativelanguage.googleapis.com/v1beta/openai', modelHint: 'Gemini model id' },
  { id: 'openrouter', label: 'OpenRouter', provider: 'openai', baseUrl: 'https://openrouter.ai/api/v1', modelHint: 'vendor/model, e.g. from openrouter.ai/models' },
  { id: 'mistral', label: 'Mistral', provider: 'openai', baseUrl: 'https://api.mistral.ai/v1', modelHint: 'Mistral model id' },
  { id: 'groq', label: 'Groq', provider: 'openai', baseUrl: 'https://api.groq.com/openai/v1', modelHint: 'Groq model id' },
  { id: 'deepseek', label: 'DeepSeek', provider: 'openai', baseUrl: 'https://api.deepseek.com/v1', modelHint: 'DeepSeek model id' },
  { id: 'ollama', label: 'Ollama (local)', provider: 'openai', baseUrl: 'http://localhost:11434/v1', modelHint: 'a model you pulled, e.g. from `ollama list`', keyOptional: true },
  { id: 'lmstudio', label: 'LM Studio (local)', provider: 'openai', baseUrl: 'http://localhost:1234/v1', modelHint: 'loaded model id', keyOptional: true },
  { id: 'custom', label: 'Other OpenAI-compatible API', provider: 'openai', baseUrl: '', modelHint: 'model id' },
];

const presetFor = (provider?: AiProvider, baseUrl?: string) =>
  provider === 'anthropic'
    ? PRESETS[0]
    : PRESETS.find((p) => p.provider === 'openai' && p.baseUrl && p.baseUrl === baseUrl) ?? PRESETS[PRESETS.length - 1];

const inputClass =
  'w-full bg-rea-bg border border-rea-border rounded-lg px-3 py-2 text-white font-mono text-xs placeholder:text-rea-muted focus:outline-none focus:border-rea-accent';

export const Settings: React.FC = () => {
  const queryClient = useQueryClient();
  const { data: current, isLoading } = useQuery({ queryKey: ['aiSettings'], queryFn: fetchAiSettings });

  const [presetId, setPresetId] = useState('anthropic');
  const [model, setModel] = useState('claude-opus-5-5');
  const [baseUrl, setBaseUrl] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [busy, setBusy] = useState<'save' | 'test' | 'clear' | null>(null);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  // Load the saved configuration into the form
  useEffect(() => {
    if (!current || current.source === 'none') return;
    const preset = presetFor(current.provider, current.baseUrl);
    setPresetId(preset.id);
    setModel(current.model ?? '');
    setBaseUrl(current.baseUrl ?? '');
  }, [current]);

  const preset = PRESETS.find((p) => p.id === presetId)!;
  const sameProviderSaved = current?.source === 'portal' && current.provider === preset.provider;

  const choosePreset = (id: string) => {
    const p = PRESETS.find((x) => x.id === id)!;
    setPresetId(id);
    setBaseUrl(p.baseUrl);
    setModel(p.provider === 'anthropic' ? 'claude-opus-5-5' : '');
    setMessage(null);
  };

  const formValue = (): AiSettingsUpdate => ({
    provider: preset.provider,
    model: model.trim(),
    baseUrl: preset.provider === 'openai' ? baseUrl.trim() : baseUrl.trim() || undefined,
    // Blank keeps the saved key
    apiKey: apiKey.trim() ? apiKey.trim() : undefined,
  });

  const run = async (kind: 'save' | 'test' | 'clear') => {
    setBusy(kind);
    setMessage(null);
    try {
      if (kind === 'test') {
        const r = await testAiSettings(formValue());
        setMessage(r.ok ? { ok: true, text: `Connected to ${r.model}. Reply: "${r.reply}"` } : { ok: false, text: r.error ?? 'Failed' });
      } else if (kind === 'save') {
        await saveAiSettings(formValue());
        setApiKey('');
        setMessage({ ok: true, text: 'Saved. AI explanations now use this provider.' });
      } else {
        if (!window.confirm('Remove the AI provider and its stored API key?')) return;
        await clearAiSettings();
        setApiKey('');
        setMessage({ ok: true, text: 'Removed.' });
      }
      queryClient.invalidateQueries({ queryKey: ['aiSettings'] });
      queryClient.invalidateQueries({ queryKey: ['engineStatus'] });
    } catch (err: any) {
      setMessage({ ok: false, text: err.message });
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="max-w-3xl mx-auto py-10 px-6 space-y-6">
      <div className="border-b border-rea-border pb-4">
        <h1 className="text-2xl font-extrabold text-white">Settings</h1>
        <p className="text-xs text-rea-muted mt-1">Configuration for this Web RE Engine server.</p>
      </div>

      <div className="border border-rea-border rounded-xl bg-rea-surface overflow-hidden text-xs">
        <div className="px-5 py-3 border-b border-rea-border flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Sparkles className="w-4 h-4 text-violet-400" />
            <span className="font-bold text-white text-sm">AI provider</span>
          </div>
          {isLoading ? (
            <Loader2 className="w-4 h-4 animate-spin text-rea-muted" />
          ) : current?.configured ? (
            <span className="text-emerald-400">
              Active: {current.provider === 'anthropic' ? 'Anthropic' : current.baseUrl} · {current.model}
              {current.source === 'env' ? ' (from backend/.env)' : ''}
            </span>
          ) : (
            <span className="text-rea-muted">Not configured</span>
          )}
        </div>

        <div className="p-5 space-y-4">
          <p className="text-rea-muted leading-relaxed">
            Used for "Explain with AI". Analysis data from the job (hashes, imports, strings, indicators with secrets masked,
            pseudo-code or file content) is sent to the provider you choose. Local providers such as Ollama keep everything on
            your network.
          </p>

          <label className="block space-y-1.5">
            <span className="text-rea-text font-semibold">Provider</span>
            <select value={presetId} onChange={(e) => choosePreset(e.target.value)} className={inputClass}>
              {PRESETS.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.label}
                </option>
              ))}
            </select>
          </label>

          {preset.provider === 'openai' && (
            <label className="block space-y-1.5">
              <span className="text-rea-text font-semibold">Base URL</span>
              <input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="https://…/v1" className={inputClass} />
              <span className="text-rea-muted block">The server calls {baseUrl ? `${baseUrl.replace(/\/+$/, '')}/chat/completions` : '<base URL>/chat/completions'}.</span>
            </label>
          )}

          <label className="block space-y-1.5">
            <span className="text-rea-text font-semibold">Model</span>
            <input value={model} onChange={(e) => setModel(e.target.value)} placeholder={preset.modelHint} className={inputClass} />
          </label>

          <label className="block space-y-1.5">
            <span className="text-rea-text font-semibold flex items-center space-x-1.5">
              <KeyRound className="w-3.5 h-3.5" />
              <span>API key{preset.keyOptional ? ' (optional for local servers)' : ''}</span>
            </span>
            <input
              type="password"
              autoComplete="new-password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder={sameProviderSaved && current?.keyHint ? `Saved key ${current.keyHint} — leave blank to keep it` : 'Paste the API key'}
              className={inputClass}
            />
            <span className="text-rea-muted block">Stored encrypted on the server and never sent back to the browser.</span>
          </label>

          {message && (
            <div className={`flex items-start space-x-2 ${message.ok ? 'text-emerald-400' : 'text-red-400'}`}>
              {message.ok ? <CheckCircle2 className="w-4 h-4 flex-shrink-0" /> : <XCircle className="w-4 h-4 flex-shrink-0" />}
              <span className="break-all">{message.text}</span>
            </div>
          )}

          <div className="flex items-center justify-between pt-2">
            <div className="flex items-center space-x-2">
              <button
                onClick={() => run('test')}
                disabled={!!busy || !model.trim()}
                className="px-3 py-1.5 rounded-lg border border-rea-border text-white hover:bg-rea-border disabled:opacity-40"
              >
                {busy === 'test' ? 'Testing…' : 'Test connection'}
              </button>
              <button
                onClick={() => run('save')}
                disabled={!!busy || !model.trim() || (preset.provider === 'openai' && !baseUrl.trim())}
                className="px-3 py-1.5 rounded-lg bg-rea-accent hover:bg-rea-accentHover text-white font-semibold disabled:opacity-40"
              >
                {busy === 'save' ? 'Saving…' : 'Save'}
              </button>
            </div>
            {current?.source === 'portal' && (
              <button
                onClick={() => run('clear')}
                disabled={!!busy}
                className="flex items-center space-x-1 px-3 py-1.5 rounded-lg text-rea-muted hover:text-red-400"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Remove</span>
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
