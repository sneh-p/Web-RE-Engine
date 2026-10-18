import type { AnalysisJob } from '../../../shared/types.js';

export interface SetDiff {
  added: string[];
  removed: string[];
  common: number;
}

export interface JobComparison {
  a: { id: string; name: string; type: string; sha256?: string };
  b: { id: string; name: string; type: string; sha256?: string };
  identical: boolean;
  sections: Record<string, SetDiff>;
  changedFunctions: { name: string; sizeA: number; sizeB: number }[];
}

const MAX_LIST = 500;

function diff(a: Iterable<string>, b: Iterable<string>): SetDiff {
  const sa = new Set(a);
  const sb = new Set(b);
  const added = [...sb].filter((x) => !sa.has(x));
  const removed = [...sa].filter((x) => !sb.has(x));
  return {
    added: added.sort().slice(0, MAX_LIST),
    removed: removed.sort().slice(0, MAX_LIST),
    common: [...sa].filter((x) => sb.has(x)).length,
  };
}

const jobName = (j: AnalysisJob) =>
  'fileName' in j.input ? j.input.fileName : 'url' in j.input ? j.input.url : j.input.type === 'evm' ? j.input.value : j.id;

// Everything comparable about a job, as named sets of strings
function features(j: AnalysisJob): Record<string, string[]> {
  const f: Record<string, string[]> = {};
  const r = j.result;
  if (r?.type === 'native') {
    f.imports = r.imports.map((i) => `${i.library}!${i.name}`);
    f.exports = r.exports.map((e) => e.name);
    f.functions = r.functions.map((fn) => fn.name);
    f.sections = r.sections.map((s) => s.name);
    f.strings = r.strings.map((s) => s.value);
    if (r.packer?.pythonModules) f.pythonModules = r.packer.pythonModules.thirdParty;
  } else if (r?.type === 'android') {
    f.permissions = r.permissions;
    f.components = [...r.activities, ...r.services, ...r.receivers, ...r.providers].map((c) => `${c.name}${c.exported ? ' (exported)' : ''}`);
    f.classes = r.classes.map((c) => c.name);
  } else if (r?.type === 'javascript') {
    f.modules = r.modules.map((m) => m.path);
  } else if (r?.type === 'dotnet') {
    f.types = r.namespaces.flatMap((n) => n.types.map((t) => t.fullName));
  } else if (r?.type === 'browser') {
    f.requests = r.networkRequests.map((q) => q.url);
    f.scripts = r.scriptSources.map((s) => s.url);
  } else if (r?.type === 'evm') {
    f.selectors = r.functionSelectors.map((s) => s.selector);
  } else if (r?.type === 'extension') {
    f.permissions = r.permissions.map((p) => p.name);
    f.hostPermissions = r.hostPermissions.map((p) => p.name);
    f.contentScriptTargets = r.contentScripts.flatMap((cs) => cs.matches);
    f.extensionApis = r.apiUsage.map((a) => a.api);
    f.findings = r.findings.map((x) => `[${x.severity}] ${x.title}`);
    f.version = [`${r.name} ${r.version}`];
    if (r.updateUrl) f.updateUrl = [r.updateUrl];
  }
  for (const [cat, values] of Object.entries(j.iocs ?? {})) f[`iocs.${cat}`] = values;
  f.yaraRules = [...new Set((j.yara?.matches ?? []).map((m) => m.rule))];
  f.capabilities = (j.capabilities?.capabilities ?? []).map((c) => c.name);
  return f;
}

export function compareJobs(a: AnalysisJob, b: AnalysisJob): JobComparison {
  const fa = features(a);
  const fb = features(b);
  const sections: Record<string, SetDiff> = {};
  for (const key of new Set([...Object.keys(fa), ...Object.keys(fb)])) {
    const d = diff(fa[key] ?? [], fb[key] ?? []);
    if (d.added.length || d.removed.length || d.common) sections[key] = d;
  }

  // Same-named functions whose size changed are the likely code changes between versions
  const changedFunctions: JobComparison['changedFunctions'] = [];
  if (a.result?.type === 'native' && b.result?.type === 'native') {
    const sizesA = new Map(a.result.functions.map((f) => [f.name, f.size]));
    for (const f of b.result.functions) {
      const sa = sizesA.get(f.name);
      if (sa !== undefined && sa !== f.size) changedFunctions.push({ name: f.name, sizeA: sa, sizeB: f.size });
    }
  }

  return {
    a: { id: a.id, name: jobName(a), type: a.type, sha256: a.fingerprint?.sha256 },
    b: { id: b.id, name: jobName(b), type: b.type, sha256: b.fingerprint?.sha256 },
    identical: !!a.fingerprint && a.fingerprint.sha256 === b.fingerprint?.sha256,
    sections,
    changedFunctions: changedFunctions.slice(0, MAX_LIST),
  };
}
