import fs from 'fs';
import path from 'path';
import type { AnalysisJob } from '../../../shared/types.js';

export interface SearchHit {
  kind: 'function' | 'string' | 'import' | 'ioc' | 'yara' | 'file';
  title: string;
  // Where to go: a function address, or a workspace-relative file path
  target?: string;
  line?: number;
  snippet: string;
}

const MAX_HITS = 300;
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_TOTAL_BYTES = 100 * 1024 * 1024;

function snippetAround(text: string, idx: number, len: number): string {
  const start = Math.max(0, idx - 60);
  const end = Math.min(text.length, idx + len + 60);
  return `${start > 0 ? '…' : ''}${text.slice(start, end).replace(/\s+/g, ' ')}${end < text.length ? '…' : ''}`;
}

export function searchJob(job: AnalysisJob, query: string): { hits: SearchHit[]; truncated: boolean } {
  const q = query.toLowerCase();
  const hits: SearchHit[] = [];
  const full = () => hits.length >= MAX_HITS;
  const push = (hit: SearchHit) => {
    if (!full()) hits.push(hit);
  };
  const r = job.result;

  if (r?.type === 'native') {
    for (const fn of r.functions) {
      if (full()) break;
      if (fn.name.toLowerCase().includes(q) || fn.address.toLowerCase() === q) {
        push({ kind: 'function', title: fn.name, target: fn.address, snippet: `${fn.address} · ${fn.size} bytes` });
        continue;
      }
      const code = fn.decompiledCode ?? '';
      const ci = code.toLowerCase().indexOf(q);
      if (ci >= 0) {
        push({ kind: 'function', title: `${fn.name} (pseudo-code)`, target: fn.address, snippet: snippetAround(code, ci, q.length) });
        continue;
      }
      const line = fn.disassembly?.find((l) => `${l.mnemonic} ${l.operands} ${l.comment ?? ''}`.toLowerCase().includes(q));
      if (line) {
        push({ kind: 'function', title: `${fn.name} (disassembly)`, target: fn.address, snippet: `${line.address}  ${line.mnemonic} ${line.operands}` });
      }
    }
    for (const s of r.strings) {
      if (s.value.toLowerCase().includes(q)) push({ kind: 'string', title: s.value.slice(0, 120), snippet: `${s.address} · ${s.encoding}` });
    }
    for (const imp of r.imports) {
      if (`${imp.library}!${imp.name}`.toLowerCase().includes(q)) {
        push({ kind: 'import', title: `${imp.library}!${imp.name}`, snippet: imp.address ?? '' });
      }
    }
  }

  for (const [category, values] of Object.entries(job.iocs ?? {})) {
    for (const v of values) {
      // Secrets are masked in the UI; don't leak them through search snippets either
      if (v.toLowerCase().includes(q)) push({ kind: 'ioc', title: category === 'secrets' ? `${v.slice(0, 4)}…${v.slice(-4)}` : v, snippet: category });
    }
  }

  for (const m of job.yara?.matches ?? []) {
    if (m.rule.toLowerCase().includes(q) || (m.meta.description ?? '').toLowerCase().includes(q)) {
      push({ kind: 'yara', title: m.rule, snippet: `${m.file} · ${m.meta.description ?? ''}` });
    }
  }

  // Grep the extracted workspace (decompiled sources, unpacked files)
  let truncated = false;
  const root = job.extractedPath;
  if (root && fs.existsSync(root)) {
    let bytesRead = 0;
    const walk = (dir: string) => {
      for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
        if (full() || bytesRead > MAX_TOTAL_BYTES) {
          truncated = true;
          return;
        }
        const abs = path.join(dir, ent.name);
        if (ent.isDirectory()) {
          walk(abs);
          continue;
        }
        if (!ent.isFile()) continue;
        const size = fs.statSync(abs).size;
        if (size > MAX_FILE_BYTES) continue;
        const buf = fs.readFileSync(abs);
        bytesRead += size;
        if (buf.subarray(0, 8192).includes(0)) continue;
        const rel = path.relative(root, abs);
        const lines = buf.toString('utf8').split('\n');
        for (let i = 0; i < lines.length && !full(); i++) {
          const li = lines[i].toLowerCase().indexOf(q);
          if (li >= 0) push({ kind: 'file', title: rel, target: rel, line: i + 1, snippet: snippetAround(lines[i], li, q.length) });
        }
      }
    };
    walk(root);
  }

  return { hits, truncated: truncated || full() };
}
