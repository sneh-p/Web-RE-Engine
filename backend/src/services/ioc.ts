import fs from 'fs';
import path from 'path';
import type { AnalysisJob, AnalysisResult } from '../../../shared/types.js';

export interface IocCollector {
  urls: Set<string>;
  domains: Set<string>;
  ipv4: Set<string>;
  emails: Set<string>;
  ethereum: Set<string>;
  bitcoin: Set<string>;
  secrets: Set<string>;
}

export function createIocCollector(): IocCollector {
  return {
    urls: new Set<string>(),
    domains: new Set<string>(),
    ipv4: new Set<string>(),
    emails: new Set<string>(),
    ethereum: new Set<string>(),
    bitcoin: new Set<string>(),
    secrets: new Set<string>(),
  };
}

// Common known top-level domains to prevent matching Java classes/code artifacts as domains
const COMMON_TLDS = new Set([
  'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'io', 'co', 'ai', 'me', 'app', 'dev',
  'info', 'biz', 'online', 'xyz', 'site', 'top', 'tech', 'store', 'vip', 'pro', 'club',
  'work', 'link', 'live', 'news', 'world', 'today', 'cloud', 'cc', 'ru', 'cn', 'uk', 'de',
  'ca', 'fr', 'au', 'jp', 'eu', 'us', 'in', 'br', 'nl', 'es', 'ch', 'se', 'no', 'pl', 'it',
  'kr', 'za', 'tw', 'hk', 'sg', 'nz', 'mx', 'ar', 'cl', 'id', 'tr', 'ua', 'be', 'at', 'cz',
  'ro', 'gr', 'pt', 'fi', 'dk', 'hu', 'ie', 'il', 'th', 'vn', 'ph', 'my'
]);

// Ignored domain/url noise patterns (schemas, android namespaces, example.com)
const NOISE_DOMAIN_PATTERNS = [
  /w3\.org/i,
  /schemas\.android\.com/i,
  /android\.com\/apk\/res/i,
  /example\.(com|org|net)/i,
  /schemas\.microsoft\.com/i,
  /schema\.org/i,
  /apache\.org\/xml/i,
  /openxmlformats\.org/i,
  /apple\.com\/dtds/i,
  /localhost/i,
];

// Bare (non-URL) matches in decompiled/minified code are mostly member accesses
// (this.id, e.app) or reverse-DNS package names (com.phonegap.app, java.io)
const CODE_RECEIVERS = new Set([
  'this', 'self', 'super', 'that', 'window', 'document', 'module', 'exports', 'console',
  'math', 'object', 'string', 'array', 'json', 'java', 'javax', 'android', 'androidx',
  'kotlin', 'dalvik', 'sun', 'junit', 'okhttp3', 'retrofit2',
]);

function looksLikeCodeReference(parts: string[]): boolean {
  const first = parts[0];
  if (first.length === 1) return true;
  if (CODE_RECEIVERS.has(first)) return true;
  // Reverse-DNS package name: starts with a TLD-like label and has 3+ labels
  if (parts.length >= 3 && COMMON_TLDS.has(first)) return true;
  return false;
}

function isNoiseDomain(domain: string): boolean {
  const d = domain.toLowerCase();
  if (d === 'android.com' || d === 'example.com' || d === 'w3.org') return true;
  return NOISE_DOMAIN_PATTERNS.some((pat) => pat.test(d));
}

// Text extensions to scan when walking extracted directories
const TEXT_EXTS = new Set([
  '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.json', '.html', '.htm',
  '.css', '.smali', '.java', '.xml', '.txt', '.properties', '.yaml', '.yml',
  '.env', '.config', '.ini', '.gradle', '.kt', '.md', '.svg', '.map',
  '.py', '.pyw'
]);

/**
 * Extracts IOCs from a single string of text.
 */
export function extractIocsFromText(text: string, collector: IocCollector): void {
  if (!text || text.length === 0) return;

  // 1. URLs: http:// or https://
  const urlRegex = /https?:\/\/[^\s"'<>\`{}|\\^]+/g;
  let match: RegExpExecArray | null;
  while ((match = urlRegex.exec(text)) !== null) {
    if (collector.urls.size >= 500) break;
    let url = match[0].replace(/[.,;:)>\]]+$/, '');
    if (!NOISE_DOMAIN_PATTERNS.some((pat) => pat.test(url))) {
      collector.urls.add(url);
      try {
        const u = new URL(url);
        const host = u.hostname.toLowerCase();
        if (host && !isNoiseDomain(host) && !/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
          const tld = host.split('.').pop() || '';
          if (COMMON_TLDS.has(tld) && collector.domains.size < 500) {
            collector.domains.add(host);
          }
        }
      } catch {
        // ignore
      }
    }
  }

  // 2. Domains
  const domainRegex = /\b(?!(?:https?:\/\/))([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+([a-zA-Z]{2,24})\b/g;
  while ((match = domainRegex.exec(text)) !== null) {
    if (collector.domains.size >= 500) break;
    const dom = match[0].toLowerCase();
    const parts = dom.split('.');
    const tld = parts[parts.length - 1];

    if (COMMON_TLDS.has(tld) && !isNoiseDomain(dom) && !looksLikeCodeReference(parts)) {
      collector.domains.add(dom);
    }
  }

  // 3. IPv4 Addresses
  const ipv4Regex = /\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b/g;
  while ((match = ipv4Regex.exec(text)) !== null) {
    if (collector.ipv4.size >= 500) break;
    const ip = match[0];
    // Version strings (1.0.0.0, 2.96.2.0) look like IPs; real hosts rarely end in .0,
    // and a preceding "v"/"version" or trailing ".<digit>" marks a version number
    const before = text.slice(Math.max(0, match.index - 8), match.index).toLowerCase();
    const after = text.slice(match.index + ip.length, match.index + ip.length + 2);
    const looksLikeVersion = ip.endsWith('.0') || /(v|version\s*)$/.test(before) || /^\.\d/.test(after);
    if (!looksLikeVersion && ip !== '255.255.255.255' && ip !== '127.0.0.1') {
      collector.ipv4.add(ip);
    }
  }

  // 4. Email Addresses
  const emailRegex = /\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/g;
  while ((match = emailRegex.exec(text)) !== null) {
    if (collector.emails.size >= 500) break;
    const email = match[0];
    const host = match[1].toLowerCase();
    if (!isNoiseDomain(host) && !email.toLowerCase().includes('example.com')) {
      collector.emails.add(email);
    }
  }

  // 5. Ethereum Addresses
  const ethRegex = /\b0x[a-fA-F0-9]{40}\b/g;
  while ((match = ethRegex.exec(text)) !== null) {
    if (collector.ethereum.size >= 500) break;
    const eth = match[0];
    if (!/^0x0{40}$/i.test(eth) && !/^0xf{40}$/i.test(eth)) {
      collector.ethereum.add(eth);
    }
  }

  // 6. Bitcoin Addresses
  const btcRegex = /\b(?:[13][1-9A-HJ-NP-Za-km-z]{25,34}|bc1[a-z0-9]{39,59})\b/g;
  while ((match = btcRegex.exec(text)) !== null) {
    if (collector.bitcoin.size >= 500) break;
    collector.bitcoin.add(match[0]);
  }

  // 7. Likely Secrets
  // AWS Access Key ID: AKIA...
  const awsRegex = /\b(AKIA[0-9A-Z]{16})\b/g;
  while ((match = awsRegex.exec(text)) !== null) {
    if (collector.secrets.size >= 500) break;
    collector.secrets.add(match[1]);
  }

  // Google API Key: AIza... (35 chars after AIza = 39 total)
  const gapiKeyRegex = /\b(AIza[A-Za-z0-9_-]{35})\b/g;
  while ((match = gapiKeyRegex.exec(text)) !== null) {
    if (collector.secrets.size >= 500) break;
    collector.secrets.add(match[1]);
  }

  // GitHub Tokens: ghp_... or github_pat_...
  const ghTokenRegex = /\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b/g;
  while ((match = ghTokenRegex.exec(text)) !== null) {
    if (collector.secrets.size >= 500) break;
    collector.secrets.add(match[1]);
  }

  // Slack Tokens: xox[baprs]-...
  const slackRegex = /\b(xox[baprs]-[0-9a-zA-Z-]{10,72})\b/g;
  while ((match = slackRegex.exec(text)) !== null) {
    if (collector.secrets.size >= 500) break;
    collector.secrets.add(match[1]);
  }

  // Private Key PEM Header
  const pemRegex = /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/g;
  while ((match = pemRegex.exec(text)) !== null) {
    if (collector.secrets.size >= 500) break;
    collector.secrets.add(match[0]);
  }

  // JWTs: eyJ...
  const jwtRegex = /\beyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b/g;
  while ((match = jwtRegex.exec(text)) !== null) {
    if (collector.secrets.size >= 500) break;
    collector.secrets.add(match[0]);
  }
}

/**
 * Recursively walks a directory reading text files (skip > 2MB, cap total read at 50MB).
 */
export async function walkAndExtractTextFiles(
  dirPath: string,
  collector: IocCollector,
  state: { totalBytes: number } = { totalBytes: 0 }
): Promise<void> {
  const MAX_FILE_SIZE = 2 * 1024 * 1024; // 2MB
  const MAX_TOTAL_BYTES = 50 * 1024 * 1024; // 50MB

  if (!fs.existsSync(dirPath)) return;

  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dirPath, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (state.totalBytes >= MAX_TOTAL_BYTES) break;

    const fullPath = path.join(dirPath, entry.name);

    if (entry.isDirectory()) {
      await walkAndExtractTextFiles(fullPath, collector, state);
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (!TEXT_EXTS.has(ext)) continue;

      try {
        const stat = fs.statSync(fullPath);
        if (stat.size > MAX_FILE_SIZE) continue;

        const bytesToRead = Math.min(stat.size, MAX_TOTAL_BYTES - state.totalBytes);
        if (bytesToRead <= 0) break;

        const content = fs.readFileSync(fullPath, 'utf8');
        state.totalBytes += stat.size;
        extractIocsFromText(content, collector);
      } catch {
        // skip unreadable file
      }
    }
  }
}

function extractStringsFromBuffer(buf: Buffer, minLen = 5): string[] {
  const strings: string[] = [];
  let current = '';

  for (let i = 0; i < buf.length; i++) {
    const b = buf[i];
    if (b >= 0x20 && b < 0x7f) {
      current += String.fromCharCode(b);
    } else {
      if (current.length >= minLen) {
        strings.push(current);
      }
      current = '';
    }
  }
  if (current.length >= minLen) {
    strings.push(current);
  }
  return strings;
}

/**
 * Extracts IOCs across all sources relevant to an analysis job.
 */
export async function extractJobIocs(
  job: AnalysisJob,
  result: AnalysisResult,
  extractedPath?: string
): Promise<Record<string, string[]>> {
  const collector = createIocCollector();

  // 1. Native Binary Strings
  if (result.type === 'native') {
    if (result.strings && result.strings.length > 0) {
      const text = result.strings.map((s) => s.value).join('\n');
      extractIocsFromText(text, collector);
    }
  }

  // 2. Android / JavaScript source files
  const dir = extractedPath || job.extractedPath;
  if (dir && fs.existsSync(dir)) {
    await walkAndExtractTextFiles(dir, collector);
  }

  if (result.type === 'android' && result.classes) {
    for (const c of result.classes) {
      if (c.decompiledCode) extractIocsFromText(c.decompiledCode, collector);
      if (c.smaliCode) extractIocsFromText(c.smaliCode, collector);
    }
  }

  // 3. Browser script contents & network request URLs
  if (result.type === 'browser') {
    if (result.networkRequests) {
      for (const req of result.networkRequests) {
        if (req.url) extractIocsFromText(req.url, collector);
      }
    }
    if (result.scriptSources) {
      for (const s of result.scriptSources) {
        if (s.url) extractIocsFromText(s.url, collector);
        if (s.content) extractIocsFromText(s.content, collector);
      }
    }
  }

  // 4. DotNet strings and decompiled code
  if (result.type === 'dotnet') {
    if (result.namespaces) {
      for (const ns of result.namespaces) {
        for (const t of ns.types) {
          for (const m of t.methods) {
            if (m.decompiledCode) extractIocsFromText(m.decompiledCode, collector);
            if (m.ilCode) extractIocsFromText(m.ilCode, collector);
          }
        }
      }
    }
    if (job.input && 'filePath' in job.input && job.input.filePath && fs.existsSync(job.input.filePath)) {
      try {
        const buf = fs.readFileSync(job.input.filePath);
        const strings = extractStringsFromBuffer(buf);
        if (strings.length > 0) {
          extractIocsFromText(strings.join('\n'), collector);
        }
      } catch {
        // ignore
      }
    }
  }

  const finalIocs: Record<string, string[]> = {};
  for (const [key, set] of Object.entries(collector) as [string, Set<string>][]) {
    if (set.size > 0) {
      finalIocs[key] = Array.from(set).slice(0, 500);
    }
  }

  return finalIocs;
}
