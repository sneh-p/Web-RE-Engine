import fs from 'fs';
import path from 'path';
import type {
  Evidence,
  ExtensionApiUsage,
  ExtensionCodeLocation,
  ExtensionContentScript,
  ExtensionFinding,
  ExtensionInput,
  ExtensionPermission,
  ExtensionResult,
  FileTreeNode,
  RiskLevel,
} from '../../../shared/types.js';
import { extractWith7z } from './archive.js';
import { buildFileTree } from './fileTree.js';

type ProgressCallback = (msg: string, pct?: number) => void;

const MAX_SCAN_FILE_BYTES = 3 * 1024 * 1024;
const MAX_SCAN_TOTAL_BYTES = 80 * 1024 * 1024;
const MAX_LOCATIONS_PER_FINDING = 15;

// ---------- Package unpacking ----------

// CRX2: "Cr24", version 2, key length, signature length, key, signature, zip.
// CRX3: "Cr24", version 3, header length, protobuf header, zip.
export function crxZipOffset(buf: Buffer): { format: 'crx2' | 'crx3'; offset: number } | null {
  if (buf.length < 16 || buf.toString('latin1', 0, 4) !== 'Cr24') return null;
  const version = buf.readUInt32LE(4);
  if (version === 3) return { format: 'crx3', offset: 12 + buf.readUInt32LE(8) };
  if (version === 2) return { format: 'crx2', offset: 16 + buf.readUInt32LE(8) + buf.readUInt32LE(12) };
  return null;
}

async function unpackExtension(
  filePath: string,
  outDir: string,
  limitations: string[]
): Promise<ExtensionResult['packageFormat']> {
  const fd = fs.openSync(filePath, 'r');
  const head = Buffer.alloc(16);
  fs.readSync(fd, head, 0, 16, 0);
  fs.closeSync(fd);

  const crx = crxZipOffset(head);
  let archive = filePath;
  let format: ExtensionResult['packageFormat'] = /\.xpi$/i.test(filePath) ? 'xpi' : 'zip';

  if (crx) {
    // 7z cannot read the CRX header; hand it the embedded zip
    const size = fs.statSync(filePath).size;
    if (crx.offset >= size) throw new Error('CRX header points past the end of the file');
    archive = path.join(path.dirname(outDir), `${path.basename(outDir)}.zip`);
    fs.writeFileSync(archive, fs.readFileSync(filePath).subarray(crx.offset));
    format = crx.format;
  }

  try {
    const res = await extractWith7z(archive, outDir);
    limitations.push(...res.limitations);
    if (res.extractedCount === 0) throw new Error('The extension package contained no extractable files');
  } finally {
    if (archive !== filePath) fs.rmSync(archive, { force: true });
  }
  return format;
}

// Zipped unpacked extensions often have a single top-level folder around manifest.json
function findExtensionRoot(dir: string): string | null {
  if (fs.existsSync(path.join(dir, 'manifest.json'))) return dir;
  const entries = fs.readdirSync(dir, { withFileTypes: true }).filter((e) => !e.name.startsWith('__MACOSX'));
  if (entries.length === 1 && entries[0].isDirectory()) return findExtensionRoot(path.join(dir, entries[0].name));
  return null;
}

// ---------- Manifest ----------

// Chrome accepts comments in manifest.json; strip them outside of strings
export function stripJsonComments(text: string): string {
  let out = '';
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      out += c;
      if (c === '\\') out += text[++i] ?? '';
      else if (c === '"') inString = false;
    } else if (c === '"') {
      inString = true;
      out += c;
    } else if (c === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i++;
      out += '\n';
    } else if (c === '/' && text[i + 1] === '*') {
      i += 2;
      while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i++;
      i++;
    } else {
      out += c;
    }
  }
  return out;
}

function readJsonFile(file: string): any {
  return JSON.parse(stripJsonComments(fs.readFileSync(file, 'utf8').replace(/^﻿/, '')));
}

// "__MSG_appName__" -> value from _locales/<default_locale>/messages.json
function resolveMessage(root: string, manifest: any, value: unknown): string {
  if (typeof value !== 'string') return '';
  const m = value.match(/^__MSG_(\w+)__$/);
  if (!m) return value;
  for (const locale of [manifest.default_locale, 'en', 'en_US'].filter(Boolean)) {
    const file = path.join(root, '_locales', locale, 'messages.json');
    try {
      const messages = readJsonFile(file);
      const key = Object.keys(messages).find((k) => k.toLowerCase() === m[1].toLowerCase());
      if (key && typeof messages[key]?.message === 'string') return messages[key].message;
    } catch {
      // missing or malformed locale file
    }
  }
  return value;
}

const strArray = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);

// ---------- Permission risk ----------

const PERMISSION_RISK: Record<string, [RiskLevel, string]> = {
  debugger: ['critical', 'Can attach the DevTools protocol to any tab: read and change everything, including other extensions'],
  proxy: ['high', 'Can route all browser traffic through a server of its choosing'],
  nativeMessaging: ['high', 'Can talk to a native program installed on the computer, escaping the browser sandbox'],
  cookies: ['high', 'Can read and change cookies, including login session cookies'],
  webRequest: ['high', 'Can observe all network requests (and modify them in Manifest V2 with webRequestBlocking)'],
  webRequestBlocking: ['high', 'Can block or rewrite network requests'],
  declarativeNetRequestWithHostAccess: ['medium', 'Can redirect or modify requests on the sites it has access to'],
  declarativeNetRequest: ['medium', 'Can block, redirect or modify headers of requests via rules'],
  management: ['high', 'Can list, disable or uninstall other extensions (e.g. security extensions)'],
  history: ['high', 'Can read the full browsing history'],
  tabs: ['medium', 'Can see the URL and title of every open tab'],
  webNavigation: ['medium', 'Can track every page navigation'],
  scripting: ['medium', 'Can inject scripts into pages it has host access to'],
  clipboardRead: ['high', 'Can read the clipboard (passwords, wallet addresses)'],
  clipboardWrite: ['low', 'Can write to the clipboard (clipboard hijacking of wallet addresses)'],
  downloads: ['medium', 'Can start downloads and see download history'],
  'downloads.open': ['high', 'Can open downloaded files'],
  privacy: ['medium', 'Can change browser privacy settings'],
  contentSettings: ['medium', 'Can change site permissions such as JavaScript, cookies and notifications'],
  browsingData: ['medium', 'Can delete browsing data'],
  identity: ['medium', 'Can obtain OAuth tokens for the signed-in Google account'],
  'identity.email': ['medium', 'Can read the email address of the signed-in user'],
  geolocation: ['medium', 'Can read the device location'],
  desktopCapture: ['high', 'Can capture the screen'],
  tabCapture: ['high', 'Can capture the content of tabs'],
  pageCapture: ['medium', 'Can save complete pages as MHTML'],
  topSites: ['low', 'Can read the most visited sites'],
  bookmarks: ['low', 'Can read and change bookmarks'],
  sessions: ['medium', 'Can read recently closed tabs and synced sessions from other devices'],
  enterprise: ['medium', 'Uses enterprise APIs (device attributes)'],
  'enterprise.deviceAttributes': ['medium', 'Can read enterprise device attributes'],
  vpnProvider: ['high', 'Can act as a VPN for the device'],
  certificateProvider: ['high', 'Can provide client certificates'],
  offscreen: ['low', 'Can create hidden documents (used for DOM access from a service worker)'],
  background: ['low', 'Keeps running when the browser window is closed'],
  unlimitedStorage: ['low', 'Can store unlimited local data'],
  notifications: ['low', 'Can show system notifications'],
  storage: ['low', 'Uses extension storage'],
  alarms: ['low', 'Can schedule periodic tasks'],
  contextMenus: ['low', 'Adds context-menu items'],
  activeTab: ['low', 'Temporary access to the current tab after the user clicks the extension'],
  sidePanel: ['low', 'Shows a side panel'],
};

const ALL_HOSTS = /^(<all_urls>|\*:\/\/\*\/\*|https?:\/\/\*\/\*|\*:\/\/\*\/|file:\/\/\/\*)$/;

function hostRisk(pattern: string): [RiskLevel, string] {
  if (ALL_HOSTS.test(pattern)) return ['critical', 'Access to every website, including banking and email'];
  if (/^\*:\/\/\*\.|^https?:\/\/\*\./.test(pattern)) return ['medium', 'Access to every subdomain of a site'];
  if (/^file:/.test(pattern)) return ['high', 'Access to local files'];
  return ['low', 'Access limited to specific sites'];
}

function classifyPermissions(manifest: any): { permissions: ExtensionPermission[]; hosts: ExtensionPermission[] } {
  const permissions: ExtensionPermission[] = [];
  const hosts: ExtensionPermission[] = [];
  const isHostPattern = (p: string) => p.includes('://') || p === '<all_urls>';

  const add = (p: string, optional: boolean) => {
    if (isHostPattern(p)) {
      if (hosts.some((h) => h.name === p)) return;
      const [risk, reason] = hostRisk(p);
      hosts.push({ name: p, risk, reason, optional });
    } else {
      if (permissions.some((x) => x.name === p)) return;
      const [risk, reason] = PERMISSION_RISK[p] ?? ['low', 'No elevated access known for this permission'];
      permissions.push({ name: p, risk, reason, optional });
    }
  };

  // Manifest V2 mixes hosts into "permissions"; V3 has "host_permissions"
  for (const p of strArray(manifest.permissions)) add(p, false);
  for (const p of strArray(manifest.host_permissions)) add(p, false);
  for (const p of strArray(manifest.optional_permissions)) add(p, true);
  for (const p of strArray(manifest.optional_host_permissions)) add(p, true);
  return { permissions, hosts };
}

// ---------- Code scanning ----------

interface ScanFile {
  rel: string;
  text: string;
  isContentScript: boolean;
}

interface Detector {
  id: string;
  title: string;
  severity: RiskLevel;
  category: string;
  description: string;
  pattern: RegExp;
  // Only meaningful inside content scripts (code running in web pages)
  contentScriptOnly?: boolean;
  // Also applies to JSON (declarativeNetRequest rule files); other detectors only scan code
  jsonToo?: boolean;
}

const DETECTORS: Detector[] = [
  {
    id: 'remote-code-eval',
    title: 'Dynamic code execution',
    severity: 'high',
    category: 'remote-code',
    description: 'eval / new Function / string timers run code built at runtime, a common way to load remote payloads past store review.',
    pattern: /(?<![.\w$])eval\s*\(|\bnew\s+Function\s*\(|\bset(?:Timeout|Interval)\s*\(\s*['"`]/,
  },
  {
    id: 'remote-script-injection',
    title: 'Injects external scripts into pages',
    severity: 'high',
    category: 'remote-code',
    description: 'Creates <script> elements whose source is a remote URL, executing third-party code inside visited pages.',
    pattern: /\.src\s*=\s*['"`]https?:\/\/[^'"`]+\.js|importScripts\s*\(\s*['"`]https?:/,
  },
  {
    id: 'execute-script-code',
    title: 'Executes code strings in tabs',
    severity: 'high',
    category: 'remote-code',
    description: 'tabs.executeScript / scripting.executeScript with a "code" string can run arbitrary (possibly downloaded) code in pages.',
    pattern: /executeScript\s*\([^)]*\bcode\s*:/,
  },
  {
    id: 'cookie-access',
    title: 'Reads cookies',
    severity: 'medium',
    category: 'credential-access',
    description: 'Reads page cookies or uses the cookies API; combined with network access this can steal login sessions.',
    pattern: /document\.cookie\b(?!\s*=)|\b(?:chrome|browser)\.cookies\.(?:getAll|get)\b/,
  },
  {
    id: 'keylogging',
    title: 'Captures keystrokes in web pages',
    severity: 'high',
    category: 'collection',
    description: 'A content script listens to keyboard or input events in every page it runs on.',
    pattern: /addEventListener\s*\(\s*['"`](?:keydown|keypress|keyup|input)['"`]|\.on(?:keydown|keypress|keyup)\s*=/,
    contentScriptOnly: true,
  },
  {
    id: 'password-fields',
    title: 'Reads password or form fields',
    severity: 'high',
    category: 'credential-access',
    description: 'A content script selects password inputs or harvests form values.',
    pattern: /type\s*=\s*\\?['"]?password|\[type=["']?password|querySelectorAll\s*\(\s*['"`](?:input|form)/i,
    contentScriptOnly: true,
  },
  {
    id: 'clipboard-read',
    title: 'Reads the clipboard',
    severity: 'medium',
    category: 'collection',
    description: 'Reads clipboard contents (passwords, seed phrases, wallet addresses).',
    pattern: /navigator\.clipboard\.read(?:Text)?\s*\(|execCommand\s*\(\s*['"`]paste/,
  },
  {
    id: 'crypto-wallet',
    title: 'Targets crypto wallets',
    severity: 'high',
    category: 'credential-access',
    description: 'Accesses injected wallet providers or references well-known wallet extension ids.',
    pattern: /window\.ethereum\b|window\.solana\b|nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|\bseed\s*phrase\b|\bmnemonic\b/i,
  },
  {
    id: 'csp-stripping',
    title: 'Removes security headers',
    severity: 'critical',
    category: 'defense-evasion',
    description: 'Strips Content-Security-Policy or X-Frame-Options from responses, disabling page protections.',
    // declarativeNetRequest "remove" operations, or webRequest code filtering the header out of responseHeaders
    pattern:
      /"header"\s*:\s*"(?:content-security-policy|x-frame-options)"[^}]{0,80}"operation"\s*:\s*"remove"|"operation"\s*:\s*"remove"[^}]{0,80}"header"\s*:\s*"(?:content-security-policy|x-frame-options)"|responseHeaders[^;]{0,120}(?:filter|splice)[^;]{0,160}(?:content-security-policy|x-frame-options)/i,
    jsonToo: true,
  },
  {
    id: 'disable-extensions',
    title: 'Disables or uninstalls other extensions',
    severity: 'critical',
    category: 'defense-evasion',
    description: 'Uses the management API to turn off or remove extensions (often security tools).',
    pattern: /\b(?:chrome|browser)\.management\.(?:setEnabled|uninstall)\b/,
  },
  {
    id: 'native-messaging',
    title: 'Talks to a native application',
    severity: 'high',
    category: 'execution',
    description: 'Connects to a program on the computer through native messaging.',
    pattern: /\b(?:chrome|browser)\.runtime\.(?:connectNative|sendNativeMessage)\b/,
  },
  {
    id: 'debugger-attach',
    title: 'Attaches the debugger to tabs',
    severity: 'critical',
    category: 'collection',
    description: 'chrome.debugger.attach gives full control over a tab, including reading network bodies and form data.',
    pattern: /\b(?:chrome|browser)\.debugger\.attach\b/,
  },
  {
    id: 'history-read',
    title: 'Reads browsing history',
    severity: 'medium',
    category: 'collection',
    description: 'Queries the browsing history.',
    pattern: /\b(?:chrome|browser)\.history\.search\b/,
  },
  {
    id: 'beacon-exfil',
    title: 'Sends data with beacons or tracking pixels',
    severity: 'medium',
    category: 'exfiltration',
    description: 'navigator.sendBeacon or image pixels send data out without waiting for a response.',
    pattern: /navigator\.sendBeacon\s*\(|new\s+Image\s*\(\s*\)\s*\.src\s*=/,
  },
];

const NETWORK_PATTERN = /\bfetch\s*\(|new\s+XMLHttpRequest\b|new\s+WebSocket\s*\(|\$\.(?:ajax|get|post)\s*\(|axios\.|navigator\.sendBeacon/;
const API_PATTERN = /\b(?:chrome|browser)\.([a-zA-Z]+(?:\.[a-zA-Z]+)?)\.([a-zA-Z]+)\b/g;

// Minified is normal; obfuscated (string-array rotation, hex soup, giant encoded blobs) is not
function obfuscationReason(text: string): string | null {
  const hexIds = text.match(/\b_0x[0-9a-f]{4,6}\b/g)?.length ?? 0;
  if (hexIds > 40) return `javascript-obfuscator style identifiers (${hexIds} _0x… names)`;
  const hexEscapes = text.match(/\\x[0-9a-f]{2}/gi)?.length ?? 0;
  if (hexEscapes > 500 && hexEscapes / text.length > 0.02) return `dense \\x hex escapes (${hexEscapes})`;
  const blob = text.match(/['"`][A-Za-z0-9+/=]{4000,}['"`]/);
  if (blob) return `embedded encoded blob of ${blob[0].length.toLocaleString()} characters`;
  if (/\beval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,/.test(text)) return 'Dean Edwards "p,a,c,k,e,d" packer';
  return null;
}

function collectFiles(root: string, contentScriptFiles: Set<string>, limitations: string[]): ScanFile[] {
  const files: ScanFile[] = [];
  let total = 0;
  const walk = (dir: string) => {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      const abs = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        walk(abs);
        continue;
      }
      if (!ent.isFile() || !/\.(m?js|cjs|html?|json)$/i.test(ent.name) || ent.name === 'messages.json') continue;
      const size = fs.statSync(abs).size;
      if (size > MAX_SCAN_FILE_BYTES) {
        limitations.push(`Skipped ${path.relative(root, abs)} (${(size / 1048576).toFixed(1)} MB) during code scanning`);
        continue;
      }
      if (total + size > MAX_SCAN_TOTAL_BYTES) {
        if (!limitations.some((l) => l.startsWith('Code scanning stopped'))) limitations.push('Code scanning stopped at 80 MB of source');
        return;
      }
      total += size;
      const rel = path.relative(root, abs).split(path.sep).join('/');
      files.push({ rel, text: fs.readFileSync(abs, 'utf8'), isContentScript: contentScriptFiles.has(rel) });
    }
  };
  walk(root);
  return files;
}

function scanCode(files: ScanFile[]) {
  const findings = new Map<string, ExtensionFinding>();
  const api = new Map<string, { count: number; files: Set<string> }>();
  const networkFiles = new Set<string>();
  const obfuscated: { file: string; reason: string }[] = [];

  for (const f of files) {
    if (/\.m?js$|\.cjs$/i.test(f.rel)) {
      const reason = obfuscationReason(f.text);
      if (reason) obfuscated.push({ file: f.rel, reason });
    }
    const lines = f.text.split('\n');
    for (let i = 0; i < lines.length; i++) {
      // Minified files have megabyte-long lines; cap the per-line work and snippet
      const line = lines[i].length > 20000 ? lines[i].slice(0, 20000) : lines[i];
      if (NETWORK_PATTERN.test(line)) networkFiles.add(f.rel);

      for (const m of line.matchAll(API_PATTERN)) {
        const key = `${m[1]}.${m[2]}`;
        const entry = api.get(key) ?? { count: 0, files: new Set<string>() };
        entry.count++;
        entry.files.add(f.rel);
        api.set(key, entry);
      }

      const trimmed = line.trimStart();
      const isComment = trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*');
      const isJson = /\.json$/i.test(f.rel);
      for (const d of DETECTORS) {
        if (d.contentScriptOnly && !f.isContentScript) continue;
        if ((isJson && !d.jsonToo) || (isComment && !isJson)) continue;
        const hit = d.pattern.exec(line);
        // "new Function" as the start of a string literal is data (e.g. filter lists), not a call
        if (!hit || (!isJson && /['"`]/.test(line[hit.index - 1] ?? ''))) continue;
        const finding = findings.get(d.id) ?? {
          id: d.id,
          title: d.title,
          severity: d.severity,
          category: d.category,
          description: d.description,
          locations: [],
        };
        if (finding.locations.length < MAX_LOCATIONS_PER_FINDING) {
          const start = Math.max(0, hit.index - 60);
          finding.locations.push({ file: f.rel, line: i + 1, snippet: line.slice(start, hit.index + 100).trim() });
        }
        findings.set(d.id, finding);
      }
    }
  }

  const apiUsage: ExtensionApiUsage[] = [...api]
    .map(([name, v]) => ({ api: name, count: v.count, files: [...v.files].sort() }))
    .sort((a, b) => a.api.localeCompare(b.api));
  return { findings: [...findings.values()], apiUsage, networkFiles, obfuscated };
}

// ---------- Risk scoring ----------

const SEVERITY_WEIGHT: Record<RiskLevel, number> = { critical: 30, high: 15, medium: 6, low: 1 };
const PERMISSION_WEIGHT: Record<RiskLevel, number> = { critical: 25, high: 10, medium: 4, low: 0 };
const SEVERITY_ORDER: RiskLevel[] = ['critical', 'high', 'medium', 'low'];

function escalate(f: ExtensionFinding, to: RiskLevel, why: string) {
  if (SEVERITY_ORDER.indexOf(to) < SEVERITY_ORDER.indexOf(f.severity)) {
    f.severity = to;
    f.description += ` ${why}`;
  }
}

// ---------- Entry point ----------

export async function runExtensionAnalysis(
  input: ExtensionInput,
  onProgress: ProgressCallback
): Promise<{ result: ExtensionResult; fileTree?: FileTreeNode[]; extractedPath?: string }> {
  if (!input.filePath || !fs.existsSync(input.filePath)) throw new Error(`File not found: ${input.filePath}`);
  const limitations: string[] = [];
  const evidence: Evidence[] = [];

  onProgress('Unpacking extension package...', 15);
  const extractDir = path.join(path.dirname(input.filePath), `extracted_${path.basename(input.filePath)}`);
  const packageFormat = await unpackExtension(input.filePath, extractDir, limitations);
  const root = findExtensionRoot(extractDir);
  if (!root) throw new Error('No manifest.json found: this does not look like a browser extension');

  onProgress('Parsing manifest.json...', 30);
  let manifest: any;
  try {
    manifest = readJsonFile(path.join(root, 'manifest.json'));
  } catch (err: any) {
    throw new Error(`manifest.json is not valid JSON: ${err.message}`);
  }

  const manifestVersion = Number(manifest.manifest_version) || 0;
  const gecko = manifest.browser_specific_settings?.gecko ?? manifest.applications?.gecko;
  const browser: ExtensionResult['browser'] =
    gecko || packageFormat === 'xpi' || input.store?.browser === 'firefox'
      ? 'firefox'
      : packageFormat.startsWith('crx') || input.store?.browser === 'chrome' || manifest.update_url
        ? 'chrome'
        : 'unknown';

  const { permissions, hosts } = classifyPermissions(manifest);

  const contentScripts: ExtensionContentScript[] = (Array.isArray(manifest.content_scripts) ? manifest.content_scripts : []).map(
    (cs: any) => ({
      matches: strArray(cs.matches),
      excludeMatches: strArray(cs.exclude_matches),
      js: strArray(cs.js),
      css: strArray(cs.css),
      runAt: typeof cs.run_at === 'string' ? cs.run_at : undefined,
      allFrames: cs.all_frames === true,
      world: typeof cs.world === 'string' ? cs.world : undefined,
    })
  );
  // Content-script match patterns grant page access just like host permissions
  for (const cs of contentScripts) {
    for (const m of cs.matches) {
      if (!hosts.some((h) => h.name === m)) {
        const [risk, reason] = hostRisk(m);
        hosts.push({ name: m, risk, reason: `${reason} (content script)` });
      }
    }
  }

  const bg = manifest.background ?? {};
  const background: ExtensionResult['background'] =
    typeof bg.service_worker === 'string'
      ? { kind: 'service_worker', files: [bg.service_worker] }
      : Array.isArray(bg.scripts)
        ? { kind: 'scripts', files: strArray(bg.scripts) }
        : typeof bg.page === 'string'
          ? { kind: 'page', files: [bg.page] }
          : { kind: 'none', files: [] };

  const war = manifest.web_accessible_resources;
  const webAccessibleResources = Array.isArray(war)
    ? war.flatMap((w: any) => (typeof w === 'string' ? [w] : strArray(w?.resources)))
    : [];

  const csp =
    typeof manifest.content_security_policy === 'string'
      ? manifest.content_security_policy
      : typeof manifest.content_security_policy?.extension_pages === 'string'
        ? manifest.content_security_policy.extension_pages
        : undefined;

  const updateUrl = typeof manifest.update_url === 'string' ? manifest.update_url : undefined;
  const offStoreUpdates = !!updateUrl && !/^https:\/\/(clients2\.google\.com\/service\/update2\/crx|edge\.microsoft\.com\/extensionwebstorebase)/.test(updateUrl);

  const overrides = [
    ...Object.keys(manifest.chrome_url_overrides ?? {}).map((k) => `chrome_url_overrides.${k}`),
    ...Object.keys(manifest.chrome_settings_overrides ?? {}).map((k) => `chrome_settings_overrides.${k}`),
  ];

  onProgress('Scanning extension code...', 50);
  const contentScriptFiles = new Set(contentScripts.flatMap((cs) => cs.js.map((f) => f.replace(/^\.?\//, ''))));
  const files = collectFiles(root, contentScriptFiles, limitations);
  const { findings, apiUsage, networkFiles, obfuscated } = scanCode(files);

  // ---- Manifest-level findings ----
  const manifestFinding = (id: string, title: string, severity: RiskLevel, category: string, description: string) =>
    findings.push({ id, title, severity, category, description, locations: [{ file: 'manifest.json', line: 1, snippet: '' }] });

  if (offStoreUpdates) {
    manifestFinding('off-store-updates', 'Updates from a non-store server', 'high', 'persistence', `update_url points to ${updateUrl}: updates bypass store review and can be swapped for malware at any time.`);
  }
  if (csp && /unsafe-eval|'wasm-unsafe-eval'|https?:\/\/(?!localhost)/.test(csp)) {
    manifestFinding('weak-csp', 'Weakened extension Content-Security-Policy', 'medium', 'remote-code', `The extension's CSP allows eval or remote script sources: ${csp}`);
  }
  if (overrides.some((o) => /search_provider|homepage|startup_pages/.test(o))) {
    manifestFinding('settings-override', 'Changes search engine or homepage', 'medium', 'hijacking', `Overrides browser settings: ${overrides.join(', ')}. Typical of search hijackers and affiliate fraud.`);
  }
  const ec = manifest.externally_connectable;
  const externallyConnectable = ec ? { matches: strArray(ec.matches), ids: strArray(ec.ids) } : undefined;
  if (externallyConnectable?.ids.includes('*') || externallyConnectable?.matches.some((m) => ALL_HOSTS.test(m))) {
    manifestFinding('open-messaging', 'Accepts messages from any website or extension', 'high', 'exposure', 'externally_connectable allows every site or extension to send it commands.');
  }
  if (obfuscated.length > 0) {
    manifestFinding('obfuscated-code', 'Obfuscated code', 'high', 'defense-evasion', `Code is deliberately obfuscated (${obfuscated.map((o) => o.file).join(', ')}), hiding behaviour from review. Chrome Web Store policy forbids obfuscation.`);
  }

  // ---- Combine signals: the same API is much worse with broad access and a way out ----
  const allSites = hosts.some((h) => h.risk === 'critical' && !h.optional);
  for (const f of findings) {
    if (f.id === 'keylogging' && allSites) escalate(f, 'critical', 'It runs on every website.');
    if (f.id === 'password-fields' && allSites) escalate(f, 'critical', 'It runs on every website.');
    if (f.id === 'cookie-access' && f.locations.some((l) => networkFiles.has(l.file))) {
      escalate(f, 'high', 'The same file also makes network requests, so cookies could be sent out.');
    }
  }

  // ---- Score ----
  // Power (what it may do) is scored separately from behaviour (what the code does):
  // "<all_urls>", "http://*/*" and "https://*/*" are one capability, and permissions alone top out at "high"
  const reasons: string[] = [];
  const required = (list: ExtensionPermission[]) => list.filter((p) => !p.optional);
  const broadestHost = required(hosts).sort((a, b) => SEVERITY_ORDER.indexOf(a.risk) - SEVERITY_ORDER.indexOf(b.risk))[0];
  let powerScore = broadestHost ? PERMISSION_WEIGHT[broadestHost.risk] : 0;
  if (broadestHost && (broadestHost.risk === 'critical' || broadestHost.risk === 'high')) {
    reasons.push(`${broadestHost.risk} site access ${broadestHost.name}: ${broadestHost.reason}`);
  }
  for (const p of required(permissions)) {
    powerScore += PERMISSION_WEIGHT[p.risk];
    if (p.risk === 'critical' || p.risk === 'high') reasons.push(`${p.risk} permission ${p.name}: ${p.reason}`);
  }
  powerScore = Math.min(powerScore, 50);

  let behaviourScore = 0;
  for (const f of findings) {
    behaviourScore += SEVERITY_WEIGHT[f.severity];
    if (f.severity === 'critical' || f.severity === 'high') reasons.push(`${f.severity}: ${f.title}`);
  }

  const riskScore = Math.min(100, powerScore + behaviourScore);
  const hasCriticalBehaviour = findings.some((f) => f.severity === 'critical');
  const riskLevel: RiskLevel =
    riskScore >= 70 && hasCriticalBehaviour ? 'critical' : riskScore >= 40 ? 'high' : riskScore >= 15 ? 'medium' : 'low';

  findings.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || a.title.localeCompare(b.title));
  permissions.sort((a, b) => SEVERITY_ORDER.indexOf(a.risk) - SEVERITY_ORDER.indexOf(b.risk) || a.name.localeCompare(b.name));
  hosts.sort((a, b) => SEVERITY_ORDER.indexOf(a.risk) - SEVERITY_ORDER.indexOf(b.risk) || a.name.localeCompare(b.name));

  evidence.push({
    kind: 'code',
    description: `Scanned ${files.length} files: ${findings.length} findings, ${apiUsage.length} distinct extension APIs, ${networkFiles.size} files making network requests`,
    confidence: 'high',
  });
  if (manifestVersion === 2) {
    limitations.push('Manifest V2 extension: Chrome no longer runs these, but other Chromium browsers and Firefox may.');
  }
  if (root !== extractDir) {
    limitations.push(`manifest.json was found in the subfolder ${path.relative(extractDir, root)}/`);
  }

  onProgress('Extension analysis complete.', 95);
  return {
    result: {
      type: 'extension',
      browser,
      packageFormat,
      name: resolveMessage(root, manifest, manifest.name) || '(unnamed)',
      version: String(manifest.version ?? ''),
      description: resolveMessage(root, manifest, manifest.description) || undefined,
      manifestVersion,
      extensionId: input.store?.id ?? (typeof gecko?.id === 'string' ? gecko.id : undefined),
      permissions,
      hostPermissions: hosts,
      contentScripts,
      background,
      externallyConnectable,
      webAccessibleResources,
      csp,
      updateUrl,
      offStoreUpdates,
      overrides,
      apiUsage,
      findings,
      obfuscatedFiles: obfuscated,
      riskScore,
      riskLevel,
      riskReasons: reasons.slice(0, 20),
      filesScanned: files.length,
      evidence,
      limitations,
    },
    fileTree: buildFileTree(extractDir, extractDir),
    extractedPath: extractDir,
  };
}
