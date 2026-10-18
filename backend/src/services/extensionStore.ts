import fs from 'fs';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { validateBrowserUrl } from './ssrf.js';

const MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024;
const MAX_REDIRECTS = 5;
// The update service only serves a CRX when the requested browser version is recent enough
const CHROME_VERSION = '140.0.0.0';

export interface StoreRef {
  browser: 'chrome' | 'firefox';
  id: string;
}

// Accepts a bare id/slug or a store URL:
//   chromewebstore.google.com/detail/<name>/<32-char id>, chrome.google.com/webstore/detail/...
//   microsoftedge.microsoft.com/addons/detail/<name>/<32-char id> (Edge uses the same id format)
//   addons.mozilla.org/<locale>/firefox/addon/<slug>/
export function parseStoreRef(raw: string, browserHint?: 'chrome' | 'firefox'): StoreRef | null {
  const value = raw.trim();
  const chromeId = /^[a-p]{32}$/;

  if (/^https?:\/\//i.test(value)) {
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      return null;
    }
    if (/(^|\.)addons\.mozilla\.org$/i.test(url.hostname)) {
      const m = url.pathname.match(/\/addon\/([^/]+)/);
      return m ? { browser: 'firefox', id: decodeURIComponent(m[1]) } : null;
    }
    if (/(^|\.)(chromewebstore\.google\.com|chrome\.google\.com)$/i.test(url.hostname)) {
      const id = url.pathname.split('/').find((seg) => chromeId.test(seg));
      return id ? { browser: 'chrome', id } : null;
    }
    return null;
  }

  if (chromeId.test(value) && browserHint !== 'firefox') return { browser: 'chrome', id: value };
  if (browserHint === 'firefox' && /^[\w@.{}-]{2,200}$/.test(value)) return { browser: 'firefox', id: value };
  return null;
}

// fetch with redirects followed by hand, so every hop is checked against private/internal addresses
async function guardedFetch(url: string): Promise<Response> {
  let current = url;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const blocked = await validateBrowserUrl(current);
    if (blocked) throw new Error(`Refusing to fetch ${current}: ${blocked}`);
    const res = await fetch(current, { redirect: 'manual', headers: { 'User-Agent': 'Mozilla/5.0 WebREEngine' } });
    if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
      current = new URL(res.headers.get('location')!, current).toString();
      continue;
    }
    return res;
  }
  throw new Error('Too many redirects');
}

async function saveCapped(res: Response, dest: string): Promise<number> {
  if (!res.ok || !res.body) throw new Error(`Download failed with HTTP ${res.status}`);
  const declared = Number(res.headers.get('content-length') ?? 0);
  if (declared > MAX_DOWNLOAD_BYTES) throw new Error('Extension package is larger than 100 MB');

  const out = fs.createWriteStream(dest);
  let size = 0;
  try {
    for await (const chunk of res.body as unknown as AsyncIterable<Uint8Array>) {
      size += chunk.length;
      if (size > MAX_DOWNLOAD_BYTES) throw new Error('Extension package is larger than 100 MB');
      if (!out.write(chunk)) await new Promise<void>((r) => out.once('drain', () => r()));
    }
  } catch (err) {
    out.destroy();
    fs.rmSync(dest, { force: true });
    throw err;
  }
  await new Promise<void>((resolve, reject) => out.end((err?: Error | null) => (err ? reject(err) : resolve())));
  return size;
}

export async function downloadFromStore(ref: StoreRef, uploadsDir: string): Promise<{ filePath: string; fileName: string; size: number }> {
  if (ref.browser === 'chrome') {
    const url =
      'https://clients2.google.com/service/update2/crx?response=redirect' +
      `&prodversion=${CHROME_VERSION}&acceptformat=crx2,crx3&x=${encodeURIComponent(`id=${ref.id}&uc`)}`;
    const filePath = path.join(uploadsDir, `${uuidv4()}.crx`);
    const res = await guardedFetch(url);
    if (res.status === 204 || res.status === 404) throw new Error(`Chrome Web Store has no downloadable extension with id ${ref.id}`);
    const size = await saveCapped(res, filePath);
    return { filePath, fileName: `${ref.id}.crx`, size };
  }

  // Firefox: ask the AMO API for the current version's file URL
  const meta = await guardedFetch(`https://addons.mozilla.org/api/v5/addons/addon/${encodeURIComponent(ref.id)}/`);
  if (meta.status === 404) throw new Error(`addons.mozilla.org has no add-on "${ref.id}"`);
  if (!meta.ok) throw new Error(`addons.mozilla.org returned HTTP ${meta.status}`);
  const info = (await meta.json()) as any;
  const fileUrl: unknown = info?.current_version?.file?.url;
  if (typeof fileUrl !== 'string') throw new Error('The add-on has no downloadable file');

  const filePath = path.join(uploadsDir, `${uuidv4()}.xpi`);
  const size = await saveCapped(await guardedFetch(fileUrl), filePath);
  return { filePath, fileName: `${info.slug ?? ref.id}-${info.current_version?.version ?? ''}.xpi`, size };
}
