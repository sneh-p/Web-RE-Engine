import { execFile } from 'child_process';
import { promisify } from 'util';
import dns from 'dns';
import net from 'net';
import type { BrowserInput, BrowserResult, NetworkRequest, ScriptSource, Cookie, Evidence } from '../../../shared/types.js';
import { isBlockedIp, validateBrowserUrl } from './ssrf.js';

const execFileAsync = promisify(execFile);
type ProgressCallback = (msg: string, pct?: number) => void;

export async function runBrowserAnalysis(
  input: BrowserInput,
  onProgress: ProgressCallback
): Promise<BrowserResult> {
  onProgress(`Launching browser for: ${input.url}`, 10);

  // Check if Playwright is available
  const playwrightAvailable = await checkPlaywright();

  if (!playwrightAvailable) {
    onProgress('Playwright not installed — using rea-agents browser tools via CLI...', 20);
    return runReaBrowserAnalysis(input, onProgress);
  }

  return runPlaywrightAnalysis(input, onProgress);
}

async function checkPlaywright(): Promise<boolean> {
  try {
    const { execFile: ef } = await import('child_process');
    const efAsync = promisify(ef);
    await efAsync('npx', ['playwright', '--version'], { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

async function runReaBrowserAnalysis(
  input: BrowserInput,
  onProgress: ProgressCallback
): Promise<BrowserResult> {
  onProgress('Running rea-agents web page inspection...', 30);

  try {
    const args = ['--no-install', 'rea-agents', 'inspect-web-page', '--url', input.url, '--json'];
    const { stdout } = await execFileAsync('npx', args, {
      timeout: 120_000,
      maxBuffer: 50 * 1024 * 1024,
    });

    onProgress('Parsing results...', 80);
    const parsed = JSON.parse(stdout) as Record<string, unknown>;
    return mapReaBrowserOutput(parsed, input.url);
  } catch {
    onProgress('rea-agents browser tools unavailable — using basic HTTP analysis...', 50);
    return basicHttpAnalysis(input, onProgress);
  }
}

async function runPlaywrightAnalysis(
  input: BrowserInput,
  onProgress: ProgressCallback
): Promise<BrowserResult> {
  // Dynamic import of playwright-core
  let chromium: { launch: Function };
  try {
    const pw = await import('playwright-core');
    chromium = pw.chromium;
  } catch {
    onProgress('playwright-core not installed — falling back to HTTP analysis...', 30);
    return basicHttpAnalysis(input, onProgress);
  }

  onProgress('Launching Chromium...', 20);
  let browser: any;
  try {
    browser = await chromium.launch({ headless: true });
  } catch {
    onProgress('Chromium could not be launched (run `npx playwright install chromium`) — falling back to HTTP analysis...', 30);
    return basicHttpAnalysis(input, onProgress);
  }
  const context = await browser.newContext();
  const page = await context.newPage();

  const networkRequests: NetworkRequest[] = [];
  const scriptSources: ScriptSource[] = [];
  const evidence: Evidence[] = [];
  const cookies: Cookie[] = [];

  const dnsCache = new Map<string, Promise<boolean>>();
  const checkHostnameBlocked = (hostname: string): Promise<boolean> => {
    let p = dnsCache.get(hostname);
    if (!p) {
      p = (async () => {
        if (net.isIP(hostname)) {
          return isBlockedIp(hostname);
        }
        try {
          const addresses = await dns.promises.lookup(hostname, { all: true });
          if (!addresses || addresses.length === 0) return true;
          return addresses.some(({ address }) => isBlockedIp(address));
        } catch {
          return true;
        }
      })();
      dnsCache.set(hostname, p);
    }
    return p;
  };

  const allowPrivate = process.env.REA_ALLOW_PRIVATE_URLS === 'true';

  await page.route('**/*', async (route: any) => {
    if (allowPrivate) {
      await route.continue();
      return;
    }

    const reqUrl = route.request().url();
    let parsed: URL;
    try {
      parsed = new URL(reqUrl);
    } catch {
      await route.abort();
      return;
    }

    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      const hostname = parsed.hostname.replace(/^\[|\]$/g, '');
      const blocked = await checkHostnameBlocked(hostname);
      if (blocked) {
        evidence.push({
          kind: 'network',
          description: `Blocked request to disallowed destination: ${reqUrl}`,
          confidence: 'high',
        });
        await route.abort();
        return;
      }
    }

    await route.continue();
  });

  if (input.captureNetworkTraffic) {
    page.on('request', (req: any) => {
      networkRequests.push({
        url: req.url(),
        method: req.method(),
        requestHeaders: req.headers(),
      });
    });

    page.on('response', async (res: any) => {
      const req = networkRequests.find((r) => r.url === res.url() && !r.statusCode);
      if (req) {
        req.statusCode = res.status();
        req.responseHeaders = res.headers();
        req.contentType = res.headers()['content-type'];
        try {
          req.size = (await res.body()).length;
        } catch {
          req.size = 0;
        }
      }
    });
  }

  onProgress('Navigating to page...', 30);
  try {
    await page.goto(input.url, { waitUntil: 'networkidle', timeout: 60_000 });
  } catch (err) {
    if (evidence.some((e) => e.description.includes('Blocked'))) {
      await browser.close();
      return {
        type: 'browser',
        url: input.url,
        title: 'Blocked (SSRF Protection)',
        networkRequests,
        scriptSources,
        cookies,
        evidence,
        limitations: [`Navigation was aborted: a request to a blocked private/local address was detected.`],
      };
    }
    await browser.close();
    throw new Error(`Failed to load page: ${err}`);
  }

  onProgress('Capturing page data...', 60);

  const title = await page.title();
  let screenshot: string | undefined;

  if (input.captureScreenshot) {
    const buf = await page.screenshot({ fullPage: false });
    screenshot = buf.toString('base64');
  }

  // Capture cookies
  const rawCookies = await context.cookies();
  for (const c of rawCookies) {
    cookies.push({
      name: c.name,
      value: c.value,
      domain: c.domain,
      path: c.path,
      secure: c.secure ?? false,
      httpOnly: c.httpOnly ?? false,
      sameSite: c.sameSite,
    });
  }

  // Get loaded scripts
  const scriptUrls = await page.evaluate(() =>
    Array.from(document.querySelectorAll('script[src]')).map((s: any) => s.src)
  );
  for (const url of scriptUrls) {
    scriptSources.push({ url, size: 0, sourceMapped: false });
  }

  // Evidence
  evidence.push({
    kind: 'network',
    description: `Captured ${networkRequests.length} network requests`,
    confidence: 'high',
  });

  if (cookies.length > 0) {
    evidence.push({
      kind: 'pattern',
      description: `Found ${cookies.length} cookies (${cookies.filter((c) => c.httpOnly).length} HttpOnly)`,
      confidence: 'high',
    });
  }

  await browser.close();
  onProgress('Done.', 100);

  return {
    type: 'browser',
    url: input.url,
    title,
    screenshot,
    networkRequests,
    scriptSources,
    cookies,
    evidence,
    limitations: [],
  };
}

function mapReaBrowserOutput(raw: Record<string, unknown>, url: string): BrowserResult {
  return {
    type: 'browser',
    url,
    title: String(raw.title ?? ''),
    networkRequests: (raw.networkRequests as NetworkRequest[]) ?? [],
    scriptSources: (raw.scriptSources as ScriptSource[]) ?? [],
    cookies: (raw.cookies as Cookie[]) ?? [],
    evidence: (raw.evidence as Evidence[]) ?? [],
    limitations: (raw.limitations as string[]) ?? [],
  };
}

async function basicHttpAnalysis(
  input: BrowserInput,
  onProgress: ProgressCallback
): Promise<BrowserResult> {
  onProgress('Fetching page via HTTP...', 40);
  const { default: https } = await import('https');
  const { default: http } = await import('http');

  const networkRequests: NetworkRequest[] = [];
  const scriptSources: ScriptSource[] = [];
  const evidence: Evidence[] = [];
  const limitations: string[] = [
    'Playwright not available — only basic HTTP fetch performed.',
    'No JavaScript execution, no dynamic content capture.',
  ];

  let currentUrl = input.url;
  let redirectCount = 0;
  const maxRedirects = 5;

  const initialErr = await validateBrowserUrl(currentUrl);
  if (initialErr) {
    evidence.push({
      kind: 'network',
      description: `Blocked request to ${currentUrl}: ${initialErr}`,
      confidence: 'high',
    });
    return {
      type: 'browser',
      url: input.url,
      networkRequests: [],
      scriptSources: [],
      cookies: [],
      evidence,
      limitations: [`Access blocked: ${initialErr}`],
    };
  }

  while (redirectCount <= maxRedirects) {
    const isHttps = currentUrl.startsWith('https:');
    const client = isHttps ? https : http;

    const resData = await new Promise<{
      statusCode?: number;
      headers: Record<string, string>;
      body: string;
      redirectUrl?: string;
    } | null>((resolve) => {
      const req = client.get(currentUrl, { timeout: 30_000 }, (res) => {
        const headers = res.headers as Record<string, string>;
        networkRequests.push({
          url: currentUrl,
          method: 'GET',
          statusCode: res.statusCode,
          requestHeaders: {},
          responseHeaders: headers,
          contentType: headers['content-type'],
        });

        const status = res.statusCode || 0;
        if (status >= 300 && status < 400 && headers.location) {
          const location = headers.location;
          res.resume();
          try {
            const resolvedUrl = new URL(location, currentUrl).toString();
            return resolve({ statusCode: status, headers, body: '', redirectUrl: resolvedUrl });
          } catch {
            return resolve({ statusCode: status, headers, body: '' });
          }
        }

        let body = '';
        res.on('data', (chunk: Buffer) => (body += chunk.toString()));
        res.on('end', () => {
          resolve({ statusCode: status, headers, body });
        });
      });

      req.on('error', (err) => {
        limitations.push(`HTTP request failed for ${currentUrl}: ${err.message}`);
        resolve(null);
      });
    });

    if (!resData) {
      break;
    }

    if (resData.redirectUrl) {
      redirectCount++;
      if (redirectCount > maxRedirects) {
        limitations.push('Exceeded maximum redirect count (5)');
        break;
      }

      // Re-validate redirect target with validateBrowserUrl first!
      const redirectError = await validateBrowserUrl(resData.redirectUrl);
      if (redirectError) {
        evidence.push({
          kind: 'network',
          description: `Blocked redirect to ${resData.redirectUrl}: ${redirectError}`,
          confidence: 'high',
        });
        limitations.push(`Redirect to ${resData.redirectUrl} was blocked by SSRF protection.`);
        break;
      }

      onProgress(`Following redirect (${redirectCount}/${maxRedirects}) to ${resData.redirectUrl}...`, 45);
      currentUrl = resData.redirectUrl;
      continue;
    }

    // Terminal response
    onProgress('Parsing HTML...', 70);
    const scriptMatches = resData.body.matchAll(/<script[^>]*src=["']([^"']+)["'][^>]*>/gi);
    for (const m of scriptMatches) {
      scriptSources.push({ url: m[1], size: 0, sourceMapped: false });
    }

    evidence.push({
      kind: 'network',
      description: `HTTP ${resData.statusCode} response, ${resData.body.length} bytes`,
      confidence: 'high',
    });

    if (scriptSources.length > 0) {
      evidence.push({
        kind: 'code',
        description: `Found ${scriptSources.length} external script references`,
        confidence: 'medium',
      });
    }

    break;
  }

  onProgress('Done.', 100);
  return {
    type: 'browser',
    url: input.url,
    networkRequests,
    scriptSources,
    cookies: [],
    evidence,
    limitations,
  };
}
