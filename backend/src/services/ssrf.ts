import dns from 'dns';

export async function validateBrowserUrl(url: string): Promise<string | null> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return 'Invalid URL format';
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return 'Only http and https protocols are allowed';
  }

  if (process.env.REA_ALLOW_PRIVATE_URLS === 'true') {
    return null;
  }

  const hostname = parsed.hostname.replace(/^\[|\]$/g, '');
  let addresses: dns.LookupAddress[];
  try {
    addresses = await dns.promises.lookup(hostname, { all: true });
  } catch (err: any) {
    return `Could not resolve hostname: ${err.message}`;
  }

  if (!addresses || addresses.length === 0) {
    return 'Could not resolve hostname: no addresses found';
  }

  for (const { address } of addresses) {
    if (isBlockedIp(address)) {
      return `Access to private/local address (${address}) is forbidden`;
    }
  }

  return null;
}

export function isBlockedIp(ip: string): boolean {
  const ipv4Match = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (ipv4Match) {
    const [, s1, s2, s3, s4] = ipv4Match;
    const b = [Number(s1), Number(s2), Number(s3), Number(s4)];
    if (b.some((n) => isNaN(n) || n < 0 || n > 255)) return true;
    return isBlockedIpv4(b);
  }

  const bytes = parseIpv6(ip);
  if (!bytes) return true;

  // IPv4-mapped IPv6: ::ffff:w.x.y.z (first 10 bytes = 0, bytes 10-11 = 0xff)
  const isIpv4Mapped =
    bytes.slice(0, 10).every((x) => x === 0) && bytes[10] === 0xff && bytes[11] === 0xff;
  if (isIpv4Mapped) {
    return isBlockedIpv4(bytes.slice(12, 16));
  }

  // Loopback ::1 (first 15 bytes = 0, byte 15 = 1)
  const isLoopback = bytes.slice(0, 15).every((x) => x === 0) && bytes[15] === 1;
  if (isLoopback) return true;

  // Unspecified :: (all 16 bytes = 0)
  const isUnspecified = bytes.every((x) => x === 0);
  if (isUnspecified) return true;

  // Link-local fe80::/10 (fe80 to febf)
  if (bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0x80) return true;

  // Unique-local fc00::/7 (fc00 to fdff)
  if ((bytes[0] & 0xfe) === 0xfc) return true;

  return false;
}

function isBlockedIpv4(b: number[]): boolean {
  if (b[0] === 0) return true; // 0.0.0.0/8
  if (b[0] === 127) return true; // 127.0.0.0/8 (loopback)
  if (b[0] === 10) return true; // 10.0.0.0/8 (private)
  if (b[0] === 172 && b[1] >= 16 && b[1] <= 31) return true; // 172.16.0.0/12 (private)
  if (b[0] === 192 && b[1] === 168) return true; // 192.168.0.0/16 (private)
  if (b[0] === 169 && b[1] === 254) return true; // 169.254.0.0/16 (link-local)
  return false;
}

function parseIpv6(ip: string): number[] | null {
  let addr = ip.toLowerCase();
  let embeddedIpv4: number[] | null = null;
  const lastColon = addr.lastIndexOf(':');
  if (lastColon !== -1) {
    const tail = addr.slice(lastColon + 1);
    if (tail.includes('.')) {
      const parts = tail.split('.').map(Number);
      if (parts.length === 4 && parts.every((p) => !isNaN(p) && p >= 0 && p <= 255)) {
        embeddedIpv4 = parts;
        addr = addr.slice(0, lastColon) + ':0:0';
      } else {
        return null;
      }
    }
  }

  const halves = addr.split('::');
  if (halves.length > 2) return null;

  let blocks: string[] = [];
  if (halves.length === 2) {
    const first = halves[0] ? halves[0].split(':') : [];
    const second = halves[1] ? halves[1].split(':') : [];
    const missing = 8 - (first.length + second.length);
    if (missing < 0) return null;
    blocks = [...first, ...Array(missing).fill('0'), ...second];
  } else {
    blocks = addr.split(':');
    if (blocks.length !== 8) return null;
  }

  const bytes: number[] = [];
  for (let i = 0; i < 8; i++) {
    const val = parseInt(blocks[i] || '0', 16);
    if (isNaN(val) || val < 0 || val > 0xffff) return null;
    bytes.push((val >> 8) & 0xff, val & 0xff);
  }

  if (embeddedIpv4) {
    bytes[12] = embeddedIpv4[0];
    bytes[13] = embeddedIpv4[1];
    bytes[14] = embeddedIpv4[2];
    bytes[15] = embeddedIpv4[3];
  }

  return bytes;
}
