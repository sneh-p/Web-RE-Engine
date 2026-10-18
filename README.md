# Web RE Engine

A self-hosted web platform for static reverse engineering. Upload a file (or give a URL, contract
address or browser-extension store link) and the server unpacks it, runs the appropriate analysis
tools inside a sandbox, and presents the results in the browser.

| Target | What you get |
|---|---|
| Native binaries (PE, ELF, Mach-O) | Functions, disassembly, Ghidra-decompiled C (r2ghidra), imports/exports, entry point, sections + entropy, call graph, packer detection, capa capabilities |
| Installers and packers | UPX unpacking, Inno Setup (innoextract), NSIS and 7-Zip/zip self-extractors (7z): the installed files become browsable and are scanned |
| Python apps (PyInstaller) | Bundled files, every module as `.pyc`, third-party module list, decompiled source (pycdc) |
| .NET assemblies | Types and namespaces, full C# project decompilation (ILSpy) |
| Android APKs | Manifest, permissions, components, Java sources (jadx), resources (apktool) |
| JavaScript / Electron | Module graph, `.asar` / `.zip` / `.tar(.gz/.bz2/.xz)` extraction |
| Browser extensions | `.crx` / `.xpi` / zipped folder / Chrome Web Store or Firefox Add-ons link: permission and site-access risk, content scripts, risky code (keylogging, password/cookie theft, remote code, disabling other extensions, obfuscation, off-store updates…) with file and line, risk score |
| Web pages | Network requests, scripts, cookies, screenshot (headless Chromium) |
| EVM contracts | Opcodes, function selectors, control flow (bytecode or an address on mainnet and common L2s) |

Every file-based job also gets MD5/SHA-1/SHA-256 and entropy, IOC extraction (URLs, IPs, domains,
emails, crypto wallets, leaked secrets), YARA scanning, full-text search, notes and tags,
Markdown/PDF reports, job comparison, re-runs, and optional AI explanations through Anthropic or any
OpenAI-compatible provider (including local models).

---

## Architecture

```
Browser ──HTTPS──> Caddy (:443, TLS) ──> Node backend (127.0.0.1:3001)
                                           ├─ Express API + WebSocket (/ws, live job progress)
                                           ├─ SQLite (backend/data/rea.db): jobs, sessions, settings
                                           ├─ backend/uploads/: uploaded files and extracted workspaces
                                           └─ Analyzers ──> systemd-run (CPU/memory/task limits)
                                                             └─> bubblewrap sandbox (no network, read-only /usr,
                                                                 only the job's own files visible)
                                                                 ├─ radare2 + r2ghidra, objdump/readelf
                                                                 ├─ 7z, innoextract, tar, upx
                                                                 ├─ yara, capa
                                                                 ├─ jadx, apktool, ilspycmd, pycdc/pycdas
                                                                 └─ rea-agents (npm, pinned)
```

| Path | Contents |
|---|---|
| `frontend/` | React 18 + Vite + Tailwind. In production it is built to `frontend/dist` and served by the backend |
| `backend/` | Node 22 + Express + TypeScript, run directly with `tsx` (there is no compile step) |
| `backend/src/services/` | One module per analyzer plus extractors, sandbox, YARA, capa, IOC, AI, reports |
| `shared/types.ts` | Types shared by backend and frontend |
| `backend/rules/` | YARA rules: `builtin/` (shipped) and `custom/` (yours) |
| `backend/test/` | Test suite and fixture builders |
| `deploy/` | systemd unit and Caddyfile |
| `start.sh` | Development launcher |

Jobs run in a FIFO queue (2 at a time by default). capa runs after a job completes, one sample at a
time, and its results arrive live on the job page.

### Backend modules (`backend/src/`)

| Module | Role |
|---|---|
| `app.ts` | Express app: `.env` loading, CSRF/auth middleware, routes, `/ws` upgrade, production static serving |
| `queue/jobQueue.ts` | SQLite job store, FIFO queue, per-job pipeline (analyzer → IOCs → YARA → background capa), retention cleanup, delete/re-run |
| `routes/*.ts` | `analysis` (uploads, bulk, store downloads), `jobs` (CRUD, notes/tags, search, report, AI explain), `files`, `compare`, `settings`, `status`, `auth` |
| `services/native.ts` | PE/ELF/Mach-O via radare2 (+ r2ghidra `pdg` or `pdc`), objdump fallback, packer handling (UPX, PyInstaller, Inno, NSIS, SFX) |
| `services/android.ts` | APK: jadx Java sources, apktool manifest/resources |
| `services/dotnet.ts` | .NET: ILSpy type listing and C# project decompilation |
| `services/javascript.ts` | JavaScript/Electron: archive extraction, rea-agents analysis or built-in fallback |
| `services/extension.ts`, `extensionStore.ts` | Browser extensions: CRX/XPI unpacking, manifest/permission risk, code scanning, scoring; store downloads |
| `services/browser.ts` | Web pages: Playwright/Chromium capture with per-request SSRF blocking, HTTP fallback |
| `services/evm.ts` | EVM bytecode disassembly, selectors, control flow; RPC fetch by address |
| `services/archive.ts` | Hardened extractors: 7z, tar, asar, innoextract, with shared limits |
| `services/pyinstaller.ts`, `pyz.ts` | PyInstaller CArchive and PYZ extraction (marshal reader), pycdc/pycdas decompilation; `python-stdlib.json` (from Python's `sys.stdlib_module_names`) separates standard-library from third-party modules |
| `services/packer.ts`, `detector.ts` | Packer/installer signatures; file-type auto-detection |
| `services/yara.ts`, `capa.ts`, `ioc.ts`, `fingerprint.ts` | YARA scanning, capa planning/running, IOC extraction, hashes and entropy |
| `services/sandbox.ts` | `runTool()`: every external tool through systemd-run + bubblewrap |
| `services/ai.ts`, `settings.ts` | AI providers (Anthropic SDK, OpenAI-compatible), encrypted provider settings |
| `services/search.ts`, `report.ts`, `compare.ts` | Job search, Markdown/HTML/PDF reports, job diffing |
| `services/auth.ts`, `password.ts`, `ssrf.ts`, `disk.ts`, `fileTree.ts` | Sessions, scrypt hashing, private-address checks, disk usage, workspace trees |
| `lib/markdown.ts` | Safe Markdown renderer (raw HTML escaped, http(s) links only) |

### Frontend (`frontend/src/`)

| Area | Files |
|---|---|
| Pages | `Home` (new analysis, auto-detect, bulk, extension store links), `JobDetails`, `JobList`, `Compare`, `Settings`, `Login` |
| Result views | `components/results/`: `GhidraDisassemblyStudio` (native), `AndroidResultsView`, `DotNetResultsView`, `JavaScriptResultsView`, `ExtensionResultsView`, `BrowserResultsView`, `EvmResultsView`, plus `OverviewPanel`, `SignatureFindings` (YARA/capa), `LimitationsView`, `EvidenceView` |
| Shared | `components/shared/CodeExplorer` (paged file viewer), `components/ai/AiExplainPanel`, `components/job/` (search, notes/tags), `api/client.ts`, `lib/markdown.ts` |

---

## Requirements

- Ubuntu 25.04 x86-64 (what this was built and tested on). Other recent Debian/Ubuntu releases should
  work, but package versions differ. radare2 in particular decides which r2ghidra release you build (step 4).
- Root access (the guide installs to `/root/rea-web`; change `deploy/web-re-engine.service` if you
  put it elsewhere).
- About 5 GB of disk for tools, plus room for uploads (each upload may be up to 500 MB, and extracted
  workspaces add to that).
- RAM:
  - 4 GB is the minimum: the default limits are tuned for it.
  - 8 GB or more is recommended if you want capa on large programs. It needed over 2 GB for a 34 MB executable, and runs in its own memory scope next to the backend.

### Tested versions

| Component | Version | Source |
|---|---|---|
| Node.js | 22.23 | NodeSource |
| radare2 | 5.9.8 | Ubuntu package |
| r2ghidra | 5.9.8 (must equal radare2) | built from the `5.9.8` tag |
| jadx | 1.5.0 (1.5.6 is available and should work) | GitHub release |
| apktool | 2.7.0 | Ubuntu package |
| ILSpy (ilspycmd) | 9.1.0.7988 on .NET SDK 8.0.122 | NuGet global tool |
| pycdc / pycdas | git `b428976` (2026-04-06) | built from source |
| capa | 10.0.0 | GitHub release |
| YARA | 4.5.2 | Ubuntu package |
| UPX | 4.2.4 | Ubuntu package (`upx-ucl`) |
| innoextract | 1.9 | Ubuntu package |
| 7-Zip | 24.09 | Ubuntu package (`7zip`) |
| bubblewrap | 0.11.0 | Ubuntu package |
| OpenJDK | 21 | Ubuntu package |
| Caddy | 2.6.2 | Ubuntu package |
| playwright-core / Chromium | 1.58.2 / headless shell 145 | npm (pinned) |
| rea-agents | 6.3.0 | npm (pinned) |

---

## Installing on a fresh server

Everything below runs as root, in this order. Each step ends with a check; don't continue past a
failing check.

| Step | What | Check |
|---|---|---|
| 1 | System packages | `7z`, `r2`, `yara`, `caddy`… all found |
| 2 | Node.js 22 | `node -v` → v22.x |
| 3–6 | jadx, r2ghidra, capa, ILSpy, pycdc | "Check everything at once" prints only `ok` |
| 7 | Copy the project, install dependencies, build, install Chromium | `npm run build` succeeds; `npm test` passes |
| 8 | Admin password | `backend/.env` contains `WEB_RE_ADMIN_PASSWORD_HASH` |
| 9 | systemd service + Caddy (HTTPS) | the checks in 9f pass |
| 10 | AI provider (optional) | Settings → Test connection |

A complete install takes about 30–45 minutes, most of it compiling r2ghidra.

### 1. System packages

```bash
apt-get update
apt-get install -y \
  git curl unzip ca-certificates \
  build-essential cmake meson ninja-build pkg-config \
  python3 python3-venv \
  binutils 7zip innoextract radare2 yara upx-ucl \
  bubblewrap \
  openjdk-21-jre-headless apktool \
  dotnet-sdk-8.0 \
  caddy
```

If `7zip` is not available on your release, install `p7zip-full` instead (both provide the `7z` command).

Caddy starts automatically on install and grabs port 80; stop it until it is configured:

```bash
systemctl stop caddy
```

### 2. Node.js 22

```bash
curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
apt-get install -y nodejs
node -v   # v22.x
```

### 3. jadx (Android decompiler)

```bash
JADX=1.5.0
curl -fsSL -o /tmp/jadx.zip https://github.com/skylot/jadx/releases/download/v$JADX/jadx-$JADX.zip
mkdir -p /opt/jadx && unzip -o -q /tmp/jadx.zip -d /opt/jadx
ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx
jadx --version
```

jadx runs on the Java 21 runtime from step 1. To upgrade, change `JADX` (e.g. `1.5.6`), remove
`/opt/jadx` and repeat.

### 4. r2ghidra (Ghidra decompiler inside radare2)

r2ghidra must match the installed radare2 version exactly. The latest r2ghidra source does not
build against older radare2 releases (e.g. `'sdb_const_getf' was not declared`), so check out the
matching tag. Install it under `/usr`, not with `r2pm` into `~/.local`: the analysis sandbox hides
home directories, so a per-user plugin is invisible to the analyzer.

```bash
R2V=$(r2 -v | head -1 | awk '{print $2}')      # e.g. 5.9.8
mkdir -p /opt/src && cd /opt/src
git clone --branch "$R2V" --depth 1 --recursive https://github.com/radareorg/r2ghidra r2ghidra-$R2V
cd r2ghidra-$R2V
./preconfigure
./configure --prefix=/usr
make -j"$(nproc)"
make install

# Debian/Ubuntu put radare2 under a multiarch lib dir, but r2ghidra looks for its processor specs
# under /usr/lib/radare2/<version>/. Link them so a plain `r2` session finds them too
# (the app passes the path itself, so this only matters for manual use):
ARCHLIB=/usr/lib/$(dpkg-architecture -qDEB_HOST_MULTIARCH)/radare2/$R2V
if [ -d "$ARCHLIB/r2ghidra_sleigh" ]; then
  mkdir -p /usr/lib/radare2/$R2V && ln -sfn "$ARCHLIB/r2ghidra_sleigh" /usr/lib/radare2/$R2V/r2ghidra_sleigh
fi

cd / && rm -rf /opt/src/r2ghidra-$R2V && rmdir /opt/src 2>/dev/null   # build tree no longer needed

# Check: the plugin is listed and decompiles without a "sleigh home" error
r2 -qc 'Lc' -- | grep -i ghidra      # -> "r2ghidra  Ghidra decompiler with pdg command"
r2 -e scr.color=0 -qc 'aa; pdg @ main' /usr/bin/true 2>&1 | grep -i sleigh || echo "r2ghidra OK"
```

`make install` may print `cannot stat … hexagon …` warnings; they only affect the Hexagon DSP
processor and can be ignored. The backend finds the processor specs (`r2ghidra_sleigh`) under
`/usr/lib/<arch>-linux-gnu/radare2/<version>/` automatically; set `R2GHIDRA_SLEIGH_HOME` if your
distribution puts them elsewhere.

If no tag matches your radare2 version, install radare2 from source instead
(`git clone https://github.com/radareorg/radare2 && radare2/sys/install.sh`) and then build the
r2ghidra release with the same version number.

Without r2ghidra the app still works and shows radare2's approximate `pdc` pseudo-code instead.

### 5. capa (capability detection, ATT&CK mapping)

```bash
CAPA=10.0.0
mkdir -p /opt/capa && cd /opt/capa
curl -fsSL -o capa.zip https://github.com/mandiant/capa/releases/download/v$CAPA/capa-v$CAPA-linux.zip
unzip -o -q capa.zip && chmod +x capa && rm capa.zip
ln -sf /opt/capa/capa /usr/local/bin/capa
capa --version      # the first run unpacks itself and takes a few seconds
```

capa is a self-contained binary with its rules built in. To upgrade, change `CAPA` to a newer
release from https://github.com/mandiant/capa/releases and repeat. The app parses capa's JSON
output, so test a sample after a major version change.

capa is slow and memory-hungry on large code:
- **Measured cost:** about 3 minutes and 1 GB for an 8 MB executable; over 2 GB and 8+ minutes for a 34 MB one.
- **When it runs:** after the job finishes, one sample at a time. Results appear on the job page when ready.
- **What it looks at:**
  - For installers (Inno Setup, NSIS, self-extractors) and UPX, it analyzes the main program inside, not the wrapper.
  - PyInstaller apps are skipped, because capa cannot see Python code.
  - Programs over `WEB_RE_CAPA_MAX_MB` (default 24 MB) are skipped with an explanation.
- **Limits:** a run that exceeds its memory or time limit is reported as such. On a bigger server, raise
  `WEB_RE_CAPA_MAX_MB`, `WEB_RE_CAPA_MEMORY_MB` and `WEB_RE_CAPA_TIMEOUT_MIN`.

### 6. Decompilers for .NET and Python

**ILSpy (.NET):**

```bash
# 9.1.0.7988 is the newest ilspycmd built for .NET 8; later releases target newer .NET and fail to
# install on the dotnet-sdk-8.0 package ("DotnetToolSettings.xml was not found in the package")
dotnet tool install -g ilspycmd --version 9.1.0.7988
ln -sf /root/.dotnet/tools/ilspycmd /usr/local/bin/ilspycmd
ilspycmd --version
```

The sandbox automatically exposes `~/.dotnet/tools` (read-only) to ilspycmd, and the app runs it
with `--disable-updatecheck` (its online update check would otherwise stall in the network-less
sandbox and print a notice into the output). To use a newer ilspycmd, install the matching newer
.NET SDK first.

**pycdc (Python bytecode):** decompiles PyInstaller modules to `.py`; modules it can't decompile
fall back to `pycdas` disassembly. Support for new Python versions lags behind: as of this writing it
rejects Python 3.14 bytecode entirely, which the job page reports. Those modules stay available as
`.pyc` files plus extracted strings.

```bash
git clone https://github.com/zrax/pycdc /opt/pycdc
git -C /opt/pycdc checkout b428976      # tested commit; skip this line to build the newest code
cmake -S /opt/pycdc -B /opt/pycdc/build -DCMAKE_BUILD_TYPE=Release
cmake --build /opt/pycdc/build -j"$(nproc)"
ln -sf /opt/pycdc/build/pycdc /usr/local/bin/pycdc
ln -sf /opt/pycdc/build/pycdas /usr/local/bin/pycdas
```

pycdc has no releases; the binaries run from `/opt/pycdc/build`, so keep that directory. To pick
up support for newer Python versions later: `git -C /opt/pycdc pull`, then rerun the two `cmake`
commands.

Every tool from steps 3–6 is optional and detected at runtime. If one is missing, that part of the
analysis is skipped and the job page says why; the navbar shows which tools are available.

**Check everything at once:**

```bash
for t in r2 objdump 7z innoextract upx yara jadx apktool capa ilspycmd pycdc pycdas bwrap systemd-run java dotnet node; do
  printf '%-12s %s\n' "$t" "$(command -v $t >/dev/null && echo ok || echo MISSING)"
done
r2 -qc 'Lc' -- | grep -qi ghidra && echo "r2ghidra     ok" || echo "r2ghidra     MISSING"
```

### 7. The application

**Get the source code into `/root/rea-web`**, using either option:

- **A. From a git repository** (if you keep the project in one):

  ```bash
  cd /root && git clone <your repository URL> rea-web
  ```

- **B. From an existing installation** (this is how the project is moved today). On the *old*
  server, package the source without dependencies, data, uploads or secrets:

  ```bash
  cd /root && tar \
    --exclude='rea-web/backend/node_modules' --exclude='rea-web/frontend/node_modules' \
    --exclude='rea-web/frontend/dist' --exclude='rea-web/backend/data' \
    --exclude='rea-web/backend/uploads' --exclude='rea-web/backend/.env' \
    -czf /root/web-re-engine-src.tgz rea-web
  ```

  Copy it to the new server and unpack it:

  ```bash
  scp root@<old-server>:/root/web-re-engine-src.tgz /root/      # run on the new server
  cd /root && tar -xzf web-re-engine-src.tgz                    # creates /root/rea-web
  ```

**Install dependencies and build the web UI:**

```bash
cd /root/rea-web
cd backend && npm ci && cd ..
cd frontend && npm ci && npm run build && cd ..
```

`npm ci` in `backend/` compiles the SQLite module, which needs `build-essential` from step 1. The
production service serves `frontend/dist`, so the build must succeed before step 9.

Headless Chromium (web-page analysis and PDF reports) must match the backend's `playwright-core`
version, so install it with the backend's own copy. `npx playwright` may be a different version
and download a browser the backend can't use.

```bash
cd /root/rea-web/backend
node node_modules/playwright-core/cli.js install --with-deps chromium
```

On Ubuntu 25.04 this prints `BEWARE: your OS is not officially supported by Playwright` and uses the
Ubuntu 24.04 builds; that is expected and works.

**Check the whole installation** before going further. The test suite starts its own temporary
backend and exercises every analyzer against the tools from steps 1–6. All tests should pass, and
none should be skipped if every optional tool was installed:

```bash
cd /root/rea-web/backend && npm run typecheck && npm test
```

### 8. Admin password

```bash
cd /root/rea-web/backend
npm run set-password          # prompts twice; at least 12 characters
```

This writes `WEB_RE_ADMIN_PASSWORD_HASH` (scrypt) to `backend/.env` (mode 0600). For unattended
setups, `WEB_RE_NEW_PASSWORD='…' npm run set-password` skips the prompt. Run it again to change the
password, then restart the backend (`systemctl restart web-re-engine` once step 9 is done). Until a
password is set, every API call answers "Authentication not configured".

When moving from an old server and you want to keep the same password, copy just that line instead:

```bash
ssh root@<old-server> "grep '^WEB_RE_ADMIN_PASSWORD_HASH=' /root/rea-web/backend/.env" > /root/rea-web/backend/.env
chmod 600 /root/rea-web/backend/.env
```

### 9. Run as a service behind HTTPS

This makes the app permanent: it starts at boot, restarts after a crash, and is reached at
`https://<server>/`. (For development instead, see [Development](#development); don't run both,
they use the same port 3001.)

#### 9a. Backend service

```bash
cp /root/rea-web/deploy/web-re-engine.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now web-re-engine
systemctl status web-re-engine --no-pager        # "active (running)"
```

The service runs `tsx src/app.ts` from `/root/rea-web/backend` with `NODE_ENV=production`: the
backend serves the built frontend, listens on `127.0.0.1:3001` only (not reachable from other
machines without Caddy), restarts on failure, starts at boot, and is limited to 3 GB of memory.
If you installed the project somewhere other than `/root/rea-web`, edit `WorkingDirectory` in the
unit file first.

Check it before adding Caddy:

```bash
curl -s http://127.0.0.1:3001/api/auth/me      # {"success":true,…,"authConfigured":true,…}
curl -s http://127.0.0.1:3001/ | grep -o '<title>.*</title>'      # <title>Web RE Engine</title>
```

`authConfigured:false` means step 8 was skipped; `Cannot GET /` means the frontend wasn't built (step 7).

#### 9b. Point the Caddyfile at your server

`deploy/Caddyfile` ships with the addresses of the original server. Its site line looks like
`https://192.168.40.61:443, https://37.19.211.48:443 {`. Replace it with **one** of these:

```bash
cd /root/rea-web/deploy

# (1) Reached by IP address on your network, self-signed certificate:
LAN_IP=$(hostname -I | awk '{print $1}')
sed -i -E "s#^https://[^{]+\{#https://$LAN_IP:443 {#" Caddyfile

# (2) Same, plus a public IP (cloud server, or router forwarding ports 80/443 to this machine):
PUBLIC_IP=$(curl -s https://api.ipify.org)
sed -i -E "s#^https://[^{]+\{#https://$LAN_IP:443, https://$PUBLIC_IP:443 {#" Caddyfile

# (3) A domain whose DNS points at this server: a real Let's Encrypt certificate, no browser warning
DOMAIN=re.example.com
sed -i -E "s#^https://[^{]+\{#$DOMAIN {#; /^\s*tls internal\s*$/d" Caddyfile

grep -nE '^(https://|[a-z0-9.-]+ \{)' Caddyfile      # shows the site line you now have
```

Variants (1) and (2) use Caddy's internal certificate authority (`tls internal`). Variant (3) removes
that line so Caddy obtains a certificate from Let's Encrypt automatically, which needs ports 80 and
443 reachable from the internet.

#### 9c. Start Caddy

```bash
cp /root/rea-web/deploy/Caddyfile /etc/caddy/Caddyfile
caddy validate --config /etc/caddy/Caddyfile          # "Valid configuration"
systemctl enable --now caddy
systemctl restart caddy
systemctl is-active caddy                             # "active"
```

Caddy terminates TLS, redirects HTTP to HTTPS, adds security headers (HSTS, nosniff, no-referrer,
frame-deny), allows request bodies up to 520 MB, and proxies everything (including the `/ws`
WebSocket) to the backend. The Caddyfile's global `skip_install_trust` option stops Caddy from
trying to add its root certificate to the server's own trust store (it would log a `sudo` error;
the certificate is meant for browsers, not the server).

#### 9d. Firewall and port forwarding

Ports 80 and 443 must be reachable from the computers that use the app. Port 3001 must **not**
be opened; only Caddy talks to it.

```bash
ufw status        # if "Status: active":
ufw allow 80/tcp && ufw allow 443/tcp
```

For a public IP behind a router (NAT), forward TCP 80 and 443 to this server. On a cloud server,
allow them in the provider's security group/firewall.

#### 9e. Certificate (IP-address setups only)

**Trusting the self-signed certificate.** With IP addresses, Caddy's internal authority issues
short-lived certificates (12 hours, renewed automatically). Clicking through the browser warning
works, but may have to be repeated. To get rid of the warning for good, trust Caddy's root
certificate (valid 10 years) once on each computer that uses the app:

```bash
# on the server: the root certificate (public, safe to share)
cp /var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt /root/web-re-engine-root-ca.crt
openssl x509 -in /root/web-re-engine-root-ca.crt -noout -subject -fingerprint -sha256
# on your computer:
scp root@<server>:/root/web-re-engine-root-ca.crt .
```

Then import it as a trusted root on your computer, and compare the SHA-256 fingerprint with the one printed on the server:

| System | How to import |
|---|---|
| Windows | `certutil -addstore -f Root web-re-engine-root-ca.crt` in an administrator prompt, or double-click → Install Certificate → Local Machine → Trusted Root Certification Authorities |
| macOS | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain web-re-engine-root-ca.crt` |
| Linux | copy to `/usr/local/share/ca-certificates/` and run `update-ca-certificates` |
| Firefox (own store) | Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import |

Restart the browser afterwards. The root stays the same as long as `/var/lib/caddy` is kept, so back
that directory up too, or browsers will warn again after a reinstall.

#### 9f. Verify the deployment

Run these on the server (replace `<server>` with the IP or domain from 9b; `-k` accepts the
self-signed certificate):

```bash
S=<server>
curl -sk https://$S/ | grep -o '<title>.*</title>'                       # <title>Web RE Engine</title>
curl -s -o /dev/null -w '%{http_code} -> %{redirect_url}\n' http://$S/  # 308 -> https://<server>/
curl -skI https://$S/ | grep -iE 'strict-transport|x-frame'             # both headers present
curl -sk -o /dev/null -w '%{http_code}\n' https://$S/api/jobs           # 401 (login required)
echo | openssl s_client -connect $S:443 2>/dev/null | openssl x509 -noout -issuer -ext subjectAltName
systemctl is-enabled web-re-engine caddy                                # enabled, enabled
```

Then open `https://<server>/` in a browser, log in, and check that the engine indicators in the
navbar are green (radare2, YARA, Browser, Sandbox; hover "+N tools" for the rest). Upload any small
executable to confirm a job completes.

### 10. AI explanations (optional)

Open **Settings** in the web UI, pick a provider, enter the model id and API key, click
**Test connection**, then **Save**.

| Provider | Base URL |
|---|---|
| Anthropic (Claude) | built in (default model `claude-opus-5-5`) |
| OpenAI | `https://api.openai.com/v1` |
| Google Gemini | `https://generativelanguage.googleapis.com/v1beta/openai` |
| OpenRouter | `https://openrouter.ai/api/v1` |
| Mistral | `https://api.mistral.ai/v1` |
| Groq | `https://api.groq.com/openai/v1` |
| DeepSeek | `https://api.deepseek.com/v1` |
| Ollama (local, no key) | `http://localhost:11434/v1` |
| LM Studio (local, no key) | `http://localhost:1234/v1` |
| Anything else that speaks the OpenAI Chat Completions API | its `/v1` base URL |

- Anthropic is called through the official SDK. On current Claude models it uses adaptive thinking,
  prompt caching, and the server-side refusal fallback, so security content that a model declines is
  retried on a fallback model.
- Other providers are called via streaming `POST <base URL>/chat/completions` with a bearer key.
- Keys are encrypted at rest (AES-256-GCM) with a key generated in `backend/data/secret.key` (or
  derived from `WEB_RE_SECRET_KEY`), and the browser only ever sees the last four characters.
- If nothing is configured in Settings, `ANTHROPIC_API_KEY` in `backend/.env` is used as a fallback.
- AI requests are limited to 30 per 10 minutes, and connection tests to 20 per 10 minutes.

Explaining a sample sends its analysis data (hashes, imports, strings, IOCs with secrets masked,
pseudo-code or one extracted file) to the configured provider. Use a local model (Ollama) if
samples must not leave your network.

---

## Using it

- **New analysis (Home):**
  - Pick a target type, or **Auto-detect**, which recognizes APK, .NET, PE/ELF/Mach-O, CRX/XPI extensions, zip/asar/tar archives and JavaScript files from their content.
  - In Auto-detect you can drop up to 50 files at once; each becomes its own job, and unsupported files are listed and deleted.
  - For extensions, either upload a package or paste a Chrome Web Store / Edge Add-ons link or 32-letter id, or a Firefox Add-ons link or slug. The server downloads the current version; nothing is installed or run.
  - The maximum upload size is 500 MB.
- **Job page:**
  - Live progress, then the results for that type, an Overview panel (hashes, VirusTotal link, IOCs, YARA hits, capa capabilities), limitations, and evidence.
  - **Code & Artifact Explorer** browses every extracted, decompiled or unpacked file. Large and binary files are shown in pages (1 MB of text or 64 KB of hex at a time) with Prev/Next and a jump-to-offset box.
  - **Search** covers functions, pseudo-code, disassembly, strings, imports, IOCs, YARA hits and extracted files. Function results jump to the function; file results open the file.
  - **Notes** (Markdown) and **tags** are saved with the job and included in reports.
  - **Markdown** / **PDF** buttons download a report.
  - **Re-run** analyzes the same uploaded file again with the current tools. Use it after installing or upgrading a tool.
  - **Explain with AI** works for the whole sample, the selected function (below the Disassembly Studio), or the open file (below the explorer).
- **Jobs & History:** filter by tag, tick two completed jobs and click **Compare** to see added/removed imports, functions, strings, IOCs, permissions, YARA rules and more, and delete jobs (with confirmation; deleting removes the job's files unless another job still uses them).
- **Settings:** the AI provider.

---

## Configuration reference (`backend/.env`)

The backend reads `backend/.env` at startup. Variables already set in the environment take precedence.

| Variable | Default | Purpose |
|---|---|---|
| `WEB_RE_ADMIN_PASSWORD_HASH` | (none: API refuses all requests) | Written by `npm run set-password` |
| `WEB_RE_NEW_PASSWORD` | | Used by `npm run set-password` instead of prompting |
| `PORT` / `HOST` | `3001` / `127.0.0.1` in production, `0.0.0.0` otherwise | Backend listen address |
| `NODE_ENV` | | `production` serves `frontend/dist` and binds to localhost |
| `REA_MAX_CONCURRENCY` | `2` | Analyses running at the same time |
| `WEB_RE_RETENTION_DAYS` | `30` | Hourly cleanup deletes jobs (and their files) older than this; `0` keeps everything. Files not belonging to any job are never deleted |
| `WEB_RE_SANDBOX` | on | `off` runs tools without bubblewrap (not recommended) |
| `REA_ALLOW_PRIVATE_URLS` | `false` | Allow web-page analysis and store downloads to reach private/internal addresses |
| `WEB_RE_SECRET_KEY` | (random `data/secret.key`) | Key used to encrypt stored API keys |
| `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN`, `WEB_RE_AI_MODEL` | | AI fallback when nothing is configured in Settings |
| `R2GHIDRA_SLEIGH_HOME` | auto-detected | Location of r2ghidra's processor specs |
| `WEB_RE_CAPA_MAX_MB` | `24` | Largest program capa will analyze |
| `WEB_RE_CAPA_MEMORY_MB` | `3072` | Memory limit for one capa run |
| `WEB_RE_CAPA_TIMEOUT_MIN` | `15` | Time limit for one capa run |
| `WEB_RE_DATA_DIR`, `WEB_RE_UPLOADS_DIR` | `backend/data`, `backend/uploads` | Storage locations |
| `FRONTEND_URL` | `http://localhost:5173` | CORS origin in development |

Fixed limits:
- Uploads: 500 MB each, 50 files per bulk upload.
- Extraction: 2,000 files, 500 MB total, 200 MB per file.
- Extension store downloads: 100 MB.
- Native analysis: disassembly and pseudo-code are shown for up to 150 functions per binary (entry/main first).

**YARA rules:**
- **Built in:** `backend/rules/builtin/` covers packers and installers, suspicious capabilities (injection, keylogging, credential and wallet theft, persistence, anti-debug/VM, ransomware, encoded PowerShell), crypto constants and Android abuse.
- **Your own:** put `.yar` files in `backend/rules/custom/`, optionally with `description`, `severity` (`low`/`medium`/`high`) and `category` meta.
- **Bad rule files:** a file that fails to compile is skipped and reported on the job page; it does not disable the others.

---

## API

All endpoints are under `/api` and, except `/api/auth/*`, need the session cookie from login.
State-changing requests from another origin are rejected. Responses are
`{ "success": true, "data": … }` or `{ "success": false, "error": "…" }`.

| Method & path | Purpose |
|---|---|
| `POST /api/auth/login` `{password}` · `POST /api/auth/logout` · `GET /api/auth/me` | Session |
| `POST /api/analysis/auto` (multipart `file`) · `POST /api/analysis/bulk` (multipart `files`, ≤ 50) | Auto-detected jobs |
| `POST /api/analysis/{native,javascript,dotnet,android,extension}` (multipart `file`) | Typed upload |
| `POST /api/analysis/extension/store` `{ref, browser}` | Download from a store and analyze |
| `POST /api/analysis/browser` `{url}` · `POST /api/analysis/evm` `{source, value, network?}` | URL / contract jobs |
| `GET /api/jobs` · `GET /api/jobs/:id` · `DELETE /api/jobs/:id` · `POST /api/jobs/:id/rerun` | Jobs |
| `PATCH /api/jobs/:id` `{notes?, tags?}` | Notes and tags |
| `GET /api/jobs/:id/search?q=` | Search within a job |
| `GET /api/jobs/:id/report?format=md\|html\|pdf` | Report download |
| `POST /api/jobs/:id/explain` `{scope: 'job'} \| {scope: 'function', address} \| {scope: 'file', path}` | AI explanation (server-sent events) |
| `GET /api/files/:jobId?path=&offset=` | Browse the job workspace / read a file window |
| `GET /api/compare?a=&b=` | Compare two jobs |
| `GET /api/status` | Available tools, sandbox, AI, disk usage |
| `GET/PUT/DELETE /api/settings/ai` · `POST /api/settings/ai/test` | AI provider settings |

Live progress: open a WebSocket to `/ws` (with the session cookie) and send
`{"type":"subscribe","jobId":"…"}`; events are `job:started`, `job:progress`, `job:completed`,
`job:failed` and `job:updated` (late results such as capa).

---

## Operations

**Day-to-day:**

| Task | Command |
|---|---|
| Backend logs | `journalctl -u web-re-engine -f` |
| Caddy logs | `journalctl -u caddy -f` |
| Restart the backend (after changing `.env`, the password or rules) | `systemctl restart web-re-engine` |
| Apply a changed Caddyfile | `cp deploy/Caddyfile /etc/caddy/Caddyfile && systemctl reload caddy` |
| Stop / start everything | `systemctl stop web-re-engine caddy` / `systemctl start web-re-engine caddy` |

**Moving to another server:** package the source as in step 7 (option B), and copy
`backend/data/` (database and `secret.key`), `backend/.env` and, to keep browsers trusting the
certificate, `/var/lib/caddy`. Then follow the installation steps on the new server.

**Back up:**
- `backend/data/rea.db` (jobs, sessions, settings) and `backend/data/secret.key`. Without `secret.key`, saved AI keys can't be decrypted after a restore.
- `backend/.env` (password hash and settings).
- `backend/uploads/` (samples and extracted workspaces; large).
- `backend/rules/custom/`.
- `/var/lib/caddy` (Caddy's internal certificate authority), if browsers trust its root certificate.

**Update the application:**

```bash
cd /root/rea-web && git pull
cd backend && npm ci && cd ../frontend && npm ci && npm run build && cd ..
# if playwright-core changed version:
node backend/node_modules/playwright-core/cli.js install chromium
systemctl restart web-re-engine
```

Existing jobs keep their old results; use **Re-run** to analyze them with new tools or rules.

**After installing or upgrading an analysis tool:** no restart is needed. A missing tool is
re-checked every 5 minutes. Re-run jobs to use it.

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| "Authentication not configured" | Run `npm run set-password` in `backend/`, then restart the backend |
| "Too many login attempts" | 10 failed logins per 15 minutes per address; wait |
| "Forbidden: CSRF check failed" | A proxy changed the `Host` header. Caddy keeps it; in development the Vite proxy is configured with `changeOrigin: false` for the same reason |
| Pseudo-code says "radare2 pdc (approximate)" | r2ghidra not installed or built for a different radare2 version (step 4) |
| `Cannot find the sleigh home` | Harmless for the app (it passes the path itself); create the `/usr/lib/radare2/<version>/r2ghidra_sleigh` link from step 4 to silence it, or set `R2GHIDRA_SLEIGH_HOME` |
| capa "ran out of memory" / "did not finish" | Program too large for the limits: raise `WEB_RE_CAPA_MEMORY_MB` / `WEB_RE_CAPA_TIMEOUT_MIN` on a bigger server, or accept the skip |
| capa "was not installed yet when this job ran" | The job predates the install: **Re-run** it |
| Web-page analysis falls back to "basic HTTP" | Chromium missing or the wrong version: install it with the backend's `playwright-core` (step 7) |
| Inno Setup installer shows only `.text`, `.rsrc`… | innoextract missing or the Inno version is unsupported: install/upgrade `innoextract` |
| "pycdc does not support this Python version yet" | Expected for very new Python versions; use the `.pyc` files and `*.strings.txt`, or the AI explanation |
| Sandbox shown as offline in the navbar | `bubblewrap` missing or user namespaces disabled; tools then run unsandboxed |
| `https://<server>/` doesn't load at all | Check `systemctl is-active caddy`, that the site line in `/etc/caddy/Caddyfile` has the address you are using (9b), and that ports 80/443 are open and forwarded (9d) |
| Caddy shows **502 Bad Gateway** | The backend isn't running: `systemctl status web-re-engine` and `journalctl -u web-re-engine -n 50` |
| `web-re-engine` keeps restarting / `EADDRINUSE` | Something else holds port 3001, usually `./start.sh` from development. Stop it (`fuser -k 3001/tcp 5173/tcp`), then `systemctl restart web-re-engine` |
| The page loads but shows `Cannot GET /` | `frontend/dist` is missing: `cd frontend && npm run build`, then restart the service |
| Browser certificate warning keeps coming back | Expected with IP addresses (12-hour certificates). Trust Caddy's root certificate once (9e), or use a domain with Let's Encrypt (9b, variant 3) |
| Warning returned after a reinstall | `/var/lib/caddy` was not kept, so Caddy created a new root certificate: import the new one (9e), and back up `/var/lib/caddy` |
| Let's Encrypt certificate not issued (domain setup) | The domain's DNS must point at the server and ports 80/443 must be reachable from the internet; see `journalctl -u caddy` |

---

## Development

```bash
./start.sh        # backend on :3001 (auto-reload) + Vite on :5173 (all interfaces) with /api and /ws proxied
```

The development servers are not for production: they stop when the terminal closes and serve
unminified code. Use the systemd service for anything long-running.

| Command (in `backend/`) | Purpose |
|---|---|
| `npm run dev` | Backend with auto-reload |
| `npm run start:prod` | Backend in production mode without systemd |
| `npm run typecheck` | Type-check the backend |
| `npm test` | Test suite |
| `npm run set-password` | Set the admin password |

Frontend (`frontend/`): `npm run dev`, `npm run build` (type-checks, then builds to `dist/`).

The test suite:
- **Isolation:** it starts its own backend on a random port with a temporary database and uploads
  folder, never touches `backend/data` or `backend/uploads`, and never calls a real AI provider.
- **Fixtures:** it builds them at run time: a C binary, a UPX-packed copy, a real Python PYZ archive,
  malicious and benign browser extensions, and hostile archives.
- **Tool dependencies:** tests needing gcc, upx, radare2, yara, or the .NET SDK with ilspycmd are skipped when those are missing.
  The extractor tests need 7z, tar and python3.

---

## Security model

- **Login:** a single admin account, 12-hour sessions in SQLite, and `HttpOnly` + `SameSite=Strict` cookies (`Secure` over HTTPS). Login is limited to 10 attempts per 15 minutes. Cross-origin state-changing requests and WebSocket upgrades are rejected.
- **Sandbox:** every analyzer that reads uploaded data runs through `systemd-run` (memory, CPU and task limits) and `bubblewrap`: no network, read-only system directories, and only the job's own input and output paths are visible.
- **Extraction:**
  - Archives are listed before extracting, and the limits above are enforced.
  - Entries with `..`, absolute paths or links are refused.
  - Symlinks are removed after extraction, and the file viewer resolves real paths so nothing outside a job's workspace can be read.
- **Server-side requests:** web-page analysis checks every request the page makes, and store downloads check every redirect hop. Private, loopback and link-local addresses are refused unless `REA_ALLOW_PRIVATE_URLS=true`.
- **Secrets:** AI provider keys are encrypted at rest and never returned to the browser. Leaked secrets found in samples are masked in the UI, in reports and in AI prompts.
- **Untrusted content:**
  - AI prompts mark all sample content as untrusted data.
  - Markdown from AI output and notes is rendered with raw HTML escaped, images dropped and only `http(s)` links allowed.
  - Reports are generated by Chromium with JavaScript and network access disabled, and are always served as downloads.

Dynamic analysis (actually running samples) is intentionally not implemented; everything is static.
