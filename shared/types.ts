// Shared types between frontend and backend

export type AnalysisType =
  | 'javascript'
  | 'native'
  | 'browser'
  | 'dotnet'
  | 'android'
  | 'evm'
  | 'extension';

export type JobStatus = 'queued' | 'running' | 'completed' | 'failed';

export interface FileFingerprint {
  md5: string;
  sha1: string;
  sha256: string;
  size: number;
  entropy: number;
}

export interface AnalysisJob {
  id: string;
  type: AnalysisType;
  status: JobStatus;
  createdAt: string;
  updatedAt: string;
  input: AnalysisInput;
  result?: AnalysisResult;
  extractedPath?: string;
  fileTree?: FileTreeNode[];
  error?: string;
  progress?: number; // 0-100
  logs?: string[];
  fingerprint?: FileFingerprint;
  iocs?: Record<string, string[]>;
  yara?: YaraResult;
  capabilities?: CapaResult;
  notes?: string;
  tags?: string[];
  // Saved AI explanations keyed by scope: 'job', 'fn:<address>', 'file:<path>'
  explanations?: Record<string, AiExplanation>;
}

export interface AiExplanation {
  text: string;
  model: string;
  createdAt: string;
  // Set when a refusal was answered by a fallback model, or the whole chain refused
  note?: string;
}

export type ExplainScope =
  | { scope: 'job' }
  | { scope: 'function'; address: string }
  | { scope: 'file'; path: string };

export interface FileTreeNode {
  name: string;
  path: string; // relative or key
  type: 'file' | 'directory';
  size?: number;
  children?: FileTreeNode[];
}

// ---------- Inputs ----------

export type AnalysisInput =
  | JavaScriptInput
  | NativeInput
  | BrowserInput
  | DotNetInput
  | AndroidInput
  | EvmInput
  | ExtensionInput;

export interface JavaScriptInput {
  type: 'javascript';
  fileName: string;
  fileSize: number;
  filePath?: string; // server-side temp path
}

export interface NativeInput {
  type: 'native';
  fileName: string;
  fileSize: number;
  filePath?: string;
  provider?: 'ghidra' | 'hopper' | 'ida' | 'auto';
}

export interface BrowserInput {
  type: 'browser';
  url: string;
  captureNetworkTraffic: boolean;
  captureScreenshot: boolean;
}

export interface DotNetInput {
  type: 'dotnet';
  fileName: string;
  fileSize: number;
  filePath?: string;
}

export interface AndroidInput {
  type: 'android';
  fileName: string;
  fileSize: number;
  filePath?: string;
  useAdb?: boolean;
  deviceId?: string;
}

export interface EvmInput {
  type: 'evm';
  source: 'address' | 'bytecode';
  value: string; // contract address or raw hex bytecode
  network?: string; // e.g. 'mainnet', 'sepolia'
}

export interface ExtensionInput {
  type: 'extension';
  fileName: string;
  fileSize: number;
  filePath?: string;
  // Set when the package was downloaded from a store rather than uploaded
  store?: { browser: 'chrome' | 'firefox'; id: string };
}

// ---------- Results ----------

export type AnalysisResult =
  | JavaScriptResult
  | NativeResult
  | BrowserResult
  | DotNetResult
  | AndroidResult
  | EvmResult
  | ExtensionResult;

// ---- JavaScript ----

export interface JavaScriptResult {
  type: 'javascript';
  summary: string;
  modules: JsModule[];
  entryPoints: string[];
  electronBoundaries?: ElectronBoundary[];
  imports: ImportEdge[];
  evidence: Evidence[];
  limitations: string[];
}

export interface JsModule {
  id: string;
  path: string;
  size: number;
  exports: string[];
  isEntry: boolean;
  isElectronMain?: boolean;
  isElectronRenderer?: boolean;
}

export interface ImportEdge {
  from: string;
  to: string;
  isDynamic: boolean;
}

export interface ElectronBoundary {
  type: 'ipcMain' | 'ipcRenderer' | 'contextBridge';
  channel?: string;
  location: SourceLocation;
}

export type PackerKind = 'pyinstaller' | 'nsis' | 'inno' | 'upx' | 'sfx-7z' | 'sfx-zip' | 'none';

export interface PackerInfo {
  kind: PackerKind;
  details: string;
  version?: string;
  entryPoints?: string[];
  extractedCount?: number;
  // PyInstaller only: modules found in the PYZ archive
  pythonModules?: { thirdParty: string[]; stdlibCount: number };
  // PyInstaller only: how .pyc files were turned into readable output
  pythonDecompiler?: 'pycdc' | 'pycdas' | 'none';
}

export interface NativeResult {
  type: 'native';
  format: 'PE' | 'ELF' | 'Mach-O' | 'unknown';
  architecture: string;
  provider: string;
  entryPoint?: string;
  functions: NativeFunction[];
  imports: NativeImport[];
  exports: NativeExport[];
  strings: StringEntry[];
  sections: BinarySection[];
  evidence: Evidence[];
  limitations: string[];
  packer?: PackerInfo;
  // Which engine produced NativeFunction.decompiledCode
  decompiler?: 'r2ghidra' | 'r2-pdc' | 'none';
}

export interface NativeFunction {
  address: string;
  name: string;
  size: number;
  disassembly?: DisassemblyLine[];
  decompiledCode?: string;
  callers: string[];
  callees: string[];
}

export interface DisassemblyLine {
  address: string;
  bytes: string;
  mnemonic: string;
  operands: string;
  comment?: string;
}

export interface NativeImport {
  library: string;
  name: string;
  address?: string;
}

export interface NativeExport {
  name: string;
  address: string;
  ordinal?: number;
}

export interface StringEntry {
  value: string;
  address: string;
  encoding: 'ascii' | 'utf16' | 'utf8';
}

export interface BinarySection {
  name: string;
  address: string;
  size: number;
  permissions: string;
  offset?: number;
  entropy?: number;
}

// ---- Browser ----

export interface BrowserResult {
  type: 'browser';
  url: string;
  title?: string;
  screenshot?: string; // base64
  networkRequests: NetworkRequest[];
  scriptSources: ScriptSource[];
  cookies: Cookie[];
  localStorage?: Record<string, string>;
  evidence: Evidence[];
  limitations: string[];
}

export interface NetworkRequest {
  url: string;
  method: string;
  statusCode?: number;
  requestHeaders: Record<string, string>;
  responseHeaders?: Record<string, string>;
  contentType?: string;
  size?: number;
  timing?: number; // ms
}

export interface ScriptSource {
  url: string;
  content?: string;
  sourceMapped?: boolean;
  size: number;
}

export interface Cookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: string;
}

// ---- .NET ----

export interface DotNetResult {
  type: 'dotnet';
  targetFramework: string;
  namespaces: DotNetNamespace[];
  evidence: Evidence[];
  limitations: string[];
}

export interface DotNetNamespace {
  name: string;
  types: DotNetType[];
}

export interface DotNetType {
  name: string;
  fullName: string;
  kind: 'class' | 'interface' | 'struct' | 'enum' | 'delegate';
  methods: DotNetMethod[];
  fields: DotNetField[];
  properties: DotNetProperty[];
  baseType?: string;
  interfaces: string[];
}

export interface DotNetMethod {
  name: string;
  returnType: string;
  parameters: DotNetParameter[];
  isPublic: boolean;
  isStatic: boolean;
  ilCode?: string;
  decompiledCode?: string;
}

export interface DotNetField {
  name: string;
  type: string;
  isPublic: boolean;
  isStatic: boolean;
}

export interface DotNetProperty {
  name: string;
  type: string;
  hasGetter: boolean;
  hasSetter: boolean;
}

export interface DotNetParameter {
  name: string;
  type: string;
}

// ---- Android ----

export interface AndroidResult {
  type: 'android';
  packageName: string;
  version: string;
  targetSdk?: number;
  minSdk?: number;
  permissions: string[];
  activities: AndroidComponent[];
  services: AndroidComponent[];
  receivers: AndroidComponent[];
  providers: AndroidComponent[];
  classes: AndroidClass[];
  evidence: Evidence[];
  limitations: string[];
}

export interface AndroidComponent {
  name: string;
  exported: boolean;
  intentFilters: string[];
}

export interface AndroidClass {
  name: string;
  superClass?: string;
  methods: string[];
  decompiledCode?: string;
  smaliCode?: string;
}

// ---- EVM ----

export interface EvmResult {
  type: 'evm';
  bytecodeLength: number;
  functionSelectors: FunctionSelector[];
  opcodes: EvmOpcode[];
  controlFlow: ControlFlowBlock[];
  evidence: Evidence[];
  limitations: string[];
}

export interface FunctionSelector {
  selector: string;
  possibleSignatures: string[];
}

export interface EvmOpcode {
  offset: number;
  opcode: string;
  operand?: string;
}

export interface ControlFlowBlock {
  start: number;
  end: number;
  successors: number[];
  predecessors: number[];
}

// ---------- Shared ----------

export interface Evidence {
  kind: 'code' | 'reference' | 'pattern' | 'string' | 'network';
  description: string;
  location?: SourceLocation;
  snippet?: string;
  confidence: 'high' | 'medium' | 'low';
}

export interface SourceLocation {
  file?: string;
  line?: number;
  column?: number;
  address?: string;
}

// ---------- API ----------

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}

export interface CreateJobRequest {
  type: AnalysisType;
  options?: Record<string, unknown>;
}

export interface EngineStatus {
  javascript: boolean;
  ghidra: boolean;
  radare2: boolean;
  hopper: boolean;
  ida: boolean;
  playwright: boolean;
  adb: boolean;
  ilspy: boolean;
  apktool: boolean;
  yara?: boolean;
  upx?: boolean;
  capa?: boolean;
  pycdc?: boolean;
  r2ghidra?: boolean;
  // ANTHROPIC_API_KEY configured for AI explanations
  ai?: boolean;
  sandbox?: boolean;
  uploadsBytes?: number;
}

// ---------- WebSocket Events ----------

export type WsMessage =
  | { event: 'job:progress'; jobId: string; progress: number; log: string }
  | {
      event: 'job:completed';
      jobId: string;
      result: AnalysisResult;
      fingerprint?: FileFingerprint;
      iocs?: Record<string, string[]>;
      yara?: YaraResult;
      capabilities?: CapaResult;
    }
  | { event: 'job:failed'; jobId: string; error: string }
  | { event: 'job:updated'; jobId: string; patch: Partial<AnalysisJob> }
  | { event: 'job:started'; jobId: string };

// ---------- YARA / capa ----------

export interface YaraStringMatch {
  offset: number;
  identifier: string;
  data: string;
}

export interface YaraMatch {
  rule: string;
  meta: Record<string, string>;
  // Path relative to the job workspace, or the uploaded file name
  file: string;
  strings: YaraStringMatch[];
}

export interface YaraResult {
  matches: YaraMatch[];
  rulesLoaded: number;
  errors: string[];
}

export interface CapaCapability {
  name: string;
  namespace?: string;
  attack: string[];
  mbc: string[];
}

export interface CapaResult {
  available: boolean;
  capabilities: CapaCapability[];
  error?: string;
  // capa can take minutes on large binaries, so it finishes after the job does
  pending?: boolean;
  // Which file capa analyzed (e.g. the main program inside an installer), relative to the workspace
  target?: string;
  // Why capa was not run on this job
  skipped?: string;
}

// ---- Browser extensions ----

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export interface ExtensionPermission {
  name: string;
  risk: RiskLevel;
  reason: string;
  // Declared as optional_permissions / optional_host_permissions (requested at runtime)
  optional?: boolean;
}

export interface ExtensionContentScript {
  matches: string[];
  excludeMatches: string[];
  js: string[];
  css: string[];
  runAt?: string;
  allFrames: boolean;
  world?: string;
}

export interface ExtensionCodeLocation {
  file: string;
  line: number;
  snippet: string;
}

export interface ExtensionFinding {
  id: string;
  title: string;
  severity: RiskLevel;
  category: string;
  description: string;
  locations: ExtensionCodeLocation[];
}

export interface ExtensionApiUsage {
  // e.g. "cookies.getAll"
  api: string;
  count: number;
  files: string[];
}

export interface ExtensionResult {
  type: 'extension';
  browser: 'chrome' | 'firefox' | 'unknown';
  packageFormat: 'crx3' | 'crx2' | 'xpi' | 'zip';
  name: string;
  version: string;
  description?: string;
  manifestVersion: number;
  // Gecko id for Firefox, store id when downloaded from the Chrome Web Store
  extensionId?: string;
  permissions: ExtensionPermission[];
  hostPermissions: ExtensionPermission[];
  contentScripts: ExtensionContentScript[];
  background: { kind: 'service_worker' | 'scripts' | 'page' | 'none'; files: string[] };
  externallyConnectable?: { matches: string[]; ids: string[] };
  webAccessibleResources: string[];
  csp?: string;
  updateUrl?: string;
  offStoreUpdates: boolean;
  overrides: string[];
  apiUsage: ExtensionApiUsage[];
  findings: ExtensionFinding[];
  obfuscatedFiles: { file: string; reason: string }[];
  riskScore: number;
  riskLevel: RiskLevel;
  riskReasons: string[];
  filesScanned: number;
  evidence: Evidence[];
  limitations: string[];
}
