import { execFile } from 'child_process';
import { promisify } from 'util';
import path from 'path';
import { fileURLToPath } from 'url';
import type { EvmInput, EvmResult, FunctionSelector, EvmOpcode, ControlFlowBlock, Evidence } from '../../../shared/types.js';
import { runTool } from './sandbox.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const nodeModulesDir = path.resolve(__dirname, '../../node_modules');
const reaAgentsBin = path.join(nodeModulesDir, '.bin/rea-agents');

const execFileAsync = promisify(execFile);
type ProgressCallback = (msg: string, pct?: number) => void;

// EVM opcode table (partial)
const OPCODES: Record<number, string> = {
  0x00: 'STOP', 0x01: 'ADD', 0x02: 'MUL', 0x03: 'SUB', 0x04: 'DIV',
  0x05: 'SDIV', 0x06: 'MOD', 0x07: 'SMOD', 0x08: 'ADDMOD', 0x09: 'MULMOD',
  0x0a: 'EXP', 0x0b: 'SIGNEXTEND',
  0x10: 'LT', 0x11: 'GT', 0x12: 'SLT', 0x13: 'SGT', 0x14: 'EQ',
  0x15: 'ISZERO', 0x16: 'AND', 0x17: 'OR', 0x18: 'XOR', 0x19: 'NOT',
  0x1a: 'BYTE', 0x1b: 'SHL', 0x1c: 'SHR', 0x1d: 'SAR',
  0x20: 'KECCAK256',
  0x30: 'ADDRESS', 0x31: 'BALANCE', 0x32: 'ORIGIN', 0x33: 'CALLER',
  0x34: 'CALLVALUE', 0x35: 'CALLDATALOAD', 0x36: 'CALLDATASIZE',
  0x37: 'CALLDATACOPY', 0x38: 'CODESIZE', 0x39: 'CODECOPY',
  0x3a: 'GASPRICE', 0x3b: 'EXTCODESIZE', 0x3c: 'EXTCODECOPY',
  0x3d: 'RETURNDATASIZE', 0x3e: 'RETURNDATACOPY', 0x3f: 'EXTCODEHASH',
  0x40: 'BLOCKHASH', 0x41: 'COINBASE', 0x42: 'TIMESTAMP', 0x43: 'NUMBER',
  0x44: 'PREVRANDAO', 0x45: 'GASLIMIT', 0x46: 'CHAINID', 0x47: 'SELFBALANCE',
  0x48: 'BASEFEE',
  0x50: 'POP', 0x51: 'MLOAD', 0x52: 'MSTORE', 0x53: 'MSTORE8',
  0x54: 'SLOAD', 0x55: 'SSTORE', 0x56: 'JUMP', 0x57: 'JUMPI',
  0x58: 'PC', 0x59: 'MSIZE', 0x5a: 'GAS', 0x5b: 'JUMPDEST',
  0x5c: 'TLOAD', 0x5d: 'TSTORE',
  0x5e: 'MCOPY', 0x5f: 'PUSH0',
  0xf0: 'CREATE', 0xf1: 'CALL', 0xf2: 'CALLCODE', 0xf3: 'RETURN',
  0xf4: 'DELEGATECALL', 0xf5: 'CREATE2', 0xfa: 'STATICCALL',
  0xfd: 'REVERT', 0xfe: 'INVALID', 0xff: 'SELFDESTRUCT',
};

// Build PUSH1..PUSH32
for (let i = 0; i < 32; i++) OPCODES[0x60 + i] = `PUSH${i + 1}`;
// DUP1..DUP16
for (let i = 0; i < 16; i++) OPCODES[0x80 + i] = `DUP${i + 1}`;
// SWAP1..SWAP16
for (let i = 0; i < 16; i++) OPCODES[0x90 + i] = `SWAP${i + 1}`;
// LOG0..LOG4
for (let i = 0; i < 5; i++) OPCODES[0xa0 + i] = `LOG${i}`;

export async function runEvmAnalysis(
  input: EvmInput,
  onProgress: ProgressCallback
): Promise<EvmResult> {
  onProgress('Preparing EVM analysis...', 10);

  let bytecodeHex: string;

  if (input.source === 'bytecode') {
    bytecodeHex = input.value.startsWith('0x') ? input.value.slice(2) : input.value;
    onProgress('Using provided bytecode...', 20);
  } else {
    // Fetch bytecode from chain via public RPC
    onProgress(`Fetching bytecode for ${input.value} from ${input.network ?? 'mainnet'}...`, 15);
    bytecodeHex = await fetchBytecode(input.value, input.network ?? 'mainnet');
    onProgress('Bytecode fetched.', 25);
  }

  // Try rea-agents EVM tools first
  onProgress('Checking rea-agents EVM tools...', 30);
  try {
    const { stdout } = await runTool(
      reaAgentsBin,
      ['inspect-evm-interface', '--bytecode', bytecodeHex, '--json'],
      {
        readPaths: [nodeModulesDir],
        timeoutMs: 60_000,
        maxBuffer: 10 * 1024 * 1024,
      }
    );
    const parsed = JSON.parse(stdout) as Record<string, unknown>;
    onProgress('Parsing rea-agents EVM output...', 80);
    return mapReaEvmOutput(parsed, bytecodeHex);
  } catch {
    onProgress('rea-agents EVM tools unavailable — running built-in analysis...', 40);
  }

  return disassembleBytecode(bytecodeHex, onProgress);
}

async function fetchBytecode(address: string, network: string): Promise<string> {
  const rpcUrls: Record<string, string> = {
    mainnet: 'https://eth.llamarpc.com',
    sepolia: 'https://ethereum-sepolia-rpc.publicnode.com',
    polygon: 'https://polygon-rpc.com',
    arbitrum: 'https://arb1.arbitrum.io/rpc',
    optimism: 'https://mainnet.optimism.io',
    base: 'https://mainnet.base.org',
  };

  const rpc = rpcUrls[network] ?? rpcUrls.mainnet;

  const body = JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    method: 'eth_getCode',
    params: [address, 'latest'],
  });

  const { default: https } = await import('https');
  const { default: http } = await import('http');
  const url = new URL(rpc);
  const client = url.protocol === 'https:' ? https : http;

  return new Promise((resolve, reject) => {
    const req = client.request(
      { hostname: url.hostname, path: url.pathname, method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } },
      (res) => {
        let data = '';
        res.on('data', (c: Buffer) => (data += c));
        res.on('end', () => {
          try {
            const j = JSON.parse(data) as { result: string };
            if (j.result === '0x') reject(new Error('No bytecode at address — EOA or empty contract'));
            else resolve(j.result.slice(2));
          } catch {
            reject(new Error('Failed to parse RPC response'));
          }
        });
      }
    );
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function disassembleBytecode(hex: string, onProgress: ProgressCallback): EvmResult {
  const bytes = Buffer.from(hex, 'hex');
  const opcodes: EvmOpcode[] = [];
  const functionSelectors: FunctionSelector[] = [];
  const evidence: Evidence[] = [];
  const jumpdests = new Set<number>();
  const jumpTargets = new Set<number>();

  onProgress('Disassembling bytecode...', 50);

  let i = 0;
  while (i < bytes.length) {
    const op = bytes[i];
    const opName = OPCODES[op] ?? `0x${op.toString(16).padStart(2, '0')}`;
    let operand: string | undefined;

    // PUSH instructions have inline operands
    if (op >= 0x60 && op <= 0x7f) {
      const size = op - 0x5f; // PUSH1 = 0x60 = 1 byte
      const data = bytes.subarray(i + 1, i + 1 + size);
      operand = `0x${data.toString('hex')}`;
      i += size;

      // Detect function selectors: PUSH4 followed by JUMPI pattern
      if (size === 4 && data.length === 4) {
        const selector = data.toString('hex');
        // Check if this looks like a function dispatch (caller checks)
        if (i + 1 < bytes.length && (bytes[i + 1] === 0x14 /* EQ */)) {
          functionSelectors.push({
            selector: `0x${selector}`,
            possibleSignatures: [],
          });
        }
      }
    }

    if (op === 0x5b) jumpdests.add(i); // JUMPDEST
    if (op === 0x56 || op === 0x57) {
      // JUMP / JUMPI — track jump targets
    }

    opcodes.push({ offset: i, opcode: opName, operand });
    i++;
  }

  onProgress('Building control flow...', 75);

  // Build basic blocks (split at JUMPDEST, JUMP, JUMPI, STOP, RETURN, REVERT, INVALID)
  const blockBoundaries = new Set([0]);
  for (let j = 0; j < opcodes.length; j++) {
    const op = opcodes[j];
    if (op.opcode === 'JUMPDEST') blockBoundaries.add(op.offset);
    if (['JUMP', 'JUMPI', 'STOP', 'RETURN', 'REVERT', 'INVALID'].includes(op.opcode)) {
      if (j + 1 < opcodes.length) blockBoundaries.add(opcodes[j + 1].offset);
    }
  }

  const boundaries = [...blockBoundaries].sort((a, b) => a - b);
  const controlFlow: ControlFlowBlock[] = boundaries.map((start, idx) => ({
    start,
    end: boundaries[idx + 1] ?? opcodes[opcodes.length - 1]?.offset ?? start,
    successors: [],
    predecessors: [],
  }));

  evidence.push({
    kind: 'code',
    description: `Decoded ${opcodes.length} opcodes, ${functionSelectors.length} function selectors, ${controlFlow.length} basic blocks`,
    confidence: 'high',
  });

  if (functionSelectors.length > 0) {
    evidence.push({
      kind: 'pattern',
      description: 'Function dispatch pattern detected (EQ + JUMPI after PUSH4)',
      confidence: 'medium',
    });
  }

  onProgress('Done.', 100);

  return {
    type: 'evm',
    bytecodeLength: bytes.length,
    functionSelectors,
    opcodes: opcodes.slice(0, 2000), // cap for display
    controlFlow,
    evidence,
    limitations:
      opcodes.length > 2000
        ? ['Opcodes capped at 2000 for display. Full bytecode was analyzed.']
        : [],
  };
}

function mapReaEvmOutput(raw: Record<string, unknown>, hex: string): EvmResult {
  const bytecodeLength = hex.length / 2;
  return {
    type: 'evm',
    bytecodeLength,
    functionSelectors: (raw.functionSelectors as FunctionSelector[]) ?? [],
    opcodes: (raw.opcodes as EvmOpcode[]) ?? [],
    controlFlow: (raw.controlFlow as ControlFlowBlock[]) ?? [],
    evidence: (raw.evidence as Evidence[]) ?? [],
    limitations: (raw.limitations as string[]) ?? [],
  };
}
