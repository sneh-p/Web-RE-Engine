import React, { useState } from 'react';
import { Layers, Terminal, FunctionSquare } from 'lucide-react';
import type { EvmResult } from '@shared/types.js';

interface EvmResultsViewProps {
  result: EvmResult;
}

export const EvmResultsView: React.FC<EvmResultsViewProps> = ({ result }) => {
  const [activeTab, setActiveTab] = useState<'selectors' | 'opcodes'>('selectors');

  return (
    <div className="space-y-6">
      <div className="p-4 rounded-xl border border-rea-border bg-rea-surface grid grid-cols-2 md:grid-cols-3 gap-4 text-xs font-mono">
        <div>
          <span className="text-rea-muted block">Bytecode Size</span>
          <span className="text-white font-bold text-sm">{result.bytecodeLength} bytes</span>
        </div>
        <div>
          <span className="text-rea-muted block">Functions Identified</span>
          <span className="text-emerald-400 font-bold text-sm">
            {result.functionSelectors.length}
          </span>
        </div>
        <div>
          <span className="text-rea-muted block">Decoded Opcodes</span>
          <span className="text-white font-bold text-sm">{result.opcodes.length}</span>
        </div>
      </div>

      <div className="flex border-b border-rea-border space-x-4">
        <button
          onClick={() => setActiveTab('selectors')}
          className={`pb-2.5 text-sm font-medium transition flex items-center space-x-2 ${
            activeTab === 'selectors'
              ? 'border-b-2 border-rea-accent text-white'
              : 'text-rea-muted hover:text-white'
          }`}
        >
          <FunctionSquare className="w-4 h-4" />
          <span>Function Selectors ({result.functionSelectors.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('opcodes')}
          className={`pb-2.5 text-sm font-medium transition flex items-center space-x-2 ${
            activeTab === 'opcodes'
              ? 'border-b-2 border-rea-accent text-white'
              : 'text-rea-muted hover:text-white'
          }`}
        >
          <Terminal className="w-4 h-4" />
          <span>Disassembly ({result.opcodes.length})</span>
        </button>
      </div>

      {activeTab === 'selectors' && (
        <div className="space-y-2 max-h-[450px] overflow-y-auto">
          {result.functionSelectors.length === 0 ? (
            <div className="p-8 text-center text-rea-muted bg-rea-surface rounded-xl border border-rea-border">
              No four-byte function dispatch selectors found in contract bytecode.
            </div>
          ) : (
            result.functionSelectors.map((sel, idx) => (
              <div
                key={idx}
                className="p-3 bg-rea-surface rounded-lg border border-rea-border flex items-center justify-between font-mono text-xs"
              >
                <div className="flex items-center space-x-3">
                  <span className="text-emerald-400 font-bold">{sel.selector}</span>
                  {sel.possibleSignatures.length > 0 && (
                    <span className="text-rea-text">{sel.possibleSignatures[0]}</span>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {activeTab === 'opcodes' && (
        <div className="max-h-[450px] overflow-y-auto space-y-1 font-mono text-xs bg-rea-bg p-3 rounded-xl border border-rea-border">
          {result.opcodes.map((op, idx) => (
            <div key={idx} className="flex space-x-4 py-0.5 hover:bg-rea-surface/50 px-1 rounded">
              <span className="text-rea-muted w-12 text-right">
                {op.offset.toString(16).padStart(4, '0')}
              </span>
              <span className="text-emerald-400 font-semibold w-24">{op.opcode}</span>
              {op.operand && <span className="text-rea-text">{op.operand}</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
