import React, { useState, useEffect } from 'react';
import Editor from '@monaco-editor/react';
import {
  Folder,
  FolderOpen,
  FileCode,
  FileText,
  ChevronRight,
  ChevronDown,
  Download,
  Copy,
  Check,
  Search,
} from 'lucide-react';
import { fetchFileContent, type FileContentWindow } from '../../api/client';
import type { FileTreeNode } from '@shared/types.js';

interface CodeExplorerProps {
  jobId: string;
  initialTree?: FileTreeNode[];
  defaultFilePath?: string;
  // Extra per-file UI (the AI explanation panel) rendered under the explorer
  renderFileTools?: (path: string) => React.ReactNode;
}

export const CodeExplorer: React.FC<CodeExplorerProps> = ({
  jobId,
  initialTree,
  defaultFilePath,
  renderFileTools,
}) => {
  const [selectedFile, setSelectedFile] = useState<string | null>(defaultFilePath || null);
  const [code, setCode] = useState<string>('// Select a file to inspect content');
  const [isLoading, setIsLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [filterText, setFilterText] = useState('');
  const [openDirs, setOpenDirs] = useState<Record<string, boolean>>({});
  const [fileWindow, setFileWindow] = useState<FileContentWindow | null>(null);
  const [offsetInput, setOffsetInput] = useState('');

  useEffect(() => {
    // If no file selected yet, try to auto-select first file in tree
    if (!selectedFile && initialTree && initialTree.length > 0) {
      const first = findFirstFile(initialTree);
      if (first) {
        loadFile(first.path);
      } else {
        // try loading root single file
        loadFile('');
      }
    } else if (selectedFile) {
      loadFile(selectedFile);
    } else {
      loadFile('');
    }
  }, [jobId]);

  // Opening a file from outside (search results, module links) after the explorer mounted
  useEffect(() => {
    if (defaultFilePath && defaultFilePath !== selectedFile) loadFile(defaultFilePath);
  }, [defaultFilePath]);

  const findFirstFile = (nodes: FileTreeNode[]): FileTreeNode | null => {
    for (const n of nodes) {
      if (n.type === 'file') return n;
      if (n.children) {
        const sub = findFirstFile(n.children);
        if (sub) return sub;
      }
    }
    return null;
  };

  const loadFile = async (path: string, offset = 0) => {
    setIsLoading(true);
    setSelectedFile(path);
    try {
      const data = await fetchFileContent(jobId, path, offset);
      setCode(data.content);
      setFileWindow(data);
    } catch (err: any) {
      setCode(`// Error loading file: ${err.message || 'File not available'}`);
      setFileWindow(null);
    } finally {
      setIsLoading(false);
    }
  };

  const goToOffset = () => {
    if (selectedFile === null) return;
    const raw = offsetInput.trim().toLowerCase();
    const value = raw.startsWith('0x') ? parseInt(raw.slice(2), 16) : parseInt(raw, 10);
    if (!Number.isNaN(value) && value >= 0) loadFile(selectedFile, value);
  };

  const formatBytes = (n: number) =>
    n >= 1024 * 1024 ? `${(n / 1024 / 1024).toFixed(1)} MB` : n >= 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} B`;

  const toggleDir = (path: string) => {
    setOpenDirs((prev) => ({ ...prev, [path]: !prev[path] }));
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Determine Monaco language from file extension
  const getLanguage = (path?: string | null): string => {
    if (!path) return 'javascript';
    if (path.endsWith('.ts') || path.endsWith('.tsx')) return 'typescript';
    if (path.endsWith('.js') || path.endsWith('.mjs') || path.endsWith('.cjs')) return 'javascript';
    if (path.endsWith('.json')) return 'json';
    if (path.endsWith('.html')) return 'html';
    if (path.endsWith('.css')) return 'css';
    if (path.endsWith('.py')) return 'python';
    if (path.endsWith('.rs')) return 'rust';
    if (path.endsWith('.go')) return 'go';
    if (path.endsWith('.c') || path.endsWith('.cpp') || path.endsWith('.h')) return 'cpp';
    if (path.endsWith('.xml') || path.endsWith('.svg')) return 'xml';
    return 'plaintext';
  };

  const renderTree = (nodes: FileTreeNode[], depth = 0) => {
    return nodes
      .filter((node) =>
        filterText
          ? node.name.toLowerCase().includes(filterText.toLowerCase()) ||
            (node.children && node.children.length > 0)
          : true
      )
      .map((node) => {
        const isOpen = openDirs[node.path] ?? depth === 0;
        const isSelected = selectedFile === node.path;

        if (node.type === 'directory') {
          return (
            <div key={node.path} className="select-none">
              <div
                onClick={() => toggleDir(node.path)}
                className="flex items-center space-x-1.5 py-1 px-2 rounded hover:bg-rea-surface/70 cursor-pointer text-xs font-mono text-rea-muted hover:text-white transition"
                style={{ paddingLeft: `${depth * 12 + 8}px` }}
              >
                {isOpen ? (
                  <ChevronDown className="w-3.5 h-3.5 text-rea-muted" />
                ) : (
                  <ChevronRight className="w-3.5 h-3.5 text-rea-muted" />
                )}
                {isOpen ? (
                  <FolderOpen className="w-4 h-4 text-amber-400" />
                ) : (
                  <Folder className="w-4 h-4 text-amber-400" />
                )}
                <span className="truncate">{node.name}</span>
              </div>
              {isOpen && node.children && (
                <div>{renderTree(node.children, depth + 1)}</div>
              )}
            </div>
          );
        }

        return (
          <div
            key={node.path}
            onClick={() => loadFile(node.path)}
            className={`flex items-center space-x-2 py-1 px-2 rounded cursor-pointer text-xs font-mono transition ${
              isSelected
                ? 'bg-rea-accent/20 text-white font-medium border-l-2 border-rea-accent'
                : 'text-rea-muted hover:text-white hover:bg-rea-surface/50'
            }`}
            style={{ paddingLeft: `${depth * 12 + 18}px` }}
          >
            <FileCode className="w-3.5 h-3.5 text-rea-info flex-shrink-0" />
            <span className="truncate">{node.name}</span>
            {node.size !== undefined && (
              <span className="text-[10px] text-rea-muted/60 ml-auto pl-2 flex-shrink-0">
                {(node.size / 1024).toFixed(1)}k
              </span>
            )}
          </div>
        );
      });
  };

  return (
    <>
    <div className="border border-rea-border rounded-xl bg-rea-surface overflow-hidden flex flex-col md:flex-row h-[650px]">
      {/* Sidebar: File Explorer Tree */}
      <div className="w-full md:w-72 border-b md:border-b-0 md:border-r border-rea-border flex flex-col bg-rea-bg/40">
        <div className="p-3 border-b border-rea-border flex items-center justify-between">
          <span className="text-xs font-bold text-white uppercase tracking-wider font-mono flex items-center space-x-1.5">
            <FileText className="w-3.5 h-3.5 text-rea-accent" />
            <span>Workspace Explorer</span>
          </span>
        </div>

        {/* Search Filter */}
        <div className="p-2 border-b border-rea-border/60">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-rea-muted" />
            <input
              type="text"
              placeholder="Search files..."
              value={filterText}
              onChange={(e) => setFilterText(e.target.value)}
              className="w-full bg-rea-bg border border-rea-border rounded pl-8 pr-2 py-1 text-xs text-white placeholder-rea-muted focus:outline-none focus:border-rea-accent"
            />
          </div>
        </div>

        {/* Tree List */}
        <div className="flex-1 overflow-y-auto p-2 space-y-0.5">
          {initialTree && initialTree.length > 0 ? (
            renderTree(initialTree)
          ) : (
            <div
              onClick={() => loadFile('')}
              className={`p-2 rounded cursor-pointer text-xs font-mono flex items-center space-x-2 ${
                selectedFile === '' || selectedFile === null
                  ? 'bg-rea-accent/20 text-white'
                  : 'text-rea-muted hover:text-white'
              }`}
            >
              <FileCode className="w-4 h-4 text-rea-accent" />
              <span>Target File Source</span>
            </div>
          )}
        </div>
      </div>

      {/* Main View: Monaco Editor & Toolbar */}
      <div className="flex-1 flex flex-col min-w-0 bg-rea-bg">
        <div className="px-4 py-2 border-b border-rea-border bg-rea-surface flex items-center justify-between">
          <div className="flex items-center space-x-2 truncate mr-4">
            <span className="text-xs font-mono text-white font-medium truncate">
              {selectedFile || 'Source Viewer'}
            </span>
            <span className="text-[10px] bg-rea-bg border border-rea-border px-1.5 py-0.5 rounded text-rea-muted font-mono uppercase">
              {fileWindow?.isBinary ? 'hex' : getLanguage(selectedFile)}
            </span>
          </div>

          <div className="flex items-center space-x-2">
            {fileWindow?.truncated && fileWindow.size !== undefined && fileWindow.offset !== undefined && (
              <div className="flex items-center space-x-1.5 text-[11px] font-mono text-rea-muted">
                <span className="whitespace-nowrap" title={`Showing a ${formatBytes(fileWindow.windowSize ?? 0)} window of a large file`}>
                  0x{fileWindow.offset.toString(16)}–0x{(fileWindow.offset + (fileWindow.length ?? 0)).toString(16)} of{' '}
                  {formatBytes(fileWindow.size)}
                </span>
                <button
                  onClick={() => loadFile(selectedFile ?? '', Math.max(0, fileWindow.offset! - (fileWindow.windowSize ?? 0)))}
                  disabled={isLoading || fileWindow.offset === 0}
                  className="px-1.5 py-0.5 rounded border border-rea-border hover:bg-rea-border/60 hover:text-white disabled:opacity-40 disabled:hover:bg-transparent"
                >
                  Prev
                </button>
                <button
                  onClick={() => loadFile(selectedFile ?? '', fileWindow.offset! + (fileWindow.length ?? 0))}
                  disabled={isLoading || fileWindow.offset + (fileWindow.length ?? 0) >= fileWindow.size}
                  className="px-1.5 py-0.5 rounded border border-rea-border hover:bg-rea-border/60 hover:text-white disabled:opacity-40 disabled:hover:bg-transparent"
                >
                  Next
                </button>
                <input
                  value={offsetInput}
                  onChange={(e) => setOffsetInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && goToOffset()}
                  placeholder="0x offset"
                  className="w-20 bg-rea-bg border border-rea-border rounded px-1.5 py-0.5 text-white placeholder:text-rea-muted focus:outline-none focus:border-rea-accent"
                />
              </div>
            )}
            <button
              onClick={handleCopy}
              className="p-1.5 rounded hover:bg-rea-border/60 text-rea-muted hover:text-white transition flex items-center space-x-1 text-xs"
              title="Copy code"
            >
              {copied ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="text-emerald-400 text-[11px]">Copied</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span className="text-[11px]">Copy</span>
                </>
              )}
            </button>
          </div>
        </div>

        <div className="flex-1 relative">
          {isLoading ? (
            <div className="absolute inset-0 flex items-center justify-center bg-rea-bg/80 z-10 text-xs font-mono text-rea-muted">
              Loading code...
            </div>
          ) : null}

          <Editor
            height="100%"
            theme="vs-dark"
            language={fileWindow?.isBinary ? 'plaintext' : getLanguage(selectedFile)}
            value={code}
            options={{
              readOnly: true,
              minimap: { enabled: true },
              fontSize: 12,
              fontFamily: "'JetBrains Mono', monospace",
              scrollBeyondLastLine: false,
              automaticLayout: true,
              lineNumbers: 'on',
              folding: true,
            }}
          />
        </div>
      </div>
    </div>
    {selectedFile && renderFileTools && <div className="mt-4">{renderFileTools(selectedFile)}</div>}
    </>
  );
};
