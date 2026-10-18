import React from 'react';
import { useDropzone } from 'react-dropzone';
import { UploadCloud, File as FileIcon } from 'lucide-react';

interface FileUploadProps {
  onFileSelect: (file: File) => void;
  selectedFile?: File | null;
  // When set, several files can be dropped at once; onFileSelect still gets the first
  onFilesSelect?: (files: File[]) => void;
  selectedCount?: number;
  accept?: Record<string, string[]>;
  description?: string;
}

export const FileUpload: React.FC<FileUploadProps> = ({
  onFileSelect,
  selectedFile,
  onFilesSelect,
  selectedCount = 0,
  accept,
  description = 'Drag & drop your target file here, or click to browse',
}) => {
  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop: (acceptedFiles) => {
      if (acceptedFiles.length > 0) {
        onFileSelect(acceptedFiles[0]);
        onFilesSelect?.(acceptedFiles);
      }
    },
    multiple: !!onFilesSelect,
    accept,
  });

  return (
    <div
      {...getRootProps()}
      className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition flex flex-col items-center justify-center min-h-[160px] ${
        isDragActive
          ? 'border-rea-accent bg-rea-surface/80'
          : selectedFile
          ? 'border-rea-accent/50 bg-rea-surface/40'
          : 'border-rea-border hover:border-rea-muted bg-rea-surface/20'
      }`}
    >
      <input {...getInputProps()} />
      {selectedFile ? (
        <div className="flex flex-col items-center space-y-2">
          <div className="p-3 bg-rea-surface rounded-full border border-rea-border text-rea-accent">
            <FileIcon className="w-8 h-8" />
          </div>
          {selectedCount > 1 ? (
            <>
              <span className="font-semibold text-white text-sm">{selectedCount} files selected</span>
              <span className="text-xs text-rea-muted">Each file becomes its own auto-detected job • Click or drag to change</span>
            </>
          ) : (
            <>
              <span className="font-semibold text-white text-sm">{selectedFile.name}</span>
              <span className="text-xs text-rea-muted">
                {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB • Click or drag to change file
              </span>
            </>
          )}
        </div>
      ) : (
        <div className="flex flex-col items-center space-y-2">
          <div className="p-3 bg-rea-surface rounded-full border border-rea-border text-rea-muted">
            <UploadCloud className="w-8 h-8" />
          </div>
          <span className="text-sm font-medium text-rea-text">{description}</span>
          <span className="text-xs text-rea-muted">Supports raw binaries, packages, ASAR, scripts</span>
        </div>
      )}
    </div>
  );
};
