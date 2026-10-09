import React, { useRef, useState } from 'react';
import { Upload, File as FileIcon, X } from 'lucide-react';

interface FileDropzoneProps {
  onFileSelect?: (file: File) => void;
  onFilesSelect?: (files: File[]) => void;
  selectedFile?: File | null;
  onClear?: () => void;
  accept?: string;
  multiple?: boolean;
  label?: string;
  hint?: string;
  disabled?: boolean;
}

export function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 2)} ${units[i]}`;
}

export const FileDropzone: React.FC<FileDropzoneProps> = ({
  onFileSelect,
  onFilesSelect,
  selectedFile,
  onClear,
  accept,
  multiple = false,
  label = 'Select document(s)',
  hint = 'Drag & drop file(s) here, or click to browse',
  disabled = false,
}) => {
  const [isDragActive, setIsDragActive] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragEnter = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (!disabled) setIsDragActive(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(false);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const processFiles = (fileList: FileList | null) => {
    if (!fileList || fileList.length === 0) return;
    const files = Array.from(fileList);

    if (multiple && onFilesSelect) {
      onFilesSelect(files);
    } else if (onFilesSelect) {
      onFilesSelect(files);
    } else if (onFileSelect) {
      onFileSelect(files[0]);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(false);

    if (disabled) return;
    processFiles(e.dataTransfer.files);
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    processFiles(e.target.files);
    // Reset input value so re-selecting same file triggers event
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleClick = () => {
    if (!disabled && fileInputRef.current) {
      fileInputRef.current.click();
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if ((e.key === 'Enter' || e.key === ' ') && !disabled) {
      e.preventDefault();
      fileInputRef.current?.click();
    }
  };

  return (
    <div>
      <input
        ref={fileInputRef}
        type="file"
        accept={accept}
        multiple={multiple}
        onChange={handleInputChange}
        style={{ display: 'none' }}
        tabIndex={-1}
        aria-hidden="true"
        disabled={disabled}
      />

      {!selectedFile ? (
        <div
          className={`dropzone ${isDragActive ? 'drag-active' : ''}`}
          onClick={handleClick}
          onKeyDown={handleKeyDown}
          onDragEnter={handleDragEnter}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          role="button"
          tabIndex={disabled ? -1 : 0}
          aria-label={label}
        >
          <div className="dropzone-label">
            <Upload size={28} aria-hidden="true" />
            <div>
              <strong>{label}</strong>
              <div style={{ fontSize: '0.8125rem', marginTop: '4px' }}>{hint}</div>
            </div>
          </div>
        </div>
      ) : (
        <div className="selected-file-badge" role="region" aria-label="Selected file details">
          <div className="selected-file-info">
            <FileIcon size={24} aria-hidden="true" />
            <div>
              <div className="selected-file-name" title={selectedFile.name}>
                {selectedFile.name}
              </div>
              <div className="selected-file-meta">
                {formatFileSize(selectedFile.size)} • {selectedFile.type || 'Binary / Unspecified'}
              </div>
            </div>
          </div>
          {onClear && (
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={onClear}
              disabled={disabled}
              aria-label="Remove selected file"
            >
              <X size={16} aria-hidden="true" />
              <span>Remove</span>
            </button>
          )}
        </div>
      )}
    </div>
  );
};
