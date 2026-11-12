import React, { useRef, useState, useEffect } from 'react';
import { Unlock, Download, RotateCcw, KeyRound, Upload, FileText, CheckCircle2 } from 'lucide-react';
import { decryptAnyDocument, DecryptAnyResult } from '../../core/crypto/service';
import { parseKeyFromInput } from '../../core/crypto/keyUtils';
import { FileDropzone, formatFileSize } from './common/FileDropzone';
import { Banner } from './common/Banner';
import { useAuth } from '../context/AuthContext';

interface DecryptPanelProps {
  searchFilter?: string;
}

export const DecryptPanel: React.FC<DecryptPanelProps> = ({ searchFilter = '' }) => {
  const [file, setFile] = useState<File | null>(null);
  const [keyInput, setKeyInput] = useState<string>('');
  const [status, setStatus] = useState<'idle' | 'processing' | 'success' | 'error'>('idle');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const [decryptedResult, setDecryptedResult] = useState<DecryptAnyResult | null>(null);
  const [downloadUrl, setDownloadUrl] = useState<string | null>(null);

  const keyFileInputRef = useRef<HTMLInputElement>(null);
  const { user, sessionEpoch } = useAuth();

  // SEC-06: Revoke object URL on component unmount
  useEffect(() => {
    return () => {
      if (downloadUrl) {
        URL.revokeObjectURL(downloadUrl);
      }
    };
  }, [downloadUrl]);

  // Teardown sensitive state immediately when sessionEpoch changes (logout, session expiry, or account switch)
  useEffect(() => {
    handleReset();
  }, [sessionEpoch, user?.id]);

  const handleKeyFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      try {
        const text = await e.target.files[0].text();
        setKeyInput(text.trim());
      } catch {
        setErrorMessage('Failed to read key file.');
      }
    }
  };

  const handleDecrypt = async () => {
    if (!file || !keyInput.trim() || status === 'processing') return;

    setStatus('processing');
    setErrorMessage(null);

    try {
      // 1. Parse and import key
      const key = await parseKeyFromInput(keyInput);

      // 2. Read .sbox file bytes
      const buffer = await file.arrayBuffer();
      const sboxBytes = new Uint8Array(buffer);

      // 3. Authenticated decryption (handles both single-file v1 and archive v2)
      const result = await decryptAnyDocument(sboxBytes, key);

      // 4. Create object URL for download (revoke previous if any)
      const url = URL.createObjectURL(result.downloadBlob);

      setDecryptedResult(result);
      setDownloadUrl(url);
      setStatus('success');
    } catch (err) {
      setStatus('error');
      setErrorMessage(
        err instanceof Error ? err.message : 'Decryption failed: invalid key or corrupted file'
      );
    }
  };

  const handleReset = () => {
    if (downloadUrl) {
      URL.revokeObjectURL(downloadUrl);
    }
    setFile(null);
    setKeyInput('');
    setStatus('idle');
    setErrorMessage(null);
    setDecryptedResult(null);
    setDownloadUrl(null);
  };

  return (
    <div className="panel-card">
      <div className="panel-header">
        <h2 className="panel-title">Decrypt documents</h2>
        <p className="panel-subtitle">
          Decrypt single files or multi-file archives locally with your 256-bit key.
        </p>
      </div>

      {status === 'error' && (
        <Banner variant="error" title="Decryption Failed">
          {errorMessage || 'Decryption failed. Please verify the key and file integrity.'}
        </Banner>
      )}

      {status !== 'success' ? (
        <div>
          <FileDropzone
            onFileSelect={(selected) => setFile(selected)}
            selectedFile={file}
            onClear={() => setFile(null)}
            accept=".sbox"
            label="Select .sbox file"
            hint="Drag & drop or click to select .sbox file"
            disabled={status === 'processing'}
          />

          <div className="form-group" style={{ marginTop: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <label className="form-label" htmlFor="decryption-key-input">
                Decryption Key
              </label>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => keyFileInputRef.current?.click()}
                disabled={status === 'processing'}
              >
                <Upload size={14} aria-hidden="true" />
                <span>Load .key file</span>
              </button>
            </div>

            <input
              ref={keyFileInputRef}
              type="file"
              accept=".key,.json"
              onChange={handleKeyFileUpload}
              style={{ display: 'none' }}
              tabIndex={-1}
              aria-hidden="true"
            />

            <input
              id="decryption-key-input"
              type="text"
              className="form-input"
              placeholder="Paste 64-character hexadecimal key or .key backup content"
              value={keyInput}
              onChange={(e) => setKeyInput(e.target.value)}
              disabled={status === 'processing'}
              aria-label="Enter the 256-bit decryption key"
            />
            <p className="form-help">
              Key is validated locally and used solely in volatile memory for decryption.
            </p>
          </div>

          <div style={{ marginTop: '20px' }}>
            <button
              type="button"
              className="btn btn-primary"
              onClick={handleDecrypt}
              disabled={!file || !keyInput.trim() || status === 'processing'}
            >
              <Unlock size={18} aria-hidden="true" />
              <span>{status === 'processing' ? 'Decrypting payload...' : 'Decrypt File / Archive'}</span>
            </button>
          </div>
        </div>
      ) : (
        <div>
          {decryptedResult?.type === 'single' ? (
            <div>
              <Banner variant="success" title="File Authenticated and Decrypted">
                Single-file document integrity and authentication tag verified.
              </Banner>

              <div className="selected-file-badge" style={{ margin: '20px 0' }}>
                <div className="selected-file-info">
                  <KeyRound size={24} aria-hidden="true" />
                  <div>
                    <div className="selected-file-name">{decryptedResult.metadata.originalName}</div>
                    <div className="selected-file-meta">
                      Restored size: {formatFileSize(decryptedResult.metadata.size)} • Type:{' '}
                      {decryptedResult.metadata.mimeType || 'Binary'}
                    </div>
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', margin: '20px 0' }}>
                {downloadUrl && (
                  <a
                    href={downloadUrl}
                    download={decryptedResult.downloadFilename}
                    className="btn btn-primary"
                    role="button"
                  >
                    <Download size={18} aria-hidden="true" />
                    <span>Download Restored File ({decryptedResult.downloadFilename})</span>
                  </a>
                )}
              </div>
            </div>
          ) : decryptedResult?.type === 'archive' ? (
            <div>
              <Banner variant="success" title="Archive Authenticated and Decrypted">
                Collection integrity and manifest verified. Recovered <strong>{decryptedResult.files.length} files</strong>{' '}
                ({formatFileSize(decryptedResult.manifest.totalPlaintextSize)}).
              </Banner>

              <div style={{ margin: '20px 0' }}>
                <div style={{ fontSize: '0.875rem', fontWeight: 600, marginBottom: '8px' }}>
                  Recovered Files ({decryptedResult.files.length}):
                </div>
                {(() => {
                  const query = searchFilter.trim().toLowerCase();
                  const displayedFiles = decryptedResult.files.filter(
                    (rf) => !query || rf.path.toLowerCase().includes(query)
                  );

                  if (displayedFiles.length === 0 && decryptedResult.files.length > 0) {
                    return (
                      <div
                        style={{
                          padding: '24px 16px',
                          textAlign: 'center',
                          color: 'var(--text-muted)',
                          fontSize: '0.875rem',
                          border: '1px solid var(--border-subtle)',
                          borderRadius: 'var(--radius-md)',
                        }}
                      >
                        No recovered files match &quot;{searchFilter}&quot;.
                      </div>
                    );
                  }

                  return (
                    <div
                      style={{
                        maxHeight: '220px',
                        overflowY: 'auto',
                        border: '1px solid var(--border-subtle)',
                        borderRadius: 'var(--radius-md)',
                      }}
                      role="region"
                      aria-label="List of recovered files"
                    >
                      {displayedFiles.map((rf, idx) => (
                        <div
                          key={`${rf.path}-${idx}`}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            padding: '8px 12px',
                            borderBottom: idx < displayedFiles.length - 1 ? '1px solid var(--border-subtle)' : 'none',
                            backgroundColor: idx % 2 === 0 ? 'var(--bg-card)' : 'var(--bg-subtle)',
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', overflow: 'hidden' }}>
                            <FileText size={16} aria-hidden="true" style={{ flexShrink: 0 }} />
                            <span
                              style={{
                                fontSize: '0.875rem',
                                fontWeight: 500,
                                textOverflow: 'ellipsis',
                                overflow: 'hidden',
                                whiteSpace: 'nowrap',
                              }}
                              title={rf.path}
                            >
                              {rf.path}
                            </span>
                            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', flexShrink: 0 }}>
                              ({formatFileSize(rf.data.byteLength)})
                            </span>
                          </div>
                          <span
                            style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '4px',
                              fontSize: '0.75rem',
                              color: 'var(--state-success-text)',
                              fontWeight: 500,
                              flexShrink: 0,
                            }}
                          >
                            <CheckCircle2 size={12} aria-hidden="true" />
                            <span>Verified</span>
                          </span>
                        </div>
                      ))}
                    </div>
                  );
                })()}
              </div>

              <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', margin: '20px 0' }}>
                {downloadUrl && (
                  <a
                    href={downloadUrl}
                    download={decryptedResult.downloadFilename}
                    className="btn btn-primary"
                    role="button"
                  >
                    <Download size={18} aria-hidden="true" />
                    <span>Download Restored ZIP ({decryptedResult.downloadFilename})</span>
                  </a>
                )}
              </div>

              <Banner variant="info" title="Folder Extraction">
                The downloaded ZIP file extracts into a dedicated folder containing all original files and directory hierarchies.
              </Banner>
            </div>
          ) : null}

          <div style={{ marginTop: '24px', borderTop: '1px solid var(--border-subtle)', paddingTop: '16px' }}>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={handleReset}
            >
              <RotateCcw size={16} aria-hidden="true" />
              <span>Decrypt Another File or Archive</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
};


