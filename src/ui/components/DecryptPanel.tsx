import React, { useRef, useState } from 'react';
import { Unlock, Download, RotateCcw, KeyRound, Upload } from 'lucide-react';
import { decryptDocument } from '../../core/crypto/service';
import { parseKeyFromInput } from '../../core/crypto/keyUtils';
import { SboxMetadata } from '../../core/crypto/types';
import { FileDropzone, formatFileSize } from './common/FileDropzone';
import { Banner } from './common/Banner';

export const DecryptPanel: React.FC = () => {
  const [file, setFile] = useState<File | null>(null);
  const [keyInput, setKeyInput] = useState<string>('');
  const [status, setStatus] = useState<'idle' | 'processing' | 'success' | 'error'>('idle');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const [decryptedBlobUrl, setDecryptedBlobUrl] = useState<string | null>(null);
  const [restoredMetadata, setRestoredMetadata] = useState<SboxMetadata | null>(null);

  const keyFileInputRef = useRef<HTMLInputElement>(null);

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

      // 3. Authenticated decryption
      const { plaintext, metadata } = await decryptDocument(sboxBytes, key);

      // 4. Create downloadable Blob for restored original file
      const blob = new Blob([plaintext as unknown as BlobPart], { type: metadata.mimeType || 'application/octet-stream' });
      const url = URL.createObjectURL(blob);

      setDecryptedBlobUrl(url);
      setRestoredMetadata(metadata);
      setStatus('success');
    } catch (err) {
      setStatus('error');
      // Generic, safe error reporting that does not leak internal buffers
      setErrorMessage(
        err instanceof Error ? err.message : 'Decryption failed: invalid key or corrupted file'
      );
    }
  };

  const handleReset = () => {
    if (decryptedBlobUrl) {
      URL.revokeObjectURL(decryptedBlobUrl);
    }
    setFile(null);
    setKeyInput('');
    setStatus('idle');
    setErrorMessage(null);
    setDecryptedBlobUrl(null);
    setRestoredMetadata(null);
  };

  return (
    <div className="panel-card">
      <div className="panel-header">
        <h2 className="panel-title">Decrypt Document</h2>
        <p className="panel-subtitle">
          Decrypt and authenticate your <code>.sbox</code> file locally with your 256-bit key.
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
            hint="Choose the encrypted SecureBox (.sbox) container"
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
              <span>{status === 'processing' ? 'Decrypting document...' : 'Decrypt File'}</span>
            </button>
          </div>
        </div>
      ) : (
        <div>
          <Banner variant="success" title="File Authenticated and Decrypted">
            Document integrity and authentication tag verified. The original file has been restored.
          </Banner>

          {restoredMetadata && (
            <div className="selected-file-badge" style={{ margin: '20px 0' }}>
              <div className="selected-file-info">
                <KeyRound size={24} aria-hidden="true" />
                <div>
                  <div className="selected-file-name">{restoredMetadata.originalName}</div>
                  <div className="selected-file-meta">
                    Restored size: {formatFileSize(restoredMetadata.size)} • Type:{' '}
                    {restoredMetadata.mimeType || 'Binary'}
                  </div>
                </div>
              </div>
            </div>
          )}

          <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', margin: '20px 0' }}>
            {decryptedBlobUrl && restoredMetadata && (
              <a
                href={decryptedBlobUrl}
                download={restoredMetadata.originalName}
                className="btn btn-primary"
                role="button"
              >
                <Download size={18} aria-hidden="true" />
                <span>Download Restored File ({restoredMetadata.originalName})</span>
              </a>
            )}
          </div>

          <div style={{ marginTop: '24px', borderTop: '1px solid var(--border-subtle)', paddingTop: '16px' }}>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={handleReset}
            >
              <RotateCcw size={16} aria-hidden="true" />
              <span>Decrypt Another Document</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
