import React, { useState, useEffect } from 'react';
import { Lock, Download, Copy, Check, ShieldAlert, RotateCcw, X, File as FileIcon } from 'lucide-react';
import { encryptDocument } from '../../core/crypto/service';
import { encryptArchive } from '../../core/archive/archiveService';
import { exportKeyBackup, exportKeyToHex } from '../../core/crypto/keyUtils';
import { FileDropzone, formatFileSize } from './common/FileDropzone';
import { Banner } from './common/Banner';

export const EncryptPanel: React.FC = () => {
  const [files, setFiles] = useState<File[]>([]);
  const [archiveName, setArchiveName] = useState<string>('securebox-archive');
  const [status, setStatus] = useState<'idle' | 'processing' | 'success' | 'error'>('idle');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const [encryptedBlobUrl, setEncryptedBlobUrl] = useState<string | null>(null);
  const [downloadFilename, setDownloadFilename] = useState<string>('');
  const [keyHex, setKeyHex] = useState<string>('');
  const [keyBackupJson, setKeyBackupJson] = useState<string>('');
  const [copiedKey, setCopiedKey] = useState<boolean>(false);
  const [encryptedSummary, setEncryptedSummary] = useState<{ fileCount: number; totalSize: number } | null>(null);

  // SEC-06: Revoke object URL on component unmount and when URL changes
  useEffect(() => {
    return () => {
      if (encryptedBlobUrl) {
        URL.revokeObjectURL(encryptedBlobUrl);
      }
    };
  }, [encryptedBlobUrl]);

  const handleFilesSelect = (newFiles: File[]) => {
    setFiles((prev) => [...prev, ...newFiles]);
  };

  const handleRemoveFile = (index: number) => {
    setFiles((prev) => prev.filter((_, i) => i !== index));
  };

  const handleClearAll = () => {
    setFiles([]);
  };

  const totalSize = files.reduce((acc, f) => acc + f.size, 0);

  const handleEncrypt = async () => {
    if (files.length === 0 || status === 'processing') return;

    setStatus('processing');
    setErrorMessage(null);

    try {
      if (files.length === 1) {
        // Single file encryption (Envelope v1)
        const file = files[0];
        const buffer = await file.arrayBuffer();
        const fileBytes = new Uint8Array(buffer);

        const result = await encryptDocument(fileBytes, {
          originalName: file.name,
          mimeType: file.type || 'application/octet-stream',
          size: file.size,
        });

        const hex = await exportKeyToHex(result.key);
        const backup = await exportKeyBackup(result.key);

        const sboxBlob = new Blob([result.sboxBytes as unknown as BlobPart], {
          type: 'application/octet-stream',
        });
        const url = URL.createObjectURL(sboxBlob);

        setEncryptedBlobUrl(url);
        setDownloadFilename(`${file.name}.sbox`);
        setKeyHex(hex);
        setKeyBackupJson(JSON.stringify(backup, null, 2));
        setEncryptedSummary({ fileCount: 1, totalSize: file.size });
        setStatus('success');
      } else {
        // Multi-file collection encryption (Envelope v2)
        const inputFiles = await Promise.all(
          files.map(async (file) => ({
            path: file.name,
            data: new Uint8Array(await file.arrayBuffer()),
            mimeType: file.type || 'application/octet-stream',
          }))
        );

        const safeArchiveName = archiveName.trim() || 'securebox-archive';
        const result = await encryptArchive(inputFiles, safeArchiveName);

        const hex = await exportKeyToHex(result.key);
        const backup = await exportKeyBackup(result.key);

        const sboxBlob = new Blob([result.sboxBytes as unknown as BlobPart], {
          type: 'application/octet-stream',
        });
        const url = URL.createObjectURL(sboxBlob);

        setEncryptedBlobUrl(url);
        setDownloadFilename(`${safeArchiveName}.sbox`);
        setKeyHex(hex);
        setKeyBackupJson(JSON.stringify(backup, null, 2));
        setEncryptedSummary({ fileCount: files.length, totalSize });
        setStatus('success');
      }
    } catch (err) {
      setStatus('error');
      setErrorMessage(err instanceof Error ? err.message : 'An error occurred during encryption.');
    }
  };

  const handleCopyKey = async () => {
    if (!keyHex) return;
    try {
      await navigator.clipboard.writeText(keyHex);
      setCopiedKey(true);
      setTimeout(() => setCopiedKey(false), 2500);
    } catch {
      setCopiedKey(false);
    }
  };

  const handleDownloadKeyFile = () => {
    if (!keyBackupJson) return;
    const blob = new Blob([keyBackupJson], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const keyFileName = downloadFilename ? `${downloadFilename.replace(/\.sbox$/i, '')}.key` : 'securebox.key';
    a.download = keyFileName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleReset = () => {
    setFiles([]);
    setArchiveName('securebox-archive');
    setStatus('idle');
    setErrorMessage(null);
    setEncryptedBlobUrl(null);
    setDownloadFilename('');
    setKeyHex('');
    setKeyBackupJson('');
    setCopiedKey(false);
    setEncryptedSummary(null);
  };

  return (
    <div className="panel-card">
      <div className="panel-header">
        <h2 className="panel-title">Encrypt Document or Collection</h2>
        <p className="panel-subtitle">
          Encrypt single or multiple files into a tamper-proof <code>.sbox</code> container using AES-256-GCM.
        </p>
      </div>

      {status === 'error' && (
        <Banner variant="error" title="Encryption Failed">
          {errorMessage || 'Unable to encrypt files. Please verify selection and try again.'}
        </Banner>
      )}

      {status !== 'success' ? (
        <div>
          <FileDropzone
            onFilesSelect={handleFilesSelect}
            multiple={true}
            label="Select file(s) to encrypt"
            hint="Drag & drop single or multiple files, or click to browse (100% client-side)"
            disabled={status === 'processing'}
          />

          {files.length > 0 && (
            <div style={{ marginTop: '20px' }}>
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: '12px',
                  paddingBottom: '8px',
                  borderBottom: '1px solid var(--border-subtle)',
                }}
              >
                <div>
                  <strong>{files.length} {files.length === 1 ? 'file' : 'files'} selected</strong>
                  <span style={{ color: 'var(--text-muted)', marginLeft: '8px', fontSize: '0.875rem' }}>
                    (Total: {formatFileSize(totalSize)})
                  </span>
                </div>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    onClick={handleClearAll}
                    disabled={status === 'processing'}
                  >
                    Clear All
                  </button>
                </div>
              </div>

              {files.length > 1 && (
                <div className="form-group" style={{ marginBottom: '16px' }}>
                  <label className="form-label" htmlFor="archive-name-input">
                    Archive Name
                  </label>
                  <input
                    id="archive-name-input"
                    type="text"
                    className="form-input"
                    value={archiveName}
                    onChange={(e) => setArchiveName(e.target.value)}
                    placeholder="securebox-archive"
                    disabled={status === 'processing'}
                  />
                  <p className="form-help">
                    The collection will be encrypted into <code>{archiveName || 'securebox-archive'}.sbox</code>.
                  </p>
                </div>
              )}

              {/* Selected Files List */}
              <div
                style={{
                  maxHeight: '220px',
                  overflowY: 'auto',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-md)',
                  marginBottom: '16px',
                }}
                role="region"
                aria-label="List of selected files"
              >
                {files.map((f, idx) => (
                  <div
                    key={`${f.name}-${idx}`}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '8px 12px',
                      borderBottom: idx < files.length - 1 ? '1px solid var(--border-subtle)' : 'none',
                      backgroundColor: idx % 2 === 0 ? 'var(--bg-card)' : 'var(--bg-subtle)',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', overflow: 'hidden' }}>
                      <FileIcon size={16} aria-hidden="true" style={{ flexShrink: 0 }} />
                      <span
                        style={{
                          fontSize: '0.875rem',
                          fontWeight: 500,
                          textOverflow: 'ellipsis',
                          overflow: 'hidden',
                          whiteSpace: 'nowrap',
                        }}
                        title={f.name}
                      >
                        {f.name}
                      </span>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', flexShrink: 0 }}>
                        ({formatFileSize(f.size)})
                      </span>
                    </div>
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={() => handleRemoveFile(idx)}
                      disabled={status === 'processing'}
                      aria-label={`Remove ${f.name}`}
                      style={{ padding: '2px 6px', height: '24px' }}
                    >
                      <X size={14} aria-hidden="true" />
                    </button>
                  </div>
                ))}
              </div>

              {totalSize > 250 * 1024 * 1024 && (
                <Banner variant="warning" title="Memory Warning">
                  Total file size ({formatFileSize(totalSize)}) exceeds 250 MB. Processing large files in browser memory may cause performance degradation or tab memory limits.
                </Banner>
              )}

              <div style={{ marginTop: '16px' }}>
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={handleEncrypt}
                  disabled={files.length === 0 || status === 'processing'}
                >
                  <Lock size={18} aria-hidden="true" />
                  <span>
                    {status === 'processing'
                      ? 'Encrypting payload...'
                      : files.length > 1
                      ? `Encrypt Collection (${files.length} files)`
                      : 'Encrypt File'}
                  </span>
                </button>
              </div>
            </div>
          )}
        </div>
      ) : (
        <div>
          <Banner variant="success" title="Encryption Complete">
            {encryptedSummary && encryptedSummary.fileCount > 1 ? (
              <div>
                Collection containing <strong>{encryptedSummary.fileCount} files</strong> ({formatFileSize(encryptedSummary.totalSize)})
                was packaged into an authenticated <code>.sbox</code> archive.
              </div>
            ) : (
              <div>Your document was securely packaged into an authenticated <code>.sbox</code> container.</div>
            )}
          </Banner>

          <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', margin: '20px 0' }}>
            {encryptedBlobUrl && (
              <a
                href={encryptedBlobUrl}
                download={downloadFilename}
                className="btn btn-primary"
                role="button"
              >
                <Download size={18} aria-hidden="true" />
                <span>Download Encrypted File ({downloadFilename})</span>
              </a>
            )}

            <button
              type="button"
              className="btn btn-secondary"
              onClick={handleDownloadKeyFile}
            >
              <Download size={18} aria-hidden="true" />
              <span>Download Key Backup (.key)</span>
            </button>
          </div>

          <div className="form-group" style={{ marginTop: '24px' }}>
            <label className="form-label" htmlFor="encryption-key-hex">
              Decryption Key (256-bit Hex)
            </label>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <input
                id="encryption-key-hex"
                type="text"
                readOnly
                value={keyHex}
                className="form-input"
                aria-label="Generated 256-bit AES encryption key in hex"
              />
              <button
                type="button"
                className="btn btn-secondary"
                onClick={handleCopyKey}
                aria-label="Copy key to clipboard"
              >
                {copiedKey ? <Check size={18} aria-hidden="true" /> : <Copy size={18} aria-hidden="true" />}
                <span>{copiedKey ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
            <p className="form-help">
              This key is required to decrypt your file later. SecureBox stores no copy.
            </p>
          </div>

          <Banner variant="warning" title="Important Key Custody Notice">
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '8px' }}>
              <ShieldAlert size={20} aria-hidden="true" style={{ flexShrink: 0, marginTop: '2px' }} />
              <div>
                There is <strong>no key recovery or password reset</strong>. If you lose this key, the encrypted file
                cannot be recovered. Anyone with this key can decrypt the file.
              </div>
            </div>
          </Banner>

          <div style={{ marginTop: '24px', borderTop: '1px solid var(--border-subtle)', paddingTop: '16px' }}>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={handleReset}
            >
              <RotateCcw size={16} aria-hidden="true" />
              <span>Encrypt Another File or Collection</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
