import React, { useState } from 'react';
import { Lock, Download, Copy, Check, ShieldAlert, RotateCcw } from 'lucide-react';
import { encryptDocument } from '../../core/crypto/service';
import { exportKeyBackup, exportKeyToHex } from '../../core/crypto/keyUtils';
import { FileDropzone } from './common/FileDropzone';
import { Banner } from './common/Banner';

export const EncryptPanel: React.FC = () => {
  const [file, setFile] = useState<File | null>(null);
  const [status, setStatus] = useState<'idle' | 'processing' | 'success' | 'error'>('idle');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const [encryptedBlobUrl, setEncryptedBlobUrl] = useState<string | null>(null);
  const [downloadFilename, setDownloadFilename] = useState<string>('');
  const [keyHex, setKeyHex] = useState<string>('');
  const [keyBackupJson, setKeyBackupJson] = useState<string>('');
  const [copiedKey, setCopiedKey] = useState<boolean>(false);

  const handleEncrypt = async () => {
    if (!file || status === 'processing') return;

    setStatus('processing');
    setErrorMessage(null);

    try {
      const buffer = await file.arrayBuffer();
      const fileBytes = new Uint8Array(buffer);

      const result = await encryptDocument(fileBytes, {
        originalName: file.name,
        mimeType: file.type || 'application/octet-stream',
        size: file.size,
      });

      // Export key representations
      const hex = await exportKeyToHex(result.key);
      const backup = await exportKeyBackup(result.key);

      // Create downloadable .sbox blob
      const sboxBlob = new Blob([result.sboxBytes as unknown as BlobPart], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(sboxBlob);

      setEncryptedBlobUrl(url);
      setDownloadFilename(`${file.name}.sbox`);
      setKeyHex(hex);
      setKeyBackupJson(JSON.stringify(backup, null, 2));
      setStatus('success');
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
      // Fallback
      setCopiedKey(false);
    }
  };

  const handleDownloadKeyFile = () => {
    if (!keyBackupJson || !file) return;
    const blob = new Blob([keyBackupJson], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${file.name}.key`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleReset = () => {
    if (encryptedBlobUrl) {
      URL.revokeObjectURL(encryptedBlobUrl);
    }
    setFile(null);
    setStatus('idle');
    setErrorMessage(null);
    setEncryptedBlobUrl(null);
    setDownloadFilename('');
    setKeyHex('');
    setKeyBackupJson('');
    setCopiedKey(false);
  };

  return (
    <div className="panel-card">
      <div className="panel-header">
        <h2 className="panel-title">Encrypt Document</h2>
        <p className="panel-subtitle">
          Encrypt your file locally with AES-256-GCM. Plaintext never leaves your browser.
        </p>
      </div>

      {status === 'error' && (
        <Banner variant="error" title="Encryption Failed">
          {errorMessage || 'Unable to encrypt document. Please verify the file and try again.'}
        </Banner>
      )}

      {status !== 'success' ? (
        <div>
          <FileDropzone
            onFileSelect={(selected) => setFile(selected)}
            selectedFile={file}
            onClear={() => setFile(null)}
            label="Select file to encrypt"
            hint="Any document, image, or file type (processed 100% locally in browser)"
            disabled={status === 'processing'}
          />

          <div style={{ marginTop: '20px' }}>
            <button
              type="button"
              className="btn btn-primary"
              onClick={handleEncrypt}
              disabled={!file || status === 'processing'}
            >
              <Lock size={18} aria-hidden="true" />
              <span>{status === 'processing' ? 'Encrypting file...' : 'Encrypt File'}</span>
            </button>
          </div>
        </div>
      ) : (
        <div>
          <Banner variant="success" title="File Encrypted Successfully">
            Your document has been packaged into an authenticated <code>.sbox</code> container.
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
              <span>Encrypt Another Document</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
