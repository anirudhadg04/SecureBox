import React, { useState } from 'react';
import { Copy, Check, CheckCircle2, XCircle, Info } from 'lucide-react';
import { computeSha256 } from '../../core/hashing/sha256';
import { compareHashes, HashComparisonResult } from '../../core/hashing/compare';
import { FileDropzone } from './common/FileDropzone';
import { Banner } from './common/Banner';

export const VerifyPanel: React.FC = () => {
  const [file, setFile] = useState<File | null>(null);
  const [computedHash, setComputedHash] = useState<string>('');
  const [referenceHash, setReferenceHash] = useState<string>('');
  const [isHashing, setIsHashing] = useState<boolean>(false);
  const [copiedHash, setCopiedHash] = useState<boolean>(false);

  const handleFileSelect = async (selected: File) => {
    setFile(selected);
    setIsHashing(true);
    try {
      const buffer = await selected.arrayBuffer();
      const hash = await computeSha256(new Uint8Array(buffer));
      setComputedHash(hash);
    } catch {
      setComputedHash('');
    } finally {
      setIsHashing(false);
    }
  };

  const handleClear = () => {
    setFile(null);
    setComputedHash('');
    setReferenceHash('');
    setCopiedHash(false);
  };

  const handleCopy = async () => {
    if (!computedHash) return;
    try {
      await navigator.clipboard.writeText(computedHash);
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 2500);
    } catch {
      setCopiedHash(false);
    }
  };

  const comparison: HashComparisonResult | null =
    computedHash && referenceHash.trim().length > 0
      ? compareHashes(computedHash, referenceHash)
      : null;

  return (
    <div className="panel-card">
      <div className="panel-header">
        <h2 className="panel-title">Verify File Integrity (SHA-256)</h2>
        <p className="panel-subtitle">
          Generate an independent cryptographic fingerprint or compare a file against a known reference.
        </p>
      </div>

      <FileDropzone
        onFileSelect={handleFileSelect}
        selectedFile={file}
        onClear={handleClear}
        label="Select file to inspect"
        hint="Computes SHA-256 fingerprint locally in memory"
        disabled={isHashing}
      />

      {isHashing && (
        <div style={{ marginTop: '16px', color: 'var(--text-secondary)', fontSize: '0.9375rem' }}>
          Computing SHA-256 fingerprint...
        </div>
      )}

      {computedHash && (
        <div style={{ marginTop: '24px' }}>
          <div className="form-group">
            <label className="form-label" htmlFor="computed-fingerprint">
              Computed SHA-256 Fingerprint
            </label>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <input
                id="computed-fingerprint"
                type="text"
                readOnly
                value={computedHash}
                className="form-input"
                aria-label="Computed SHA-256 fingerprint in hexadecimal"
              />
              <button
                type="button"
                className="btn btn-secondary"
                onClick={handleCopy}
                aria-label="Copy fingerprint to clipboard"
              >
                {copiedHash ? <Check size={18} aria-hidden="true" /> : <Copy size={18} aria-hidden="true" />}
                <span>{copiedHash ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
          </div>

          <div className="form-group" style={{ marginTop: '20px' }}>
            <label className="form-label" htmlFor="reference-hash-input">
              Compare Against Reference Fingerprint (Optional)
            </label>
            <input
              id="reference-hash-input"
              type="text"
              className="form-input"
              placeholder="Paste reference SHA-256 hash to verify..."
              value={referenceHash}
              onChange={(e) => setReferenceHash(e.target.value)}
              aria-label="Enter reference SHA-256 hash to compare against"
            />
            <p className="form-help">
              Leading/trailing whitespace, delimiters, and case differences are ignored automatically.
            </p>
          </div>

          {comparison && (
            <div style={{ marginTop: '20px' }}>
              {comparison.match ? (
                <Banner variant="success" title="Fingerprints Match">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <CheckCircle2 size={18} aria-hidden="true" />
                    <span>The file is bit-for-bit identical to the reference fingerprint.</span>
                  </div>
                </Banner>
              ) : (
                <Banner variant="error" title="Fingerprint Mismatch">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                    <XCircle size={18} aria-hidden="true" />
                    <span>
                      The file differs from the reference fingerprint. The document may have been altered or corrupted.
                    </span>
                  </div>

                  {comparison.canonicalReference.length === 64 && (
                    <div style={{ marginTop: '12px' }}>
                      <div style={{ fontSize: '0.8125rem', marginBottom: '4px', fontWeight: 600 }}>
                        Character-by-character alignment:
                      </div>
                      <div className="hash-diff-view">
                        <div>
                          <strong>Computed:  </strong>
                          {comparison.canonicalComputed.split('').map((char, idx) => {
                            const isDiff = comparison.differingIndices.includes(idx);
                            return (
                              <span
                                key={idx}
                                className={isDiff ? 'diff-char-mismatch' : 'diff-char-match'}
                              >
                                {char}
                              </span>
                            );
                          })}
                        </div>
                        <div style={{ marginTop: '4px' }}>
                          <strong>Reference: </strong>
                          {comparison.canonicalReference.split('').map((char, idx) => {
                            const isDiff = comparison.differingIndices.includes(idx);
                            return (
                              <span
                                key={idx}
                                className={isDiff ? 'diff-char-mismatch' : 'diff-char-match'}
                              >
                                {char}
                              </span>
                            );
                          })}
                        </div>
                      </div>
                    </div>
                  )}
                </Banner>
              )}
            </div>
          )}

          <Banner variant="info" title="Integrity vs. Authenticity Notice">
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '8px' }}>
              <Info size={18} aria-hidden="true" style={{ flexShrink: 0, marginTop: '2px' }} />
              <div>
                A matching SHA-256 fingerprint proves <strong>integrity</strong> (equality to the reference),
                not <strong>identity</strong> or <strong>authority</strong>. It confirms the file has not changed,
                but does not verify who authored or published it.
              </div>
            </div>
          </Banner>
        </div>
      )}
    </div>
  );
};
