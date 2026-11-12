import React, { useState } from 'react';
import { Share2, UserCheck, ShieldCheck, X } from 'lucide-react';
import { api, VaultDocument } from '../../services/api';
import { Banner } from '../components/common/Banner';
import { wrapKeyForRecipient } from '../../core/crypto/sharingKeyUtils';
import { parseKeyFromInput } from '../../core/crypto/keyUtils';

interface ShareModalProps {
  document: VaultDocument;
  onClose: () => void;
  onShareCreated: () => void;
}

export const ShareModal: React.FC<ShareModalProps> = ({ document: doc, onClose, onShareCreated }) => {
  const [recipientUsername, setRecipientUsername] = useState('');
  const [documentKeyHex, setDocumentKeyHex] = useState('');
  const [confirmedRecipient, setConfirmedRecipient] = useState<{ userId: string; username: string; publicKeyJwk: JsonWebKey } | null>(null);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<boolean>(false);

  // Step 1: Look up recipient
  const handleLookupRecipient = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!recipientUsername.trim()) return;
    setError(null);
    setLoading(true);
    try {
      const res = await api.getRecipientPublicKey(recipientUsername.trim());
      setConfirmedRecipient(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'User not found or has not published a sharing key.');
      setConfirmedRecipient(null);
    } finally {
      setLoading(false);
    }
  };

  // Step 2: Recipient-bound key wrapping and sending
  const handleSendDecryptionKey = async () => {
    if (!confirmedRecipient || !documentKeyHex.trim()) return;

    setError(null);
    setLoading(true);

    try {
      // 1. Import raw document AES key from hex
      const cryptoKey = await parseKeyFromInput(documentKeyHex.trim());
      const rawKeyBuffer = await crypto.subtle.exportKey('raw', cryptoKey);
      const rawKeyBytes = new Uint8Array(rawKeyBuffer);

      // 2. Cryptographic binding context: document ID + recipient
      const contextInfo = `doc:${doc.id}:recipient:${confirmedRecipient.userId}:v1`;

      // 3. Wrap AES key specifically for recipient's ECDH public key
      const { ephemeralPublicKeyJwk, wrappedKeyBase64 } = await wrapKeyForRecipient(
        rawKeyBytes,
        confirmedRecipient.publicKeyJwk,
        contextInfo
      );

      // 4. Send share grant to server
      await api.shareDocument({
        documentId: doc.id,
        recipientUsername: confirmedRecipient.username,
        wrappedKeyRecipient: wrappedKeyBase64,
        ephemeralPublicKeyJwk,
      });

      setSuccess(true);
      onShareCreated();
      window.dispatchEvent(new CustomEvent('securebox:shares-updated'));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to wrap and send decryption key.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-backdrop">
      <div className="modal-card panel-card" role="dialog" aria-modal="true" aria-labelledby="share-modal-title">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Share2 size={20} aria-hidden="true" />
            <h3 id="share-modal-title" style={{ fontSize: '1.2rem', fontWeight: 600, margin: 0 }}>
              Share Document: {doc.name}
            </h3>
          </div>
          <button type="button" className="btn btn-secondary btn-sm" onClick={onClose} aria-label="Close modal">
            <X size={16} aria-hidden="true" />
          </button>
        </div>

        {error && <Banner variant="error" title="Sharing Error">{error}</Banner>}

        {success ? (
          <div>
            <Banner variant="success" title="Decryption Key Delivered">
              The decryption key for <strong>{doc.name}</strong> was wrapped specifically for recipient{' '}
              <strong>{confirmedRecipient?.username}</strong> and securely registered. Only their private key can unwrap it.
            </Banner>
            <div style={{ marginTop: '20px', textAlign: 'right' }}>
              <button type="button" className="btn btn-primary" onClick={onClose}>
                Done
              </button>
            </div>
          </div>
        ) : (
          <div>
            {!confirmedRecipient ? (
              <form onSubmit={handleLookupRecipient}>
                <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginBottom: '16px' }}>
                  Search for a registered SecureBox user by username to verify their public key before sharing.
                </p>
                <div className="form-group" style={{ marginBottom: '16px' }}>
                  <label className="form-label" htmlFor="recipient-username-input">
                    Recipient Username
                  </label>
                  <input
                    id="recipient-username-input"
                    type="text"
                    required
                    className="form-input"
                    placeholder="e.g. bob"
                    value={recipientUsername}
                    onChange={(e) => setRecipientUsername(e.target.value)}
                    disabled={loading}
                  />
                </div>
                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
                  <button type="button" className="btn btn-secondary" onClick={onClose} disabled={loading}>
                    Cancel
                  </button>
                  <button type="submit" className="btn btn-primary" disabled={loading}>
                    <UserCheck size={16} aria-hidden="true" />
                    <span>{loading ? 'Verifying...' : 'Verify Recipient'}</span>
                  </button>
                </div>
              </form>
            ) : (
              <div>
                <Banner variant="info" title="Recipient Verified">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <ShieldCheck size={16} aria-hidden="true" />
                    <span>
                      Public key found for <strong>{confirmedRecipient.username}</strong> (NIST P-256 curve).
                    </span>
                  </div>
                </Banner>

                <div className="form-group" style={{ margin: '16px 0' }}>
                  <label className="form-label" htmlFor="doc-key-input">
                    Document 256-bit Decryption Key (Hex)
                  </label>
                  <input
                    id="doc-key-input"
                    type="text"
                    required
                    className="form-input"
                    placeholder="Paste the 64-character hex key for this document"
                    value={documentKeyHex}
                    onChange={(e) => setDocumentKeyHex(e.target.value)}
                    disabled={loading}
                  />
                  <p className="form-help">
                    The key is wrapped client-side via ECDH key agreement. The server never receives raw key bytes.
                  </p>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '20px' }}>
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    onClick={() => setConfirmedRecipient(null)}
                    disabled={loading}
                  >
                    Change Recipient
                  </button>
                  <div style={{ display: 'flex', gap: '8px' }}>
                    <button type="button" className="btn btn-secondary" onClick={onClose} disabled={loading}>
                      Cancel
                    </button>
                    {/* Exact label required by prompt */}
                    <button
                      type="button"
                      className="btn btn-primary"
                      onClick={handleSendDecryptionKey}
                      disabled={!documentKeyHex.trim() || loading}
                    >
                      <Share2 size={16} aria-hidden="true" />
                      <span>{loading ? 'Wrapping Key...' : 'Send decryption key'}</span>
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
