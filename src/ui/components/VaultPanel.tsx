import React, { useEffect, useState } from 'react';
import {
  FileText,
  Download,
  Trash2,
  Share2,
  Search,
  HardDrive,
  RefreshCw,
  FolderArchive,
  ArrowUpDown,
  Lock,
  Unlock,
  Copy,
  Check,
} from 'lucide-react';
import { api, VaultDocument, SharedDocumentItem, SharedByMeDocumentItem } from '../../services/api';
import { formatFileSize } from '../components/common/FileDropzone';
import { Banner } from '../components/common/Banner';
import { ShareModal } from './ShareModal';
import { useAuth } from '../context/AuthContext';
import { unwrapKeyAsRecipient } from '../../core/crypto/sharingKeyUtils';
import { bytesToHex, parseKeyFromInput } from '../../core/crypto/keyUtils';
import { decryptAnyDocument } from '../../core/crypto/service';

export interface VaultPanelProps {
  externalSearchQuery?: string;
  collaboratorFilter?: string | null;
  onClearCollaboratorFilter?: () => void;
  vaultTab?: 'mine' | 'shared-with-me' | 'shared-by-me';
  onVaultTabChange?: (tab: 'mine' | 'shared-with-me' | 'shared-by-me') => void;
}

export const VaultPanel: React.FC<VaultPanelProps> = ({
  externalSearchQuery = '',
  collaboratorFilter = null,
  onClearCollaboratorFilter,
  vaultTab = 'mine',
  onVaultTabChange,
}) => {
  const [documents, setDocuments] = useState<VaultDocument[]>([]);
  const [sharedWithMe, setSharedWithMe] = useState<SharedDocumentItem[]>([]);
  const [sharedByMe, setSharedByMe] = useState<SharedByMeDocumentItem[]>([]);
  const [usageBytes, setUsageBytes] = useState<number>(0);
  const [quotaBytes, setQuotaBytes] = useState<number>(104857600);

  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [localSearchQuery, setLocalSearchQuery] = useState<string>('');
  const [sortField, setSortField] = useState<'name' | 'created_at' | 'ciphertext_size'>('created_at');
  const [sortAsc, setSortAsc] = useState<boolean>(false);

  const [internalTab, setInternalTab] = useState<'mine' | 'shared-with-me' | 'shared-by-me'>('mine');
  const activeTab = vaultTab || internalTab;
  const setActiveTab = (tab: 'mine' | 'shared-with-me' | 'shared-by-me') => {
    setInternalTab(tab);
    if (onVaultTabChange) onVaultTabChange(tab);
  };

  const [sharingDoc, setSharingDoc] = useState<VaultDocument | null>(null);

  // Unwrapped key helper state for shared items
  const [unwrappedKeys, setUnwrappedKeys] = useState<Record<string, string>>({});
  const [unwrappingShareId, setUnwrappingShareId] = useState<string | null>(null);
  const [copiedKeyShareId, setCopiedKeyShareId] = useState<string | null>(null);
  const [decryptingShareId, setDecryptingShareId] = useState<string | null>(null);
  const [revokingShareId, setRevokingShareId] = useState<string | null>(null);

  const { user, sharingPrivateKey, sessionEpoch, ensureSharingKeypair } = useAuth();

  const loadData = async () => {
    if (!user) {
      setDocuments([]);
      setSharedWithMe([]);
      setSharedByMe([]);
      setUnwrappedKeys({});
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const [docsRes, sharedWithRes, sharedByRes] = await Promise.all([
        api.listDocuments(),
        api.listSharedWithMe(),
        api.listSharedByMe().catch(() => ({ shares: [] })),
      ]);
      setDocuments(docsRes.documents);
      setUsageBytes(docsRes.usageBytes);
      setQuotaBytes(docsRes.quotaBytes);
      setSharedWithMe(sharedWithRes.shares);
      setSharedByMe(sharedByRes.shares);
    } catch (err) {
      if (err instanceof Error && err.message === 'Request cancelled') {
        return;
      }
      setError(err instanceof Error ? err.message : 'Failed to load vault items.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!user) {
      setDocuments([]);
      setSharedWithMe([]);
      setSharedByMe([]);
      setUnwrappedKeys({});
      setSharingDoc(null);
    } else {
      loadData();
    }
    return () => {
      // Clear sensitive memory on unmount
      setDocuments([]);
      setSharedWithMe([]);
      setSharedByMe([]);
      setUnwrappedKeys({});
      setSharingDoc(null);
    };
  }, [user?.id, sessionEpoch]);

  useEffect(() => {
    const handleSharesUpdated = () => {
      if (user) loadData();
    };
    window.addEventListener('securebox:shares-updated', handleSharesUpdated);
    return () => window.removeEventListener('securebox:shares-updated', handleSharesUpdated);
  }, [user?.id]);

  const handleDelete = async (doc: VaultDocument) => {
    if (!window.confirm(`Permanently delete "${doc.name}" from your vault?`)) return;
    try {
      await api.deleteDocument(doc.id);
      setDocuments((prev) => prev.filter((d) => d.id !== doc.id));
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Delete failed');
    }
  };

  const handleDownload = async (docId: string, filename: string) => {
    try {
      const blob = await api.downloadDocumentBlob(docId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${filename}.sbox`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Download failed');
    }
  };

  const handleUnwrapSharedKey = async (share: SharedDocumentItem): Promise<string | null> => {
    let privKey = sharingPrivateKey;
    if (!privKey && user) {
      privKey = await ensureSharingKeypair();
    }
    if (!privKey || !user) {
      setError('Sharing private key not loaded for this session. Please check your account keypair settings.');
      return null;
    }
    setUnwrappingShareId(share.share_id);
    setError(null);
    try {
      const contextInfo = `doc:${share.document_id}:recipient:${user.id}:v1`;
      const unwrappedBytes = await unwrapKeyAsRecipient(
        share.wrapped_key_recipient,
        share.ephemeralPublicKeyJwk,
        privKey,
        contextInfo
      );
      const hex = bytesToHex(unwrappedBytes);
      setUnwrappedKeys((prev) => ({ ...prev, [share.share_id]: hex }));
      return hex;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to unwrap shared key.');
      return null;
    } finally {
      setUnwrappingShareId(null);
    }
  };

  const handleCopySharedKey = async (shareId: string, hex: string) => {
    try {
      await navigator.clipboard.writeText(hex);
      setCopiedKeyShareId(shareId);
      setTimeout(() => setCopiedKeyShareId(null), 2500);
    } catch {
      setCopiedKeyShareId(null);
    }
  };

  const handleDecryptSharedDoc = async (share: SharedDocumentItem) => {
    setDecryptingShareId(share.share_id);
    setError(null);
    try {
      let hex = unwrappedKeys[share.share_id];
      if (!hex) {
        let privKey = sharingPrivateKey;
        if (!privKey && user) {
          privKey = await ensureSharingKeypair();
        }
        if (!privKey || !user) {
          throw new Error('Your sharing private key is not loaded for this session.');
        }
        const contextInfo = `doc:${share.document_id}:recipient:${user.id}:v1`;
        const unwrappedBytes = await unwrapKeyAsRecipient(
          share.wrapped_key_recipient,
          share.ephemeralPublicKeyJwk,
          privKey,
          contextInfo
        );
        hex = bytesToHex(unwrappedBytes);
        setUnwrappedKeys((prev) => ({ ...prev, [share.share_id]: hex }));
      }

      let blob: Blob;
      try {
        blob = await api.downloadDocumentBlob(share.document_id);
      } catch {
        throw new Error('Document ciphertext artifact is missing on server or access was revoked.');
      }

      const arrayBuffer = await blob.arrayBuffer();
      const sboxBytes = new Uint8Array(arrayBuffer);
      const cryptoKey = await parseKeyFromInput(hex);

      const result = await decryptAnyDocument(sboxBytes, cryptoKey);

      const url = URL.createObjectURL(result.downloadBlob);
      const a = document.createElement('a');
      a.href = url;
      a.download = result.downloadFilename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Decryption failed: integrity verification error.');
    } finally {
      setDecryptingShareId(null);
    }
  };

  const handleRevokeShare = async (share: SharedByMeDocumentItem) => {
    if (!window.confirm(`Revoke access to "${share.document_name}" for @${share.recipient_username}?`)) return;
    setRevokingShareId(share.share_id);
    setError(null);
    try {
      await api.revokeShare(share.share_id);
      await loadData();
      window.dispatchEvent(new CustomEvent('securebox:shares-updated'));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to revoke document share.');
    } finally {
      setRevokingShareId(null);
    }
  };

  const effectiveSearchQuery = (externalSearchQuery || localSearchQuery).trim().toLowerCase();

  const filteredDocs = documents
    .filter((d) => {
      if (!effectiveSearchQuery) return true;
      const matchName = d.name.toLowerCase().includes(effectiveSearchQuery);
      const matchFormat = (d.format_version === 2 ? 'archive' : 'single file').includes(effectiveSearchQuery);
      return matchName || matchFormat;
    })
    .sort((a, b) => {
      let valA = a[sortField];
      let valB = b[sortField];
      if (typeof valA === 'string') {
        valA = (valA as string).toLowerCase();
        valB = (valB as string).toLowerCase();
      }
      if (valA < valB) return sortAsc ? -1 : 1;
      if (valA > valB) return sortAsc ? 1 : -1;
      return 0;
    });

  const filteredSharedWithMe = sharedWithMe.filter((s) => {
    if (collaboratorFilter && s.sender_username.toLowerCase() !== collaboratorFilter.toLowerCase()) {
      return false;
    }
    if (!effectiveSearchQuery) return true;
    const matchDoc = s.document_name.toLowerCase().includes(effectiveSearchQuery);
    const matchSender = s.sender_username.toLowerCase().includes(effectiveSearchQuery);
    return matchDoc || matchSender;
  });

  const filteredSharedByMe = sharedByMe.filter((s) => {
    if (collaboratorFilter && s.recipient_username.toLowerCase() !== collaboratorFilter.toLowerCase()) {
      return false;
    }
    if (!effectiveSearchQuery) return true;
    const matchDoc = s.document_name.toLowerCase().includes(effectiveSearchQuery);
    const matchRecipient = s.recipient_username.toLowerCase().includes(effectiveSearchQuery);
    return matchDoc || matchRecipient;
  });

  const percentUsed = Math.min(100, Math.round((usageBytes / quotaBytes) * 100));

  return (
    <div className="panel-card vault-container">
      <div className="panel-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <h2 className="panel-title">Private Document Vault</h2>
          <p className="panel-subtitle">
            Zero-knowledge encrypted storage. Plaintext and keys never leave your browser unencrypted.
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div className="storage-meter">
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              <HardDrive size={14} aria-hidden="true" />
              <span>
                {formatFileSize(usageBytes)} / {formatFileSize(quotaBytes)} ({percentUsed}%)
              </span>
            </div>
            <div className="meter-track">
              <div className="meter-fill" style={{ width: `${percentUsed}%` }} />
            </div>
          </div>
          <button type="button" className="btn btn-secondary btn-sm" onClick={loadData} disabled={loading} title="Refresh vault">
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} aria-hidden="true" />
          </button>
        </div>
      </div>

      {error && <Banner variant="error" title="Vault Notice">{error}</Banner>}

      {collaboratorFilter && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '8px 14px',
            marginBottom: '16px',
            background: 'rgba(224, 242, 254, 0.7)',
            borderRadius: 'var(--sb-radius-sm)',
            border: '1px solid var(--sb-border-focus)',
            fontSize: '0.8125rem',
          }}
        >
          <span>
            Filtering records by collaborator: <strong>@{collaboratorFilter}</strong>
          </span>
          {onClearCollaboratorFilter && (
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={onClearCollaboratorFilter}
              style={{ padding: '2px 8px', fontSize: '0.75rem' }}
            >
              Clear Filter
            </button>
          )}
        </div>
      )}

      {/* Clean, Data-Backed Stat Cards (No Fake Sparklines) */}
      <div className="reference-metrics-row">
        {/* Card 1: User Profile & Security Guarantee */}
        <div className="glass-stat-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginBottom: '8px' }}>
            <div
              style={{
                width: '42px',
                height: '42px',
                borderRadius: '50%',
                background: 'var(--sb-primary)',
                color: '#fff',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '1rem',
                fontWeight: 700,
                boxShadow: '0 4px 10px rgba(29, 114, 254, 0.25)',
              }}
            >
              {user ? user.username.slice(0, 2).toUpperCase() : 'SB'}
            </div>
            <div>
              <div style={{ fontSize: '1.25rem', fontWeight: 800, color: 'var(--sb-text)', lineHeight: 1.2 }}>
                Hello {user ? user.username : 'User'}
              </div>
              <div style={{ fontSize: '0.8125rem', color: 'var(--sb-text-secondary)', marginTop: '2px' }}>
                {documents.length} encrypted vault items
              </div>
            </div>
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--sb-text-muted)' }}>
            E2EE Client-Side Storage
          </div>
        </div>

        {/* Card 2: Vault Documents Metric */}
        <div className="glass-stat-card">
          <div className="stat-card-header">
            <span className="stat-card-title">TOTAL DOCUMENTS</span>
          </div>
          <div className="stat-card-body">
            <div>
              <div className="stat-card-num">{documents.length}</div>
              <div className="stat-card-sub">Active encrypted files</div>
            </div>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#16a34a' }}>
                AES-256-GCM
              </div>
              <div style={{ fontSize: '0.6875rem', color: 'var(--sb-text-muted)' }}>
                Authenticated
              </div>
            </div>
          </div>
        </div>

        {/* Card 3: Storage Used Metric */}
        <div className="glass-stat-card">
          <div className="stat-card-header">
            <span className="stat-card-title">STORAGE USED</span>
          </div>
          <div className="stat-card-body">
            <div>
              <div className="stat-card-num" style={{ fontSize: '1.75rem' }}>{formatFileSize(usageBytes)}</div>
              <div className="stat-card-sub">of {formatFileSize(quotaBytes)} quota</div>
            </div>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '0.8125rem', fontWeight: 700, color: percentUsed > 80 ? '#dc2626' : 'var(--sb-text)' }}>
                {percentUsed}%
              </div>
              <div style={{ fontSize: '0.6875rem', color: 'var(--sb-text-muted)' }}>
                Quota used
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Tabs between My Vault, Shared With Me, and Shared By Me */}
      <div className="vault-tabs" style={{ display: 'flex', gap: '8px', borderBottom: '1px solid var(--sb-border)', marginBottom: '16px' }}>
        <button
          type="button"
          className={`tab-btn ${activeTab === 'mine' ? 'active' : ''}`}
          onClick={() => setActiveTab('mine')}
          style={{ borderBottom: activeTab === 'mine' ? '2px solid var(--text-primary)' : '2px solid transparent' }}
        >
          <span>My Documents ({documents.length})</span>
        </button>
        <button
          type="button"
          className={`tab-btn ${activeTab === 'shared-with-me' ? 'active' : ''}`}
          onClick={() => setActiveTab('shared-with-me')}
          style={{ borderBottom: activeTab === 'shared-with-me' ? '2px solid var(--text-primary)' : '2px solid transparent' }}
        >
          <span>Shared With Me ({sharedWithMe.length})</span>
        </button>
        <button
          type="button"
          className={`tab-btn ${activeTab === 'shared-by-me' ? 'active' : ''}`}
          onClick={() => setActiveTab('shared-by-me')}
          style={{ borderBottom: activeTab === 'shared-by-me' ? '2px solid var(--text-primary)' : '2px solid transparent' }}
        >
          <span>Shared By Me ({sharedByMe.length})</span>
        </button>
      </div>

      {activeTab === 'mine' && (
        <div>
          {/* Sort Toolbar */}
          <div style={{ display: 'flex', justifyContent: 'space-between', gap: '12px', marginBottom: '16px', flexWrap: 'wrap' }}>
            <div style={{ position: 'relative', flex: '1', minWidth: '220px' }}>
              <Search size={16} style={{ position: 'absolute', left: '10px', top: '10px', color: 'var(--text-muted)' }} />
              <input
                type="text"
                className="form-input"
                style={{ paddingLeft: '32px' }}
                placeholder="Search documents by name or format..."
                value={externalSearchQuery ? externalSearchQuery : localSearchQuery}
                onChange={(e) => setLocalSearchQuery(e.target.value)}
              />
            </div>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <span style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>Sort by:</span>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => {
                  if (sortField === 'created_at') setSortField('name');
                  else if (sortField === 'name') setSortField('ciphertext_size');
                  else setSortField('created_at');
                  setSortAsc(!sortAsc);
                }}
              >
                <ArrowUpDown size={14} aria-hidden="true" />
                <span>{sortField === 'name' ? 'Name' : sortField === 'ciphertext_size' ? 'Size' : 'Date'}</span>
              </button>
            </div>
          </div>

          {/* Documents Table / List */}
          {filteredDocs.length === 0 ? (
            <div className="empty-vault-state" style={{ textAlign: 'center', padding: '40px 16px', color: 'var(--text-muted)' }}>
              <Lock size={36} style={{ margin: '0 auto 12px', opacity: 0.5 }} />
              {effectiveSearchQuery ? (
                <p>No documents match your search &quot;{effectiveSearchQuery}&quot;.</p>
              ) : (
                <>
                  <p>No documents found in your private vault.</p>
                  <p style={{ fontSize: '0.8125rem', marginTop: '4px' }}>
                    Use the Encrypt workspace above to encrypt and store documents in SecureBox.
                  </p>
                </>
              )}
            </div>
          ) : (
            <div className="vault-table-wrapper" style={{ overflowX: 'auto' }}>
              <table className="vault-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-subtle)', textAlign: 'left', color: 'var(--text-secondary)' }}>
                    <th style={{ padding: '10px 12px' }}>Name</th>
                    <th style={{ padding: '10px 12px' }}>Format</th>
                    <th style={{ padding: '10px 12px' }}>Encrypted Size</th>
                    <th style={{ padding: '10px 12px' }}>Upload Date</th>
                    <th style={{ padding: '10px 12px' }}>Shares</th>
                    <th style={{ padding: '10px 12px', textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredDocs.map((doc) => (
                    <tr key={doc.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                      <td style={{ padding: '12px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          {doc.format_version === 2 ? (
                            <FolderArchive size={18} color="var(--border-focus)" />
                          ) : (
                            <FileText size={18} color="var(--text-secondary)" />
                          )}
                          <span style={{ fontWeight: 500 }} title={doc.name}>
                            {doc.name}
                          </span>
                        </div>
                      </td>
                      <td style={{ padding: '12px', color: 'var(--text-secondary)' }}>
                        {doc.format_version === 2 ? `Archive (${doc.file_count} files)` : 'Single File'}
                      </td>
                      <td style={{ padding: '12px' }}>{formatFileSize(doc.ciphertext_size)}</td>
                      <td style={{ padding: '12px', color: 'var(--text-secondary)' }}>
                        {new Date(doc.created_at).toLocaleDateString()}
                      </td>
                      <td style={{ padding: '12px' }}>
                        {doc.active_shares_count && doc.active_shares_count > 0 ? (
                          <span className="priority-pill medium">{doc.active_shares_count} shared</span>
                        ) : (
                          <span className="priority-pill low">Encrypted</span>
                        )}
                      </td>
                      <td style={{ padding: '12px', textAlign: 'right' }}>
                        <div style={{ display: 'inline-flex', gap: '6px' }}>
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm"
                            onClick={() => handleDownload(doc.id, doc.name)}
                            title="Download .sbox file"
                          >
                            <Download size={14} aria-hidden="true" />
                          </button>
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm"
                            onClick={() => setSharingDoc(doc)}
                            title="Share with user"
                          >
                            <Share2 size={14} aria-hidden="true" />
                          </button>
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm"
                            onClick={() => handleDelete(doc)}
                            title="Delete permanently"
                            style={{ color: 'var(--state-error-text)' }}
                          >
                            <Trash2 size={14} aria-hidden="true" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {activeTab === 'shared-with-me' && (
        <div>
          {filteredSharedWithMe.length === 0 ? (
            <div className="empty-vault-state" style={{ textAlign: 'center', padding: '40px 16px', color: 'var(--text-muted)' }}>
              <Share2 size={36} style={{ margin: '0 auto 12px', opacity: 0.5 }} />
              {effectiveSearchQuery || collaboratorFilter ? (
                <p>No incoming shared documents match your filter.</p>
              ) : (
                <p>No documents have been shared with you yet.</p>
              )}
            </div>
          ) : (
            <div className="vault-table-wrapper" style={{ overflowX: 'auto' }}>
              <table className="vault-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-subtle)', textAlign: 'left', color: 'var(--text-secondary)' }}>
                    <th style={{ padding: '10px 12px' }}>Document Name</th>
                    <th style={{ padding: '10px 12px' }}>Shared By</th>
                    <th style={{ padding: '10px 12px' }}>Size</th>
                    <th style={{ padding: '10px 12px' }}>Date</th>
                    <th style={{ padding: '10px 12px' }}>Key Material</th>
                    <th style={{ padding: '10px 12px', textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredSharedWithMe.map((item) => {
                    const keyHex = unwrappedKeys[item.share_id];
                    return (
                      <tr key={item.share_id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                        <td style={{ padding: '12px', fontWeight: 500 }}>{item.document_name}</td>
                        <td style={{ padding: '12px', color: 'var(--border-focus)' }}>@{item.sender_username}</td>
                        <td style={{ padding: '12px' }}>{formatFileSize(item.ciphertext_size)}</td>
                        <td style={{ padding: '12px', color: 'var(--text-secondary)' }}>
                          {new Date(item.shared_at).toLocaleDateString()}
                        </td>
                        <td style={{ padding: '12px' }}>
                          {keyHex ? (
                            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                              <code style={{ fontSize: '0.75rem', background: 'var(--bg-subtle)', padding: '2px 6px', borderRadius: '4px' }}>
                                {keyHex.slice(0, 8)}...{keyHex.slice(-8)}
                              </code>
                              <button
                                type="button"
                                className="btn btn-secondary btn-sm"
                                onClick={() => handleCopySharedKey(item.share_id, keyHex)}
                                title="Copy 256-bit decryption key"
                                style={{ padding: '2px 6px' }}
                              >
                                {copiedKeyShareId === item.share_id ? <Check size={12} color="#16a34a" /> : <Copy size={12} />}
                              </button>
                            </div>
                          ) : (
                            <button
                              type="button"
                              className="btn btn-secondary btn-sm"
                              onClick={() => handleUnwrapSharedKey(item)}
                              disabled={unwrappingShareId === item.share_id}
                            >
                              <Lock size={12} aria-hidden="true" />
                              <span>{unwrappingShareId === item.share_id ? 'Unwrapping...' : 'Unwrap Key'}</span>
                            </button>
                          )}
                        </td>
                        <td style={{ padding: '12px', textAlign: 'right' }}>
                          <div style={{ display: 'inline-flex', gap: '6px' }}>
                            <button
                              type="button"
                              className="btn btn-primary btn-sm"
                              onClick={() => handleDecryptSharedDoc(item)}
                              disabled={decryptingShareId === item.share_id}
                              title="Decrypt and save document locally"
                            >
                              <Unlock size={14} aria-hidden="true" />
                              <span>{decryptingShareId === item.share_id ? 'Decrypting...' : 'Decrypt'}</span>
                            </button>
                            <button
                              type="button"
                              className="btn btn-secondary btn-sm"
                              onClick={() => handleDownload(item.document_id, item.document_name)}
                              title="Download encrypted .sbox file"
                            >
                              <Download size={14} aria-hidden="true" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {activeTab === 'shared-by-me' && (
        <div>
          {filteredSharedByMe.length === 0 ? (
            <div className="empty-vault-state" style={{ textAlign: 'center', padding: '40px 16px', color: 'var(--text-muted)' }}>
              <Share2 size={36} style={{ margin: '0 auto 12px', opacity: 0.5 }} />
              {effectiveSearchQuery || collaboratorFilter ? (
                <p>No outgoing shared documents match your filter.</p>
              ) : (
                <p>You have not shared any documents with others yet.</p>
              )}
            </div>
          ) : (
            <div className="vault-table-wrapper" style={{ overflowX: 'auto' }}>
              <table className="vault-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-subtle)', textAlign: 'left', color: 'var(--text-secondary)' }}>
                    <th style={{ padding: '10px 12px' }}>Document Name</th>
                    <th style={{ padding: '10px 12px' }}>Recipient</th>
                    <th style={{ padding: '10px 12px' }}>Status</th>
                    <th style={{ padding: '10px 12px' }}>Permission</th>
                    <th style={{ padding: '10px 12px' }}>Date</th>
                    <th style={{ padding: '10px 12px', textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredSharedByMe.map((item) => (
                    <tr key={item.share_id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                      <td style={{ padding: '12px', fontWeight: 500 }}>{item.document_name}</td>
                      <td style={{ padding: '12px', color: 'var(--border-focus)' }}>@{item.recipient_username}</td>
                      <td style={{ padding: '12px' }}>
                        <span className={`priority-pill ${item.status === 'active' ? 'low' : 'high'}`}>
                          {item.status}
                        </span>
                      </td>
                      <td style={{ padding: '12px', textTransform: 'capitalize', color: 'var(--text-secondary)' }}>
                        {item.permission || 'read'}
                      </td>
                      <td style={{ padding: '12px', color: 'var(--text-secondary)' }}>
                        {new Date(item.shared_at).toLocaleDateString()}
                      </td>
                      <td style={{ padding: '12px', textAlign: 'right' }}>
                        {item.status === 'active' && (
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm"
                            onClick={() => handleRevokeShare(item)}
                            disabled={revokingShareId === item.share_id}
                            title="Revoke recipient access"
                            style={{ color: 'var(--state-error-text)' }}
                          >
                            <span>{revokingShareId === item.share_id ? 'Revoking...' : 'Revoke'}</span>
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {sharingDoc && (
        <ShareModal
          document={sharingDoc}
          onClose={() => setSharingDoc(null)}
          onShareCreated={() => {
            loadData();
          }}
        />
      )}
    </div>
  );
};
